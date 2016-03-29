from datetime import datetime
import logging
import random
import re
import requests
from requests_toolbelt import user_agent
import string
import time
from urllib.parse import urljoin

from django.conf import settings
from django.db import models
from django.core.exceptions import ValidationError
from jsonfield import JSONField

from deis import __version__ as deis_version
from api.models import UuidAuditedModel, log_event, AlreadyExists

from api.utils import generate_app_name, app_build_type
from api.models.release import Release
from api.models.config import Config
from api.models.domain import Domain

from scheduler import KubeHTTPException, KubeException

logger = logging.getLogger(__name__)


# http://kubernetes.io/v1.1/docs/design/identifiers.html
def validate_id_is_docker_compatible(value):
    """
    Check that the value follows the kubernetes name constraints
    """
    match = re.match(r'^[a-z0-9-]+$', value)
    if not match:
        raise ValidationError("App name can only contain a-z (lowercase), 0-9 and hypens")


def validate_app_structure(value):
    """Error if the dict values aren't ints >= 0"""
    try:
        if any(int(v) < 0 for v in value.values()):
            raise ValueError("Must be greater than or equal to zero")
    except ValueError as err:
        raise ValidationError(err)


def validate_reserved_names(value):
    """A value cannot use some reserved names."""
    if value in settings.DEIS_RESERVED_NAMES:
        raise ValidationError('{} is a reserved name.'.format(value))


class Pod(dict):
    pass


class App(UuidAuditedModel):
    """
    Application used to service requests on behalf of end-users
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL)
    id = models.SlugField(max_length=24, unique=True, null=True,
                          validators=[validate_id_is_docker_compatible,
                                      validate_reserved_names])
    structure = JSONField(default={}, blank=True, validators=[validate_app_structure])

    class Meta:
        permissions = (('use_app', 'Can use app'),)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = generate_app_name()
            while App.objects.filter(id=self.id).exists():
                self.id = generate_app_name()

        # verify the application name doesn't exist as a k8s namespace
        # only check for it if there have been on releases
        try:
            self.release_set.latest()
        except Release.DoesNotExist:
            try:
                if self._scheduler._get_namespace(self.id).status_code == 200:
                    # Namespace already exists
                    err = "{} already exists as a namespace in this kuberenetes setup".format(self.id)  # noqa
                    log_event(self, err, logging.INFO)
                    raise AlreadyExists(err)
            except KubeHTTPException:
                pass

        application = super(App, self).save(**kwargs)

        # create all the required resources
        self.create(*args, **kwargs)

        return application

    def __str__(self):
        return self.id

    def _get_job_id(self, container_type):
        app = self.id
        release = self.release_set.latest()
        version = "v{}".format(release.version)
        job_id = "{app}-{version}-{container_type}".format(**locals())
        return job_id

    def _get_command(self, container_type):
        try:
            # if this is not procfile-based app, ensure they cannot break out
            # and run arbitrary commands on the host
            # FIXME: remove slugrunner's hardcoded entrypoint
            release = self.release_set.latest()
            if release.build.dockerfile or not release.build.sha:
                return "bash -c '{}'".format(release.build.procfile[container_type])

            return 'start {}'.format(container_type)
        # if the key is not present or if a parent attribute is None
        except (KeyError, TypeError, AttributeError):
            # handle special case for Dockerfile deployments
            return '' if container_type == 'cmd' else 'start {}'.format(container_type)

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with an application "tag" that the customized deis-logspout will
        be on the lookout for.  When it's seen, the message-- usually an application event of some
        sort like releasing or scaling, will be considered as "belonging" to the application
        instead of the controller and will be handled accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.id, message))

    def create(self, *args, **kwargs):
        """
        Create a application with an initial config, release, domain
        and k8s resource if needed
        """
        try:
            cfg = self.config_set.latest()
        except Config.DoesNotExist:
            cfg = Config.objects.create(owner=self.owner, app=self)

        # Only create if no release can be found
        try:
            rel = self.release_set.latest()
        except Release.DoesNotExist:
            rel = Release.objects.create(
                version=1, owner=self.owner, app=self,
                config=cfg, build=None
            )

        # create required minimum resources in k8s for the application
        self._scheduler.create(self.id)

        # Attach the platform specific application sub domain to the k8s service
        # Only attach it on first release in case a customer has remove the app domain
        if rel.version == 1 and not Domain.objects.filter(domain=self.id).exists():
            Domain(owner=self.owner, app=self, domain=self.id).save()

    def delete(self, *args, **kwargs):
        """Delete this application including all containers"""
        try:
            # attempt to remove application from kubernetes
            self._scheduler.destroy(self.id)
        except KubeException:
            pass

        self._clean_app_logs()
        return super(App, self).delete(*args, **kwargs)

    def restart(self, **kwargs):  # noqa
        """
        Restart found pods by deleting them (RC will recreate).
        Wait until they are all drained away and RC has gotten to a good state
        """
        try:
            # Resolve single pod name if short form (worker-asdfg) is passed
            if 'name' in kwargs and kwargs['name'].count('-') == 1:
                if 'release' not in kwargs or kwargs['release'] is None:
                    release = self.release_set.latest()
                else:
                    release = self.release_set.get(version=kwargs['release'])

                version = "v{}".format(release.version)
                kwargs['name'] = '{}-{}-{}'.format(kwargs['id'], version, kwargs['name'])

            # Iterate over RCs to get total desired count if not a single item
            desired = 1
            if 'name' not in kwargs:
                desired = 0
                labels = self._scheduler_filter(**kwargs)
                controllers = self._scheduler._get_rcs(kwargs['id'], labels=labels).json()['items']
                for controller in controllers:
                    desired += controller['spec']['replicas']
        except KubeException:
            # Nothing was found
            return []

        try:
            for pod in self.list_pods(**kwargs):
                # This function verifies the delete. Gives pod 30 seconds
                self._scheduler._delete_pod(self.id, pod['name'])
        except Exception as e:
            err = "warning, some pods failed to stop:\n{}".format(str(e))
            log_event(self, err, logging.WARNING)

        # Wait for pods to start
        try:
            timeout = 300  # 5 minutes
            elapsed = 0
            while True:
                # timed out
                if elapsed >= timeout:
                    raise RuntimeError('timeout - 5 minutes have passed and pods are not up')

                # restarting a single pod behaves differently, fetch the *newest* pod
                # and hope it is the right one. Comes back sorted
                if 'name' in kwargs:
                    del kwargs['name']
                    pods = self.list_pods(**kwargs)
                    # Add in the latest name
                    kwargs['name'] = pods[0]['name']
                    pods = pods[0]

                actual = 0
                for pod in self.list_pods(**kwargs):
                    if pod['state'] == 'up':
                        actual += 1

                if desired == actual:
                    break

                elapsed += 5
                time.sleep(5)

        except Exception as e:
            err = "warning, some pods failed to start:\n{}".format(str(e))
            log_event(self, err, logging.WARNING)

        # Return the new pods
        pods = self.list_pods(**kwargs)
        return pods

    def _clean_app_logs(self):
        """Delete application logs stored by the logger component"""
        try:
            url = 'http://{}:{}/logs/{}'.format(settings.LOGGER_HOST,
                                                settings.LOGGER_PORT, self.id)
            requests.delete(url)
        except Exception as e:
            # Ignore errors deleting application logs.  An error here should not interfere with
            # the overall success of deleting an application, but we should log it.
            err = 'Error deleting existing application logs: {}'.format(e)
            log_event(self, err, logging.WARNING)

    def scale(self, user, structure):  # noqa
        """Scale containers up or down to match requested structure."""
        # use create to make sure minimum resources are created
        self.create()

        if self.release_set.latest().build is None:
            raise EnvironmentError('No build associated with this release')

        release = self.release_set.latest()

        # test for available process types
        available_process_types = release.build.procfile or {}
        for container_type in structure:
            if container_type == 'cmd':
                continue  # allow docker cmd types in case we don't have the image source

            if container_type not in available_process_types:
                raise EnvironmentError(
                    'Container type {} does not exist in application'.format(container_type))

        # merge current structure and the new items together
        new_structure = self.structure.copy()
        new_structure.update(structure)

        if new_structure != self.structure:
            # save new structure to the database
            self.structure = new_structure
            self.save()

            self._scale_pods(structure)

            msg = '{} scaled pods '.format(user.username) + ' '.join(
                "{}={}".format(k, v) for k, v in list(structure.items()))
            log_event(self, msg)

            return True

        return False

    def _scale_pods(self, scale_types):
        release = self.release_set.latest()
        build_type = app_build_type(release)
        for scale_type in scale_types:
            image = release.image
            version = "v{}".format(release.version)
            kwargs = {
                'memory': release.config.memory,
                'cpu': release.config.cpu,
                'tags': release.config.tags,
                'envs': release.config.values,
                'version': version,
                'replicas': scale_types[scale_type],
                'app_type': scale_type,
                'build_type': build_type,
                'healthcheck': release.config.healthcheck(),
                # http://docs.deis.io/en/latest/using_deis/process-types/#web-vs-cmd-process-types
                'routable': True if scale_type in ['web', 'cmd'] else False
            }

            command = self._get_command(scale_type)
            try:
                self._scheduler.scale(
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=image,
                    command=command,
                    **kwargs
                )

            except Exception as e:
                err = '{} (scale): {}'.format(self._get_job_id(scale_type), e)
                log_event(self, err, logging.ERROR)
                raise

    def deploy(self, user, release):
        """Deploy a new release to this application"""
        if release.build is None:
            raise EnvironmentError('No build associated with this release')

        # use create to make sure minimum resources are created
        self.create()

        if self.structure == {}:
            self.structure = self._default_structure(release)
            self.save()

        # deploy application to k8s. Also handles initial scaling
        build_type = app_build_type(release)
        for scale_type in self.structure.keys():
            image = release.image
            version = "v{}".format(release.version)
            kwargs = {
                'memory': release.config.memory,
                'cpu': release.config.cpu,
                'tags': release.config.tags,
                'envs': release.config.values,
                'replicas': 0,  # Scaling up happens in a separate operation
                'version': version,
                'app_type': scale_type,
                'build_type': build_type,
                'healthcheck': release.config.healthcheck(),
                # http://docs.deis.io/en/latest/using_deis/process-types/#web-vs-cmd-process-types
                'routable': True if scale_type in ['web', 'cmd'] else False
            }

            command = self._get_command(scale_type)
            try:
                self._scheduler.deploy(
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=image,
                    command=command,
                    **kwargs
                )

                # Wait until application is available in the router
                # Only run when there is no previous build / release
                old = release.previous()
                if old is None or old.build is None:
                    self.verify_application_health(**kwargs)

            except Exception as e:
                err = '{} (app::deploy): {}'.format(self._get_job_id(scale_type), e)
                log_event(self, err, logging.ERROR)
                raise

    def _default_structure(self, release):
        """Scale to default structure based on release type"""
        # if there is no SHA, assume a docker image is being promoted
        if not release.build.sha:
            structure = {'cmd': 1}

        # if a dockerfile exists without a procfile, assume docker workflow
        elif release.build.dockerfile and not release.build.procfile:
            structure = {'cmd': 1}

        # if a procfile exists without a web entry, assume docker workflow
        elif release.build.procfile and 'web' not in release.build.procfile:
            structure = {'cmd': 1}

        # default to heroku workflow
        else:
            structure = {'web': 1}

        return structure

    def verify_application_health(self, **kwargs):
        """
        Verify an application is healthy via the router.
        This is only used in conjunction with the kubernetes health check system and should
        only run after kubernetes has reported all pods as healthy
        """
        # Bail out early if the application is not routable
        if not kwargs.get('routable', False):
            return

        app_type = kwargs.get('app_type')
        self.log(
            'Waiting for router to be ready to serve traffic to process type {}'.format(app_type),
            level=logging.DEBUG
        )

        # Get the router host and append healthcheck path
        url = 'http://{}:{}'.format(settings.ROUTER_HOST, settings.ROUTER_PORT)

        # if a health check url is available then 200 is the only acceptable status code
        if len(kwargs['healthcheck']):
            allowed = [200]
            url = urljoin(url, kwargs['healthcheck'].get('path'))
            req_timeout = kwargs['healthcheck'].get('timeout')
        else:
            allowed = set(range(200, 599))
            allowed.remove(404)
            req_timeout = 3

        session = requests.Session()
        session.headers = {
            # https://toolbelt.readthedocs.org/en/latest/user-agent.html#user-agent-constructor
            'User-Agent': user_agent('Deis Controller', deis_version),
            # set the Host header for the application being checked - not used for actual routing
            'Host': '{}.{}.nip.io'.format(self.id, settings.ROUTER_HOST)
        }

        # `mount` a custom adapter that retries failed connections for HTTP and HTTPS requests.
        # http://docs.python-requests.org/en/latest/api/#requests.adapters.HTTPAdapter
        session.mount('http://', requests.adapters.HTTPAdapter(max_retries=10))
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=10))

        # Give the router max of 10 tries or max 30 seconds to become healthy
        # Uses time module to account for the timout value of 3 seconds
        start = time.time()
        for _ in range(10):
            # http://docs.python-requests.org/en/master/user/advanced/#timeouts
            response = session.get(url, timeout=req_timeout)

            # 1 minute timeout
            if (time.time() - start) > (req_timeout * 10):
                break

            # check response against the allowed pool
            if response.status_code in allowed:
                break

            # a small sleep since router usually resolve within 10 seconds
            time.sleep(1)

        # Endpoint did not report healthy in time
        if response.status_code == 404:
            self.log(
                'Router was not ready to serve traffic to process type {} in time'.format(app_type),  # noqa
                level=logging.WARNING
            )
            return

        self.log(
            'Router is ready to serve traffic to process type {}'.format(app_type),
            level=logging.DEBUG
        )

    def logs(self, log_lines=str(settings.LOG_LINES)):
        """Return aggregated log data for this application."""
        try:
            url = "http://{}:{}/logs/{}?log_lines={}".format(settings.LOGGER_HOST,
                                                             settings.LOGGER_PORT,
                                                             self.id, log_lines)
            r = requests.get(url)
        # Handle HTTP request errors
        except requests.exceptions.RequestException as e:
            logger.error("Error accessing deis-logger using url '{}': {}".format(url, e))
            raise e

        # Handle logs empty or not found
        if r.status_code == 204 or r.status_code == 404:
            logger.info("GET {} returned a {} status code".format(url, r.status_code))
            raise EnvironmentError('Could not locate logs')

        # Handle unanticipated status codes
        if r.status_code != 200:
            logger.error("Error accessing deis-logger: GET {} returned a {} status code"
                         .format(url, r.status_code))
            raise EnvironmentError('Error accessing deis-logger')

        # cast content to string since it comes as bytes via the requests object
        return str(r.content)

    def run(self, user, command):
        def pod_name(size=5, chars=string.ascii_lowercase + string.digits):
            return ''.join(random.choice(chars) for _ in range(size))

        """Run a one-off command in an ephemeral app container."""
        release = self.release_set.latest()
        if release.build is None:
            raise EnvironmentError('No build associated with this release to run this command')

        # TODO: add support for interactive shell
        # SECURITY: shell-escape user input
        command = command.replace("'", "'\\''")

        # if this is a procfile-based app, switch the entrypoint to slugrunner's default
        # FIXME: remove slugrunner's hardcoded entrypoint
        if release.build.procfile and \
           release.build.sha and not \
           release.build.dockerfile:
            entrypoint = '/runner/init'
            command = "'{}'".format(command)
        else:
            entrypoint = '/bin/bash'
            command = "-c '{}'".format(command)

        name = self._get_job_id('run') + '-' + pod_name()

        msg = "{} on {} runs '{}'".format(user.username, name, command)
        log_event(self, msg)

        kwargs = {
            'memory': release.config.memory,
            'cpu': release.config.cpu,
            'tags': release.config.tags,
            'envs': release.config.values
        }

        try:
            rc, output = self._scheduler.run(
                self.id,
                name,
                release.image,
                entrypoint,
                command,
                **kwargs
            )

            return rc, output
        except Exception as e:
            err = '{} (run): {}'.format(name, e)
            log_event(self, err, logging.ERROR)
            raise

    def list_pods(self, *args, **kwargs):
        """Used to list basic information about pods running for a given application"""
        try:
            labels = self._scheduler_filter(**kwargs)

            # in case a singular pod is requested
            if 'name' in kwargs:
                pods = [self._scheduler._get_pod(self.id, kwargs['name']).json()]
            else:
                pods = self._scheduler._get_pods(self.id, labels=labels).json()['items']

            data = []
            for p in pods:
                # specifically ignore run pods
                if p['metadata']['labels']['type'] == 'run':
                    continue

                item = Pod()
                item['name'] = p['metadata']['name']
                item['state'] = self._scheduler.resolve_state(p).name
                item['release'] = p['metadata']['labels']['version']
                item['type'] = p['metadata']['labels']['type']
                if 'startTime' in p['status']:
                    started = p['status']['startTime']
                else:
                    started = str(datetime.utcnow().strftime(settings.DEIS_DATETIME_FORMAT))
                item['started'] = started

                data.append(item)

            # sorting so latest start date is first
            data.sort(key=lambda x: x['started'], reverse=True)

            return data
        except KubeHTTPException as e:
            pass
        except Exception as e:
            err = '(list pods): {}'.format(e)
            log_event(self, err, logging.ERROR)
            raise

    def _scheduler_filter(self, **kwargs):
        labels = {'app': self.id}

        # always supply a version, either latest or a specific one
        if 'release' not in kwargs or kwargs['release'] is None:
            release = self.release_set.latest()
        else:
            release = self.release_set.get(version=kwargs['release'])

        version = "v{}".format(release.version)
        labels.update({'version': version})

        if 'type' in kwargs:
            labels.update({'type': kwargs['type']})

        return labels
