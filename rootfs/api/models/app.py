import backoff
from collections import OrderedDict
from datetime import datetime
import functools
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
from rest_framework.exceptions import ValidationError, NotFound
from jsonfield import JSONField

from api import __version__ as deis_version
from api.models import UuidAuditedModel, AlreadyExists, DeisException, ServiceUnavailable

from api.utils import generate_app_name, async_run
from api.models.release import Release
from api.models.config import Config
from api.models.domain import Domain
from api.models.appsettings import AppSettings

from scheduler import KubeHTTPException, KubeException

logger = logging.getLogger(__name__)

session = None


def get_session():
    global session
    if session is None:
        session = requests.Session()
        session.headers = {
            # https://toolbelt.readthedocs.org/en/latest/user-agent.html#user-agent-constructor
            'User-Agent': user_agent('Deis Controller', deis_version),
        }
        # `mount` a custom adapter that retries failed connections for HTTP and HTTPS requests.
        # http://docs.python-requests.org/en/latest/api/#requests.adapters.HTTPAdapter
        session.mount('http://', requests.adapters.HTTPAdapter(max_retries=10))
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=10))
    return session


# http://kubernetes.io/v1.1/docs/design/identifiers.html
def validate_id_is_docker_compatible(value):
    """
    Check that the value follows the kubernetes name constraints
    """
    match = re.match(r'^[a-z0-9-]+$', value)
    if not match:
        raise ValidationError("App name can only contain a-z (lowercase), 0-9 and hyphens")


def validate_app_structure(value):
    """Error if the dict values aren't ints >= 0"""
    try:
        if any(int(v) < 0 for v in value.values()):
            raise ValueError("Must be greater than or equal to zero")
    except ValueError as err:
        raise ValidationError(str(err))


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

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    id = models.SlugField(max_length=24, unique=True, null=True,
                          validators=[validate_id_is_docker_compatible,
                                      validate_reserved_names])
    structure = JSONField(default={}, blank=True, validators=[validate_app_structure])

    class Meta:
        verbose_name = 'Application'
        permissions = (('use_app', 'Can use app'),)
        ordering = ['id']

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
                if self._scheduler.get_namespace(self.id).status_code == 200:
                    # Namespace already exists
                    err = "{} already exists as a namespace in this kuberenetes setup".format(self.id)  # noqa
                    self.log(err, logging.INFO)
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
        return "{app}-{container_type}".format(**locals())

    def _get_command(self, container_type):
        """
        Return the kubernetes "container arguments" to be sent off to the scheduler.

        In reality this is the command that the user it attempting to run.
        """
        try:
            # FIXME: remove slugrunner's hardcoded entrypoint
            release = self.release_set.latest()
            if release.build.dockerfile or not release.build.sha:
                return [release.build.procfile[container_type]]

            return ['start', container_type]
        # if the key is not present or if a parent attribute is None
        except (KeyError, TypeError, AttributeError):
            # handle special case for Dockerfile deployments
            return [] if container_type == 'cmd' else ['start', container_type]

    def _get_entrypoint(self, container_type):
        """
        Return the kubernetes "container command" to be sent off to the scheduler.

        In this case, it is the entrypoint for the docker image. Because of Heroku compatibility,
        Any containers that are not from a buildpack are run under /bin/bash.
        """
        # handle special case for Dockerfile deployments
        if container_type == 'cmd':
            return []

        # if this is a procfile-based app, switch the entrypoint to slugrunner's default
        # FIXME: remove slugrunner's hardcoded entrypoint
        release = self.release_set.latest()
        if release.build.procfile and \
           release.build.sha and not \
           release.build.dockerfile:
            entrypoint = ['/runner/init']
        else:
            entrypoint = ['/bin/bash', '-c']

        return entrypoint

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with an application "tag" that the customized deis-logspout will
        be on the lookout for.  When it's seen, the message-- usually an application event of some
        sort like releasing or scaling, will be considered as "belonging" to the application
        instead of the controller and will be handled accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.id, message))

    def create(self, *args, **kwargs):  # noqa
        """
        Create a application with an initial config, settings, release, domain
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
        namespace = self.id
        service = self.id
        try:
            self.log('creating Namespace {} and services'.format(namespace), level=logging.DEBUG)
            # Create essential resources
            try:
                self._scheduler.get_namespace(namespace)
            except KubeException:
                self._scheduler.create_namespace(namespace)

            try:
                self._scheduler.get_service(namespace, service)
            except KubeException:
                self._scheduler.create_service(namespace, service)
        except KubeException as e:
            # Blow it all away only if something horrible happens
            try:
                self._scheduler.delete_namespace(namespace)
            except KubeException as e:
                # Just feed into the item below
                raise ServiceUnavailable('Could not delete the Namespace in Kubernetes') from e

            raise ServiceUnavailable('Kubernetes resources could not be created') from e

        try:
            self.appsettings_set.latest()
        except AppSettings.DoesNotExist:
            AppSettings.objects.create(owner=self.owner, app=self)
        # Attach the platform specific application sub domain to the k8s service
        # Only attach it on first release in case a customer has remove the app domain
        if rel.version == 1 and not Domain.objects.filter(domain=self.id).exists():
            Domain(owner=self.owner, app=self, domain=self.id).save()

    def delete(self, *args, **kwargs):
        """Delete this application including all containers"""
        self.log("deleting environment")
        try:
            self._scheduler.delete_namespace(self.id)

            # wait 30 seconds for termination
            for _ in range(30):
                try:
                    self._scheduler.get_namespace(self.id)
                except KubeException:
                    break
        except KubeException as e:
            raise ServiceUnavailable('Could not delete Kubernetes Namespace {}'.format(self.id)) from e  # noqa

        self._clean_app_logs()
        return super(App, self).delete(*args, **kwargs)

    def restart(self, **kwargs):  # noqa
        """
        Restart found pods by deleting them (RC / Deployment will recreate).
        Wait until they are all drained away and RC / Deployment has gotten to a good state
        """
        try:
            # Resolve single pod name if short form (cmd-1269180282-1nyfz) is passed
            if 'name' in kwargs and kwargs['name'].count('-') == 2:
                kwargs['name'] = '{}-{}'.format(kwargs['id'], kwargs['name'])

            # Iterate over RCs / RSs to get total desired count if not a single item
            desired = 1
            if 'name' not in kwargs:
                desired = 0
                labels = self._scheduler_filter(**kwargs)
                # fetch RS (which represent Deployments)
                controllers = self._scheduler.get_replicasets(kwargs['id'], labels=labels)

                for controller in controllers.json()['items']:
                    desired += controller['spec']['replicas']
        except KubeException:
            # Nothing was found
            return []

        try:
            tasks = [
                functools.partial(
                    self._scheduler.delete_pod,
                    self.id,
                    pod['name']
                ) for pod in self.list_pods(**kwargs)
            ]

            async_run(tasks)
        except Exception as e:
            err = "warning, some pods failed to stop:\n{}".format(str(e))
            self.log(err, logging.WARNING)

        # Wait for pods to start
        try:
            timeout = 300  # 5 minutes
            elapsed = 0
            while True:
                # timed out
                if elapsed >= timeout:
                    raise DeisException('timeout - 5 minutes have passed and pods are not up')

                # restarting a single pod behaves differently, fetch the *newest* pod
                # and hope it is the right one. Comes back sorted
                if 'name' in kwargs:
                    del kwargs['name']
                    pods = self.list_pods(**kwargs)
                    # Add in the latest name
                    if len(pods) == 0:
                        # if pod is not even scheduled wait for it and pass dummy kwargs
                        # to indicate restart of a single pod
                        kwargs['name'] = "dummy"
                        continue
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
            self.log(err, logging.WARNING)

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
            self.log(err, logging.WARNING)

    def scale(self, user, structure):  # noqa
        """Scale containers up or down to match requested structure."""
        # use create to make sure minimum resources are created
        self.create()

        if self.release_set.latest().build is None:
            raise DeisException('No build associated with this release')

        release = self.release_set.latest()

        # Validate structure
        try:
            for target, count in structure.copy().items():
                structure[target] = int(count)
            validate_app_structure(structure)
        except (TypeError, ValueError, ValidationError) as e:
            raise DeisException('Invalid scaling format: {}'.format(e))

        # test for available process types
        available_process_types = release.build.procfile or {}
        for container_type in structure:
            if container_type == 'cmd':
                continue  # allow docker cmd types in case we don't have the image source

            if container_type not in available_process_types:
                raise NotFound(
                    'Container type {} does not exist in application'.format(container_type))

        # merge current structure and the new items together
        old_structure = self.structure
        new_structure = old_structure.copy()
        new_structure.update(structure)

        if new_structure != self.structure:
            # save new structure to the database
            self.structure = new_structure
            self.save()

            try:
                self._scale_pods(structure)
            except ServiceUnavailable:
                # scaling failed, go back to old scaling numbers
                self._scale_pods(old_structure)
                raise

            msg = '{} scaled pods '.format(user.username) + ' '.join(
                "{}={}".format(k, v) for k, v in list(structure.items()))
            self.log(msg)

            return True

        return False

    def _scale_pods(self, scale_types):
        release = self.release_set.latest()
        app_settings = self.appsettings_set.latest()
        version = "v{}".format(release.version)
        image = release.image
        envs = self._build_env_vars(release.build.type, version, image, release.config.values)

        # see if the app config has deploy batch preference, otherwise use global
        batches = release.config.values.get('DEIS_DEPLOY_BATCHES', settings.DEIS_DEPLOY_BATCHES)

        # see if the app config has deploy timeout preference, otherwise use global
        deploy_timeout = release.config.values.get('DEIS_DEPLOY_TIMEOUT', settings.DEIS_DEPLOY_TIMEOUT)  # noqa

        tasks = []
        for scale_type, replicas in scale_types.items():
            # only web / cmd are routable
            # http://docs.deis.io/en/latest/using_deis/process-types/#web-vs-cmd-process-types
            routable = True if scale_type in ['web', 'cmd'] and app_settings.routable else False
            # fetch application port and inject into ENV Vars as needed
            port = release.get_port()
            if port:
                envs['PORT'] = port

            healthcheck = release.config.get_healthcheck().get('scale_type', {})
            if not healthcheck and scale_type in ['web', 'cmd']:
                healthcheck = release.config.get_healthcheck().get('web/cmd', {})

            kwargs = {
                'memory': release.config.memory,
                'cpu': release.config.cpu,
                'tags': release.config.tags,
                'envs': envs,
                'registry': release.config.registry,
                'version': version,
                'replicas': replicas,
                'app_type': scale_type,
                'build_type': release.build.type,
                'healthcheck': healthcheck,
                'service_annotations': {'maintenance': app_settings.maintenance},
                'routable': routable,
                'deploy_batches': batches,
                'deploy_timeout': deploy_timeout,
            }

            # gather all proc types to be deployed
            tasks.append(
                functools.partial(
                    self._scheduler.scale,
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=image,
                    entrypoint=self._get_entrypoint(scale_type),
                    command=self._get_command(scale_type),
                    **kwargs
                )
            )

        try:
            # create the application config in k8s (secret in this case) for all deploy objects
            self._scheduler.set_application_config(self.id, envs, version)

            async_run(tasks)
        except Exception as e:
            err = '(scale): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

    def deploy(self, release, force_deploy=False):
        """
        Deploy a new release to this application

        force_deploy can be used when a deployment is broken, such as for Rollback
        """
        if release.build is None:
            raise DeisException('No build associated with this release')

        app_settings = self.appsettings_set.latest()

        # use create to make sure minimum resources are created
        self.create()

        if self.structure == {}:
            self.structure = self._default_structure(release)
            self.save()

        # see if the app config has deploy batch preference, otherwise use global
        batches = release.config.values.get('DEIS_DEPLOY_BATCHES', settings.DEIS_DEPLOY_BATCHES)

        # see if the app config has deploy timeout preference, otherwise use global
        deploy_timeout = release.config.values.get('DEIS_DEPLOY_TIMEOUT', settings.DEIS_DEPLOY_TIMEOUT)  # noqa

        deployment_history = release.config.values.get('KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT', settings.KUBERNETES_DEPLOYMENTS_REVISION_HISTORY_LIMIT)  # noqa

        # deploy application to k8s. Also handles initial scaling
        deploys = {}
        image = release.image
        version = "v{}".format(release.version)
        envs = self._build_env_vars(release.build.type, version, image, release.config.values)
        tags = release.config.tags

        for scale_type, replicas in self.structure.items():
            # only web / cmd are routable
            # http://docs.deis.io/en/latest/using_deis/process-types/#web-vs-cmd-process-types
            routable = True if scale_type in ['web', 'cmd'] and app_settings.routable else False
            # fetch application port and inject into ENV vars as needed
            port = release.get_port()
            if port:
                envs['PORT'] = port

            healthcheck = release.config.get_healthcheck().get('scale_type', {})
            if not healthcheck and scale_type in ['web', 'cmd']:
                healthcheck = release.config.get_healthcheck().get('web/cmd', {})

            deploys[scale_type] = {
                'memory': release.config.memory,
                'cpu': release.config.cpu,
                'tags': tags,
                'envs': envs,
                'registry': release.config.registry,
                # only used if there is no previous RC
                'replicas': replicas,
                'version': version,
                'app_type': scale_type,
                'build_type': release.build.type,
                'healthcheck': healthcheck,
                'routable': routable,
                'service_annotations': {'maintenance': app_settings.maintenance},
                'deploy_batches': batches,
                'deploy_timeout': deploy_timeout,
                'deployment_history_limit': deployment_history,
                'release_summary': release.summary
            }

        # Sort deploys so routable comes first
        deploys = OrderedDict(sorted(deploys.items(), key=lambda d: d[1].get('routable')))

        # Check if any proc type has a Deployment in progress
        for scale_type, kwargs in deploys.items():
            if force_deploy:
                continue

            # Is there an existing deployment in progress?
            name = self._get_job_id(scale_type)
            in_progress, deploy_okay = self._scheduler.deployment_in_progress(
                self.id, name, deploy_timeout, batches, replicas, tags
            )
            # throw a 409 if things are in progress but we do not want to let through the deploy
            if in_progress and not deploy_okay:
                raise AlreadyExists('Deployment for {} is already in progress'.format(name))

        try:
            # create the application config in k8s (secret in this case) for all deploy objects
            self._scheduler.set_application_config(self.id, envs, version)

            # gather all proc types to be deployed
            tasks = [
                functools.partial(
                    self._scheduler.deploy,
                    namespace=self.id,
                    name=self._get_job_id(scale_type),
                    image=image,
                    entrypoint=self._get_entrypoint(scale_type),
                    command=self._get_command(scale_type),
                    **kwargs
                ) for scale_type, kwargs in deploys.items()
            ]

            async_run(tasks)
        except Exception as e:
            err = '(app::deploy): {}'.format(e)
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

        # Wait until application is available in the router
        # Only run when there is no previous build / release
        old = release.previous()
        if old is None or old.build is None:
            self.verify_application_health(**kwargs)

        # cleanup old release objects from kubernetes
        release.cleanup_old()

    def _default_structure(self, release):
        """Scale to default structure based on release type"""
        # if there is no SHA, assume a docker image is being promoted
        if not release.build.sha:
            structure = {'cmd': 1}

        elif release.build.procfile and 'web' in release.build.procfile:
            structure = {'web': 1}

        # if a dockerfile, assume docker workflow
        elif release.build.dockerfile:
            structure = {'cmd': 1}

        # if a procfile exists without a web entry and dockerfile, assume heroku workflow
        # and return empty structure as only web type needs to be created by default and
        # other types have to be manually scaled
        elif release.build.procfile and 'web' not in release.build.procfile:
            structure = {}

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
        release = self.release_set.latest()
        app_settings = self.appsettings_set.latest()
        if not kwargs.get('routable', False) and app_settings.routable:
            return

        app_type = kwargs.get('app_type')
        self.log(
            'Waiting for router to be ready to serve traffic to process type {}'.format(app_type),
            level=logging.DEBUG
        )

        # Get the router host and append healthcheck path
        url = 'http://{}:{}'.format(settings.ROUTER_HOST, settings.ROUTER_PORT)

        # if a httpGet probe is available then 200 is the only acceptable status code
        if 'livenessProbe' in kwargs.get('healthcheck', {}) and 'httpGet' in kwargs.get('healthcheck').get('livenessProbe'):  # noqa
            allowed = [200]
            handler = kwargs['healthcheck']['livenessProbe']['httpGet']
            url = urljoin(url, handler.get('path', '/'))
            req_timeout = handler.get('timeoutSeconds', 1)
        else:
            allowed = set(range(200, 599))
            allowed.remove(404)
            req_timeout = 3

        # Give the router max of 10 tries or max 30 seconds to become healthy
        # Uses time module to account for the timout value of 3 seconds
        start = time.time()
        failed = False
        headers = {
            # set the Host header for the application being checked - not used for actual routing
            'Host': '{}.{}.nip.io'.format(self.id, settings.ROUTER_HOST),
        }
        for _ in range(10):
            try:
                # http://docs.python-requests.org/en/master/user/advanced/#timeouts
                response = get_session().get(url, timeout=req_timeout, headers=headers)
                failed = False
            except requests.exceptions.RequestException:
                # In case of a failure where response object is not available
                failed = True
                # We are fine with timeouts and request problems, lets keep trying
                time.sleep(1)  # just a bit of a buffer
                continue

            # 30 second timeout (timout per request * 10)
            if (time.time() - start) > (req_timeout * 10):
                break

            # check response against the allowed pool
            if response.status_code in allowed:
                break

            # a small sleep since router usually resolve within 10 seconds
            time.sleep(1)

        # Endpoint did not report healthy in time
        if ('response' in locals() and response.status_code == 404) or failed:
            # bankers rounding
            delta = round(time.time() - start)
            self.log(
                'Router was not ready to serve traffic to process type {} in time, waited {} seconds'.format(app_type, delta),  # noqa
                level=logging.WARNING
            )
            return

        self.log(
            'Router is ready to serve traffic to process type {}'.format(app_type),
            level=logging.DEBUG
        )

    @backoff.on_exception(backoff.expo, ServiceUnavailable, max_tries=3)
    def logs(self, log_lines=str(settings.LOG_LINES)):
        """Return aggregated log data for this application."""
        try:
            url = "http://{}:{}/logs/{}?log_lines={}".format(settings.LOGGER_HOST,
                                                             settings.LOGGER_PORT,
                                                             self.id, log_lines)
            r = requests.get(url)
        # Handle HTTP request errors
        except requests.exceptions.RequestException as e:
            msg = "Error accessing deis-logger using url '{}': {}".format(url, e)
            logger.error(msg)
            raise ServiceUnavailable(msg) from e

        # Handle logs empty or not found
        if r.status_code == 204 or r.status_code == 404:
            logger.info("GET {} returned a {} status code".format(url, r.status_code))
            raise NotFound('Could not locate logs')

        # Handle unanticipated status codes
        if r.status_code != 200:
            logger.error("Error accessing deis-logger: GET {} returned a {} status code"
                         .format(url, r.status_code))
            raise ServiceUnavailable('Error accessing deis-logger')

        # cast content to string since it comes as bytes via the requests object
        return str(r.content)

    def run(self, user, command):
        def pod_name(size=5, chars=string.ascii_lowercase + string.digits):
            return ''.join(random.choice(chars) for _ in range(size))

        """Run a one-off command in an ephemeral app container."""
        scale_type = 'run'
        release = self.release_set.latest()
        if release.build is None:
            raise DeisException('No build associated with this release to run this command')

        # see if the app config has deploy timeout preference, otherwise use global
        deploy_timeout = release.config.values.get('DEIS_DEPLOY_TIMEOUT', settings.DEIS_DEPLOY_TIMEOUT)  # noqa

        name = self._get_job_id(scale_type) + '-' + pod_name()
        self.log("{} on {} runs '{}'".format(user.username, name, command))

        image = release.image
        version = "v{}".format(release.version)
        envs = self._build_env_vars(release.build.type, version, image, release.config.values)
        kwargs = {
            'memory': release.config.memory,
            'cpu': release.config.cpu,
            'tags': release.config.tags,
            'envs': envs,
            'registry': release.config.registry,
            'version': version,
            'build_type': release.build.type,
            'deploy_timeout': deploy_timeout
        }

        try:
            exit_code, output = self._scheduler.run(
                self.id,
                name,
                image,
                self._get_entrypoint(scale_type),
                [command],
                **kwargs
            )

            return exit_code, output
        except Exception as e:
            err = '{} (run): {}'.format(name, e)
            raise ServiceUnavailable(err) from e

    def list_pods(self, *args, **kwargs):
        """Used to list basic information about pods running for a given application"""
        try:
            labels = self._scheduler_filter(**kwargs)

            # in case a singular pod is requested
            if 'name' in kwargs:
                pods = [self._scheduler.get_pod(self.id, kwargs['name']).json()]
            else:
                pods = self._scheduler.get_pods(self.id, labels=labels).json()['items']

            data = []
            for p in pods:
                labels = p['metadata']['labels']
                # specifically ignore run pods
                if labels['type'] == 'run':
                    continue

                state = str(self._scheduler.pod_state(p))

                # follows kubelete convention - these are hidden unless show-all is set
                if state in ['down', 'crashed']:
                    continue

                # hide pod if it is passed the graceful termination period
                if self._scheduler.pod_deleted(p):
                    continue

                item = Pod()
                item['name'] = p['metadata']['name']
                item['state'] = state
                item['release'] = labels['version']
                item['type'] = labels['type']
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
            self.log(err, logging.ERROR)
            raise ServiceUnavailable(err) from e

    def _scheduler_filter(self, **kwargs):
        labels = {'app': self.id, 'heritage': 'deis'}

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

    def _build_env_vars(self, build_type, version, image, envs):
        """
        Build a dict of env vars, setting default vars based on app type
        and then combining with the user set ones
        """

        # mix in default environment information deis may require
        default_env = {
            'DEIS_APP': self.id,
            'WORKFLOW_RELEASE': version
        }

        # Check if it is a slug builder image.
        if build_type == 'buildpack':
            # overwrite image so slugrunner image is used in the container
            default_env['SLUG_URL'] = image
            default_env['BUILDER_STORAGE'] = settings.APP_STORAGE
            default_env['DEIS_MINIO_SERVICE_HOST'] = settings.MINIO_HOST
            default_env['DEIS_MINIO_SERVICE_PORT'] = settings.MINIO_PORT

        # merge envs on top of default to make envs win
        default_env.update(envs)
        return default_env

    def maintenance_mode(self, mode):
        """
        Turn application maintenance mode on/off
        """
        service = self._fetch_service_config(self.id)
        old_service = service.copy()  # in case anything fails for rollback

        try:
            service['metadata']['annotations']['router.deis.io/maintenance'] = str(mode).lower()
            self._scheduler.update_service(self.id, self.id, data=service)
        except KubeException as e:
            self._scheduler.update_service(self.id, self.id, data=old_service)
            raise ServiceUnavailable(str(e)) from e

    def routable(self, routable):
        """
        Turn on/off if an application is publically routable
        """
        service = self._fetch_service_config(self.id)
        old_service = service.copy()  # in case anything fails for rollback

        try:
            service['metadata']['labels']['router.deis.io/routable'] = str(routable).lower()
            self._scheduler.update_service(self.id, self.id, data=service)
        except KubeException as e:
            self._scheduler.update_service(self.id, self.id, data=old_service)
            raise ServiceUnavailable(str(e)) from e
