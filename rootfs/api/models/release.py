import logging

from django.conf import settings
from django.db import models

from registry import publish_release, get_port as docker_get_port, RegistryException
from api.utils import dict_diff
from api.models import UuidAuditedModel
from api.exceptions import DeisException, AlreadyExists
from scheduler import KubeHTTPException

logger = logging.getLogger(__name__)


class Release(UuidAuditedModel):
    """
    Software release deployed by the application platform

    Releases contain a :class:`Build` and a :class:`Config`.
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    version = models.PositiveIntegerField()
    summary = models.TextField(blank=True, null=True)
    failed = models.BooleanField(default=False)
    exception = models.TextField(blank=True, null=True)

    config = models.ForeignKey('Config', on_delete=models.CASCADE)
    build = models.ForeignKey('Build', null=True, on_delete=models.CASCADE)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'version'),)

    def __str__(self):
        return "{0}-v{1}".format(self.app.id, self.version)

    @property
    def image(self):
        if (settings.REGISTRY_LOCATION != 'on-cluster'):
            return self.build.image
        # Builder pushes to internal registry, exclude SHA based images from being returned
        registry = self.config.registry
        if (
            registry.get('username', None) and
            registry.get('password', None) and
            # SHA means it came from a git push (builder)
            not self.build.sha and
            # hostname tells Builder where to push images
            not registry.get('hostname', None)
        ):
            return self.build.image

        # return image if it is already in a registry, test host and then host + port
        if (
            self.build.image.startswith(settings.REGISTRY_HOST) or
            self.build.image.startswith(settings.REGISTRY_URL)
        ):
            return self.build.image

        # Sort out image information based on build type
        if self.build.type == 'dockerfile':
            # DockerFile
            return '{}/{}:git-{}'.format(settings.REGISTRY_URL, self.app.id, str(self.build.sha))
        elif self.build.type == 'image':
            # Deis Pull, docker image in local registry
            return '{}/{}:v{}'.format(settings.REGISTRY_URL, self.app.id, str(self.version))
        elif self.build.type == 'buildpack':
            # Build Pack - Registry URL not prepended since slugrunner image will download slug
            return self.build.image

    def new(self, user, config, build, summary=None, source_version='latest'):
        """
        Create a new application release using the provided Build and Config
        on behalf of a user.

        Releases start at v1 and auto-increment.
        """
        # construct fully-qualified target image
        new_version = self.app.release_set.latest().version + 1
        # create new release and auto-increment version
        release = Release.objects.create(
            owner=user, app=self.app, config=config,
            build=build, version=new_version, summary=summary
        )

        try:
            release.publish()
        except DeisException as e:
            # If we cannot publish this app, just log and carry on
            self.app.log(e)
            pass
        except RegistryException as e:
            self.app.log(e)
            raise DeisException(str(e)) from e

        return release

    def publish(self):
        if self.build is None:
            raise DeisException('No build associated with this release to publish')

        # If the build has a SHA, assume it's from deis-builder and in the deis-registry already
        if self.build.source_based:
            return

        # Builder pushes to internal registry, exclude SHA based images from being returned early
        registry = self.config.registry
        if (
            registry.get('username', None) and
            registry.get('password', None) and
            # SHA means it came from a git push (builder)
            not self.build.sha and
            # hostname tells Builder where to push images
            not registry.get('hostname', None)
        ) or (settings.REGISTRY_LOCATION != 'on-cluster'):
            self.app.log('{} exists in the target registry. Using image for release {} of app {}'.format(self.build.image, self.version, self.app))  # noqa
            return

        # return image if it is already in the registry, test host and then host + port
        if (
            self.build.image.startswith(settings.REGISTRY_HOST) or
            self.build.image.startswith(settings.REGISTRY_URL)
        ):
            self.app.log('{} exists in the target registry. Using image for release {} of app {}'.format(self.build.image, self.version, self.app))  # noqa
            return

        # add tag if it was not provided
        source_image = self.build.image
        if ':' not in source_image:
            source_image = "{}:{}".format(source_image, self.build.version)

        # if build is source based then it was pushed into the deis registry
        deis_registry = bool(self.build.source_based)
        publish_release(source_image, self.image, deis_registry, self.get_registry_auth())

    def get_port(self):
        """
        Get application port for a given release. If pulling from private registry
        then use default port or read from ENV var, otherwise attempt to pull from
        the docker image
        """
        try:
            deis_registry = bool(self.build.source_based)
            envs = self.config.values
            creds = self.get_registry_auth()

            if self.build.type == "buildpack":
                self.app.log('buildpack type detected. Defaulting to $PORT 5000')
                return 5000

            # application has registry auth - $PORT is required
            if (creds is not None) or (settings.REGISTRY_LOCATION != 'on-cluster'):
                if envs.get('PORT', None) is None:
                    if not self.app.appsettings_set.latest().routable:
                        return None
                    raise DeisException(
                        'PORT needs to be set in the application config '
                        'when using a private registry'
                    )

                # User provided PORT
                return int(envs.get('PORT'))

            # If the user provides PORT
            if envs.get('PORT', None):
                return int(envs.get('PORT'))

            # discover port from docker image
            port = docker_get_port(self.image, deis_registry, creds)
            if port is None and self.app.appsettings_set.latest().routable:
                msg = "Expose a port or make the app non routable by changing the process type"
                self.app.log(msg, logging.ERROR)
                raise DeisException(msg)

            return port
        except Exception as e:
            raise DeisException(str(e)) from e

    def get_registry_auth(self):
        """
        Gather login information for private registry if needed
        """
        auth = None
        registry = self.config.registry
        if registry.get('username', None):
            auth = {
                'username': registry.get('username', None),
                'password': registry.get('password', None),
                'email': self.owner.email
            }

        return auth

    def previous(self):
        """
        Return the previous Release to this one.

        :return: the previous :class:`Release`, or None
        """
        releases = self.app.release_set
        if self.pk:
            releases = releases.exclude(pk=self.pk)

        try:
            # Get the Release previous to this one
            prev_release = releases.filter(failed=False).latest()
        except Release.DoesNotExist:
            prev_release = None
        return prev_release

    def rollback(self, user, version=None):
        try:
            # if no version is provided then grab version from object
            version = (self.version - 1) if version is None else int(version)

            if version < 1:
                raise DeisException('version cannot be below 0')
            elif version == 1:
                raise DeisException('Cannot roll back to initial release.')

            prev = self.app.release_set.get(version=version)
            if prev.failed:
                raise DeisException('Cannot roll back to failed release.')
            latest_version = self.app.release_set.latest().version
            new_release = self.new(
                user,
                build=prev.build,
                config=prev.config,
                summary="{} rolled back to v{}".format(user, version),
                source_version='v{}'.format(version)
            )

            if self.build is not None:
                self.app.deploy(new_release, force_deploy=True)
            return new_release
        except Exception as e:
            # check if the exception is during create or publish
            if ('new_release' not in locals() and 'latest_version' in locals() and
                    self.app.release_set.latest().version == latest_version+1):
                new_release = self.app.release_set.latest()
            if 'new_release' in locals():
                new_release.failed = True
                new_release.summary = "{} performed roll back to a release that failed".format(self.owner)  # noqa
                # Get the exception that has occured
                new_release.exception = "error: {}".format(str(e))
                new_release.save()
            raise DeisException(str(e)) from e

    def cleanup_old(self):  # noqa
        """
        Cleanup any old resources from Kubernetes

        This includes any RCs that are no longer considered the latest release (just a safety net)
        Secrets no longer tied to any ReplicaSet
        Stray pods no longer relevant to the latest release
        """
        latest_version = 'v{}'.format(self.version)
        self.app.log(
            'Cleaning up RCs for releases older than {} (latest)'.format(latest_version),
            level=logging.DEBUG
        )

        # Cleanup controllers
        labels = {'heritage': 'deis'}
        controller_removal = []
        controllers = self._scheduler.rc.get(self.app.id, labels=labels).json()['items']
        if not controllers:
            controllers = []
        for controller in controllers:
            current_version = controller['metadata']['labels']['version']
            # skip the latest release
            if current_version == latest_version:
                continue

            # aggregate versions together to removal all at once
            if current_version not in controller_removal:
                controller_removal.append(current_version)

        if controller_removal:
            self.app.log(
                'Found the following versions to cleanup: {}'.format(', '.join(controller_removal)),  # noqa
                level=logging.DEBUG
            )

        # this is RC related
        for version in controller_removal:
            self._delete_release_in_scheduler(self.app.id, version)

        # handle Deployments specific cleanups
        self._cleanup_deployment_secrets_and_configs(self.app.id)

        # Remove stray pods
        labels = {'heritage': 'deis'}
        pods = self._scheduler.pod.get(self.app.id, labels=labels).json()['items']
        if not pods:
            pods = []
        for pod in pods:
            if self._scheduler.pod.deleted(pod):
                continue

            current_version = pod['metadata']['labels']['version']
            # skip the latest release
            if current_version == latest_version:
                continue

            try:
                self._scheduler.pod.delete(self.app.id, pod['metadata']['name'])
            except KubeHTTPException as e:
                # Sometimes k8s will manage to remove the pod from under us
                if e.response.status_code == 404:
                    continue

    def _cleanup_deployment_secrets_and_configs(self, namespace):
        """
        Clean up any environment secrets (and in the future ConfigMaps) that
        are tied to a release Deployments no longer track

        This is done by checking the available ReplicaSets and only removing
        objects not attached to anything. This will allow releases done outside
        of Deis Controller
        """

        # Find all ReplicaSets
        versions = []
        labels = {'heritage': 'deis', 'app': namespace}
        replicasets = self._scheduler.rs.get(namespace, labels=labels).json()['items']
        if not replicasets:
            replicasets = []
        for replicaset in replicasets:
            if (
                'version' not in replicaset['metadata']['labels'] or
                replicaset['metadata']['labels']['version'] in versions
            ):
                continue

            versions.append(replicaset['metadata']['labels']['version'])

        # find all env secrets not owned by any replicaset
        labels = {
            'heritage': 'deis',
            'app': namespace,
            'type': 'env',
            # http://kubernetes.io/docs/user-guide/labels/#set-based-requirement
            'version__notin': versions
        }
        self.app.log('Cleaning up orphaned env var secrets for application {}'.format(namespace), level=logging.DEBUG)  # noqa
        secrets = self._scheduler.secret.get(namespace, labels=labels).json()['items']
        if not secrets:
            secrets = []
        for secret in secrets:
            self._scheduler.secret.delete(namespace, secret['metadata']['name'])

    def _delete_release_in_scheduler(self, namespace, version):
        """
        Deletes a specific release in k8s based on ReplicationController

        Scale RCs to 0 then delete RCs and the version specific
        secret that container the env var
        """
        labels = {
            'heritage': 'deis',
            'app': namespace,
            'version': version
        }

        # see if the app config has deploy timeout preference, otherwise use global
        timeout = self.config.values.get('DEIS_DEPLOY_TIMEOUT', settings.DEIS_DEPLOY_TIMEOUT)

        controllers = self._scheduler.rc.get(namespace, labels=labels).json()['items']
        if not controllers:
            controllers = []
        for controller in controllers:
            # Deployment takes care of this in the API, RC does not
            # Have the RC scale down pods and delete itself
            self._scheduler.rc.scale(namespace, controller['metadata']['name'], 0, timeout)
            self._scheduler.rc.delete(namespace, controller['metadata']['name'])

    def save(self, *args, **kwargs):  # noqa
        if not self.summary:
            self.summary = ''
            prev_release = self.previous()
            # compare this build to the previous build
            old_build = prev_release.build if prev_release else None
            old_config = prev_release.config if prev_release else None
            # if the build changed, log it and who pushed it
            if self.version == 1:
                self.summary += "{} created initial release".format(self.app.owner)
            elif self.build != old_build:
                if self.build.sha:
                    self.summary += "{} deployed {}".format(self.build.owner, self.build.sha[:7])
                else:
                    self.summary += "{} deployed {}".format(self.build.owner, self.build.image)

            # if the config data changed, log the dict diff
            if self.config != old_config:
                # if env vars change, log the dict diff
                dict1 = self.config.values
                dict2 = old_config.values if old_config else {}
                diff = dict_diff(dict1, dict2)
                # try to be as succinct as possible
                added = ', '.join(k for k in diff.get('added', {}))
                added = 'added ' + added if added else ''
                changed = ', '.join(k for k in diff.get('changed', {}))
                changed = 'changed ' + changed if changed else ''
                deleted = ', '.join(k for k in diff.get('deleted', {}))
                deleted = 'deleted ' + deleted if deleted else ''
                changes = ', '.join(i for i in (added, changed, deleted) if i)
                if changes:
                    if self.summary:
                        self.summary += ' and '
                    self.summary += "{} {}".format(self.config.owner, changes)

                # if the limits changed (memory or cpu), log the dict diff
                changes = []
                old_mem = old_config.memory if old_config else {}
                diff = dict_diff(self.config.memory, old_mem)
                if diff.get('added') or diff.get('changed') or diff.get('deleted'):
                    changes.append('memory')
                old_cpu = old_config.cpu if old_config else {}
                diff = dict_diff(self.config.cpu, old_cpu)
                if diff.get('added') or diff.get('changed') or diff.get('deleted'):
                    changes.append('cpu')
                if changes:
                    changes = 'changed limits for '+', '.join(changes)
                    self.summary += "{} {}".format(self.config.owner, changes)

                # if the lifecycle_post_start hooks changed, log the dict diff
                changes = []
                old_lifecycle_post_start = old_config.lifecycle_post_start if old_config else {}
                diff = dict_diff(self.config.lifecycle_post_start, old_lifecycle_post_start)
                # try to be as succinct as possible
                added = ', '.join(k for k in diff.get('added', {}))
                added = 'added lifecycle_post_start  ' + added if added else ''
                changed = ', '.join(k for k in diff.get('changed', {}))
                changed = 'changed lifecycle_post_start ' + changed if changed else ''
                deleted = ', '.join(k for k in diff.get('deleted', {}))
                deleted = 'deleted lifecycle_post_start ' + deleted if deleted else ''
                changes = ', '.join(i for i in (added, changed, deleted) if i)
                if changes:
                    if self.summary:
                        self.summary += ' and '
                    self.summary += "{} {}".format(self.config.owner, changes)

                # if the lifecycle_pre_stop hooks changed, log the dict diff
                changes = []
                old_lifecycle_pre_stop = old_config.lifecycle_pre_stop if old_config else {}
                diff = dict_diff(self.config.lifecycle_pre_stop, old_lifecycle_pre_stop)
                # try to be as succinct as possible
                added = ', '.join(k for k in diff.get('added', {}))
                added = 'added lifecycle_pre_stop  ' + added if added else ''
                changed = ', '.join(k for k in diff.get('changed', {}))
                changed = 'changed lifecycle_pre_stop ' + changed if changed else ''
                deleted = ', '.join(k for k in diff.get('deleted', {}))
                deleted = 'deleted lifecycle_pre_stop ' + deleted if deleted else ''
                changes = ', '.join(i for i in (added, changed, deleted) if i)
                if changes:
                    if self.summary:
                        self.summary += ' and '
                    self.summary += "{} {}".format(self.config.owner, changes)

                # if the tags changed, log the dict diff
                changes = []
                old_tags = old_config.tags if old_config else {}
                diff = dict_diff(self.config.tags, old_tags)
                # try to be as succinct as possible
                added = ', '.join(k for k in diff.get('added', {}))
                added = 'added tag ' + added if added else ''
                changed = ', '.join(k for k in diff.get('changed', {}))
                changed = 'changed tag ' + changed if changed else ''
                deleted = ', '.join(k for k in diff.get('deleted', {}))
                deleted = 'deleted tag ' + deleted if deleted else ''
                changes = ', '.join(i for i in (added, changed, deleted) if i)
                if changes:
                    if self.summary:
                        self.summary += ' and '
                    self.summary += "{} {}".format(self.config.owner, changes)

                # if the registry information changed, log the dict diff
                changes = []
                old_registry = old_config.registry if old_config else {}
                diff = dict_diff(self.config.registry, old_registry)
                # try to be as succinct as possible
                added = ', '.join(k for k in diff.get('added', {}))
                added = 'added registry info ' + added if added else ''
                changed = ', '.join(k for k in diff.get('changed', {}))
                changed = 'changed registry info ' + changed if changed else ''
                deleted = ', '.join(k for k in diff.get('deleted', {}))
                deleted = 'deleted registry info ' + deleted if deleted else ''
                changes = ', '.join(i for i in (added, changed, deleted) if i)
                if changes:
                    if self.summary:
                        self.summary += ' and '
                    self.summary += "{} {}".format(self.config.owner, changes)

                # if the healthcheck information changed, log the dict diff
                changes = []
                old_healthcheck = old_config.healthcheck if old_config else {}
                diff = dict_diff(self.config.healthcheck, old_healthcheck)
                # try to be as succinct as possible
                added = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('added', {})])))  # noqa
                added = 'added healthcheck info for proc type ' + added if added else ''
                changed = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('changed', {})])))  # noqa
                changed = 'changed healthcheck info for proc type ' + changed if changed else ''
                deleted = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('deleted', {})])))  # noqa
                deleted = 'deleted healthcheck info for proc type ' + deleted if deleted else ''
                changes = ', '.join(i for i in (added, changed, deleted) if i)
                if changes:
                    if self.summary:
                        self.summary += ' and '
                    self.summary += "{} {}".format(self.config.owner, changes)

            if not self.summary:
                if self.version == 1:
                    self.summary = "{} created the initial release".format(self.owner)
                else:
                    # There were no changes to this release
                    raise AlreadyExists("{} changed nothing - release stopped".format(self.owner))

        super(Release, self).save(*args, **kwargs)
