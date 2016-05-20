import logging

from django.conf import settings
from django.db import models

from registry import publish_release, get_port as docker_get_port, RegistryException
from api.utils import dict_diff
from api.models import UuidAuditedModel, DeisException
from scheduler import KubeHTTPException

logger = logging.getLogger(__name__)


class Release(UuidAuditedModel):
    """
    Software release deployed by the application platform

    Releases contain a :class:`Build` and a :class:`Config`.
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL)
    app = models.ForeignKey('App')
    version = models.PositiveIntegerField()
    summary = models.TextField(blank=True, null=True)

    config = models.ForeignKey('Config')
    build = models.ForeignKey('Build', null=True)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'version'),)

    def __str__(self):
        return "{0}-v{1}".format(self.app.id, self.version)

    @property
    def image(self):
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
            # strip registry information off first
            image = self.build.image.replace('{}/'.format(settings.REGISTRY_URL), '')
            return image.replace('{}/'.format(settings.REGISTRY_HOST), '')

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
        new_version = self.version + 1
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
        ):
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

    def get_port(self, routable=False):
        """
        Get application port for a given release. If pulling from private registry
        then use default port or read from ENV var, otherwise attempt to pull from
        the docker image
        """
        try:
            deis_registry = bool(self.build.source_based)
            envs = self.config.values
            creds = self.get_registry_auth()

            port = None
            # Only care about port for routable application
            if not routable:
                return port

            if self.build.type == "buildpack":
                msg = "Using default port 5000 for build pack image {}".format(self.image)
                self.app.log(msg)
                return 5000

            # application has registry auth - $PORT is required
            if creds is not None:
                if envs.get('PORT', None) is None:
                    self.app.log('Private registry detected but no $PORT defined. Defaulting to $PORT 5000', logging.WARNING)  # noqa
                    return 5000

                # User provided PORT
                return envs.get('PORT')

            # If the user provides PORT
            if envs.get('PORT', None):
                return envs.get('PORT')

            # discover port from docker image
            port = docker_get_port(self.image, deis_registry, creds)
            if port is None:
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
            prev_release = releases.latest()
        except Release.DoesNotExist:
            prev_release = None
        return prev_release

    def rollback(self, user, version=None):
        try:
            # if no version is provided then grab version from object
            version = (self.version - 1) if version is None else int(version)

            if version < 1:
                raise DeisException('version cannot be below 0')

            prev = self.app.release_set.get(version=version)
            new_release = self.new(
                user,
                build=prev.build,
                config=prev.config,
                summary="{} rolled back to v{}".format(user, version),
                source_version='v{}'.format(version)
            )

            if self.build is not None:
                self.app.deploy(new_release)
            return new_release
        except Exception as e:
            if 'new_release' in locals():
                new_release.delete()
            raise DeisException(str(e)) from e

    def delete(self, *args, **kwargs):
        """Delete release DB record and any RCs from the affect release"""
        try:
            self._delete_release_in_scheduler(self.app.id, self.version)
        except KubeHTTPException as e:
            # 404 means they were already cleaned up
            if e.response.status_code is not 404:
                # Another problem came up
                message = 'Could not to cleanup RCs for release {}'.format(self.version)
                self.app.log(message, level=logging.WARNING)
                logger.warning(message + ' - ' + str(e))
        finally:
            super(Release, self).delete(*args, **kwargs)

    def cleanup_old(self):
        """Cleanup all but the latest release from Kubernetes"""
        latest_version = 'v{}'.format(self.version)
        self.app.log(
            'Cleaning up RCS for releases older than {} (latest)'.format(latest_version),
            level=logging.DEBUG
        )

        # Cleanup controllers
        labels = {
            'heritage': 'deis'
        }
        controller_removal = []
        controllers = self._scheduler._get_rcs(self.app.id, labels=labels).json()
        for controller in controllers['items']:
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

        for version in controller_removal:
            self._delete_release_in_scheduler(self.app.id, version)

        # find stray env secrets to remove that may have been missed
        self.app.log('Cleaning up orphaned environment var secrets', level=logging.DEBUG)
        labels = {
            'heritage': 'deis',
            'app': self.app.id,
            'type': 'env'
        }
        secrets = self._scheduler._get_secrets(self.app.id, labels=labels).json()
        for secret in secrets['items']:
            current_version = secret['metadata']['labels']['version']
            # skip the latest release
            if current_version == latest_version:
                continue

            self._scheduler._delete_secret(self.app.id, secret['metadata']['name'])

        # Remove stray pods
        labels = {
            'heritage': 'deis'
        }
        pods = self._scheduler._get_pods(self.app.id, labels=labels).json()
        for pod in pods['items']:
            if self._scheduler._pod_deleted(pod):
                continue

            current_version = pod['metadata']['labels']['version']
            # skip the latest release
            if current_version == latest_version:
                continue

            self._scheduler._delete_pod(self.app.id, pod['metadata']['name'])

    def _delete_release_in_scheduler(self, namespace, version):
        """
        Deletes a specific release in k8s

        Scale RCs to 0 then delete RCs and the version specific
        secret that container the env var
        """
        labels = {
            'heritage': 'deis',
            'app': namespace,
            'version': 'v{}'.format(version)
        }
        controllers = self._scheduler._get_rcs(namespace, labels=labels).json()
        for controller in controllers['items']:
            self._scheduler._cleanup_release(namespace, controller)

        # remove secret that contains env vars for the release
        try:
            secret_name = "{}-{}-env".format(namespace, version)
            self._scheduler._delete_secret(namespace, secret_name)
        except KubeHTTPException:
            pass

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

            if not self.summary:
                if self.version == 1:
                    self.summary = "{} created the initial release".format(self.owner)
                else:
                    self.summary = "{} changed nothing".format(self.owner)
        super(Release, self).save(*args, **kwargs)
