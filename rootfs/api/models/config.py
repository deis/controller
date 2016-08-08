from django.conf import settings
from django.db import models
from jsonfield import JSONField

from api.models.release import Release
from api.models import UuidAuditedModel
from api.exceptions import DeisException, UnprocessableEntity


class Config(UuidAuditedModel):
    """
    Set of configuration values applied as environment variables
    during runtime execution of the Application.
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    values = JSONField(default={}, blank=True)
    memory = JSONField(default={}, blank=True)
    cpu = JSONField(default={}, blank=True)
    tags = JSONField(default={}, blank=True)
    registry = JSONField(default={}, blank=True)
    healthcheck = JSONField(default={}, blank=True)
    routable = models.BooleanField(default=True)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'uuid'),)

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def _migrate_legacy_healthcheck(self):
        """
        Get all healthchecks options together for use in scheduler
        """
        # return if no legacy healthcheck is found
        if 'HEALTHCHECK_URL' not in self.values.keys():
            return

        path = self.values.get('HEALTHCHECK_URL', '/')
        timeout = int(self.values.get('HEALTHCHECK_TIMEOUT', 50))
        delay = int(self.values.get('HEALTHCHECK_INITIAL_DELAY', 50))
        period_seconds = int(self.values.get('HEALTHCHECK_PERIOD_SECONDS', 10))
        success_threshold = int(self.values.get('HEALTHCHECK_SUCCESS_THRESHOLD', 1))
        failure_threshold = int(self.values.get('HEALTHCHECK_FAILURE_THRESHOLD', 3))

        self.healthcheck['livenessProbe'] = {
            'initialDelaySeconds': delay,
            'timeoutSeconds': timeout,
            'periodSeconds': period_seconds,
            'successThreshold': success_threshold,
            'failureThreshold': failure_threshold,
            'httpGet': {
                'path': path,
            }
        }

        self.healthcheck['readinessProbe'] = {
            'initialDelaySeconds': delay,
            'timeoutSeconds': timeout,
            'periodSeconds': period_seconds,
            'successThreshold': success_threshold,
            'failureThreshold': failure_threshold,
            'httpGet': {
                'path': path,
            }
        }

        # Unset all the old values
        self.values = {k: v for k, v in self.values.items() if not k.startswith('HEALTHCHECK_')}

    def set_registry(self):
        # lower case all registry options for consistency
        self.registry = {key.lower(): value for key, value in self.registry.copy().items()}

        # PORT must be set if private registry is being used
        if self.registry and self.values.get('PORT', None) is None:
            # only thing that can get past post_save in the views
            raise DeisException(
                'PORT needs to be set in the config '
                'when using a private registry')

    def set_tags(self, previous_config):
        """verify the tags exist on any nodes as labels"""
        if not self.tags:
            return

        # Get all nodes with label selectors
        nodes = self._scheduler.get_nodes(labels=self.tags).json()
        if nodes['items']:
            return

        labels = ['{}={}'.format(key, value) for key, value in self.tags.items()]
        message = 'No nodes matched the provided labels: {}'.format(', '.join(labels))

        # Find out if there are any other tags around
        old_tags = getattr(previous_config, 'tags')
        if old_tags:
            old = ['{}={}'.format(key, value) for key, value in old_tags.items()]
            new = set(labels) - set(old)
            if new:
                message += ' - Addition of {} is the cause'.format(', '.join(new))

        raise DeisException(message)

    def save(self, **kwargs):
        """merge the old config with the new"""
        try:
            # Get config from the latest available release
            try:
                previous_config = self.app.release_set.latest().config
            except Release.DoesNotExist:
                # If that doesn't exist then fallback on app config
                # usually means a totally new app
                previous_config = self.app.config_set.latest()

            for attr in ['cpu', 'memory', 'tags', 'registry', 'values', 'healthcheck']:
                data = getattr(previous_config, attr, {}).copy()
                new_data = getattr(self, attr, {}).copy()

                # remove config keys if a null value is provided
                for key, value in new_data.items():
                    if value is None:
                        # error if unsetting non-existing key
                        if key not in data:
                            raise UnprocessableEntity('{} does not exist under {}'.format(key, attr))  # noqa
                        data.pop(key)
                    else:
                        data[key] = value
                setattr(self, attr, data)

            self._migrate_legacy_healthcheck()
            self.set_registry()
            self.set_tags(previous_config)
        except Config.DoesNotExist:
            pass

        return super(Config, self).save(**kwargs)
