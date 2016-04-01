from django.conf import settings
from django.db import models
from jsonfield import JSONField

from api.models import UuidAuditedModel


class Config(UuidAuditedModel):
    """
    Set of configuration values applied as environment variables
    during runtime execution of the Application.
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL)
    app = models.ForeignKey('App')
    values = JSONField(default={}, blank=True)
    memory = JSONField(default={}, blank=True)
    cpu = JSONField(default={}, blank=True)
    tags = JSONField(default={}, blank=True)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'uuid'),)

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def healthcheck(self):
        """
        Get all healthchecks options together for use in scheduler
        """
        # return empty dict if no healthcheck is found
        if 'HEALTHCHECK_URL' not in self.values.keys():
            return {}

        path = self.values.get('HEALTHCHECK_URL', '/')
        timeout = int(self.values.get('HEALTHCHECK_TIMEOUT', 50))
        delay = int(self.values.get('HEALTHCHECK_INITIAL_DELAY', 50))
        port = int(self.values.get('HEALTHCHECK_PORT', 5000))

        return {'path': path, 'timeout': timeout, 'delay': delay, 'port': port}

    def set_healthchecks(self):
        """Defines default values for HTTP healthchecks"""
        if not {k: v for k, v in self.values.items() if k.startswith('HEALTHCHECK_')}:
            return

        # fetch set health values and any defaults
        # this approach allows new health items to be added without issues
        health = self.healthcheck()
        self.values['HEALTHCHECK_URL'] = health['path']
        self.values['HEALTHCHECK_TIMEOUT'] = health['timeout']
        self.values['HEALTHCHECK_INITIAL_DELAY'] = health['delay']
        self.values['HEALTHCHECK_PORT'] = health['port']

    def save(self, **kwargs):
        """merge the old config with the new"""
        try:
            previous_config = self.app.config_set.latest()
            for attr in ['cpu', 'memory', 'tags', 'values']:
                # Guard against migrations from older apps without fixes to
                # JSONField encoding.
                try:
                    data = getattr(previous_config, attr).copy()
                except AttributeError:
                    data = {}

                try:
                    new_data = getattr(self, attr).copy()
                except AttributeError:
                    new_data = {}

                data.update(new_data)
                # remove config keys if we provided a null value
                [data.pop(k) for k, v in new_data.items() if v is None]
                setattr(self, attr, data)
        except Config.DoesNotExist:
            pass

        # set any missing HEALTHCHECK_* elements
        self.set_healthchecks()

        # verify the tags exist on any nodes as labels
        if self.tags:
            # Get all nodes with label selectors
            nodes = self._scheduler._get_nodes(labels=self.tags).json()
            if not nodes['items']:
                labels = ['{}={}'.format(key, value) for key, value in self.tags.items()]
                message = 'No nodes matched the provided labels: {}'.format(', '.join(labels))

                # Find out if there are any other tags around
                old_tags = getattr(previous_config, 'tags')
                if old_tags:
                    old = ['{}={}'.format(key, value) for key, value in old_tags.items()]
                    new = set(labels) - set(old)
                    message += ' - Addition of {} is the cause'.format(', '.join(new))

                raise EnvironmentError(message)

        return super(Config, self).save(**kwargs)
