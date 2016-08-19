import logging
from django.conf import settings
from django.db import models

from api.models import UuidAuditedModel
from api.exceptions import DeisException, AlreadyExists


class AppSettings(UuidAuditedModel):
    """
    Instance of Application settings used by scheduler
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    maintenance = models.NullBooleanField(default=None)
    routable = models.NullBooleanField(default=None)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'uuid'))
        ordering = ['-created']

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def update_maintenance(self, previous_settings):
        old = getattr(previous_settings, 'maintenance', None)
        new = getattr(self, 'maintenance', None)
        # If no previous settings then assume it is the first record and default to true
        if not previous_settings:
            setattr(self, 'maintenance', False)
            self.app.maintenance_mode(False)
        # if nothing changed copy the settings from previous
        elif new is None and old is not None:
            setattr(self, 'maintenance', old)
        elif old != new:
            self.app.maintenance_mode(new)
            self.summary += ["{} changed maintenance mode from {} to {}".format(self.owner, old, new)]  # noqa

    def update_routable(self, previous_settings):
        old = getattr(previous_settings, 'routable', None)
        new = getattr(self, 'routable', None)
        # If no previous settings then assume it is the first record and default to true
        if not previous_settings:
            setattr(self, 'routable', True)
            self.app.routable(True)
        # if nothing changed copy the settings from previous
        elif new is None and old is not None:
            setattr(self, 'routable', old)
        elif old != new:
            self.app.routable(new)
            self.summary += ["{} changed routablity from {} to {}".format(self.owner, old, new)]

    def save(self, *args, **kwargs):
        self.summary = []
        previous_settings = None
        try:
            previous_settings = self.app.appsettings_set.latest()
        except AppSettings.DoesNotExist:
            pass

        try:
            self.update_maintenance(previous_settings)
            self.update_routable(previous_settings)
        except Exception as e:
            self.delete()
            raise DeisException(str(e)) from e

        if not self.summary and previous_settings:
            self.delete()
            raise AlreadyExists("{} changed nothing".format(self.owner))

        summary = ' '.join(self.summary)
        self.app.log('summary of app setting changes: {}'.format(summary), logging.DEBUG)
        return super(AppSettings, self).save(**kwargs)
