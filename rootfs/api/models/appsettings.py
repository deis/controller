import logging
from django.conf import settings
from django.db import models

from api.models import UuidAuditedModel
from api.exceptions import DeisException, AlreadyExists
from scheduler import KubeException


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

    def set_maintenance(self, maintenance):
        namespace = self.app.id
        service = self._fetch_service_config(namespace)
        old_service = service.copy()  # in case anything fails for rollback

        try:
            service['metadata']['annotations']['router.deis.io/maintenance'] = str(maintenance)
            self._scheduler.update_service(namespace, namespace, data=service)
        except Exception as e:
            self._scheduler.update_service(namespace, namespace, data=old_service)
            raise KubeException(str(e)) from e

    def set_routable(self, routable):
        namespace = self.app.id
        service = self._fetch_service_config(namespace)
        old_service = service.copy()  # in case anything fails for rollback

        try:
            service['metadata']['labels']['router.deis.io/routable'] = str(routable).lower()
            self._scheduler.update_service(namespace, namespace, data=service)
        except Exception as e:
            self._scheduler.update_service(namespace, namespace, data=old_service)
            raise KubeException(str(e)) from e

    def update_maintenance(self, previous_settings):
        prev_maintenance = getattr(previous_settings, 'maintenance', None)
        new_maintenance = getattr(self, 'maintenance', None)
        # If no previous settings, assume this is first timeout
        # and set the default maintenance as false
        if not previous_settings:
            setattr(self, 'maintenance', False)
            self.set_maintenance(False)
        # if nothing changed copy the settings from previous
        elif new_maintenance is None and prev_maintenance is not None:
            setattr(self, 'maintenance', prev_maintenance)
        elif prev_maintenance != new_maintenance:
            self.set_maintenance(new_maintenance)
            self.summary += "{} changed maintenance mode from {} to {}".format(self.owner, prev_maintenance, new_maintenance)  # noqa

    def update_routable(self, previous_settings):
        old_routable = getattr(previous_settings, 'routable', None)
        new_routable = getattr(self, 'routable', None)
        # If no previous settings, assume this is first timeout
        # and set the default maintenance as true
        if not previous_settings:
            setattr(self, 'routable', True)
            self.set_routable(True)
        # if nothing changed copy the settings from previous
        elif new_routable is None and old_routable is not None:
            setattr(self, 'routable', old_routable)
        elif old_routable != new_routable:
            self.set_routable(new_routable)
            self.summary += "{} changed routablity from {} to {}".format(self.owner, old_routable, new_routable)  # noqa

    def save(self, *args, **kwargs):
        self.summary = ''
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
        self.app.log('summary of app setting changes: {}'.format(self.summary), logging.DEBUG)

        return super(AppSettings, self).save(**kwargs)
