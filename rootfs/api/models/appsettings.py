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
    maintenance = models.BooleanField(default=False)

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

    def save(self, *args, **kwargs):
        summary = ''
        previous_settings = None
        try:
            previous_settings = self.app.appsettings_set.latest()
        except AppSettings.DoesNotExist:
            pass

        prev_maintenance = getattr(previous_settings, 'maintenance', None)
        new_maintenance = getattr(self, 'maintenance')

        try:
            if new_maintenance is None and prev_maintenance is not None:
                setattr(self, 'maintenance', prev_maintenance)
            elif prev_maintenance != new_maintenance:
                self.set_maintenance(new_maintenance)
                summary += "{} changed maintenance mode from {} to {}".format(self.owner, prev_maintenance, new_maintenance)  # noqa
        except Exception as e:
            self.delete()
            raise DeisException(str(e)) from e

        if not summary and previous_settings:
            self.delete()
            raise AlreadyExists("{} changed nothing".format(self.owner))
        self.app.log('summary of app setting changes: {}'.format(summary), logging.DEBUG)

        return super(AppSettings, self).save(**kwargs)
