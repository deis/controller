from django.db import models
from django.conf import settings

from api.exceptions import AlreadyExists
from api.models import UuidAuditedModel


class TLS(UuidAuditedModel):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    https_enforced = models.NullBooleanField(default=None)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'uuid'))
        ordering = ['-created']

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def _load_service_config(self, app, component):
        config = super()._load_service_config(app, component)

        # See if the ssl.enforce annotation is available
        if 'ssl' not in config:
            config['ssl'] = {}
        if 'enforce' not in config['ssl']:
            config['ssl']['enforce'] = 'false'

        return config

    def _check_previous_tls_settings(self):
        try:
            previous_tls_settings = self.app.tls_set.latest()

            if (
                previous_tls_settings.https_enforced is not None and
                self.https_enforced == previous_tls_settings.https_enforced
            ):
                self.delete()
                raise AlreadyExists("{} changed nothing".format(self.owner))
        except TLS.DoesNotExist:
            pass

    def save(self, *args, **kwargs):
        self._check_previous_tls_settings()

        app = str(self.app)
        https_enforced = bool(self.https_enforced)

        # get config for the service
        config = self._load_service_config(app, 'router')

        # convert from bool to string
        config['ssl']['enforce'] = str(https_enforced)

        self._save_service_config(app, 'router', config)

        # Save to DB
        return super(TLS, self).save(*args, **kwargs)

    def sync(self):
        try:
            app = str(self.app)

            config = self._load_service_config(app, 'router')
            if (
                config['ssl']['enforce'] != str(self.https_enforced) and
                self.https_enforced is not None
            ):
                config['ssl']['enforce'] = str(self.https_enforced)
                self._save_service_config(app, 'router', config)
        except TLS.DoesNotExist:
            pass
