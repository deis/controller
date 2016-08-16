# -*- coding: utf-8 -*-

"""
Data models for the Deis API.
"""
import importlib
import logging
import uuid
import morph
import re

from django.conf import settings
from django.db import models
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from rest_framework.exceptions import ValidationError
from rest_framework.authtoken.models import Token

from api.exceptions import DeisException, AlreadyExists, ServiceUnavailable  # noqa
from api.utils import dict_merge
from scheduler import KubeException

logger = logging.getLogger(__name__)


def validate_label(value):
    """
    Check that the value follows the kubernetes name constraints
    http://kubernetes.io/v1.1/docs/design/identifiers.html
    """
    match = re.match(r'^[a-z0-9-]+$', value)
    if not match:
        raise ValidationError("Can only contain a-z (lowercase), 0-9 and hyphens")


class AuditedModel(models.Model):
    """Add created and updated fields to a model."""

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Mark :class:`AuditedModel` as abstract."""
        abstract = True

    @property
    def _scheduler(self):
        mod = importlib.import_module(settings.SCHEDULER_MODULE)
        return mod.SchedulerClient()

    def _fetch_service_config(self, app):
        try:
            # Get the service from k8s to attach the domain correctly
            svc = self._scheduler.get_service(app, app).json()
        except KubeException as e:
            raise ServiceUnavailable('Could not fetch Kubernetes Service {}'.format(app)) from e

        # Get minimum structure going if it is missing on the service
        if 'metadata' not in svc or 'annotations' not in svc['metadata']:
            default = {'metadata': {'annotations': {}}}
            svc = dict_merge(svc, default)

        if 'labels' not in svc['metadata']:
            default = {'metadata': {'labels': {}}}
            svc = dict_merge(svc, default)

        return svc

    def _load_service_config(self, app, component):
        # fetch setvice definition with minimum structure
        svc = self._fetch_service_config(app)

        # always assume a .deis.io/ ending
        component = "%s.deis.io/" % component

        # Filter to only include values for the component and strip component out of it
        # Processes dots into a nested structure
        config = morph.unflatten(morph.pick(svc['metadata']['annotations'], prefix=component))

        return config

    def _save_service_config(self, app, component, data):
        # fetch setvice definition with minimum structure
        svc = self._fetch_service_config(app)

        # always assume a .deis.io ending
        component = "%s.deis.io/" % component

        # add component to data and flatten
        data = {"%s%s" % (component, key): value for key, value in list(data.items())}
        svc['metadata']['annotations'].update(morph.flatten(data))

        # Update the k8s service for the application with new service information
        try:
            self._scheduler.update_service(app, app, svc)
        except KubeException as e:
            raise ServiceUnavailable('Could not update Kubernetes Service {}'.format(app)) from e


class UuidAuditedModel(AuditedModel):
    """Add a UUID primary key to an :class:`AuditedModel`."""

    uuid = models.UUIDField('UUID',
                            default=uuid.uuid4,
                            primary_key=True,
                            editable=False,
                            auto_created=True,
                            unique=True)

    class Meta:
        """Mark :class:`UuidAuditedModel` as abstract."""
        abstract = True


from .app import App, validate_id_is_docker_compatible, validate_reserved_names, validate_app_structure  # noqa
from .key import Key, validate_base64  # noqa
from .certificate import Certificate, validate_certificate  # noqa
from .domain import Domain  # noqa
from .release import Release  # noqa
from .config import Config  # noqa
from .build import Build  # noqa
from .appsettings import AppSettings  # noqa

# define update/delete callbacks for synchronizing
# models with the configuration management backend


def _log_build_created(**kwargs):
    if kwargs.get('created'):
        build = kwargs['instance']
        # log only to the controller; this event will be logged in the release summary
        build.app.log("build {} created".format(build))


def _log_release_created(**kwargs):
    if kwargs.get('created'):
        release = kwargs['instance']
        # append release lifecycle logs to the app
        release.app.log(release.summary)


def _log_config_updated(**kwargs):
    config = kwargs['instance']
    # log only to the controller; this event will be logged in the release summary
    config.app.log("config {} updated".format(config))


def _log_app_settings_updated(**kwargs):
    appSettings = kwargs['instance']
    # log only to the controller; this event will be logged in the release summary
    appSettings.app.log("application settings {} updated".format(appSettings))


def _log_domain_added(**kwargs):
    if kwargs.get('created'):
        domain = kwargs['instance']
        domain.app.log("domain {} added".format(domain))


def _log_domain_removed(**kwargs):
    domain = kwargs['instance']
    domain.app.log("domain {} removed".format(domain))


def _log_cert_added(**kwargs):
    if kwargs.get('created'):
        cert = kwargs['instance']
        logger.info("cert {} added".format(cert))


def _log_cert_removed(**kwargs):
    cert = kwargs['instance']
    logger.info("cert {} removed".format(cert))


# Log significant app-related events
post_save.connect(_log_build_created, sender=Build, dispatch_uid='api.models.log')
post_save.connect(_log_release_created, sender=Release, dispatch_uid='api.models.log')
post_save.connect(_log_config_updated, sender=Config, dispatch_uid='api.models.log')
post_save.connect(_log_domain_added, sender=Domain, dispatch_uid='api.models.log')
post_save.connect(_log_cert_added, sender=Certificate, dispatch_uid='api.models.log')
post_save.connect(_log_app_settings_updated, sender=AppSettings, dispatch_uid='api.models.log')
post_delete.connect(_log_domain_removed, sender=Domain, dispatch_uid='api.models.log')
post_delete.connect(_log_cert_removed, sender=Certificate, dispatch_uid='api.models.log')


# automatically generate a new token on creation
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
