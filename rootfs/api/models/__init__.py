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

from api.exceptions import DeisException, AlreadyExists, ServiceUnavailable, UnprocessableEntity  # noqa
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
        return mod.SchedulerClient(settings.SCHEDULER_URL, settings.K8S_API_VERIFY_TLS)

    def _fetch_service_config(self, app):
        try:
            # Get the service from k8s to attach the domain correctly
            svc = self._scheduler.svc.get(app, app).json()
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
            self._scheduler.svc.update(app, app, svc)
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
from .appsettings import AppSettings  # noqa
from .build import Build  # noqa
from .certificate import Certificate, validate_certificate  # noqa
from .config import Config  # noqa
from .domain import Domain  # noqa
from .key import Key, validate_base64  # noqa
from .release import Release  # noqa
from .tls import TLS  # noqa

# define update/delete callbacks for synchronizing
# models with the configuration management backend


def _log_instance_created(**kwargs):
    if kwargs.get('created'):
        instance = kwargs['instance']
        message = '{} {} created'.format(instance.__class__.__name__.lower(), instance)
        if hasattr(instance, 'app'):
            instance.app.log(message)
        else:
            logger.info(message)


def _log_instance_added(**kwargs):
    if kwargs.get('created'):
        instance = kwargs['instance']
        message = '{} {} added'.format(instance.__class__.__name__.lower(), instance)
        if hasattr(instance, 'app'):
            instance.app.log(message)
        else:
            logger.info(message)


def _log_instance_updated(**kwargs):
    instance = kwargs['instance']
    message = '{} {} updated'.format(instance.__class__.__name__.lower(), instance)
    if hasattr(instance, 'app'):
        instance.app.log(message)
    else:
        logger.info(message)


def _log_instance_removed(**kwargs):
    instance = kwargs['instance']
    message = '{} {} removed'.format(instance.__class__.__name__.lower(), instance)
    if hasattr(instance, 'app'):
        instance.app.log(message)
    else:
        logger.info(message)


# special case: log the release summary
def _log_release_created(**kwargs):
    if kwargs.get('created'):
        release = kwargs['instance']
        # append release lifecycle logs to the app
        release.app.log(release.summary)


# Log significant app-related events
post_save.connect(_log_release_created, sender=Release, dispatch_uid='api.models.log')

post_save.connect(_log_instance_created, sender=Build, dispatch_uid='api.models.log')
post_save.connect(_log_instance_added, sender=Certificate, dispatch_uid='api.models.log')
post_save.connect(_log_instance_added, sender=Domain, dispatch_uid='api.models.log')

post_save.connect(_log_instance_updated, sender=AppSettings, dispatch_uid='api.models.log')
post_save.connect(_log_instance_updated, sender=Config, dispatch_uid='api.models.log')

post_delete.connect(_log_instance_removed, sender=Certificate, dispatch_uid='api.models.log')
post_delete.connect(_log_instance_removed, sender=Domain, dispatch_uid='api.models.log')
post_delete.connect(_log_instance_removed, sender=TLS, dispatch_uid='api.models.log')


# automatically generate a new token on creation
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
