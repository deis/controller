from __future__ import unicode_literals

from django.utils.encoding import python_2_unicode_compatible
from django.db import models
from django.conf import settings

# local models
from api.models.audit import UuidAuditedModel


@python_2_unicode_compatible
class Push(UuidAuditedModel):
    """
    Instance of a push used to trigger an application build
    """
    owner = models.ForeignKey(settings.AUTH_USER_MODEL)
    app = models.ForeignKey('App')
    sha = models.CharField(max_length=40)

    fingerprint = models.CharField(max_length=255)
    receive_user = models.CharField(max_length=255)
    receive_repo = models.CharField(max_length=255)

    ssh_connection = models.CharField(max_length=255)
    ssh_original_command = models.CharField(max_length=255)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'uuid'),)
        db_table = 'push'
        app_label = 'api'

    def __str__(self):
        return "{0}-{1}".format(self.app.id, self.sha[:7])
