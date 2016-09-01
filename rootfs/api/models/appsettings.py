import logging
from django.conf import settings
from django.db import models
from django.contrib.postgres.fields import ArrayField
from jsonfield import JSONField
from rest_framework.exceptions import NotFound

from api.utils import dict_diff
from api.models import UuidAuditedModel
from api.exceptions import DeisException, AlreadyExists, UnprocessableEntity


class AppSettings(UuidAuditedModel):
    """
    Instance of Application settings used by scheduler
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    maintenance = models.NullBooleanField(default=None)
    routable = models.NullBooleanField(default=None)
    whitelist = ArrayField(models.CharField(max_length=50), default=[])
    autoscale = JSONField(default={}, blank=True)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'uuid'))
        ordering = ['-created']

    def __str__(self):
        return "{}-{}".format(self.app.id, str(self.uuid)[:7])

    def new(self, user, whitelist):
        """
        Create a new application appSettings using the provided whitelist
        on behalf of a user.
        """

        appSettings = AppSettings.objects.create(
            owner=user, app=self.app, whitelist=whitelist)

        return appSettings

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

    def update_whitelist(self, previous_settings):
        # If no previous settings then assume it is the first record and do nothing
        if not previous_settings:
            return
        old = getattr(previous_settings, 'whitelist', [])
        new = getattr(self, 'whitelist', [])
        # if nothing changed copy the settings from previous
        if len(new) == 0 and len(old) != 0:
            setattr(self, 'whitelist', old)
        elif set(old) != set(new):
            self.app.whitelist(new)
            added = ', '.join(k for k in set(new)-set(old))
            added = 'added ' + added if added else ''
            deleted = ', '.join(k for k in set(old)-set(new))
            deleted = 'deleted ' + deleted if deleted else ''
            changes = ', '.join(i for i in (added, deleted) if i)
            if changes:
                if self.summary:
                    self.summary += ' and '
                self.summary += "{} {}".format(self.owner, changes)

    def update_autoscale(self, previous_settings):
        data = getattr(previous_settings, 'autoscale', {}).copy()
        new = getattr(self, 'autoscale', {}).copy()
        # If no previous settings then do nothing
        if not previous_settings:
            return

        # if nothing changed copy the settings from previous
        if not new and data:
            setattr(self, 'autoscale', data)
        elif data != new:
            for proc, scale in new.items():
                if scale is None:
                    # error if unsetting non-existing key
                    if proc not in data:
                        raise UnprocessableEntity('{} does not exist under {}'.format(proc, 'autoscale'))  # noqa
                    del data[proc]
                else:
                    data[proc] = scale
            setattr(self, 'autoscale', data)

            # only apply new items
            for proc, scale in new.items():
                self.app.autoscale(proc, scale)

            # if the autoscale information changed, log the dict diff
            changes = []
            old_autoscale = getattr(previous_settings, 'autoscale', {})
            diff = dict_diff(self.autoscale, old_autoscale)
            # try to be as succinct as possible
            added = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('added', {})])))  # noqa
            added = 'added autoscale for process type ' + added if added else ''
            changed = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('changed', {})])))  # noqa
            changed = 'changed autoscale for process type ' + changed if changed else ''
            deleted = ', '.join(list(map(lambda x: 'default' if x == '' else x, [k for k in diff.get('deleted', {})])))  # noqa
            deleted = 'deleted autoscale for process type ' + deleted if deleted else ''
            changes = ', '.join(i for i in (added, changed, deleted) if i)
            if changes:
                self.summary += ["{} {}".format(self.owner, changes)]

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
            self.update_whitelist(previous_settings)
            self.update_autoscale(previous_settings)
        except (UnprocessableEntity, NotFound):
            raise
        except Exception as e:
            self.delete()
            raise DeisException(str(e)) from e

        if not self.summary and previous_settings:
            self.delete()
            raise AlreadyExists("{} changed nothing".format(self.owner))

        summary = ' '.join(self.summary)
        self.app.log('summary of app setting changes: {}'.format(summary), logging.DEBUG)
        return super(AppSettings, self).save(**kwargs)
