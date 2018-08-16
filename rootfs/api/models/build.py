from django.conf import settings
from django.db import models
from jsonfield import JSONField

from api.models import UuidAuditedModel
from api.exceptions import DeisException, Conflict

import logging
logger = logging.getLogger(__name__)


class Build(UuidAuditedModel):
    """
    Instance of a software build used by runtime nodes
    """

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    image = models.TextField()

    # optional fields populated by builder
    sha = models.CharField(max_length=40, blank=True)
    procfile = JSONField(default={}, blank=True)
    dockerfile = models.TextField(blank=True)
    sidecarfile = JSONField(default={}, blank=True)

    class Meta:
        get_latest_by = 'created'
        ordering = ['-created']
        unique_together = (('app', 'uuid'),)

    @property
    def type(self):
        """Figures out what kind of build type is being deal it with"""
        if self.dockerfile:
            return 'dockerfile'
        elif self.sha:
            return 'buildpack'
        else:
            # docker image (or any sort of image) used via deis pull
            return 'image'

    @property
    def source_based(self):
        """
        Checks if a build is source (has a sha) based or not
        If True then the Build is coming from the deis builder or something that
        built from git / svn / hg / etc directly
        """
        return self.sha != ''

    @property
    def version(self):
        return 'git-{}'.format(self.sha) if self.source_based else 'latest'

    def create(self, user, *args, **kwargs):
        latest_release = self.app.release_set.filter(failed=False).latest()
        latest_version = self.app.release_set.latest().version
        try:
            new_release = latest_release.new(
                user,
                build=self,
                config=latest_release.config,
                source_version=self.version
            )
            self.app.deploy(new_release)
            return new_release
        except Exception as e:
            # check if the exception is during create or publish
            if ('new_release' not in locals() and
                    self.app.release_set.latest().version == latest_version+1):
                new_release = self.app.release_set.latest()
            if 'new_release' in locals():
                new_release.failed = True
                new_release.summary = "{} deployed {} which failed".format(self.owner, str(self.uuid)[:7])  # noqa
                new_release.save()
            else:
                self.delete()

            raise DeisException(str(e)) from e

    def _validate_sidecars(self, previous_release):
        if (
            settings.DEIS_DEPLOY_REJECT_IF_SIDECARFILE_MISSING is True and
            # previous release had a Sidecarfile and the current one does not
            (
                previous_release.build is not None and
                len(previous_release.build.sidecarfile) > 0 and
                len(self.sidecarfile) == 0
            )
        ):
            # Reject deployment
            raise Conflict(
                'Last deployment had a Sidecarfile but is missing in this deploy. '
                'For a successful deployment provide a Sidecarfile.'
            )

        # make sure the latest build has sidecarfile if the intent is to
        # allow empty Sidecarfile without removals
        if (
            settings.DEIS_DEPLOY_SIDECARFILE_MISSING_REMOVE is False and
            previous_release.build is not None and
            len(previous_release.build.sidecarfile) > 0 and
            len(self.sidecarfile) == 0
        ):
            self.sidecarfile = previous_release.build.sidecarfile

    def save(self, **kwargs):
        previous_release = self.app.release_set.filter(failed=False).latest()

        if (
            settings.DEIS_DEPLOY_REJECT_IF_PROCFILE_MISSING is True and
            # previous release had a Procfile and the current one does not
            (
                previous_release.build is not None and
                len(previous_release.build.procfile) > 0 and
                len(self.procfile) == 0
            )
        ):
            # Reject deployment
            raise Conflict(
                'Last deployment had a Procfile but is missing in this deploy. '
                'For a successful deployment provide a Procfile.'
            )

        # See if processes are permitted to be removed
        remove_procs = (
            # If set to True then contents of Procfile does not affect the outcome
            settings.DEIS_DEPLOY_PROCFILE_MISSING_REMOVE is True or
            # previous release had a Procfile and the current one does as well
            (
                previous_release.build is not None and
                len(previous_release.build.procfile) > 0 and
                len(self.procfile) > 0
            )
        )

        # spin down any proc type removed between the last procfile and the newest one
        if remove_procs and previous_release.build is not None:
            removed = {}
            for proc in previous_release.build.procfile:
                if proc not in self.procfile:
                    # Scale proc type down to 0
                    removed[proc] = 0

            self.app.scale(self.owner, removed)

        # make sure the latest build has procfile if the intent is to
        # allow empty Procfile without removals
        if (
            settings.DEIS_DEPLOY_PROCFILE_MISSING_REMOVE is False and
            previous_release.build is not None and
            len(previous_release.build.procfile) > 0 and
            len(self.procfile) == 0
        ):
            self.procfile = previous_release.build.procfile

        self._validate_sidecars(previous_release)
        return super(Build, self).save(**kwargs)

    def __str__(self):
        return "{0}-{1}".format(self.app.id, str(self.uuid)[:7])
