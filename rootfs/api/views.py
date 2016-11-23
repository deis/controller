"""
RESTful view classes for presenting Deis API objects.
"""
from django.http import Http404, HttpResponse
from django.conf import settings
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from guardian.shortcuts import assign_perm, get_objects_for_user, \
    get_users_with_perms, remove_perm
from django.views.generic import View
from django.db.models.deletion import ProtectedError
from rest_framework import mixins, renderers, status
from rest_framework.exceptions import PermissionDenied, NotFound, AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.authtoken.models import Token

from api import authentication, models, permissions, serializers, viewsets
from api.models import AlreadyExists, ServiceUnavailable, DeisException, UnprocessableEntity

import logging

logger = logging.getLogger(__name__)


class ReadinessCheckView(View):
    """
    Simple readiness check view to determine DB connection / query.
    """

    def get(self, request):
        try:
            import django.db
            with django.db.connection.cursor() as c:
                c.execute("SELECT 0")
        except django.db.Error as e:
            raise ServiceUnavailable("Database health check failed") from e

        return HttpResponse("OK")
    head = get


class LivenessCheckView(View):
    """
    Simple liveness check view to determine if the server
    is responding to HTTP requests.
    """

    def get(self, request):
        return HttpResponse("OK")
    head = get


class UserRegistrationViewSet(GenericViewSet,
                              mixins.CreateModelMixin):
    """ViewSet to handle registering new users. The logic is in the serializer."""
    authentication_classes = [authentication.AnonymousOrAuthenticatedAuthentication]
    permission_classes = [permissions.HasRegistrationAuth]
    serializer_class = serializers.UserSerializer


class UserManagementViewSet(GenericViewSet):
    serializer_class = serializers.UserSerializer

    def get_queryset(self):
        return User.objects.filter(pk=self.request.user.pk)

    def get_object(self):
        return self.get_queryset()[0]

    def list(self, request, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, many=False)
        return Response(serializer.data)

    def destroy(self, request, **kwargs):
        calling_obj = self.get_object()
        target_obj = calling_obj

        if request.data.get('username'):
            # if you "accidentally" target yourself, that should be fine
            if calling_obj.username == request.data['username'] or calling_obj.is_superuser:
                target_obj = get_object_or_404(User, username=request.data['username'])
            else:
                raise PermissionDenied()

        # A user can not be removed without apps changing ownership first
        if len(models.App.objects.filter(owner=target_obj)) > 0:
            msg = '{} still has applications assigned. Delete or transfer ownership'.format(str(target_obj))  # noqa
            raise AlreadyExists(msg)

        try:
            target_obj.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except ProtectedError as e:
            raise AlreadyExists(e)

    def passwd(self, request, **kwargs):
        if not request.data.get('new_password'):
            raise DeisException("new_password is a required field")

        caller_obj = self.get_object()
        target_obj = self.get_object()
        if request.data.get('username'):
            # if you "accidentally" target yourself, that should be fine
            if caller_obj.username == request.data['username'] or caller_obj.is_superuser:
                target_obj = get_object_or_404(User, username=request.data['username'])
            else:
                raise PermissionDenied()

        if not caller_obj.is_superuser:
            if not request.data.get('password'):
                raise DeisException("password is a required field")
            if not target_obj.check_password(request.data['password']):
                raise AuthenticationFailed('Current password does not match')

        target_obj.set_password(request.data['new_password'])
        target_obj.save()
        return Response({'status': 'password set'})


class TokenManagementViewSet(GenericViewSet,
                             mixins.DestroyModelMixin):
    serializer_class = serializers.UserSerializer
    permission_classes = [permissions.CanRegenerateToken]

    def get_queryset(self):
        return User.objects.filter(pk=self.request.user.pk)

    def get_object(self):
        return self.get_queryset()[0]

    def regenerate(self, request, **kwargs):
        obj = self.get_object()

        if 'all' in request.data:
            for user in User.objects.all():
                if not user.is_anonymous:
                    token = Token.objects.get(user=user)
                    token.delete()
                    Token.objects.create(user=user)
            return Response("")

        if 'username' in request.data:
            obj = get_object_or_404(User,
                                    username=request.data['username'])
            self.check_object_permissions(self.request, obj)

        token = Token.objects.get(user=obj)
        token.delete()
        token = Token.objects.create(user=obj)
        return Response({'token': token.key})


class BaseDeisViewSet(viewsets.OwnerViewSet):
    """
    A generic ViewSet for objects related to Deis.

    To use it, at minimum you'll need to provide the `serializer_class` attribute and
    the `model` attribute shortcut.
    """
    lookup_field = 'id'
    permission_classes = [IsAuthenticated, permissions.IsAppUser]
    renderer_classes = [renderers.JSONRenderer]


class AppResourceViewSet(BaseDeisViewSet):
    """A viewset for objects which are attached to an application."""

    def get_app(self):
        app = get_object_or_404(models.App, id=self.kwargs['id'])
        self.check_object_permissions(self.request, app)
        return app

    def get_queryset(self, **kwargs):
        app = self.get_app()
        return self.model.objects.filter(app=app)

    def get_object(self, **kwargs):
        return self.get_queryset(**kwargs).latest('created')

    def create(self, request, **kwargs):
        request.data['app'] = self.get_app()
        return super(AppResourceViewSet, self).create(request, **kwargs)


class ReleasableViewSet(AppResourceViewSet):
    """A viewset for application resources which affect the release cycle."""
    def get_object(self):
        """Retrieve the object based on the latest release's value"""
        return getattr(self.get_app().release_set.filter(failed=False).latest(), self.model.__name__.lower())  # noqa


class AppViewSet(BaseDeisViewSet):
    """A viewset for interacting with App objects."""
    model = models.App
    serializer_class = serializers.AppSerializer

    def get_queryset(self, *args, **kwargs):
        return self.model.objects.all(*args, **kwargs)

    def list(self, request, *args, **kwargs):
        """
        HACK: Instead of filtering by the queryset, we limit the queryset to list only the apps
        which are owned by the user as well as any apps they have been given permission to
        interact with.
        """
        queryset = super(AppViewSet, self).get_queryset(**kwargs) | \
            get_objects_for_user(self.request.user, 'api.use_app')
        instance = self.filter_queryset(queryset)
        page = self.paginate_queryset(instance)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(instance, many=True)
        return Response(serializer.data)

    def scale(self, request, **kwargs):
        self.get_object().scale(request.user, request.data)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def logs(self, request, **kwargs):
        app = self.get_object()
        try:
            logs = app.logs(request.query_params.get('log_lines', str(settings.LOG_LINES)))
            return HttpResponse(logs, status=status.HTTP_200_OK, content_type='text/plain')
        except NotFound:
            return HttpResponse(status=status.HTTP_204_NO_CONTENT)
        except ServiceUnavailable:
            # TODO make 503
            return HttpResponse("Error accessing logs for {}".format(app.id),
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                content_type='text/plain')

    def run(self, request, **kwargs):
        app = self.get_object()
        if not request.data.get('command'):
            raise DeisException("command is a required field")
        rc, output = app.run(self.request.user, request.data['command'])
        return Response({'exit_code': rc, 'output': str(output)})

    def update(self, request, **kwargs):
        app = self.get_object()

        if request.data.get('owner'):
            if self.request.user != app.owner and not self.request.user.is_superuser:
                raise PermissionDenied()
            new_owner = get_object_or_404(User, username=request.data['owner'])
            app.owner = new_owner
        app.save()
        return Response(status=status.HTTP_200_OK)


class BuildViewSet(ReleasableViewSet):
    """A viewset for interacting with Build objects."""
    model = models.Build
    serializer_class = serializers.BuildSerializer

    def post_save(self, build):
        self.release = build.create(self.request.user)
        super(BuildViewSet, self).post_save(build)


class ConfigViewSet(ReleasableViewSet):
    """A viewset for interacting with Config objects."""
    model = models.Config
    serializer_class = serializers.ConfigSerializer

    def post_save(self, config):
        release = config.app.release_set.filter(failed=False).latest()
        latest_version = config.app.release_set.latest().version
        try:
            self.release = release.new(self.request.user, config=config, build=release.build)
            # It's possible to set config values before a build
            if self.release.build is not None:
                config.app.deploy(self.release)
        except Exception as e:
            if (not hasattr(self, 'release') and
                    config.app.release_set.latest().version == latest_version+1):
                self.release = config.app.release_set.latest()
            if hasattr(self, 'release'):
                self.release.failed = True
                self.release.summary = "{} deployed a config that failed".format(self.request.user)  # noqa
                self.release.save()
            else:
                config.delete()
            if isinstance(e, AlreadyExists):
                raise
            raise DeisException(str(e)) from e


class PodViewSet(AppResourceViewSet):
    model = models.App
    serializer_class = serializers.PodSerializer

    def list(self, *args, **kwargs):
        pods = self.get_app().list_pods(*args, **kwargs)
        data = self.get_serializer(pods, many=True).data
        # fake out pagination for now
        pagination = {'results': data, 'count': len(data)}
        return Response(pagination, status=status.HTTP_200_OK)

    def restart(self, *args, **kwargs):
        pods = self.get_app().restart(**kwargs)
        data = self.get_serializer(pods, many=True).data
        # fake out pagination for now
        # pagination = {'results': data, 'count': len(data)}
        pagination = data
        return Response(pagination, status=status.HTTP_200_OK)


class AppSettingsViewSet(AppResourceViewSet):
    model = models.AppSettings
    serializer_class = serializers.AppSettingsSerializer


class WhitelistViewSet(AppResourceViewSet):
    model = models.AppSettings
    serializer_class = serializers.AppSettingsSerializer

    def list(self, *args, **kwargs):
        appSettings = self.get_app().appsettings_set.latest()
        data = {"addresses": appSettings.whitelist}
        return Response(data, status=status.HTTP_200_OK)

    def create(self, request, **kwargs):
        appSettings = self.get_app().appsettings_set.latest()
        addresses = self.get_serializer().validate_whitelist(request.data.get('addresses'))
        addresses = list(set(appSettings.whitelist) | set(addresses))
        new_appsettings = appSettings.new(self.request.user, whitelist=addresses)
        return Response({"addresses": new_appsettings.whitelist}, status=status.HTTP_201_CREATED)

    def delete(self, request, **kwargs):
        appSettings = self.get_app().appsettings_set.latest()
        addresses = self.get_serializer().validate_whitelist(request.data.get('addresses'))

        unfound_addresses = set(addresses) - set(appSettings.whitelist)
        if len(unfound_addresses) != 0:
            raise UnprocessableEntity('addresses {} does not exist in whitelist'.format(unfound_addresses))  # noqa
        addresses = list(set(appSettings.whitelist) - set(addresses))
        appSettings.new(self.request.user, whitelist=addresses)
        return Response(status=status.HTTP_204_NO_CONTENT)


class DomainViewSet(AppResourceViewSet):
    """A viewset for interacting with Domain objects."""
    model = models.Domain
    serializer_class = serializers.DomainSerializer

    def get_object(self, **kwargs):
        qs = self.get_queryset(**kwargs)
        domain = self.kwargs['domain']
        # support IDN domains, i.e. accept Unicode encoding too
        try:
            import idna
            if domain.startswith("*."):
                ace_domain = "*." + idna.encode(domain[2:]).decode("utf-8", "strict")
            else:
                ace_domain = idna.encode(domain).decode("utf-8", "strict")
        except:
            ace_domain = domain
        return get_object_or_404(qs, domain=ace_domain)


class CertificateViewSet(BaseDeisViewSet):
    """A viewset for interacting with Certificate objects."""
    model = models.Certificate
    serializer_class = serializers.CertificateSerializer

    def get_object(self, **kwargs):
        """Retrieve domain certificate by its name"""
        qs = self.get_queryset(**kwargs)
        return get_object_or_404(qs, name=self.kwargs['name'])

    def attach(self, request, *args, **kwargs):
        try:
            if kwargs['domain'] is None and not request.data.get('domain'):
                raise DeisException("domain is a required field")
            elif request.data.get('domain'):
                kwargs['domain'] = request.data['domain']

            self.get_object().attach(*args, **kwargs)
        except Http404:
            raise

        return Response(status=status.HTTP_201_CREATED)

    def detach(self, request, *args, **kwargs):
        try:
            self.get_object().detach(*args, **kwargs)
        except Http404:
            raise

        return Response(status=status.HTTP_204_NO_CONTENT)


class KeyViewSet(BaseDeisViewSet):
    """A viewset for interacting with Key objects."""
    model = models.Key
    permission_classes = [IsAuthenticated, permissions.IsOwner]
    serializer_class = serializers.KeySerializer


class ReleaseViewSet(AppResourceViewSet):
    """A viewset for interacting with Release objects."""
    model = models.Release
    serializer_class = serializers.ReleaseSerializer

    def get_object(self, **kwargs):
        """Get release by version always"""
        qs = self.get_queryset(**kwargs)
        return get_object_or_404(qs, version=self.kwargs['version'])

    def rollback(self, request, **kwargs):
        """
        Create a new release as a copy of the state of the compiled slug and config vars of a
        previous release.
        """
        release = self.get_app().release_set.filter(failed=False).latest()
        new_release = release.rollback(request.user, request.data.get('version', None))
        response = {'version': new_release.version}
        return Response(response, status=status.HTTP_201_CREATED)


class TLSViewSet(AppResourceViewSet):
    model = models.TLS
    serializer_class = serializers.TLSSerializer


class BaseHookViewSet(BaseDeisViewSet):
    permission_classes = [permissions.HasBuilderAuth]


class KeyHookViewSet(BaseHookViewSet):
    """API hook to create new :class:`~api.models.Push`"""
    model = models.Key
    serializer_class = serializers.KeySerializer

    def public_key(self, request, *args, **kwargs):
        fingerprint = kwargs['fingerprint'].strip()
        key = get_object_or_404(models.Key, fingerprint=fingerprint)

        queryset = models.App.objects.all() | \
            get_objects_for_user(self.request.user, 'api.use_app')
        items = self.filter_queryset(queryset)

        apps = []
        for item in items:
            apps.append(item.id)

        data = {
            'username': key.owner.username,
            'apps': apps
        }

        return Response(data, status=status.HTTP_200_OK)

    def app(self, request, *args, **kwargs):
        app = get_object_or_404(models.App, id=kwargs['id'])

        perm_name = "api.use_app"
        usernames = [u.id for u in get_users_with_perms(app)
                     if u.has_perm(perm_name, app)]

        data = {}
        result = models.Key.objects \
                       .filter(owner__in=usernames) \
                       .values('owner__username', 'public', 'fingerprint') \
                       .order_by('created')
        for info in result:
            user = info['owner__username']
            if user not in data:
                data[user] = []

            data[user].append({
                'key': info['public'],
                'fingerprint': info['fingerprint']
            })

        return Response(data, status=status.HTTP_200_OK)

    def users(self, request, *args, **kwargs):
        app = get_object_or_404(models.App, id=kwargs['id'])
        request.user = get_object_or_404(User, username=kwargs['username'])
        # check the user is authorized for this app
        if not permissions.is_app_user(request, app):
            raise PermissionDenied()

        data = {request.user.username: []}
        keys = models.Key.objects \
                     .filter(owner__username=kwargs['username']) \
                     .values('public', 'fingerprint') \
                     .order_by('created')
        if not keys:
            raise NotFound("No Keys match the given query.")

        for info in keys:
            data[request.user.username].append({
                'key': info['public'],
                'fingerprint': info['fingerprint']
            })

        return Response(data, status=status.HTTP_200_OK)


class BuildHookViewSet(BaseHookViewSet):
    """API hook to create new :class:`~api.models.Build`"""
    model = models.Build
    serializer_class = serializers.BuildSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.App, id=request.data['receive_repo'])
        self.user = request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        if not permissions.is_app_user(request, app):
            raise PermissionDenied()
        request.data['app'] = app
        request.data['owner'] = self.user
        super(BuildHookViewSet, self).create(request, *args, **kwargs)
        # return the application databag
        response = {'release': {'version': app.release_set.filter(failed=False).latest().version}}
        return Response(response, status=status.HTTP_200_OK)

    def post_save(self, build):
        build.create(self.user)


class ConfigHookViewSet(BaseHookViewSet):
    """API hook to grab latest :class:`~api.models.Config`"""
    model = models.Config
    serializer_class = serializers.ConfigSerializer

    def create(self, request, *args, **kwargs):
        app = get_object_or_404(models.App, id=request.data['receive_repo'])
        request.user = get_object_or_404(User, username=request.data['receive_user'])
        # check the user is authorized for this app
        if not permissions.is_app_user(request, app):
            raise PermissionDenied()
        config = app.release_set.filter(failed=False).latest().config
        serializer = self.get_serializer(config)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AppPermsViewSet(BaseDeisViewSet):
    """RESTful views for sharing apps with collaborators."""

    model = models.App  # models class
    perm = 'use_app'    # short name for permission

    def get_queryset(self):
        return self.model.objects.all()

    def list(self, request, **kwargs):
        app = self.get_object()
        perm_name = "api.{}".format(self.perm)
        usernames = [u.username for u in get_users_with_perms(app)
                     if u.has_perm(perm_name, app)]
        return Response({'users': usernames})

    def create(self, request, **kwargs):
        app = self.get_object()
        if not permissions.IsOwnerOrAdmin.has_object_permission(permissions.IsOwnerOrAdmin(),
                                                                request, self, app):
            raise PermissionDenied()

        user = get_object_or_404(User, username=request.data['username'])
        assign_perm(self.perm, user, app)
        app.log("User {} was granted access to {}".format(user, app))
        return Response(status=status.HTTP_201_CREATED)

    def destroy(self, request, **kwargs):
        app = get_object_or_404(models.App, id=self.kwargs['id'])
        user = get_object_or_404(User, username=kwargs['username'])

        perm_name = "api.{}".format(self.perm)
        if not user.has_perm(perm_name, app):
            raise PermissionDenied()

        if (user != request.user and
            not permissions.IsOwnerOrAdmin.has_object_permission(permissions.IsOwnerOrAdmin(),
                                                                 request, self, app)):
            raise PermissionDenied()
        remove_perm(self.perm, user, app)
        app.log("User {} was revoked access to {}".format(user, app))
        return Response(status=status.HTTP_204_NO_CONTENT)


class AdminPermsViewSet(BaseDeisViewSet):
    """RESTful views for sharing admin permissions with other users."""

    model = User
    serializer_class = serializers.AdminUserSerializer
    permission_classes = [permissions.IsAdmin]

    def get_queryset(self, **kwargs):
        self.check_object_permissions(self.request, self.request.user)
        return self.model.objects.filter(is_active=True, is_superuser=True)

    def create(self, request, **kwargs):
        user = get_object_or_404(User, username=request.data['username'])
        user.is_superuser = user.is_staff = True
        user.save(update_fields=['is_superuser', 'is_staff'])
        return Response(status=status.HTTP_201_CREATED)

    def destroy(self, request, **kwargs):
        user = get_object_or_404(User, username=kwargs['username'])
        user.is_superuser = user.is_staff = False
        user.save(update_fields=['is_superuser', 'is_staff'])
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserView(BaseDeisViewSet):
    """A Viewset for interacting with User objects."""
    model = User
    serializer_class = serializers.UserSerializer
    permission_classes = [permissions.IsAdmin]

    def get_queryset(self):
        return self.model.objects.exclude(username='AnonymousUser')
