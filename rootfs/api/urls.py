"""
URL routing patterns for the Deis REST API.
"""


from django.conf import settings
from django.conf.urls import include, url
from rest_framework.authtoken.views import obtain_auth_token as views_obtain_auth_token
from rest_framework.routers import DefaultRouter

from api import views


router = DefaultRouter(trailing_slash=False)

# Add the generated REST URLs and login/logout endpoint
urlpatterns = [
    url(r'^', include(router.urls)),
    # application release components
    url(r"^apps/(?P<id>{})/config/?".format(settings.APP_URL_REGEX),
        views.ConfigViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    url(r"^apps/(?P<id>{})/builds/(?P<uuid>[-_\w]+)/?".format(settings.APP_URL_REGEX),
        views.BuildViewSet.as_view({'get': 'retrieve'})),
    url(r"^apps/(?P<id>{})/builds/?".format(settings.APP_URL_REGEX),
        views.BuildViewSet.as_view({'get': 'list', 'post': 'create'})),
    url(r"^apps/(?P<id>{})/releases/v(?P<version>[0-9]+)/?".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'get': 'retrieve'})),
    url(r"^apps/(?P<id>{})/releases/rollback/?".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'post': 'rollback'})),
    url(r"^apps/(?P<id>{})/releases/?".format(settings.APP_URL_REGEX),
        views.ReleaseViewSet.as_view({'get': 'list'})),
    # restart pods
    url(r"^apps/(?P<id>{})/pods/restart/?".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'post': 'restart'})),
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w.]+)/restart/?".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'post': 'restart'})),
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w]+)/(?P<name>[-_\w]+)/restart/?".format(
        settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'post': 'restart'})),
    # list pods
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w]+)/(?P<name>[-_\w]+)/?".format(
        settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'get': 'list'})),
    url(r"^apps/(?P<id>{})/pods/(?P<type>[-_\w.]+)/?".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'get': 'list'})),
    url(r"^apps/(?P<id>{})/pods/?".format(settings.APP_URL_REGEX),
        views.PodViewSet.as_view({'get': 'list'})),
    # application domains
    url(r"^apps/(?P<id>{})/domains/(?P<domain>\**\.?[-\._\w]+)/?".format(settings.APP_URL_REGEX),
        views.DomainViewSet.as_view({'delete': 'destroy'})),
    url(r"^apps/(?P<id>{})/domains/?".format(settings.APP_URL_REGEX),
        views.DomainViewSet.as_view({'post': 'create', 'get': 'list'})),
    # application actions
    url(r"^apps/(?P<id>{})/scale/?".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'post': 'scale'})),
    url(r"^apps/(?P<id>{})/logs/?".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'get': 'logs'})),
    url(r"^apps/(?P<id>{})/run/?".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'post': 'run'})),
    # application settings
    url(r"^apps/(?P<id>{})/settings/?".format(settings.APP_URL_REGEX),
        views.AppSettingsViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    # application ip whitelist
    url(r"^apps/(?P<id>{})/whitelist/?".format(settings.APP_URL_REGEX),
        views.WhitelistViewSet.as_view({'post': 'create', 'get': 'list', 'delete': 'delete'})),
    # application TLS settings
    url(r"^apps/(?P<id>{})/tls/?".format(settings.APP_URL_REGEX),
        views.TLSViewSet.as_view({'get': 'retrieve', 'post': 'create'})),
    # apps sharing
    url(r"^apps/(?P<id>{})/perms/(?P<username>[-_\w]+)/?".format(settings.APP_URL_REGEX),
        views.AppPermsViewSet.as_view({'delete': 'destroy'})),
    url(r"^apps/(?P<id>{})/perms/?".format(settings.APP_URL_REGEX),
        views.AppPermsViewSet.as_view({'get': 'list', 'post': 'create'})),
    # apps base endpoint
    url(r"^apps/(?P<id>{})/?".format(settings.APP_URL_REGEX),
        views.AppViewSet.as_view({'get': 'retrieve', 'post': 'update', 'delete': 'destroy'})),
    url(r'^apps/?',
        views.AppViewSet.as_view({'get': 'list', 'post': 'create'})),
    # key
    url(r'^keys/(?P<id>.+)/?',
        views.KeyViewSet.as_view({'get': 'retrieve', 'delete': 'destroy'})),
    url(r'^keys/?',
        views.KeyViewSet.as_view({'get': 'list', 'post': 'create'})),
    # hooks
    url(r'^hooks/keys/(?P<id>{})/(?P<username>[-_\w]+)?'.format(settings.APP_URL_REGEX),
        views.KeyHookViewSet.as_view({'get': 'users'})),
    url(r'^hooks/keys/(?P<id>{})/?'.format(settings.APP_URL_REGEX),
        views.KeyHookViewSet.as_view({'get': 'app'})),
    url(r'^hooks/key/(?P<fingerprint>.+)/?',
        views.KeyHookViewSet.as_view({'get': 'public_key'})),
    url(r'^hooks/build/?',
        views.BuildHookViewSet.as_view({'post': 'create'})),
    url(r'^hooks/config/?',
        views.ConfigHookViewSet.as_view({'post': 'create'})),
    # authn / authz
    url(r'^auth/register/?',
        views.UserRegistrationViewSet.as_view({'post': 'create'})),
    url(r'^auth/cancel/?',
        views.UserManagementViewSet.as_view({'delete': 'destroy'})),
    url(r'^auth/passwd/?',
        views.UserManagementViewSet.as_view({'post': 'passwd'})),
    url(r'^auth/whoami/?',
        views.UserManagementViewSet.as_view({'get': 'list'})),
    url(r'^auth/login/',
        views_obtain_auth_token),
    url(r'^auth/tokens/',
        views.TokenManagementViewSet.as_view({'post': 'regenerate'})),
    # admin sharing
    url(r'^admin/perms/(?P<username>[-_\w]+)/?',
        views.AdminPermsViewSet.as_view({'delete': 'destroy'})),
    url(r'^admin/perms/?',
        views.AdminPermsViewSet.as_view({'get': 'list', 'post': 'create'})),
    # certificates
    url(r'^certs/(?P<name>[-_*.\w]+)/domain/(?P<domain>\**\.?[-\._\w]+)?',
        views.CertificateViewSet.as_view({'delete': 'detach', 'post': 'attach'})),
    url(r'^certs/(?P<name>[-_*.\w]+)/?',
        views.CertificateViewSet.as_view({
            'get': 'retrieve',
            'delete': 'destroy'
        })),
    url(r'^certs/?',
        views.CertificateViewSet.as_view({'get': 'list', 'post': 'create'})),
    # list users
    url(r'^users/?', views.UserView.as_view({'get': 'list'})),
]
