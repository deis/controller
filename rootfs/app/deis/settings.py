"""
Django settings for the Deis project.
"""

from __future__ import unicode_literals
import os.path
import random
import semantic_version as semver
import string
import sys
import tempfile


PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

MANAGERS = ADMINS

CONN_MAX_AGE = 60 * 3

# SECURITY: change this to allowed fqdn's to prevent host poisioning attacks
# https://docs.djangoproject.com/en/1.6/ref/settings/#allowed-hosts
ALLOWED_HOSTS = ['*']

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'UTC'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = os.path.abspath(os.path.join(__file__, '..', '..', 'static'))

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    "django.contrib.auth.context_processors.auth",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.media",
    "django.core.context_processors.request",
    "django.core.context_processors.static",
    "django.core.context_processors.tz",
    "django.contrib.messages.context_processors.messages",
    "deis.context_processors.site",
)

MIDDLEWARE_CLASSES = (
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'api.middleware.APIVersionMiddleware',
    'deis.middleware.PlatformVersionMiddleware',
    # Uncomment the next line for simple clickjacking protection:
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'deis.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'deis.wsgi.application'

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.humanize',
    'django.contrib.messages',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.staticfiles',
    # Third-party apps
    'guardian',
    'json_field',
    'gunicorn',
    'rest_framework',
    'rest_framework.authtoken',
    'south',
    'corsheaders',
    # Deis apps
    'api',
    'registry',
)

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
)

ANONYMOUS_USER_ID = -1
LOGIN_URL = '/v1/auth/login/'
LOGIN_REDIRECT_URL = '/'

SOUTH_TESTS_MIGRATE = False

CORS_ORIGIN_ALLOW_ALL = True

CORS_ALLOW_HEADERS = (
    'content-type',
    'accept',
    'origin',
    'Authorization',
    'Host',
)

CORS_EXPOSE_HEADERS = (
    'X_DEIS_API_VERSION',  # DEPRECATED
    'X_DEIS_PLATFORM_VERSION',  # DEPRECATED
    'X-Deis-Release',  # DEPRECATED
    'DEIS_API_VERSION',
    'DEIS_PLATFORM_VERSION',
    'Deis-Release',
)

REST_FRAMEWORK = {
    'DEFAULT_MODEL_SERIALIZER_CLASS':
    'rest_framework.serializers.ModelSerializer',
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.TokenAuthentication',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ),
    'PAGINATE_BY': 100,
    'PAGINATE_BY_PARAM': 'page_size',
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
}

# URLs that end with slashes are ugly
APPEND_SLASH = False

# Determine where to send syslog messages
if os.path.exists('/dev/log'):           # Linux rsyslog
    SYSLOG_ADDRESS = '/dev/log'
elif os.path.exists('/var/log/syslog'):  # Mac OS X syslog
    SYSLOG_ADDRESS = '/var/log/syslog'
else:                                    # default SysLogHandler address
    SYSLOG_ADDRESS = ('localhost', 514)

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        'rsyslog': {
            'class': 'logging.handlers.SysLogHandler',
            'address': SYSLOG_ADDRESS,
            'facility': 'local0',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['null'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['console', 'mail_admins'],
            'level': 'WARNING',
            'propagate': True,
        },
        'api': {
            'handlers': ['console', 'mail_admins', 'rsyslog'],
            'level': 'INFO',
            'propagate': True,
        },
        'registry': {
            'handlers': ['console', 'mail_admins', 'rsyslog'],
            'level': 'INFO',
            'propagate': True,
        },
    }
}
TEST_RUNNER = 'api.tests.SilentDjangoTestSuiteRunner'

# etcd settings
ETCD_HOST = os.environ.get('DEIS_ETCD_1_SERVICE_HOST', '127.0.0.1')
ETCD_PORT = os.environ.get('DEIS_ETCD_1_SERVICE_PORT_CLIENT', 4001)

# default deis settings
LOG_LINES = 1000
TEMPDIR = tempfile.mkdtemp(prefix='deis')
DEIS_DOMAIN = 'deisapp.local'

# standard datetime format used for logging, model timestamps, etc.
DEIS_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S%Z'

# names which apps cannot reserve for routing
DEIS_RESERVED_NAMES = ['deis']

SCHEDULER_MODULE = 'scheduler.k8s'
SCHEDULER_HOST = os.environ.get('KUBERNETES_SERVICE_HOST', 'localhost')
SCHEDULER_PORT = os.environ.get('KUBERNETES_SERVICE_PORT', 443)
SCHEDULER_URL = "{}:{}".format(SCHEDULER_HOST, SCHEDULER_PORT)

# security keys and auth tokens
SECRET_KEY = os.environ.get('DEIS_SECRET_KEY', 'CHANGEME_sapm$s%upvsw5l_zuy_&29rkywd^78ff(qi')
BUILDER_KEY = os.environ.get('DEIS_BUILDER_KEY', 'CHANGEME_sapm$s%upvsw5l_zuy_&29rkywd^78ff(qi')

# docker client settings
DOCKER_URL = os.environ.get('DOCKER_SERVICE_HOST', 'unix://var/run/docker.sock')

# registry settings
REGISTRY_HOST = os.environ.get('REGISTRY_SERVICE_HOST', 'localhost')
REGISTRY_PORT = os.environ.get('REGISTRY_SERVICE_PORT', 5000)

# logger settings
LOGGER_HOST = os.environ.get('LOGGER_SERVICE_HOST', 'localhost')
LOGGER_PORT = os.environ.get('LOGGER_SERVICE_PORT', 8088)

# check if we can register users with `deis register`
REGISTRATION_ENABLED = True

# if True, enable the /admin web views
ADMIN_ENABLED = False

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get('DATABASE_NAME', 'deis'),
        'USER': os.environ.get('DATABASE_USER', 'deis'),
        'PASSWORD': os.environ.get('DATABASE_PASSWORD', ''),
        'HOST': os.environ.get('DATABASE_SERVICE_HOST', 'localhost'),
        'PORT': os.environ.get('DATABASE_SERVICE_PORT', 5432),
    }
}

APP_URL_REGEX = '[a-z0-9-]+'

# Honor HTTPS from a trusted proxy
# see https://docs.djangoproject.com/en/1.6/ref/settings/#secure-proxy-ssl-header
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
