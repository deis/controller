import random
import string
import os

from api.settings.production import DATABASES
from api.settings.production import *  # noqa

# A boolean that turns on/off debug mode.
# https://docs.djangoproject.com/en/1.9/ref/settings/#debug
DEBUG = True

# If set to True, Django's normal exception handling of view functions
# will be suppressed, and exceptions will propagate upwards
# https://docs.djangoproject.com/en/1.9/ref/settings/#debug-propagate-exceptions
DEBUG_PROPAGATE_EXCEPTIONS = True

# scheduler for testing
SCHEDULER_MODULE = 'scheduler.mock'
SCHEDULER_URL = 'http://test-scheduler.example.com'

# router information
ROUTER_HOST = 'deis-router.example.com'
ROUTER_PORT = 80

# randomize test database name so we can run multiple unit tests simultaneously
DATABASES['default']['NAME'] = "unittest-{}".format(''.join(
    random.choice(string.ascii_letters + string.digits) for _ in range(8)))

# use DB name to isolate the data for each test run
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': DATABASES['default']['NAME'],
        'KEY_PREFIX': DATABASES['default']['NAME'],
    }
}

# How long k8s waits for a pod to finish work after a SIGTERM before sending SIGKILL
KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS = int(os.environ.get('KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS', 2))  # noqa
KUBERNETES_NAMESPACE_DEFAULT_QUOTA_SPEC = '{"spec":{"hard":{"pods":"10"}}}'

DEIS_DEFAULT_CONFIG_TAGS = os.environ.get('DEIS_DEFAULT_CONFIG_TAGS', '')
