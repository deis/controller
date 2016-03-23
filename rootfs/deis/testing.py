import random
import string
from deis.settings import *  # noqa

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
