import logging
import random
import requests_mock
import time

from django.conf import settings
from django.test.runner import DiscoverRunner


# Mock out router requests and add in some jitter
# Used for application is available in router checks
def fake_responses(request, context):
    responses = [
        # increasing the chance of 404
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'Not Found', 'status_code': 404},
        {'text': 'OK', 'status_code': 200},
        {'text': 'Gateway timeout', 'status_code': 504},
        {'text': 'Bad gateway', 'status_code': 502},
    ]
    random.shuffle(responses)
    response = responses.pop()

    context.status_code = response['status_code']
    context.reason = response['text']
    # Random float x, 1.0 <= x < 4.0 for some sleep jitter
    time.sleep(random.uniform(1, 4))
    return response['text']

url = 'http://{}:{}'.format(settings.ROUTER_HOST, settings.ROUTER_PORT)
adapter = requests_mock.Adapter()
adapter.register_uri('GET', url + '/', text=fake_responses)
adapter.register_uri('GET', url + '/health', text=fake_responses)
adapter.register_uri('GET', url + '/healthz', text=fake_responses)


class SilentDjangoTestSuiteRunner(DiscoverRunner):
    """Prevents api log messages from cluttering the console during tests."""

    def run_tests(self, test_labels, extra_tests=None, **kwargs):
        """Run tests with all but critical log messages disabled."""
        # hide any log messages less than critical
        logging.disable(logging.ERROR)
        return super(SilentDjangoTestSuiteRunner, self).run_tests(
            test_labels, extra_tests, **kwargs)
