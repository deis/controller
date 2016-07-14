"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from django.core.cache import cache
from django.test import TestCase

from scheduler import mock


class SchedulerTest(TestCase):
    """Tests scheduler calls"""

    def setUp(self):
        self.scheduler_client = mock.MockSchedulerClient()

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_set_container_applies_healthcheck_with_routable(self):
        """
        Test that when _set_container is called with the 'routable' kwarg set to True,
        a healthcheck is attached to the dictionary.
        """
        data = {}
        healthcheck = {
            'livenessProbe': {
                'httpGet': {
                    'port': 80,
                }
            }
        }
        self.scheduler_client._set_container('foo',
                                             'bar',
                                             data,
                                             routable=True,
                                             healthcheck=healthcheck)
        self.assertDictContainsSubset(healthcheck, data)
        # clear the dict to call again with routable as false
        data = {}
        self.scheduler_client._set_container('foo',
                                             'bar',
                                             data,
                                             routable=False,
                                             healthcheck=healthcheck)
        self.assertEqual(data.get('livenessProbe'), None)
        # now call without setting 'routable', should default to False
        data = {}
        self.scheduler_client._set_container('foo',
                                             'bar',
                                             data,
                                             healthcheck=healthcheck)
        self.assertEqual(data.get('livenessProbe'), None)
