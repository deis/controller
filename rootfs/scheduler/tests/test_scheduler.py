"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from django.core.cache import cache
from django.test import TestCase

from scheduler import mock
import base64
import json


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

    def test_set_container_limits(self):
        """
        Test that when _set_container has limits that is sets them properly
        """
        data = {}
        self.scheduler_client._set_container(
            'foo', 'bar', data, app_type='fake', cpu={'fake': '500M'}, memory={'fake': '1024m'}
        )
        # make sure CPU gets lower cased
        self.assertEqual(data['resources']['limits']['cpu'], '500m', 'CPU should be lower cased')
        # make sure first char of Memory is upper cased
        self.assertEqual(data['resources']['limits']['memory'], '1024Mi', 'Memory should be upper cased')  # noqa

    def test_get_private_registry_config(self):
        registry = {'username': 'test', 'password': 'test'}
        auth = bytes('{}:{}'.format("test", "test"), 'UTF-8')
        encAuth = base64.b64encode(auth).decode(encoding='UTF-8')
        image = 'test/test'

        dockerConfig = self.scheduler_client._get_private_registry_config(registry, image)
        dockerConfig = json.loads(dockerConfig)
        expected = {"https://index.docker.io/v1/": {
            "auth": encAuth
        }}
        self.assertEqual(dockerConfig.get('auths'), expected)

        image = "quay.io/test/test"

        dockerConfig = self.scheduler_client._get_private_registry_config(registry, image)
        dockerConfig = json.loads(dockerConfig)
        expected = {"quay.io": {
            "auth": encAuth
        }}
        self.assertEqual(dockerConfig.get('auths'), expected)
