"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from django.core.cache import cache
from django.test import TestCase
from django.conf import settings

from scheduler import mock
import base64
import json


class SchedulerTest(TestCase):
    """Tests scheduler calls"""

    def setUp(self):
        self.scheduler = mock.MockSchedulerClient()

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

        readinessHealthCheck = {
                # an exec probe
                'exec': {
                    "command": [
                        "bash",
                        "-c",
                        "[[ '$(ps -p 1 -o args)' != *'bash /runner/init'* ]]"
                    ]
                },
                # length of time to wait for a pod to initialize
                # after pod startup, before applying health checking
                'initialDelaySeconds': 30,
                'timeoutSeconds': 5,
                'periodSeconds': 5,
                'successThreshold': 1,
                'failureThreshold': 1,
            }

        self.scheduler._set_container(
            'foo', 'bar', data, routable=True, healthcheck=healthcheck
        )
        self.assertDictContainsSubset(healthcheck, data)
        data = {}
        self.scheduler._set_container(
            'foo', 'bar', data, routable=True, build_type="buildpack", healthcheck={}
        )
        self.assertEqual(data.get('livenessProbe'), None)
        self.assertEqual(data.get('readinessProbe'), readinessHealthCheck)

        # clear the dict to call again with routable as false
        data = {}
        self.scheduler._set_container(
            'foo', 'bar', data,
            routable=False, healthcheck=healthcheck
        )
        self.assertEqual(data.get('livenessProbe'), None)
        self.assertEqual(data.get('readinessProbe'), None)

        # now call without setting 'routable', should default to False
        data = {}
        self.scheduler._set_container(
            'foo', 'bar', data, healthcheck=healthcheck
        )
        self.assertEqual(data.get('livenessProbe'), None)
        self.assertEqual(data.get('readinessProbe'), None)

    def test_set_container_limits(self):
        """
        Test that when _set_container has limits that is sets them properly
        """
        data = {}
        self.scheduler._set_container(
            'foo', 'bar', data, app_type='fake',
            cpu={'fake': '500M'}, memory={'fake': '1024m'}
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

        docker_config, secret_name, secret_create = self.scheduler._get_private_registry_config(registry, image)  # noqa
        dockerConfig = json.loads(docker_config)
        expected = {"https://index.docker.io/v1/": {
            "auth": encAuth
        }}
        self.assertEqual(dockerConfig.get('auths'), expected)
        self.assertEqual(secret_name, "private-registry")
        self.assertEqual(secret_create, True)

        image = "quay.io/test/test"

        docker_config, secret_name, secret_create = self.scheduler._get_private_registry_config(registry, image)  # noqa
        dockerConfig = json.loads(docker_config)
        expected = {"quay.io": {
            "auth": encAuth
        }}
        self.assertEqual(dockerConfig.get('auths'), expected)
        self.assertEqual(secret_name, "private-registry")
        self.assertEqual(secret_create, True)

        settings.REGISTRY_LOCATION = "ecr"
        registry = {}
        image = "test.com/test/test"
        docker_config, secret_name, secret_create = self.scheduler._get_private_registry_config(registry, image)  # noqa
        self.assertEqual(docker_config, None)
        self.assertEqual(secret_name, "private-registry-ecr")
        self.assertEqual(secret_create, False)

        settings.REGISTRY_LOCATION = "off-cluster"
        docker_config, secret_name, secret_create = self.scheduler._get_private_registry_config(registry, image)  # noqa
        dockerConfig = json.loads(docker_config)
        expected = {"https://index.docker.io/v1/": {
            "auth": encAuth
        }}
        self.assertEqual(dockerConfig.get('auths'), expected)
        self.assertEqual(secret_name, "private-registry-off-cluster")
        self.assertEqual(secret_create, True)

        settings.REGISTRY_LOCATION = "ecra"
        image = "test.com/test/test"
        docker_config, secret_name, secret_create = self.scheduler._get_private_registry_config(registry, image)  # noqa
        self.assertEqual(docker_config, None)
        self.assertEqual(secret_name, None)
        self.assertEqual(secret_create, None)
