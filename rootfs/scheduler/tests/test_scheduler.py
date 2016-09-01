"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from scheduler.tests import TestCase


class SchedulerTest(TestCase):
    """Tests scheduler calls"""

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

        self.scheduler.pod._set_container(
            'foo', 'bar', data, routable=True, healthcheck=healthcheck
        )
        self.assertDictContainsSubset(healthcheck, data)
        data = {}
        self.scheduler.pod._set_container(
            'foo', 'bar', data, routable=True, build_type="buildpack", healthcheck={}
        )
        self.assertEqual(data.get('livenessProbe'), None)
        self.assertEqual(data.get('readinessProbe'), readinessHealthCheck)

        data = {}
        self.scheduler.pod._set_container(
            'foo', 'bar', data, routable=False, healthcheck={}
        )
        self.assertEqual(data.get('livenessProbe'), None)
        self.assertEqual(data.get('readinessProbe'), None)

        # clear the dict to call again with routable as false
        data = {}
        self.scheduler.pod._set_container(
            'foo', 'bar', data,
            routable=False, healthcheck=healthcheck
        )
        self.assertDictContainsSubset(healthcheck, data)
        self.assertEqual(data.get('readinessProbe'), None)

        # now call without setting 'routable', should default to False
        data = {}
        self.scheduler.pod._set_container(
            'foo', 'bar', data, healthcheck=healthcheck
        )
        self.assertDictContainsSubset(healthcheck, data)
        self.assertEqual(data.get('readinessProbe'), None)

        data = {}
        livenessProbe = {
            'livenessProbe': {
                'httpGet': {
                    'port': None,
                }
            }
        }
        self.scheduler.pod._set_health_checks(
            data, {'PORT': 80}, healthcheck=livenessProbe
        )
        self.assertDictContainsSubset(healthcheck, data)
        self.assertEqual(data.get('readinessProbe'), None)

    def test_set_container_limits(self):
        """
        Test that when _set_container has limits that is sets them properly
        """
        data = {}
        self.scheduler.pod._set_container(
            'foo', 'bar', data, app_type='fake',
            cpu={'fake': '500M'}, memory={'fake': '1024m'}
        )
        # make sure CPU gets lower cased
        self.assertEqual(data['resources']['limits']['cpu'], '500m', 'CPU should be lower cased')
        # make sure first char of Memory is upper cased
        self.assertEqual(data['resources']['limits']['memory'], '1024Mi', 'Memory should be upper cased')  # noqa
