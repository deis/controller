import json
import requests_mock
from unittest import mock

from django.core.cache import cache
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from api.models import App
from api.tests import adapter, mock_port, DeisTransactionTestCase


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
@mock.patch('api.models.release.docker_get_port', mock_port)
class TestHealthchecks(DeisTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_healthchecks_validations(self, mock_requests):
        """
        Test that healthchecks validations work
        """
        app_id = self.create_app()

        # Set one of the values that require a numeric value to a string
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'values': json.dumps({'HEALTHCHECK_INITIAL_DELAY': 'horse'})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # test URL - Path is the only allowed thing
        # Try setting various things such as query param

        # query param
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'values': json.dumps({'HEALTHCHECK_URL': '/health?testing=0'})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # fragment
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'values': json.dumps({'HEALTHCHECK_URL': '/health#db'})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # netloc
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'values': json.dumps({'HEALTHCHECK_URL': 'http://someurl.com/health/'})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # no path
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'values': json.dumps({'HEALTHCHECK_URL': 'http://someurl.com'})}
        )
        self.assertEqual(response.status_code, 400, response.data)

    def test_config_healthchecks(self, mock_requests):
        """
        Test that healthchecks can be applied
        """
        app_id = self.create_app()
        readiness_probe = {'healthcheck': {'readinessProbe': {'httpGet': {'port': 5000}}}}

        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            readiness_probe)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('readinessProbe', response.data['healthcheck'])
        self.assertEqual(response.data['healthcheck'], readiness_probe['healthcheck'])

        liveness_probe = {'healthcheck': {'livenessProbe':
                                          {'httpGet': {'port': 5000},
                                           'successThreshold': 1}}}
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            liveness_probe)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('livenessProbe', response.data['healthcheck'])
        self.assertEqual(
            response.data['healthcheck']['livenessProbe'],
            liveness_probe['healthcheck']['livenessProbe'])
        # check that the readiness probe is still there too!
        self.assertIn('readinessProbe', response.data['healthcheck'])
        self.assertEqual(
            response.data['healthcheck']['readinessProbe'],
            readiness_probe['healthcheck']['readinessProbe'])

        # post a new build
        response = self.client.post(
            "/v2/apps/{app_id}/builds".format(**locals()),
            {'image': 'quay.io/autotest/example'}
        )
        self.assertEqual(response.status_code, 201, response.data)

    def test_config_healthchecks_validations(self, mock_requests):
        """
        Test that healthchecks validations work
        """
        app_id = self.create_app()

        # Set one of the values that require a numeric value to a string
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'healthcheck': json.dumps({'livenessProbe':
                                        {'httpGet': {'port': '50'}, 'initialDelaySeconds': "t"}})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # Don't set one of the mandatory value
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'healthcheck': json.dumps({'livenessProbe':
                                        {'httpGet': {'path': '/'}, 'initialDelaySeconds': 1}})}
        )
        self.assertEqual(response.status_code, 400, response.data)

        # set liveness success threshold to a non-1 value
        # Don't set one of the mandatory value
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'healthcheck': {'livenessProbe':
                             {'httpGet': {'path': '/', 'port': 5000},
                              'successThreshold': 5}}}
        )
        self.assertEqual(response.status_code, 400, response.data)

    def test_config_healthchecks_legacy(self, mock_requests):
        """
        Test that when a user uses `deis config:set HEALTHCHECK_URL=/`, the config
        object is rolled over to the `healthcheck` field.
        """
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        # Set healthcheck URL to get defaults set
        response = self.client.post(
            '/v2/apps/{app.id}/config'.format(**locals()),
            {'values': json.dumps({'HEALTHCHECK_URL': '/health'})}
        )
        self.assertEqual(response.status_code, 201, response.data)
        # this gets migrated to the new healtcheck format
        self.assertNotIn('HEALTHCHECK_URL', response.data['values'])
        # legacy defaults
        expected = {
            'livenessProbe': {
                'initialDelaySeconds': 50,
                'timeoutSeconds': 50,
                'periodSeconds': 10,
                'successThreshold': 1,
                'failureThreshold': 3,
                'httpGet': {
                    'path': '/health'
                }
            },
            'readinessProbe': {
                'initialDelaySeconds': 50,
                'timeoutSeconds': 50,
                'periodSeconds': 10,
                'successThreshold': 1,
                'failureThreshold': 3,
                'httpGet': {
                    'path': '/health'
                }
            }
        }
        actual = app.config_set.latest().healthcheck
        self.assertEqual(actual, expected)
        # Now set all the envvars and check to make sure they are written properly
        response = self.client.post(
            '/v2/apps/{app.id}/config'.format(**locals()),
            {
                'values': json.dumps({
                    'HEALTHCHECK_URL': '/health',
                    'HEALTHCHECK_INITIAL_DELAY': '25',
                    'HEALTHCHECK_TIMEOUT': '10',
                    'HEALTHCHECK_PERIOD_SECONDS': '5',
                    'HEALTHCHECK_SUCCESS_THRESHOLD': '2',
                    'HEALTHCHECK_FAILURE_THRESHOLD': '2'})
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        # this gets migrated to the new healtcheck format
        self.assertNotIn('HEALTHCHECK_INITIAL_DELAY', response.data['values'])
        expected['livenessProbe'] = {
            'initialDelaySeconds': 25,
            'timeoutSeconds': 10,
            'periodSeconds': 5,
            'successThreshold': 2,
            'failureThreshold': 2,
            'httpGet': {
                'path': '/health'
            }
        }
        expected['readinessProbe'] = expected['livenessProbe']
        actual = app.config_set.latest().healthcheck
        self.assertEqual(expected, actual)
