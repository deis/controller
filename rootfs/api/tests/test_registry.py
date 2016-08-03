import json
import requests_mock

from django.core.cache import cache
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from api.tests import adapter, DeisTransactionTestCase


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestRegistry(DeisTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_registry(self, mock_requests):
        """
        Test that registry information can be set on an application
        """
        app_id = self.create_app()

        # check default
        url = '/v2/apps/{app_id}/config'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('registry', response.data)
        self.assertEqual(response.data['registry'], {})

        # set some registry information without PORT
        body = {'registry': json.dumps({'username': 'bob'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        registry1 = response.data

        # set required PORT
        body = {'values': json.dumps({'PORT': '80'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry1 = response.data

        # set some registry information
        body = {'registry': json.dumps({'username': 'bob'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry1 = response.data

        # check registry information again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('registry', response.data)
        registry = response.data['registry']
        self.assertIn('username', registry)
        self.assertEqual(registry['username'], 'bob')

        # set an additional value
        # set them upper case, internally it should translate to lower
        body = {'registry': json.dumps({'PASSWORD': 's3cur3pw1'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry2 = response.data
        self.assertNotEqual(registry1['uuid'], registry2['uuid'])
        registry = response.data['registry']
        self.assertIn('password', registry)
        self.assertEqual(registry['password'], 's3cur3pw1')
        self.assertIn('username', registry)
        self.assertEqual(registry['username'], 'bob')

        # read the registry information again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        registry3 = response.data
        self.assertEqual(registry2, registry3)
        registry = response.data['registry']
        self.assertIn('password', registry)
        self.assertEqual(registry['password'], 's3cur3pw1')
        self.assertIn('username', registry)
        self.assertEqual(registry['username'], 'bob')

        # unset a value
        body = {'registry': json.dumps({'password': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        registry4 = response.data
        self.assertNotEqual(registry3['uuid'], registry4['uuid'])
        self.assertNotIn('password', json.dumps(response.data['registry']))

        # bad registry key values
        body = {'registry': json.dumps({'pa$$w0rd': 'woop'})}
        response = self.client.post(url, body)
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        # disallow put/patch/delete
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405, response.data)

    def test_registry_deploy(self, mock_requests):
        """
        Test that registry information can be applied
        """
        app_id = self.create_app()

        # Set mandatory PORT
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            {'values': json.dumps({'PORT': '4999'})}
        )

        # Set registry information
        body = {'registry': json.dumps({
            'username': 'bob',
            'password': 's3cur3pw1'
        })}
        response = self.client.post(
            '/v2/apps/{app_id}/config'.format(**locals()),
            body
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('username', response.data['registry'])
        self.assertIn('password', response.data['registry'])
        self.assertEqual(response.data['registry']['username'], 'bob')
        self.assertEqual(response.data['registry']['password'], 's3cur3pw1')

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
