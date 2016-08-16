import requests_mock

from django.core.cache import cache
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from api.models import App
from api.tests import adapter, DeisTransactionTestCase


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestAppSettings(DeisTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_settings_maintenance(self, mock_requests):
        """
        Test that maintenance can be applied
        """
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        settings = {'maintenance': True}
        response = self.client.post(
            '/v2/apps/{app_id}/settings'.format(**locals()),
            settings)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(response.data['maintenance'])
        self.assertTrue(app.appsettings_set.latest().maintenance)

        settings = {'routable': False}
        response = self.client.post(
            '/v2/apps/{app_id}/settings'.format(**locals()),
            settings)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(app.appsettings_set.latest().maintenance)

        settings['maintenance'] = False
        response = self.client.post(
            '/v2/apps/{app_id}/settings'.format(**locals()),
            settings)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(response.data['maintenance'])
        self.assertFalse(app.appsettings_set.latest().maintenance)

        response = self.client.post(
            '/v2/apps/{app_id}/settings'.format(**locals()),
            settings)
        self.assertEqual(response.status_code, 409, response.data)
        self.assertFalse(app.appsettings_set.latest().maintenance)

        settings['maintenance'] = "test"
        response = self.client.post(
            '/v2/apps/{app_id}/settings'.format(**locals()),
            settings)
        self.assertEqual(response.status_code, 400, response.data)

    def test_settings_routable(self, mock_requests):
        """
        Create an application with the routable flag turned on or off
        """
        # create app, expecting routable to be true
        body = {'id': 'myid'}
        response = self.client.post('/v2/apps', body)
        self.assertEqual(response.status_code, 201, response.data)
        app = App.objects.get(id='myid')
        self.assertTrue(app.appsettings_set.latest().routable)
        # Set routable to false
        response = self.client.post(
            '/v2/apps/{app.id}/settings'.format(**locals()),
            {'routable': False}
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.appsettings_set.latest().routable)

        settings = {'maintenance': True}
        response = self.client.post(
            '/v2/apps/{app.id}/settings'.format(**locals()),
            settings)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.appsettings_set.latest().routable)
