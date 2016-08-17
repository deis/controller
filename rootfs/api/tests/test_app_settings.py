import requests_mock

from django.core.cache import cache
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from api.models import App
from unittest import mock
from scheduler import KubeException
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
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
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

    def test_settings_whitelist(self, mock_requests):
        """
        Test that addresses can be added/deleted to whitelist
        """
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        # add addresses to empty whitelist
        addresses = ["1.2.3.4", "0.0.0.0/0"]
        whitelist = {'addresses': addresses}
        response = self.client.post(
            '/v2/apps/{app_id}/whitelist'.format(**locals()),
            whitelist)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(set(response.data['addresses']),
                         set(app.appsettings_set.latest().whitelist), response.data)
        self.assertEqual(set(response.data['addresses']), set(addresses), response.data)
        # get the whitelist
        response = self.client.get('/v2/apps/{app_id}/whitelist'.format(**locals()))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(set(response.data['addresses']),
                         set(app.appsettings_set.latest().whitelist), response.data)
        self.assertEqual(set(response.data['addresses']), set(addresses), response.data)
        # add addresses to non-empty whitelist
        whitelist = {'addresses': ["2.3.4.5"]}
        addresses.extend(["2.3.4.5"])
        response = self.client.post(
            '/v2/apps/{app_id}/whitelist'.format(**locals()),
            whitelist)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(set(response.data['addresses']),
                         set(app.appsettings_set.latest().whitelist), response.data)
        self.assertEqual(set(response.data['addresses']), set(addresses), response.data)
        # add exisitng addresses to whitelist
        response = self.client.post(
            '/v2/apps/{app_id}/whitelist'.format(**locals()),
            whitelist)
        self.assertEqual(response.status_code, 409, response.data)
        # delete non-exisitng address from whitelist
        whitelist = {'addresses': ["2.3.4.6"]}
        response = self.client.delete(
            '/v2/apps/{app_id}/whitelist'.format(**locals()),
            whitelist)
        self.assertEqual(response.status_code, 422)
        # delete an address from whitelist
        whitelist = {'addresses': ["2.3.4.5"]}
        addresses.remove("2.3.4.5")
        response = self.client.delete(
            '/v2/apps/{app_id}/whitelist'.format(**locals()),
            whitelist)
        self.assertEqual(response.status_code, 204, response.data)
        self.assertEqual(set(addresses), set(app.appsettings_set.latest().whitelist))
        # pass invalid address
        whitelist = {'addresses': ["2.3.4.6.7"]}
        response = self.client.post(
            '/v2/apps/{app_id}/whitelist'.format(**locals()),
            whitelist)
        self.assertEqual(response.status_code, 400, response.data)
        # update other appsettings and whitelist should be retained
        settings = {'maintenance': True}
        response = self.client.post(
            '/v2/apps/{app.id}/settings'.format(**locals()),
            settings)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(set(addresses), set(app.appsettings_set.latest().whitelist))

    def test_kubernetes_service_failure(self, mock_requests):
        """
        Cause an Exception in kubernetes services
        """
        app_id = self.create_app()

        # scheduler.svc.update exception
        with mock.patch('scheduler.resources.service.Service.update') as mock_kube:
            mock_kube.side_effect = KubeException('Boom!')
            addresses = ["2.3.4.5"]
            url = '/v2/apps/{}/whitelist'.format(app_id)
            response = self.client.post(url, {'addresses': addresses})
            self.assertEqual(response.status_code, 400, response.data)
