import requests_mock

from django.core.cache import cache
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from api.models import App
from api.tests import adapter, DeisTransactionTestCase


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestTLS(DeisTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_tls_enforced(self, mock_requests):
        """
        Test that tls redirection can be enforced
        """
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        data = {'https_enforced': True}
        response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(response.data.get('https_enforced'), response.data)
        self.assertTrue(app.tls_set.latest().https_enforced)

        data = {'https_enforced': False}
        response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(app.tls_set.latest().https_enforced)

        # when the same data is sent again, a 409 is returned
        conflict_response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(conflict_response.status_code, 409, conflict_response.data)
        self.assertFalse(app.tls_set.latest().https_enforced)
        # also ensure that the previous tls UUID matches the latest,
        # confirming this conflicting TLS object was deleted
        self.assertEqual(response.data['uuid'], str(app.tls_set.latest().uuid))

        # sending bad data returns a 400
        data['https_enforced'] = "test"
        response = self.client.post(
            '/v2/apps/{app_id}/tls'.format(**locals()),
            data)
        self.assertEqual(response.status_code, 400, response.data)

    def test_tls_created_on_app_create(self, mock_requests):
        """
        Ensure that a TLS object is created for an App with default values.

        See https://github.com/deisthree/controller/issues/1042
        """
        app_id = self.create_app()
        response = self.client.get('/v2/apps/{}/tls'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['https_enforced'], None)
