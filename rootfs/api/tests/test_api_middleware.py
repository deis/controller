"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""

from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token

from api import __version__


class APIMiddlewareTest(APITestCase):

    """Tests middleware.py's business logic"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def test_deis_version_header_good(self):
        """
        Test that when the version header is sent, the request is accepted.
        """
        response = self.client.get(
            '/v2/apps',
            HTTP_DEIS_VERSION=__version__.rsplit('.', 2)[0]
        )
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.has_header('DEIS_API_VERSION'), True)
        self.assertEqual(response['DEIS_API_VERSION'], __version__.rsplit('.', 1)[0])

    def test_deis_version_header_bad(self):
        """
        Test that when an improper version header is sent, the request is declined.
        """
        response = self.client.get(
            '/v2/apps',
            HTTP_DEIS_VERSION='1234.5678'
        )
        self.assertEqual(response.status_code, 405, response.content)

    def test_deis_version_header_not_present(self):
        """
        Test that when the version header is not present, the request is accepted.
        """
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
