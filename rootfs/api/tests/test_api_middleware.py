"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""

from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from api.tests import DeisTestCase

from api import __version__


class APIMiddlewareTest(DeisTestCase):

    """Tests middleware.py's business logic"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def test_deis_version_header_good(self):
        """
        Test that when the version header is sent.
        """
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.has_header('DEIS_API_VERSION'), True)
        self.assertEqual(response['DEIS_API_VERSION'], __version__.rsplit('.', 1)[0])
