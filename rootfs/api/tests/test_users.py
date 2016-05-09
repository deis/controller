

from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token


class TestUsers(APITestCase):
    """ Tests users endpoint"""

    fixtures = ['tests.json']

    def test_super_user_can_list(self):
        user = User.objects.get(username='autotest')
        token = Token.objects.get(user=user)

        for url in ['/v2/users', '/v2/users/']:
            response = self.client.get(url,
                                       HTTP_AUTHORIZATION='token {}'.format(token))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.data['results']), 3)

    def test_non_super_user_cannot_list(self):
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user)

        for url in ['/v2/users', '/v2/users/']:
            response = self.client.get(url,
                                       HTTP_AUTHORIZATION='token {}'.format(token))
            self.assertEqual(response.status_code, 403)
