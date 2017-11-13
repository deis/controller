"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
from django.contrib.auth.models import User
from django.test.utils import override_settings
from rest_framework.authtoken.models import Token
from unittest import mock

from api.tests import TEST_ROOT, DeisTestCase
from api.models import Certificate


class AuthTest(DeisTestCase):

    fixtures = ['test_auth.json']

    """Tests user registration, authentication and authorization"""

    def setUp(self):
        self.admin = User.objects.get(username='autotest')
        self.admin_token = Token.objects.get(user=self.admin).key
        self.user1 = User.objects.get(username='autotest2')
        self.user1_token = Token.objects.get(user=self.user1).key
        self.user2 = User.objects.get(username='autotest3')
        self.user2_token = Token.objects.get(user=self.user2).key

    def test_auth(self):
        """
        Test that a user can register using the API, login, whoami and logout
        """
        # test registration workflow
        username, password = 'newuser', 'password'
        first_name, last_name = 'Otto', 'Test'
        email = 'autotest@deis.io'
        submit = {
            'username': username,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            # try to abuse superuser/staff level perms (not the first signup!)
            'is_superuser': True,
            'is_staff': True,
        }
        url = '/v2/auth/register'
        response = self.client.post(url, submit)
        self.assertEqual(response.status_code, 201, response.data)
        for key in response.data:
            self.assertIn(key, ['id', 'last_login', 'is_superuser', 'username', 'first_name',
                                'last_name', 'email', 'is_active', 'is_superuser', 'is_staff',
                                'date_joined', 'groups', 'user_permissions'])
        expected = {
            'username': username,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'is_active': True,
            'is_superuser': False,
            'is_staff': False
        }
        self.assertDictContainsSubset(expected, response.data)

        # test login
        response = self.client.login(username=username, password=password)
        self.assertEqual(response, True)

        user = User.objects.get(username=username)
        token = Token.objects.get(user=user).key
        url = '/v2/auth/whoami'
        response = self.client.get(url, HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 200)
        for key in response.data:
            self.assertIn(key, ['id', 'last_login', 'is_superuser', 'username', 'first_name',
                                'last_name', 'email', 'is_active', 'is_superuser', 'is_staff',
                                'date_joined', 'groups', 'user_permissions'])
        expected = {
            'username': username,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'is_active': True,
            'is_superuser': False,
            'is_staff': False
        }
        self.assertDictContainsSubset(expected, response.data)

    @override_settings(REGISTRATION_MODE="disabled")
    def test_auth_registration_disabled(self):
        """test that a new user cannot register when registration is disabled."""
        url = '/v2/auth/register'
        submit = {
            'username': 'testuser',
            'password': 'password',
            'first_name': 'test',
            'last_name': 'user',
            'email': 'test@user.com',
            'is_superuser': False,
            'is_staff': False,
        }
        response = self.client.post(url, submit)
        self.assertEqual(response.status_code, 403)

    @override_settings(REGISTRATION_MODE="admin_only")
    def test_auth_registration_admin_only_fails_if_not_admin(self):
        """test that a non superuser cannot register when registration is admin only."""
        url = '/v2/auth/register'
        submit = {
            'username': 'testuser',
            'password': 'password',
            'first_name': 'test',
            'last_name': 'user',
            'email': 'test@user.com',
            'is_superuser': False,
            'is_staff': False,
        }
        response = self.client.post(url, submit)
        self.assertEqual(response.status_code, 403)

    @override_settings(REGISTRATION_MODE="admin_only")
    def test_auth_registration_admin_only_works(self):
        """test that a superuser can register when registration is admin only."""
        url = '/v2/auth/register'

        username, password = 'newuser_by_admin', 'password'
        first_name, last_name = 'Otto', 'Test'
        email = 'autotest@deis.io'

        submit = {
            'username': username,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            # try to abuse superuser/staff level perms (not the first signup!)
            'is_superuser': True,
            'is_staff': True,
        }
        response = self.client.post(url, submit,
                                    HTTP_AUTHORIZATION='token {}'.format(self.admin_token))

        self.assertEqual(response.status_code, 201, response.data)
        for key in response.data:
            self.assertIn(key, ['id', 'last_login', 'is_superuser', 'username', 'first_name',
                                'last_name', 'email', 'is_active', 'is_superuser', 'is_staff',
                                'date_joined', 'groups', 'user_permissions'])
        expected = {
            'username': username,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'is_active': True,
            'is_superuser': False,
            'is_staff': False
        }
        self.assertDictContainsSubset(expected, response.data)

        # test login
        response = self.client.login(username=username, password=password)
        self.assertEqual(response, True)

    @override_settings(REGISTRATION_MODE="not_a_mode")
    def test_auth_registration_fails_with_nonexistant_mode(self):
        """test that a registration should fail with a nonexistant mode"""
        url = '/v2/auth/register'
        submit = {
            'username': 'testuser',
            'password': 'password',
            'first_name': 'test',
            'last_name': 'user',
            'email': 'test@user.com',
            'is_superuser': False,
            'is_staff': False,
        }

        try:
            self.client.post(url, submit)
        except Exception as e:
            self.assertEqual(str(e), 'not_a_mode is not a valid registation mode')

    def test_cancel(self):
        """Test that a registered user can cancel her account."""
        # test registration workflow
        username, password = 'newuser', 'password'
        submit = {
            'username': username,
            'password': password,
            'first_name': 'Otto',
            'last_name': 'Test',
            'email': 'autotest@deis.io',
            # try to abuse superuser/staff level perms
            'is_superuser': True,
            'is_staff': True,
        }

        other_username, other_password = 'newuser2', 'password'
        other_submit = {
            'username': other_username,
            'password': other_password,
            'first_name': 'Test',
            'last_name': 'Tester',
            'email': 'autotest-2@deis.io',
            'is_superuser': False,
            'is_staff': False,
        }
        url = '/v2/auth/register'
        response = self.client.post(url, submit)
        self.assertEqual(response.status_code, 201, response.data)

        # cancel the account
        url = '/v2/auth/cancel'
        user = User.objects.get(username=username)
        token = Token.objects.get(user=user).key
        response = self.client.delete(url, HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 204, response.data)

        url = '/v2/auth/register'
        response = self.client.post(url, other_submit)
        self.assertEqual(response.status_code, 201, response.data)

        # normal user can't delete another user
        url = '/v2/auth/cancel'
        other_user = User.objects.get(username=other_username)
        other_token = Token.objects.get(user=other_user).key
        response = self.client.delete(url, {'username': self.admin.username},
                                      HTTP_AUTHORIZATION='token {}'.format(other_token))
        self.assertEqual(response.status_code, 403)

        # admin can delete another user
        response = self.client.delete(url, {'username': other_username},
                                      HTTP_AUTHORIZATION='token {}'.format(self.admin_token))
        self.assertEqual(response.status_code, 204, response.data)

        # user can not be deleted if it has an app attached to it
        response = self.client.post(
            '/v2/apps',
            HTTP_AUTHORIZATION='token {}'.format(self.admin_token)
        )
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['id']  # noqa
        self.assertIn('id', response.data)

        response = self.client.delete(url, {'username': str(self.admin)},
                                      HTTP_AUTHORIZATION='token {}'.format(self.admin_token))
        self.assertEqual(response.status_code, 409)

        # user can not be deleted if it has a downstream object owned by them, like a certificate
        domain_name = 'foo.com'
        with open('{}/certs/{}.key'.format(TEST_ROOT, domain_name)) as f:
            key = f.read()
        with open('{}/certs/{}.cert'.format(TEST_ROOT, domain_name)) as f:
            cert = f.read()

        Certificate.objects.create(owner=self.admin, certificate=cert, key=key)
        response = self.client.delete(url, {'username': str(self.admin)},
                                      HTTP_AUTHORIZATION='token {}'.format(self.admin_token))
        self.assertEqual(response.status_code, 409, response.data)

    def test_passwd(self):
        """Test that a registered user can change the password."""
        # test registration workflow
        username, password = 'newuser', 'password'
        first_name, last_name = 'Otto', 'Test'
        email = 'autotest@deis.io'
        submit = {
            'username': username,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
        }
        url = '/v2/auth/register'
        response = self.client.post(url, submit)
        self.assertEqual(response.status_code, 201, response.data)
        # change password without new password
        url = '/v2/auth/passwd'
        user = User.objects.get(username=username)
        token = Token.objects.get(user=user).key
        response = self.client.post(url, {},
                                    HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'new_password is a required field'})
        # change password without password field
        response = self.client.post(url, {'new_password': 'test'},
                                    HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'password is a required field'})
        # change password
        submit = {
            'password': 'password2',
            'new_password': password,
        }
        response = self.client.post(url, submit,
                                    HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 401, response.data)
        self.assertEqual(response.data, {'detail': 'Current password does not match'})
        self.assertEqual(response.get('content-type'), 'application/json')
        submit = {
            'password': password,
            'new_password': 'password2',
        }
        response = self.client.post(url, submit,
                                    HTTP_AUTHORIZATION='token {}'.format(token))
        self.assertEqual(response.status_code, 200, response.data)

        # test login with old password
        response = self.client.login(username=username, password=password)
        self.assertEqual(response, False)

        # test login with new password
        response = self.client.login(username=username, password='password2')
        self.assertEqual(response, True)

    def test_change_user_passwd(self):
        """
        Test that an administrator can change a user's password, while a regular user cannot.
        """
        # change password
        url = '/v2/auth/passwd'
        old_password = self.user1.password
        new_password = 'password'
        submit = {
            'username': self.user1.username,
            'new_password': new_password,
        }
        response = self.client.post(url, submit,
                                    HTTP_AUTHORIZATION='token {}'.format(self.admin_token))
        self.assertEqual(response.status_code, 200, response.data)

        # test login with old password
        response = self.client.login(username=self.user1.username, password=old_password)
        self.assertEqual(response, False)

        # test login with new password
        response = self.client.login(username=self.user1.username, password=new_password)
        self.assertEqual(response, True)

        # Non-admins can't change another user's password
        submit['password'], submit['new_password'] = submit['new_password'], old_password
        url = '/v2/auth/passwd'
        response = self.client.post(url, submit,
                                    HTTP_AUTHORIZATION='token {}'.format(self.user2_token))
        self.assertEqual(response.status_code, 403)

        # change back password with a regular user
        response = self.client.post(url, submit,
                                    HTTP_AUTHORIZATION='token {}'.format(self.user1_token))
        self.assertEqual(response.status_code, 200, response.data)

        # test login with new password
        response = self.client.login(username=self.user1.username, password=old_password)
        self.assertEqual(response, True)

    def test_regenerate(self):
        """ Test that token regeneration works"""
        url = '/v2/auth/tokens/'

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.admin_token)
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotEqual(response.data['token'], self.admin_token)

        self.admin_token = Token.objects.get(user=self.admin).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.admin_token)

        response = self.client.post(url, {"username": "autotest2"})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotEqual(response.data['token'], self.user1_token)

        response = self.client.post(url, {"all": "true"})
        self.assertEqual(response.status_code, 200, response.data)

        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 401, response.data)

    @mock.patch('django_auth_ldap.backend.logger')
    def test_auth_no_ldap_by_default(self, mock_logger):
        """Ensure that LDAP authentication is disabled by default."""
        self.test_auth()
        # NOTE(bacongobbler): Using https://github.com/deisthree/controller/issues/1189
        # as a test case
        mock_logger.warning.assert_not_called()
