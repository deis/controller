"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.test import APITransactionTestCase
from unittest import mock
from rest_framework.authtoken.models import Token

from . import adapter
import requests_mock

RSA_PUBKEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfQkkUUoxpvcNMkvv7jqnfodgs37M2eBO"
    "APgLK+KNBMaZaaKB4GF1QhTCMfFhoiTW3rqa0J75bHJcdkoobtTHlK8XUrFqsquWyg3XhsT"
    "Yr/3RQQXvO86e2sF7SVDJqVtpnbQGc5SgNrHCeHJmf5HTbXSIjCO/AJSvIjnituT/SIAMGe"
    "Bw0Nq/iSltwYAek1hiKO7wSmLcIQ8U4A00KEUtalaumf2aHOcfjgPfzlbZGP0S0cuBwSqLr"
    "8b5XGPmkASNdUiuJY4MJOce7bFU14B7oMAy2xacODUs1momUeYtGI9T7X2WMowJaO7tP3Gl"
    "sgBMP81VfYTfYChAyJpKp2yoP autotest@autotesting comment"
)

RSA_PUBKEY2 = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4xELdubosJ2/bQuiSUyWclVVa71pXpmq"
    "aXTwfau/XFLgD5yE+TOFbVT22xvEr4AwZqS9w0TBMp4RLfi4pTdjoIK+lau2lDMuEpbF4xg"
    "PWAveAqKuLcKJbJrZQdo5VWn5//7+M1RHQCPqjeN2iS9I3C8yiPg3mMPT2mKuyZYB9VD3hK"
    "mhT4xRAsS6vfKZr7CmFHgAmRBqdaU1RetR5nfTj0R5yyAv7Z2BkE8UhUAseFZ0djBs6kzjs"
    "5ddgM4Gv2Zajs7qVvpVPzZpq3vFB16Q5TMj2YtoYF6UZFFf4u/4KAW8xfYJAFdpNsvh279s"
    "dJS08nTeElUg6pn83A3hqWX+J testing"
)


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
class HookTest(APITransactionTestCase):

    """Tests API hooks used to trigger actions from external components"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_key_hook(self, mock_requests):
        """Test fetching keys for an app and a user"""

        # Create app to use
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']

        # give user permission to app
        url = "/v2/apps/{}/perms".format(app_id)
        body = {'username': str(self.user)}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        # Create key
        url = '/v2/keys'
        body = {'id': str(self.user), 'public': RSA_PUBKEY}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        public = response.data['public']

        # Create another keys
        url = '/v2/keys'
        body = {'id': str(self.user), 'public': RSA_PUBKEY2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        public2 = response.data['public']

        # Make sure 404 is returned for a random app
        url = '/v2/hooks/keys/doesnotexist'
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 404)

        # Test app that exists
        url = '/v2/hooks/keys/{}'.format(app_id)
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"autotest": [
            {'key': public, 'fingerprint': '54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:f5'},
            {'key': public2, 'fingerprint': '43:fd:22:bc:dc:ca:6a:28:ba:71:4c:18:41:1d:d1:e2'}
        ]})

        # Test against an app that exist but user does not
        url = '/v2/hooks/keys/{}/foooooo'.format(app_id)
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 404)

        # Test against an app that exists and user that does
        url = '/v2/hooks/keys/{}/{}'.format(app_id, str(self.user))
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"autotest": [
            {'key': public, 'fingerprint': '54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:f5'},
            {'key': public2, 'fingerprint': '43:fd:22:bc:dc:ca:6a:28:ba:71:4c:18:41:1d:d1:e2'}
        ]})

        # Fetch a valid ssh key
        url = '/v2/hooks/key/54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:f5'
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {
            "username": str(self.user),
            "apps": [
                app_id
            ]
        })

        # Fetch an non-existent base64 encoded ssh key
        url = '/v2/hooks/key/54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:wooooo'
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 404)

        # Fetch an invalid (not encoded) ssh key
        url = '/v2/hooks/key/nope'
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 404)

    def test_push_hook(self, mock_requests):
        """Test creating a Push via the API"""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']

        # prepare a push body
        body = {
            'sha': 'df1e628f2244b73f9cdf944f880a2b3470a122f4',
            'fingerprint': '88:25:ed:67:56:91:3d:c6:1b:7f:42:c6:9b:41:24:80',
            'receive_user': 'autotest',
            'receive_repo': '{app_id}'.format(**locals()),
            'ssh_connection': '10.0.1.10 50337 172.17.0.143 22',
            'ssh_original_command': "git-receive-pack '{app_id}.git'".format(**locals()),
        }
        # post a request without the auth header
        url = "/v2/hooks/push".format(**locals())
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)
        # now try with the builder key in the special auth header
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 201)
        for k in ('owner', 'app', 'sha', 'fingerprint', 'receive_repo', 'receive_user',
                  'ssh_connection', 'ssh_original_command'):
            self.assertIn(k, response.data)

    def test_push_abuse(self, mock_requests):
        """Test a user pushing to an unauthorized application"""
        # create a legit app as "autotest"
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # register an evil user
        username, password = 'eviluser', 'password'
        first_name, last_name = 'Evil', 'User'
        email = 'evil@deis.io'
        submit = {
            'username': username,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
        }
        url = '/v2/auth/register'
        response = self.client.post(url, submit)
        self.assertEqual(response.status_code, 201)
        # prepare a push body that simulates a git push
        body = {
            'sha': 'df1e628f2244b73f9cdf944f880a2b3470a122f4',
            'fingerprint': '88:25:ed:67:56:91:3d:c6:1b:7f:42:c6:9b:41:24:99',
            'receive_user': 'eviluser',
            'receive_repo': '{app_id}'.format(**locals()),
            'ssh_connection': '10.0.1.10 50337 172.17.0.143 22',
            'ssh_original_command': "git-receive-pack '{app_id}.git'".format(**locals()),
        }
        # try to push as "eviluser"
        url = "/v2/hooks/push".format(**locals())
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 403)

    def test_build_hook(self, mock_requests):
        """Test creating a Build via an API Hook"""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/builds'.format(**locals())
        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': '{app_id}:v2'.format(**locals())}
        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401)
        # post the build with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])

    def test_build_hook_slug_url(self, mock_requests):
        """Test creating a slug_url build via an API Hook"""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/builds'.format(**locals())
        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': 'http://example.com/slugs/foo-12345354.tar.gz'}

        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401)

        # post the build with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])

    def test_build_hook_procfile(self, mock_requests):
        """Test creating a Procfile build via an API Hook"""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/builds'.format(**locals())
        PROCFILE = {'web': 'node server.js', 'worker': 'node worker.js'}
        SHA = 'ecdff91c57a0b9ab82e89634df87e293d259a3aa'
        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': '{app_id}:v2'.format(**locals()),
                'sha': SHA,
                'procfile': PROCFILE}

        # post the build with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])
        # make sure build fields were populated
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('results', response.data)
        build = response.data['results'][0]
        self.assertEqual(build['sha'], SHA)
        self.assertEqual(build['procfile'], PROCFILE)
        # test listing/retrieving container info
        url = "/v2/apps/{app_id}/pods/web".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'web')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-v2-web-[a-z0-9]{5}')

        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401)

    def test_build_hook_dockerfile(self, mock_requests):
        """Test creating a Dockerfile build via an API Hook"""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/builds'.format(**locals())
        SHA = 'ecdff91c57a0b9ab82e89634df87e293d259a3aa'
        DOCKERFILE = """FROM busybox
        CMD /bin/true"""

        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': '{app_id}:v2'.format(**locals()),
                'sha': SHA,
                'dockerfile': DOCKERFILE}
        # post the build with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])
        # make sure build fields were populated
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('results', response.data)
        build = response.data['results'][0]
        self.assertEqual(build['sha'], SHA)
        self.assertEqual(build['dockerfile'], DOCKERFILE)
        # test default container
        url = "/v2/apps/{app_id}/pods/cmd".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'cmd')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-v2-cmd-[a-z0-9]{5}')

        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401)

    def test_config_hook(self, mock_requests):
        """Test reading Config via an API Hook"""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        url = '/v2/apps/{app_id}/config'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('values', response.data)
        values = response.data['values']
        # prepare the config hook
        config = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/config'.format(**locals())
        body = {'receive_user': 'autotest',
                'receive_repo': app_id}
        # post without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401)
        # post with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertIn('values', response.data)
        self.assertEqual(values, response.data['values'])

    def test_admin_can_hook(self, mock_requests):
        """Administrator should be able to create build hooks on non-admin apps.
        """
        """Test creating a Push via the API"""
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # prepare a push body
        DOCKERFILE = """
        FROM busybox
        CMD /bin/true
        """
        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': '{app_id}:v2'.format(**locals()),
                'sha': 'ecdff91c57a0b9ab82e89634df87e293d259a3aa',
                'dockerfile': DOCKERFILE}
        url = '/v2/hooks/builds'
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['release']['version'], 2)
