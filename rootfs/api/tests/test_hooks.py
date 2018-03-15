"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from unittest import mock
from rest_framework.authtoken.models import Token

from api.tests import adapter, mock_port, DeisTransactionTestCase
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

ECDSA_PUBKEY = (
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAB"
    "BBCGB0x9lmubbLJTF5NekCI0Cgjyip6jJh/t/qQQi1LAZisbREBJ8Wy+hwSn3tnbf/Imh9X"
    "+MQnrrza0jaQ3QUAQ= autotest@autotesting comment"
)

ED25519_PUBKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAPYa7ztrkGyl/LSpBxv0DjPej74GCSVItX"
    "9Y2+/zxc+ testing"
)

BAD_KEY = (
    "ssh-rsa foooooooooooooooooooooooooooooooooooooooooooooooooooobaaaaaaarrr"
    "rrrrr testing"
)


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
@mock.patch('api.models.release.docker_get_port', mock_port)
class HookTest(DeisTransactionTestCase):

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
        app_id = self.create_app()

        # give user permission to app
        url = "/v2/apps/{}/perms".format(app_id)
        body = {'username': str(self.user)}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # Create rsa key
        body = {'id': str(self.user), 'public': RSA_PUBKEY}
        response = self.client.post('/v2/keys', body)
        self.assertEqual(response.status_code, 201, response.data)
        rsa_pub = response.data['public']

        # Create another rsa key
        body = {'id': str(self.user) + '-2', 'public': RSA_PUBKEY2}
        response = self.client.post('/v2/keys', body)
        self.assertEqual(response.status_code, 201, response.data)
        rsa_pub2 = response.data['public']

        # Create dsa key
        body = {'id': str(self.user) + '-3', 'public': ECDSA_PUBKEY}
        response = self.client.post('/v2/keys', body)
        self.assertEqual(response.status_code, 201, response.data)
        dsa_pub = response.data['public']

        # Create ed25519 key
        body = {'id': str(self.user) + '-4', 'public': ED25519_PUBKEY}
        response = self.client.post('/v2/keys', body)
        self.assertEqual(response.status_code, 201, response.data)
        ed25519_pub = response.data['public']

        # Attempt adding a bad SSH pubkey
        body = {'id': str(self.user) + '-5', 'public': BAD_KEY}
        response = self.client.post('/v2/keys', body)
        self.assertEqual(response.status_code, 400, response.data)

        # Make sure 404 is returned for a random app
        url = '/v2/hooks/keys/doesnotexist'
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 404)

        # Test app that exists
        url = '/v2/hooks/keys/{}'.format(app_id)
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data, {"autotest": [
            {'key': rsa_pub, 'fingerprint': '54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:f5'},
            {'key': rsa_pub2, 'fingerprint': '43:fd:22:bc:dc:ca:6a:28:ba:71:4c:18:41:1d:d1:e2'},
            {'key': dsa_pub, 'fingerprint': '28:dd:ef:f9:12:ab:f9:80:6f:4c:0a:e7:e7:a4:59:95'},
            {'key': ed25519_pub, 'fingerprint': '75:9a:b3:81:13:40:c2:78:32:aa:e3:b4:93:2a:12:c9'}
        ]})

        # Test against an app that exist but user does not
        url = '/v2/hooks/keys/{}/foooooo'.format(app_id)
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 404)

        # Test against an app that exists and user that does
        url = '/v2/hooks/keys/{}/{}'.format(app_id, str(self.user))
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data, {"autotest": [
            {'key': rsa_pub, 'fingerprint': '54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:f5'},
            {'key': rsa_pub2, 'fingerprint': '43:fd:22:bc:dc:ca:6a:28:ba:71:4c:18:41:1d:d1:e2'},
            {'key': dsa_pub, 'fingerprint': '28:dd:ef:f9:12:ab:f9:80:6f:4c:0a:e7:e7:a4:59:95'},
            {'key': ed25519_pub, 'fingerprint': '75:9a:b3:81:13:40:c2:78:32:aa:e3:b4:93:2a:12:c9'}

        ]})

        # Fetch a valid ssh key
        url = '/v2/hooks/key/54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:f5'
        response = self.client.get(url, HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
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

    def test_build_hook(self, mock_requests):
        """Test creating a Build via an API Hook"""
        app_id = self.create_app()

        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/build'.format(**locals())
        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': '{app_id}:v2'.format(**locals())}
        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401, response.data)
        # post the build with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])

    def test_build_hook_slug_url(self, mock_requests):
        """Test creating a slug_url build via an API Hook"""
        app_id = self.create_app()
        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/build'.format(**locals())
        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': 'http://example.com/slugs/foo-12345354.tar.gz'}

        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401, response.data)

        # post the build with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])

    def test_build_hook_procfile(self, mock_requests):
        """Test creating a Procfile build via an API Hook"""
        app_id = self.create_app()

        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/build'.format(**locals())
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
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])

        # make sure build fields were populated
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('results', response.data)
        build = response.data['results'][0]
        self.assertEqual(build['sha'], SHA)
        self.assertEqual(build['procfile'], PROCFILE)

        # test listing/retrieving container info
        url = "/v2/apps/{app_id}/pods/web".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'web')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-web-[0-9]{8,10}-[a-z0-9]{5}')

        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401, response.data)

    def test_build_hook_sidecarfile(self, mock_requests):
        """Test creating a Sidecarfile build via an API Hook"""
        app_id = self.create_app()

        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/build'.format(**locals())
        PROCFILE = {'web': 'node server.js', 'worker': 'node worker.js'}
        SIDECARFILE = {'web': [{'name': 'busybox', 'image': 'busybox:latest'}]}
        SHA = 'ecdff91c57a0b9ab82e89634df87e293d259a3aa'
        body = {'receive_user': 'autotest',
                'receive_repo': app_id,
                'image': '{app_id}:v2'.format(**locals()),
                'sha': SHA,
                'procfile': PROCFILE,
                'sidecarfile': SIDECARFILE}

        # post the build with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])

        # make sure build fields were populated
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('results', response.data)
        build = response.data['results'][0]
        self.assertEqual(build['sha'], SHA)
        self.assertEqual(build['procfile'], PROCFILE)
        self.assertEqual(build['sidecarfile'], SIDECARFILE)

        # test listing/retrieving container info
        url = "/v2/apps/{app_id}/pods/web".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'web')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-web-[0-9]{8,10}-[a-z0-9]{5}')

        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401, response.data)

    def test_build_hook_dockerfile(self, mock_requests):
        """Test creating a Dockerfile build via an API Hook"""
        app_id = self.create_app()
        build = {'username': 'autotest', 'app': app_id}
        url = '/v2/hooks/build'.format(**locals())
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
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('release', response.data)
        self.assertIn('version', response.data['release'])
        # make sure build fields were populated
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('results', response.data)
        build = response.data['results'][0]
        self.assertEqual(build['sha'], SHA)
        self.assertEqual(build['dockerfile'], DOCKERFILE)
        # test default container
        url = "/v2/apps/{app_id}/pods/cmd".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'cmd')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-cmd-[0-9]{8,10}-[a-z0-9]{5}')

        # post the build without an auth token
        self.client.credentials()
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 401, response.data)

    def test_config_hook(self, mock_requests):
        """Test reading Config via an API Hook"""
        app_id = self.create_app()
        url = '/v2/apps/{app_id}/config'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
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
        self.assertEqual(response.status_code, 401, response.data)
        # post with the builder auth key
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('values', response.data)
        self.assertEqual(values, response.data['values'])

    def test_admin_can_hook(self, mock_requests):
        """Administrator should be able to create build hooks on non-admin apps.
        """
        """Test creating a Push via the API"""
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        app_id = self.create_app()
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
        url = '/v2/hooks/build'
        response = self.client.post(url, body,
                                    HTTP_X_DEIS_BUILDER_AUTH=settings.BUILDER_KEY)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['release']['version'], 2)
