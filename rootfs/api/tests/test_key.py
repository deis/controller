# -*- coding: utf-8 -*-
"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from api.models import Key
from api.utils import fingerprint
from api.tests import DeisTestCase


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

ECDSA_PUBKEY2 = (
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAAB"
    "BBK6Vbpuk4DjPtIcPUw0L2j1ahuRMItM5IZzi0kU0xCNVSSFtF21yEqLMOzdJOQYKCgaGzl"
    "pSPf7VWhYbJ753csQ= testing"
)

BAD_KEY = (
    "ssh-rsa foo_bar"
)


class KeyTest(DeisTestCase):

    """Tests cloud provider credentials"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def _check_key(self, pubkey):
        """
        Test that a user can add, remove and manage their SSH public keys
        """
        url = '/v2/keys'
        body = {'id': 'mykey@box.local', 'public': pubkey}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        key_id = response.data['id']

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        url = '/v2/keys/{key_id}'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(body['id'], response.data['id'])
        self.assertEqual(body['public'], response.data['public'])

        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

    def _check_bad_key(self, pubkey):
        """
        Test that a user cannot add invalid SSH public keys
        """
        url = '/v2/keys'
        body = {'id': 'mykey@box.local', 'public': pubkey}
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        return response

    def test_rsa_key(self):
        self._check_key(RSA_PUBKEY)

    def test_ecdsa_key(self):
        self._check_key(ECDSA_PUBKEY)

    def test_bad_key(self):
        response = self._check_bad_key(BAD_KEY)
        self.assertEqual(response.data, {'public': ['Key contains invalid base64 chars']})

    def _check_duplicate_fingerprint(self, pubkey, pubkey2):
        """
        Test that a user cannot add a duplicate key
        """
        url = '/v2/keys'
        # initial key
        body = {'id': 'mykey@box.local', 'public': pubkey}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # test that adding a key with the same fingerprint fails
        body = {'id': 'mykey2@box.local', 'public': pubkey}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'public': ['Public Key is already in use']}, response.data)  # noqa

        body = {'id': 'mykey3@box.local', 'public': pubkey2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

    def test_rsa_duplicate_key(self):
        self._check_duplicate_fingerprint(RSA_PUBKEY, RSA_PUBKEY2)

    def test_ecdsa_duplicate_key(self):
        self._check_duplicate_fingerprint(ECDSA_PUBKEY, ECDSA_PUBKEY2)

    def test_duplicate_id(self):
        url = '/v2/keys'
        body = {'id': 'duplicae@box.local', 'public': RSA_PUBKEY}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # same name, diff key
        body = {'id': 'duplicae@box.local', 'public': RSA_PUBKEY2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'id': ['SSH Key with this id already exists.']}, response.data)  # noqa

    def test_rsa_key_str(self):
        """Test the text representation of a key"""
        url = '/v2/keys'
        body = {'id': 'autotest', 'public':
                'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzqPAwHN70xsB0LXG//KzO'
                'gcPikyhdN/KRc4x3j/RA0pmFj63Ywv0PJ2b1LcMSqfR8F11WBlrW8c9xFua0'
                'ZAKzI+gEk5uqvOR78bs/SITOtKPomW4e/1d2xEkJqOmYH30u94+NZZYwEBqY'
                'aRb34fhtrnJS70XeGF0RhXE5Qea5eh7DBbeLxPfSYd8rfHgzMSb/wmx3h2vm'
                'HdQGho20pfJktNu7DxeVkTHn9REMUphf85su7slTgTlWKq++3fASE8PdmFGz'
                'b6PkOR4c+LS5WWXd2oM6HyBQBxxiwXbA2lSgQxOdgDiM2FzT0GVSFMUklkUH'
                'MdsaG6/HJDw9QckTS0vN autotest@deis.io'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        key = Key.objects.get(uuid=response.data['uuid'])
        self.assertEqual(str(key), 'ssh-rsa AAAAB3NzaC.../HJDw9QckTS0vN autotest@deis.io')

    def test_rsa_key_fingerprint(self):
        fp = fingerprint(RSA_PUBKEY)
        self.assertEqual(fp, '54:6d:da:1f:91:b5:2b:6f:a2:83:90:c4:f9:73:76:f5')

    def test_key_api_with_non_superuser_rsa(self):
        self.user = User.objects.get(username='autotest2')
        self.token = self.user.auth_token.key
        self._check_key(RSA_PUBKEY)

    def test_key_api_with_non_superuser_ecdsa(self):
        self.user = User.objects.get(username='autotest2')
        self.token = self.user.auth_token.key
        self._check_key(ECDSA_PUBKEY)
