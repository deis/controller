from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authtoken.models import Token
from django.core.exceptions import SuspiciousOperation

from api.models import Certificate
from api.tests import TEST_ROOT, DeisTestCase


class CertificateTest(DeisTestCase):

    """Tests creation of domain SSL certificates"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.url = '/v2/certs'
        self.domain = 'autotest.example.com'

        with open('{}/certs/{}.key'.format(TEST_ROOT, self.domain)) as f:
            self.key = f.read()

        with open('{}/certs/{}.cert'.format(TEST_ROOT, self.domain)) as f:
            self.cert = f.read()

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_create_certificate_with_domain(self):
        """Tests creating a certificate."""
        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert',
                'certificate': self.cert,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

    def test_update_certificate(self):
        """Tests update of a certificate."""
        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert',
                'certificate': self.cert,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

    def test_create_certificate_with_different_common_name(self):
        """
        Make sure common_name is read-only
        """
        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert',
                'certificate': self.cert,
                'key': self.key,
                'common_name': 'foo.example.com'
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['common_name'], 'autotest.example.com')

    def test_get_certificate_screens_data(self):
        """
        When a user retrieves a certificate, only the common name and expiry date should be
        displayed.
        """
        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert',
                'certificate': self.cert,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.get('{}/{}'.format(self.url, 'random-test-cert'))
        self.assertEqual(response.status_code, 200, response.data)

        expected = {
            'common_name': 'autotest.example.com',
            'expires': '2016-03-05T17:14:27Z',
            'fingerprint': '37:24:D8:EB:DC:A4:2C:DA:88:55:C5:19:71:D3:9B:43:BA:AC:3A:CE:33:8E:07:52:1C:51:01:A0:97:43:C9:4D',  # noqa
            'san': [],
            'domains': [],
        }
        for key, value in list(expected.items()):
            self.assertEqual(response.data[key], value, key)

    def test_get_certificate_self_signed(self):
        """
        Load a certificate without Common Name (self signed most likely)
        """
        with open('{}/certs/{}.key'.format(TEST_ROOT, 'self-signed')) as f:
            key = f.read()

        with open('{}/certs/{}.cert'.format(TEST_ROOT, 'self-signed')) as f:
            cert = f.read()

        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert-self',
                'certificate': cert,
                'key': key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.get('{}/{}'.format(self.url, 'random-test-cert-self'))
        self.assertEqual(response.status_code, 200, response.data)

        expected = {
            'common_name': None,
            'expires': '2017-08-30T00:51:54Z',
            'fingerprint': 'AD:F7:AF:C2:E1:3D:F5:26:47:4E:B9:2D:1C:75:AD:26:6F:05:2C:A7:6F:24:84:A2:8C:39:B3:3F:97:AB:2C:B3',  # noqa
            'san': [],
            'domains': [],
        }
        for key, value in list(expected.items()):
            self.assertEqual(response.data[key], value, key)

    def test_certficate_denied_requests(self):
        """Disallow put/patch requests"""
        response = self.client.put(self.url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, 405, response.content)

    def test_delete_certificate(self):
        """Destroying a certificate should generate a 204 response"""
        Certificate.objects.create(
            name='random-test-cert',
            owner=self.user,
            common_name='autotest.example.com',
            certificate=self.cert,
            key=self.key
        )
        url = '/v2/certs/random-test-cert'
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

    def test_create_invalid_cert(self):
        """Upload a cert that can't be loaded by pyopenssl"""
        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert',
                'certificate': 'i am bad data',
                'key': 'i am bad data as well'
            }
        )
        self.assertEqual(response.status_code, 400, response.data)
        # match partial since right now the rest is pyopenssl errors
        self.assertIn('Could not load certificate', response.data['certificate'][0])

    def test_load_invalid_cert(self):
        """Inject a cert that can't be loaded by pyopenssl"""

        with self.assertRaises(SuspiciousOperation):
            Certificate.objects.create(
                owner=self.user,
                name='random-test-cert',
                certificate='i am bad data',
                key='i am bad data as well'
            )

    def test_create_invalid_key(self):
        """Upload a private key that can't be loaded by pyopenssl"""
        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert',
                'certificate': self.cert,
                'key': 'I am Groot.'
            }
        )
        self.assertEqual(response.status_code, 400, response.data)
        # match partial since right now the rest is pyopenssl errors
        self.assertIn('Could not load private key', response.data['key'][0])

    def test_load_invalid_key(self):
        """Inject a private key that can't be loaded by pyopenssl"""

        with self.assertRaises(SuspiciousOperation):
            Certificate.objects.create(
                owner=self.user,
                name='random-test-cert',
                certificate=self.cert,
                key='I am Groot.'
            )

    def test_certs_fetch_limit(self):
        """
        When a user retrieves a certificate, make sure limits work
        """
        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert1',
                'certificate': self.cert,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

        response = self.client.post(
            self.url,
            {
                'name': 'random-test-cert2',
                'certificate': self.cert,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

        # limit=0 is invalid as of DRF 3.4
        # https://github.com/tomchristie/django-rest-framework/pull/4194
        response = self.client.get('{}?limit=0'.format(self.url))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 2, 'limit=0 should return 2')

        response = self.client.get('{}?limit=1'.format(self.url))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1, 'limit=1 should return 1')

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 2)
