from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from api.models import App, Certificate, Domain
from api.tests import TEST_ROOT, DeisTestCase


class CertificateUseCase1Test(DeisTestCase):

    """
    Tests creation of domain SSL certificate and attach the
    certificate to a domain and then detach
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.url = '/v2/certs'
        self.app = App.objects.create(owner=self.user, id='test-app-use-case-1')
        self.domain = Domain.objects.create(owner=self.user, app=self.app, domain='foo.com')
        self.name = 'foo-com'  # certificate name

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
                'name': self.name,
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
                'name': self.name,
                'certificate': self.cert,
                'key': self.key,
                'common_name': 'foo.example.com'
            }
        )
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['common_name'], 'foo.com')

    def test_get_certificate_screens_data(self):
        """
        When a user retrieves a certificate make sure proper data is returned
        """
        # Create certificate
        response = self.client.post(
            self.url,
            {
                'name': self.name,
                'certificate': self.cert,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

        # Attach to domain that does not exist
        response = self.client.post(
            '{}/{}/domain/'.format(self.url, self.name),
            {'domain': 'random.com'}
        )
        self.assertEqual(response.status_code, 404)

        # Attach domain to certificate
        response = self.client.post(
            '{}/{}/domain/'.format(self.url, self.name),
            {'domain': str(self.domain)}
        )
        self.assertEqual(response.status_code, 201, response.data)

        # Attach domain to cert but post no body
        response = self.client.post(
            '{}/{}/domain/'.format(self.url, self.name),
            {}
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'domain is a required field'})

        # Assert data
        response = self.client.get('{}/{}'.format(self.url, self.name))
        self.assertEqual(response.status_code, 200, response.data)

        expected = {
            'name': self.name,
            'common_name': str(self.domain),
            'expires': '2017-01-14T23:55:59Z',
            'fingerprint': 'AC:82:58:80:EA:C4:B9:75:C1:1C:52:48:40:28:15:1D:47:AC:ED:88:4B:D4:72:95:B2:C0:A0:DF:4A:A7:60:B6',  # noqa
            'san': [],
            'domains': ['foo.com']
        }
        for key, value in list(expected.items()):
            self.assertEqual(response.data[key], value, key)

        # detach domain from a certificate
        response = self.client.delete(
            '{}/{}/domain/{}'.format(self.url, self.name, self.domain)
        )
        self.assertEqual(response.status_code, 204, response.data)

        # detach a domain that does not exist from a certificate
        response = self.client.delete(
            '{}/{}/domain/{}'.format(self.url, self.name, 'i-am-fake.com')
        )
        self.assertEqual(response.status_code, 404)

        # Assert data
        response = self.client.get('{}/{}'.format(self.url, self.name))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['domains'], [])

    def test_certficate_denied_requests(self):
        """Disallow put/patch requests"""
        response = self.client.put(self.url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, 405, response.content)

    def test_delete_certificate(self):
        """Destroying a certificate should generate a 204 response"""
        Certificate.objects.create(
            owner=self.user,
            name=self.name,
            certificate=self.cert,
            key=self.key
        )

        url = '/v2/certs/{}'.format(self.name)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

    def test_delete_certificate_with_attached_domain(self):
        """
        Destroy a certificate with attached domain.
        Domain should not have assigned cert anymore
        """
        # Create certificate
        response = self.client.post(
            self.url,
            {
                'name': self.name,
                'certificate': self.cert,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 201, response.data)

        # Attach domain to certificate
        response = self.client.post(
            '{}/{}/domain/'.format(self.url, self.name),
            {'domain': str(self.domain)}
        )
        self.assertEqual(response.status_code, 201, response.data)

        # Assert data from cert side
        response = self.client.get('{}/{}'.format(self.url, self.name))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['domains'], [str(self.domain)])

        # Assert data from domain side
        domain = Domain.objects.get(id=self.domain.id)
        self.assertEqual(domain.certificate.name, self.name)

        # Delete certificate
        url = '/v2/certs/{}'.format(self.name)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

        # verify certificate is not attached to domain anymore
        domain = Domain.objects.get(id=self.domain.id)
        self.assertEqual(domain.certificate, None)
