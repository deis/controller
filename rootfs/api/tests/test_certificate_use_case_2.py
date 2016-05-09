import os

from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token

from api.models import App, Certificate, Domain


class CertificateUseCase2Test(APITestCase):

    """
    Tests creation of 2 domains and SSL certificate.
    Attach the certificate to only one domain and then detach.
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.url = '/v2/certs'
        self.app = App.objects.create(owner=self.user, id='test-app-use-case-2')
        self.domains = {
            'foo.com': Domain.objects.create(owner=self.user, app=self.app, domain='foo.com'),
            'bar.com': Domain.objects.create(owner=self.user, app=self.app, domain='bar.com'),
        }

        # only foo.com has a cert
        self.domain = 'foo.com'

        path = os.path.dirname(os.path.realpath(__file__))
        self.certificates = {self.domain: {'name': self.domain.replace('.', '-')}}
        with open('{}/certs/{}.key'.format(path, self.domain)) as f:
            self.certificates[self.domain]['key'] = f.read()

        with open('{}/certs/{}.cert'.format(path, self.domain)) as f:
            self.certificates[self.domain]['cert'] = f.read()

        # add expires and fingerprints
        self.certificates['foo.com']['expires'] = '2017-01-14T23:55:59Z'
        self.certificates['foo.com']['fingerprint'] = 'AC:82:58:80:EA:C4:B9:75:C1:1C:52:48:40:28:15:1D:47:AC:ED:88:4B:D4:72:95:B2:C0:A0:DF:4A:A7:60:B6'  # noqa

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_create_certificate_with_domain(self):
        """Tests creating a certificate."""
        for domain, certificate in self.certificates.items():
            response = self.client.post(
                self.url,
                {
                    'name': certificate['name'],
                    'certificate': certificate['cert'],
                    'key': certificate['key']
                }
            )
            self.assertEqual(response.status_code, 201)

    def test_get_certificate_screens_data(self):
        """
        When a user retrieves a certificate, only the common name and expiry date should be
        displayed.
        """
        for domain, certificate in self.certificates.items():
            # Create certificate
            response = self.client.post(
                self.url,
                {
                    'name': certificate['name'],
                    'certificate': certificate['cert'],
                    'key': certificate['key']
                }
            )
            self.assertEqual(response.status_code, 201)

            # Attach domain to certificate
            response = self.client.post(
                '{}/{}/domain/'.format(self.url, certificate['name']),
                {'domain': domain}
            )
            self.assertEqual(response.status_code, 201)

            # Assert data
            response = self.client.get(
                '{}/{}'.format(self.url, certificate['name'])
            )
            self.assertEqual(response.status_code, 200)

            expected = {
                'name': certificate['name'],
                'common_name': str(domain),
                'expires': certificate['expires'],
                'fingerprint': certificate['fingerprint'],
                'san': [],
                'domains': [domain]
            }
            for key, value in list(expected.items()):
                self.assertEqual(
                    response.data[key],
                    value,
                    '{} - {}'.format(certificate['name'], key)
                )

            # detach domain to certificate
            response = self.client.delete(
                '{}/{}/domain/{}'.format(self.url, certificate['name'], domain)
            )
            self.assertEqual(response.status_code, 204)

            # Assert data
            response = self.client.get('{}/{}'.format(self.url, certificate['name']))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data['domains'], [])

    def test_certficate_denied_requests(self):
        """Disallow put/patch requests"""
        response = self.client.put(self.url)
        self.assertEqual(response.status_code, 405)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, 405)

    def test_delete_certificate(self):
        """Destroying a certificate should generate a 204 response"""
        for domain, certificate in self.certificates.items():
            Certificate.objects.create(
                name=certificate['name'],
                owner=self.user,
                common_name=domain,
                certificate=certificate['cert']
            )
            url = '/v2/certs/{}'.format(certificate['name'])
            response = self.client.delete(url)
            self.assertEqual(response.status_code, 204)
