from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from api.models import App, Certificate, Domain
from api.tests import TEST_ROOT, DeisTestCase


class CertificateUseCase5Test(DeisTestCase):

    """
    Tests creation of 3 domains (one is a wildcard) and 2 SSL certificate (one is a wildcard).
    Attach each certificate to a matching domain(s) and then detach.
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.url = '/v2/certs'
        self.app = App.objects.create(owner=self.user, id='test-app-use-case-5')
        # Done out of scope as it gets the same cert as the wildcard
        Domain.objects.create(owner=self.user, app=self.app, domain='foo.com')
        self.domains = {
            '*.foo.com': Domain.objects.create(owner=self.user, app=self.app, domain='*.foo.com'),
            'bar.com': Domain.objects.create(owner=self.user, app=self.app, domain='bar.com'),
        }

        self.certificates = {}

        # load up the certs
        for domain in self.domains:
            self.certificates[domain] = {'name': domain.replace('.', '-').replace('*', 'wildcard')}
            filename = domain.replace('*', 'wildcard')

            with open('{}/certs/{}.key'.format(TEST_ROOT, filename)) as f:
                self.certificates[domain]['key'] = f.read()

            with open('{}/certs/{}.cert'.format(TEST_ROOT, filename)) as f:
                self.certificates[domain]['cert'] = f.read()

        # add expires, common_name and fingerprints
        self.certificates['*.foo.com']['expires'] = '2017-01-21T21:56:15Z'
        self.certificates['*.foo.com']['fingerprint'] = '8F:8E:5F:F6:7A:78:07:5B:75:3E:10:D5:91:AE:30:4A:48:F4:40:39:90:12:88:B3:41:C6:68:7F:62:F5:CD:EB'  # noqa
        self.certificates['*.foo.com']['common_name'] = '*.foo.com'
        self.certificates['*.foo.com']['san'] = ['foo.com']

        self.certificates['bar.com']['expires'] = '2017-01-14T23:57:57Z'
        self.certificates['bar.com']['fingerprint'] = '7A:CA:B8:50:FF:8D:EB:03:3D:AC:AD:13:4F:EE:03:D5:5D:EB:5E:37:51:8C:E0:98:F8:1B:36:2B:20:83:0D:C0'  # noqa
        self.certificates['bar.com']['common_name'] = 'bar.com'
        self.certificates['bar.com']['san'] = []

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
            self.assertEqual(response.status_code, 201, response.data)

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
            self.assertEqual(response.status_code, 201, response.data)

            # Attach domain to certificate
            response = self.client.post(
                '{}/{}/domain/'.format(self.url, certificate['name']),
                {'domain': domain}
            )
            self.assertEqual(response.status_code, 201, response.data)

            if certificate['san']:
                for san in certificate['san']:
                    response = self.client.post(
                        '{}/{}/domain/'.format(self.url, certificate['name']),
                        {'domain': san}
                    )
                    self.assertEqual(response.status_code, 201, response.data)

            # Assert data
            response = self.client.get(
                '{}/{}'.format(self.url, certificate['name'])
            )
            self.assertEqual(response.status_code, 200, response.data)

            expected = {
                'name': certificate['name'],
                'common_name': certificate['common_name'],
                'expires': certificate['expires'],
                'fingerprint': certificate['fingerprint'],
                'san': certificate['san'],
                'domains': [domain] + certificate['san']
            }
            for key, value in list(expected.items()):
                self.assertEqual(
                    response.data[key],
                    value,
                    '{} - {}'.format(certificate['name'], key)
                )

            # detach domain from certificate
            response = self.client.delete(
                '{}/{}/domain/{}'.format(self.url, certificate['name'], domain)
            )
            self.assertEqual(response.status_code, 204, response.data)

            if certificate['san']:
                for san in certificate['san']:
                    response = self.client.delete(
                        '{}/{}/domain/{}'.format(self.url, certificate['name'], san)
                    )
                    self.assertEqual(response.status_code, 204, response.data)

            # Assert data
            response = self.client.get(
                '{}/{}'.format(self.url, certificate['name'])
            )
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
        for domain, certificate in self.certificates.items():
            # Create certificate
            Certificate.objects.create(
                name=certificate['name'],
                owner=self.user,
                common_name=domain,
                certificate=certificate['cert'],
                key=certificate['key']
            )

            # Remove certificate
            url = '/v2/certs/{}'.format(certificate['name'])
            response = self.client.delete(url)
            self.assertEqual(response.status_code, 204, response.data)
