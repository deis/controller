"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from api.models import Domain
from api.tests import DeisTestCase
from scheduler import KubeException

import idna


class DomainTest(DeisTestCase):

    """Tests creation of domains"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        self.app_id = self.create_app()

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_response_data(self):
        """Test that the serialized response contains only relevant data."""
        app_id = self.create_app()

        response = self.client.post(
            '/v2/apps/{}/domains'.format(app_id),
            {'domain': 'test-domain.example.com'}
        )
        self.assertEqual(response.status_code, 201, response.data)

        for key in response.data:
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'domain'])

        expected = {
            'owner': self.user.username,
            'app': app_id,
            'domain': 'test-domain.example.com'
        }
        self.assertDictContainsSubset(expected, response.data)

    def test_strip_dot(self):
        """Test that a dot on the right side of the domain gets stripped"""
        domain = 'autotest.127.0.0.1.xip.io.'
        msg = "failed on '{}'".format(domain)
        url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)

        # Create
        response = self.client.post(url, {'domain': domain})
        self.assertEqual(response.status_code, 201, msg)

        # Fetch
        domain = 'autotest.127.0.0.1.xip.io'  # stripped version
        url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
        response = self.client.get(url)
        expected = [data['domain'] for data in response.data['results']]
        self.assertEqual(sorted([self.app_id, domain]), expected, msg)

    def test_manage_idn_domain(self):
        url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
        test_domains = [
            'ドメイン.テスト',
            'xn--eckwd4c7c.xn--zckzah',
            'xn--80ahd1agd.ru',
            'домена.ru',
            '*.домена.испытание',
            'täst.königsgäßchen.de',
            'xn--tst-qla.xn--knigsgsschen-lcb0w.de',
            'ドメイン.xn--zckzah',
            'xn--eckwd4c7c.テスト',
            'täst.xn--knigsgsschen-lcb0w.de',
            '*.xn--tst-qla.königsgäßchen.de'
        ]
        for domain in test_domains:
            msg = "failed on '{}'".format(domain)

            # Generate ACE and Unicode variant for domain
            if domain.startswith("*."):
                ace_domain = "*." + idna.encode(domain[2:]).decode("utf-8", "strict")
                unicode_domain = "*." + idna.decode(ace_domain[2:])
            else:
                ace_domain = idna.encode(domain).decode("utf-8", "strict")
                unicode_domain = idna.decode(ace_domain)

            # Create
            response = self.client.post(url, {'domain': domain})
            self.assertEqual(response.status_code, 201, msg)

            # Fetch
            url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
            response = self.client.get(url)
            expected = [data['domain'] for data in response.data['results']]
            self.assertEqual(sorted([self.app_id, ace_domain]), sorted(expected), msg)

            # Verify creation failure for same domain with different encoding
            if ace_domain != domain:
                response = self.client.post(url, {'domain': ace_domain})
                self.assertEqual(response.status_code, 400, msg)

            # Verify creation failure for same domain with different encoding
            if unicode_domain != domain:
                response = self.client.post(url, {'domain': unicode_domain})
                self.assertEqual(response.status_code, 400, msg)

            # Delete
            url = '/v2/apps/{app_id}/domains/{hostname}'.format(hostname=domain,
                                                                app_id=self.app_id)
            response = self.client.delete(url)
            self.assertEqual(response.status_code, 204, msg)

            # Verify removal
            url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
            response = self.client.get(url)
            self.assertEqual(1, response.data['count'], msg)

            # verify only app domain is left
            expected = [data['domain'] for data in response.data['results']]
            self.assertEqual([self.app_id], expected, msg)

            # Use different encoding for creating and deleting (ACE)
            if ace_domain != domain:
                # Create
                response = self.client.post(url, {'domain': domain})
                self.assertEqual(response.status_code, 201, msg)

                # Fetch
                url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
                response = self.client.get(url)
                expected = [data['domain'] for data in response.data['results']]
                self.assertEqual(sorted([self.app_id, ace_domain]), sorted(expected), msg)

                # Delete
                url = '/v2/apps/{app_id}/domains/{hostname}'.format(hostname=ace_domain,
                                                                    app_id=self.app_id)
                response = self.client.delete(url)
                self.assertEqual(response.status_code, 204, msg)

                # Verify removal
                url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
                response = self.client.get(url)
                self.assertEqual(1, response.data['count'], msg)

                # verify only app domain is left
                expected = [data['domain'] for data in response.data['results']]
                self.assertEqual([self.app_id], expected, msg)

            # Use different encoding for creating and deleting (Unicode)
            if unicode_domain != domain:
                # Create
                response = self.client.post(url, {'domain': domain})
                self.assertEqual(response.status_code, 201, msg)

                # Fetch
                url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
                response = self.client.get(url)
                expected = [data['domain'] for data in response.data['results']]
                self.assertEqual(sorted([self.app_id, ace_domain]), sorted(expected), msg)

                # Delete
                url = '/v2/apps/{app_id}/domains/{hostname}'.format(hostname=unicode_domain,
                                                                    app_id=self.app_id)
                response = self.client.delete(url)
                self.assertEqual(response.status_code, 204, msg)

                # Verify removal
                url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
                response = self.client.get(url)
                self.assertEqual(1, response.data['count'], msg)

                # verify only app domain is left
                expected = [data['domain'] for data in response.data['results']]
                self.assertEqual([self.app_id], expected, msg)

    def test_manage_domain(self):
        url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
        test_domains = [
            'test-domain.example.com',
            'django.paas-sandbox',
            'django.paas--sandbox',
            'domain',
            'not.too.loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong',
            '3com.com',
            'domain1',
            '3333.xyz',
            'w3.example.com',
            'MYDOMAIN.NET',
            'autotest.127.0.0.1.xip.io',
            '*.deis.example.com'
        ]

        for domain in test_domains:
            msg = "failed on '{}'".format(domain)

            # Create
            response = self.client.post(url, {'domain': domain})
            self.assertEqual(response.status_code, 201, msg)

            # Fetch
            url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
            response = self.client.get(url)
            expected = [data['domain'] for data in response.data['results']]
            self.assertEqual(sorted([self.app_id, domain]), sorted(expected), msg)

            # Delete
            url = '/v2/apps/{app_id}/domains/{hostname}'.format(hostname=domain,
                                                                app_id=self.app_id)
            response = self.client.delete(url)
            self.assertEqual(response.status_code, 204, msg)

            # Verify removal
            url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
            response = self.client.get(url)
            self.assertEqual(1, response.data['count'], msg)

            # verify only app domain is left
            expected = [data['domain'] for data in response.data['results']]
            self.assertEqual([self.app_id], expected, msg)

    def test_delete_domain_does_not_exist(self):
        """Remove a domain that does not exist"""
        url = '/v2/apps/{app_id}/domains/{domain}'.format(domain='test-domain.example.com',
                                                          app_id=self.app_id)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 404)

    def test_delete_domain_does_not_remove_latest(self):
        """https://github.com/deisthree/deis/issues/3239"""
        url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
        test_domains = [
            'test-domain.example.com',
            'django.paas-sandbox',
        ]
        for domain in test_domains:
            response = self.client.post(url, {'domain': domain})
            self.assertEqual(response.status_code, 201, response.data)

        url = '/v2/apps/{app_id}/domains/{domain}'.format(domain=test_domains[0],
                                                          app_id=self.app_id)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)
        with self.assertRaises(Domain.DoesNotExist):
            Domain.objects.get(domain=test_domains[0])

    def test_delete_domain_does_not_remove_others(self):
        """https://github.com/deisthree/deis/issues/3475"""
        self.test_delete_domain_does_not_remove_latest()
        self.assertEqual(Domain.objects.all().count(), 2)

    def test_manage_domain_invalid_app(self):
        # Create domain
        url = '/v2/apps/{app_id}/domains'.format(app_id="this-app-does-not-exist")
        response = self.client.post(url, {'domain': 'test-domain.example.com'})
        self.assertEqual(response.status_code, 404)

        # verify
        url = '/v2/apps/{app_id}/domains'.format(app_id='this-app-does-not-exist')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_manage_domain_invalid_domain(self):
        url = '/v2/apps/{app_id}/domains'.format(app_id=self.app_id)
        test_domains = [
            'this_is_an.invalid.domain',
            'this-is-an.invalid.1',
            'django.pa--assandbox',
            'too.looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong',
            'foo.*.bar.com',
            '*',
            'a' * 300,
            '.'.join(['a'] * 128)
        ]
        for domain in test_domains:
            msg = "failed on \"{}\"".format(domain)
            response = self.client.post(url, {'domain': domain})
            self.assertEqual(response.status_code, 400, msg)

    def test_admin_can_add_domains_to_other_apps(self):
        """If a non-admin user creates an app, an administrator should be able to add
        domains to it.
        """
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        app_id = self.create_app()

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        url = '/v2/apps/{}/domains'.format(app_id)
        response = self.client.post(url, {'domain': 'example.deis.example.com'})
        self.assertEqual(response.status_code, 201, response.data)

    def test_unauthorized_user_cannot_modify_domain(self):
        """
        An unauthorized user should not be able to modify other domains.

        Since an unauthorized user should not know about the application at all, these
        requests should return a 404.
        """
        app_id = self.create_app()

        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = Token.objects.get(user=unauthorized_user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)

        url = '/v2/apps/{}/domains'.format(app_id)
        response = self.client.post(url, {'domain': 'example.com'})
        self.assertEqual(response.status_code, 403)

    def test_kubernetes_service_failure(self):
        """
        Cause an Exception in kubernetes services
        """
        app_id = self.create_app()

        # scheduler.svc.get exception
        with mock.patch('scheduler.resources.service.Service.get') as mock_kube:
            mock_kube.side_effect = KubeException('Boom!')
            domain = 'foo.com'
            url = '/v2/apps/{}/domains'.format(app_id)
            response = self.client.post(url, {'domain': domain})
            self.assertEqual(response.status_code, 503, response.data)

        # scheduler.svc.update exception
        with mock.patch('scheduler.resources.service.Service.update') as mock_kube:
            domain = 'foo.com'
            url = '/v2/apps/{}/domains'.format(app_id)
            response = self.client.post(url, {'domain': domain})
            self.assertEqual(response.status_code, 201, response.data)

            mock_kube.side_effect = KubeException('Boom!')
            url = '/v2/apps/{}/domains/{}'.format(app_id, domain)
            response = self.client.delete(url)
            self.assertEqual(response.status_code, 503, response.data)
