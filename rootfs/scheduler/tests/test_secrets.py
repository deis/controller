"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException, KubeException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class SecretsTest(TestCase):
    """Tests scheduler secret calls"""

    def create(self):
        """
        Helper function to create and verify a secret on the namespace
        """
        name = generate_random_name()
        data = {
            'foo': 'bar',
            'this': 'that',
            'empty': None,
        }
        secret = self.scheduler.create_secret(self.namespace, name, data)
        data = secret.json()
        self.assertEqual(secret.status_code, 201, data)
        self.assertEqual(data['metadata']['name'], name)
        self.assertIn('foo', data['data'])
        self.assertIn('this', data['data'])
        return name

    def test_create_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create Secret doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.create_secret('doesnotexist', 'doesnotexist', {})

        with self.assertRaises(
            KubeException,
            msg='invlaid is not a supported secret type. Use one of the following: Opaque, kubernetes.io/dockerconfigjson'  # noqa
        ):
            self.scheduler.create_secret(self.namespace, 'foo', {}, secret_type='invalid')

    def test_create(self):
        name = self.create()
        secret = self.scheduler.get_secret(self.namespace, name).json()
        self.assertEqual(secret['data']['foo'], 'bar', secret)
        self.assertEqual(secret['data']['this'], 'that', secret)
        self.assertEqual(secret['type'], 'Opaque')

    def test_update_secret_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update Secret foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.update_secret(self.namespace, 'foo', {})

    def test_update(self):
        # test success
        name = self.create()
        secret = self.scheduler.get_secret(self.namespace, name).json()
        self.assertEqual(secret['data']['foo'], 'bar', secret)
        self.assertEqual(secret['data']['this'], 'that', secret)
        self.assertEqual(secret['type'], 'Opaque')

        secret['data']['foo'] = 5001
        response = self.scheduler.update_secret(self.namespace, name, secret['data'])
        self.assertEqual(response.status_code, 200, response.json())

        secret = self.scheduler.get_secret(self.namespace, name).json()
        self.assertEqual(secret['data']['foo'], '5001', secret)

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete Secret foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.delete_secret(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.delete_secret(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_secrets(self):
        # test success
        name = self.create()
        response = self.scheduler.get_secrets(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name)

    def test_get_secret_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Secret doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.get_secret(self.namespace, 'doesnotexist')

    def test_get_secret(self):
        # test success
        name = self.create()
        response = self.scheduler.get_secret(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'Secret')
        self.assertDictContainsSubset(
            {
                'name': name,
                'labels': {
                    'app': self.namespace,
                    'heritage': 'deis'
                }
            },
            data['metadata']
        )
        self.assertEqual(data['data']['foo'], 'bar', data)
        self.assertEqual(data['data']['this'], 'that', data)
        self.assertEqual(data['type'], 'Opaque')
