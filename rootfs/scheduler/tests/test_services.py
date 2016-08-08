"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class ServicesTest(TestCase):
    """Tests scheduler service calls"""

    def create(self, data={}):
        """
        Helper function to create and verify a service on the namespace
        """
        name = generate_random_name()
        service = self.scheduler.create_service(self.namespace, name, data=data)
        data = service.json()
        self.assertEqual(service.status_code, 201, data)
        self.assertEqual(data['metadata']['name'], name)
        return name

    def test_create_failure(self):
        # Kubernetes does not throw a 404 if queried on a non-existant Namespace
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create Service doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.create_service('doesnotexist', 'doesnotexist')

    def test_create(self):
        # helper method takes care of the verification
        self.create()

        # create with more ports
        name = self.create(data={
            'spec': {
                'ports': [{
                    'name': 'http',
                    'port': 80,
                    'targetPort': 5001,
                    'protocol': 'TCP'
                }],
            }
        })

        service = self.scheduler.get_service(self.namespace, name).json()
        self.assertEqual(service['spec']['ports'][0]['targetPort'], 5000, service)
        self.assertEqual(service['spec']['ports'][1]['targetPort'], 5001, service)

    def test_update_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update Service foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.update_service(self.namespace, 'foo', {})

    def test_update(self):
        # test success
        name = self.create()
        service = self.scheduler.get_service(self.namespace, name).json()
        self.assertEqual(service['spec']['ports'][0]['targetPort'], 5000, service)

        service['spec']['ports'][0]['targetPort'] = 5001
        response = self.scheduler.update_service(self.namespace, name, service)
        self.assertEqual(response.status_code, 200, response.json())

        service = self.scheduler.get_service(self.namespace, name).json()
        self.assertEqual(service['spec']['ports'][0]['targetPort'], 5001, service)

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete Service foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.delete_service(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.delete_service(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_services(self):
        # test success
        name = self.create()
        response = self.scheduler.get_services(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name)

    def test_get_service_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Service doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.get_service(self.namespace, 'doesnotexist')

    def test_get_service(self):
        # test success
        name = self.create()
        response = self.scheduler.get_service(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'Service')
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
        self.assertEqual(data['spec']['ports'][0]['targetPort'], 5000)
