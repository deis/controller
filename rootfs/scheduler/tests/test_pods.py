"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class PodsTest(TestCase):
    """Tests scheduler pod calls"""

    def create(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to create and verify a pod on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'replicas': kwargs.get('replicas', 4),
            'pod_termination_grace_period_seconds': 2,
            'image': 'quay.io/fake/image',
            'entrypoint': 'sh',
            'command': 'start',
            'deploy_timeout': 10,
        }

        pod = self.scheduler.pod.create(namespace, name, **kwargs)
        self.assertEqual(pod.status_code, 201, pod.json())
        return name

    def test_create_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create Pod doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.create('doesnotexist', 'doesnotexist')

    def test_create(self):
        self.create()

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete Pod foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.pod.delete(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.pod.delete(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_pods(self):
        # test success
        name = self.create()
        response = self.scheduler.pod.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name, data)

    def test_get_pod_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Pod doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.pod.get(self.namespace, 'doesnotexist')

    def test_get_pod(self):
        # test success
        name = self.create()
        response = self.scheduler.pod.get(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['kind'], 'Pod')
        self.assertEqual(data['metadata']['name'], name)
        self.assertDictContainsSubset(
            {
                'app': self.namespace,
                'heritage': 'deis'
            },
            data['metadata']['labels']
        )
