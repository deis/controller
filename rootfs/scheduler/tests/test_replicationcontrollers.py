"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class ReplicationControllersTest(TestCase):
    """Tests scheduler rc calls"""

    def create(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to create and verify a rc on the namespace
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
        }

        rc = self.scheduler.rc.create(namespace, name, **kwargs)
        data = rc.json()
        self.assertEqual(rc.status_code, 201, data)
        return name

    def scale_rc(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to scale and verify a deployment on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'replicas': kwargs.get('replicas', 4),
            'deploy_timeout': 120,
            'pod_termination_grace_period_seconds': 2,
            'image': 'quay.io/fake/image',
            'entrypoint': 'sh',
            'command': 'start',
        }

        self.scheduler.scale_rc(namespace, name, **kwargs)
        return name

    def test_create_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create ReplicationController doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.create('doesnotexist', 'doesnotexist')

    def test_create(self):
        self.create()

    def test_update_rc_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update ReplicationController foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.rc.update(self.namespace, 'foo', {})

    def test_update(self):
        # test success
        name = self.create()
        rc = self.scheduler.rc.get(self.namespace, name).json()
        self.assertEqual(rc['spec']['replicas'], 4, rc)

        rc['spec']['replicas'] = 2
        response = self.scheduler.rc.update(self.namespace, name, rc)
        self.assertEqual(response.status_code, 200, response.json())

        rc = self.scheduler.rc.get(self.namespace, name).json()
        self.assertEqual(rc['spec']['replicas'], 2, rc)

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete ReplicationController foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.rc.delete(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.rc.delete(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_rcs(self):
        # test success
        name = self.create()
        response = self.scheduler.rc.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name)

    def test_get_rc_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get ReplicationController doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.rc.get(self.namespace, 'doesnotexist')

    def test_get_rc(self):
        # test success
        name = self.create()
        response = self.scheduler.rc.get(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'ReplicationController')
        self.assertEqual(data['metadata']['name'], name)
        self.assertDictContainsSubset(
            {
                'app': self.namespace,
                'heritage': 'deis'
            },
            data['metadata']['labels']
        )
