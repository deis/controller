"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException, KubeException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class DeploymentsTest(TestCase):
    """Tests scheduler deployment calls"""

    def create(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to create and verify a deployment on the namespace
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

        deployment = self.scheduler.deployment.create(namespace, name, **kwargs)
        self.assertEqual(deployment.status_code, 201, deployment.json())
        return name

    def update(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to update and verify a deployment on the namespace
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

        deployment = self.scheduler.deployment.update(namespace, name, **kwargs)
        data = deployment.json()
        self.assertEqual(deployment.status_code, 200, data)
        return name

    def scale(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to scale and verify a deployment on the namespace
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

        self.scheduler.scale(namespace, name, **kwargs)
        return name

    def test_create_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create Deployment doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.create('doesnotexist', 'doesnotexist')

    def test_create(self):
        self.create()

    def test_update_deployment_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update Deployment foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.update(self.namespace, 'foo')
        name = 'image-pull-failed-test'
        self.create(name=name)
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update Deployment "{}": 503 Network Unreachable'.format(name)
        ):
            self.update(self.namespace, name)

    def test_update(self):
        # test success
        name = self.create()
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 4, deployment)

        # emulate scale without calling scale
        self.update(self.namespace, name, replicas=2)

        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 2, deployment)

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete Deployment foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.deployment.delete(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.deployment.delete(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_deployments(self):
        # test when no deployments exist
        response = self.scheduler.deployment.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(data['items'], None)
        # test success
        name = self.create()
        response = self.scheduler.deployment.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name, data)

    def test_get_deployment_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Deployment doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.deployment.get(self.namespace, 'doesnotexist')

    def test_get_deployment(self):
        # test success
        name = self.create()
        response = self.scheduler.deployment.get(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'extensions/v1beta1')
        self.assertEqual(data['kind'], 'Deployment')
        self.assertEqual(data['metadata']['name'], name)
        self.assertDictContainsSubset(
            {
                'app': self.namespace,
                'heritage': 'deis'
            },
            data['metadata']['labels']
        )

    def test_scale(self):
        name = self.scale()
        data = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(data['kind'], 'Deployment')
        self.assertEqual(data['metadata']['name'], name)

        labels = {'app': self.namespace, 'version': 'v99', 'type': 'web'}
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertEqual(len(pods['items']), 4)

        # scale to 8
        name = self.scale(replicas=8)
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertEqual(len(pods['items']), 8)

        # scale to 3
        name = self.scale(replicas=3)
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertEqual(len(pods['items']), 3)

    def test_get_deployment_replicasets(self):
        """
        Look at ReplicaSets that a Deployment created
        """
        # test success
        deployment = self.create()
        data = self.scheduler.deployment.get(self.namespace, deployment).json()

        response = self.scheduler.rs.get(self.namespace, labels=data['metadata']['labels'])
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['labels']['app'], self.namespace, data)

    def test_get__deployment_replicaset_failure(self):
        """
        Look at ReplicaSets that a Deployment created
        """
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get ReplicaSet doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.rs.get(self.namespace, 'doesnotexist')

    def test_get_deployment_replicaset(self):
        """
        Look at ReplicaSets that a Deployment created
        """
        # test success
        deployment = self.create()
        data = self.scheduler.deployment.get(self.namespace, deployment).json()

        # get all replicasets and fish out the first one to match on
        response = self.scheduler.rs.get(self.namespace, labels=data['metadata']['labels'])
        data = response.json()

        replica_name = data['items'][0]['metadata']['name']
        response = self.scheduler.rs.get(self.namespace, replica_name)
        data = response.json()

        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'extensions/v1beta1', data)
        self.assertEqual(data['kind'], 'ReplicaSet', data)
        self.assertEqual(data['metadata']['name'], replica_name, data)
        self.assertDictContainsSubset(
            {
                'app': self.namespace,
                'heritage': 'deis'
            },
            data['metadata']['labels'],
            data
        )

    def test_check_for_failed_events(self):
        deploy_name = self.create(self.namespace)
        deployment = self.scheduler.deployment.get(self.namespace, deploy_name).json()
        response = self.scheduler.rs.get(self.namespace, labels=deployment['metadata']['labels'])
        rs = response.json()
        involved_object = {
            'involvedObject.kind': 'ReplicaSet',
            'involvedObject.name': rs['items'][0]['metadata']['name'],
            'involvedObject.namespace': self.namespace,
            'involvedObject.uid': rs['items'][0]['metadata']['uid'],
        }
        message = 'Quota exeeded'
        self.scheduler.ev.create(self.namespace,
                                 '{}'.format(generate_random_name()),
                                 message,
                                 type='Warning',
                                 involved_object=involved_object,
                                 reason='FailedCreate')
        with self.assertRaisesRegex(KubeException,
                                    'Message:{}.*'.format(message)):
            self.scheduler.deployment._check_for_failed_events(self.namespace,
                                                               labels=deployment['metadata']['labels'])  # noqa
