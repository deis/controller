"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase
from scheduler.utils import generate_random_name


class HorizontalPodAutoscalersTest(TestCase):
    """Tests scheduler horizontalpodautoscaler calls"""

    def create(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to create and verify a horizontalpodautoscaler on the namespace

        Creates a Deployment so that HPA can work off an object
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'replicas': kwargs.get('replicas', 1),
        }

        # create a Deployment to test HPA with
        deployment = self.scheduler.deployment.create(namespace, name, 'quay.io/fake/image',
                                                      'sh', 'start', **kwargs)
        self.assertEqual(deployment.status_code, 201, deployment.json())

        # create HPA referencing the Deployment above
        kwargs = {
            'min': 2,
            'max': 4,
            'cpu_percent': 45,
            'wait': True
        }
        horizontalpodautoscaler = self.scheduler.hpa.create(namespace, name, deployment.json(), **kwargs)  # noqa
        self.assertEqual(horizontalpodautoscaler.status_code, 201, horizontalpodautoscaler.json())  # noqa
        return name

    def update(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to update and verify a horizontalpodautoscaler on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        deployment = self.scheduler.deployment.get(namespace, name)

        kwargs = {
            'min': kwargs.get('replicas'),
            'max': 4,
            'cpu_percent': 45,
            'wait': True
        }
        horizontalpodautoscaler = self.scheduler.hpa.update(namespace, name, deployment.json(), **kwargs)  # noqa
        self.assertEqual(horizontalpodautoscaler.status_code, 200, horizontalpodautoscaler.json())  # noqa
        return name

    def update_deployment(self, namespace=None, name=generate_random_name(), **kwargs):
        """
        Helper function to update and verify a deployment on the namespace
        """
        namespace = self.namespace if namespace is None else namespace
        # these are all required even if it is kwargs...
        kwargs = {
            'app_type': kwargs.get('app_type', 'web'),
            'version': kwargs.get('version', 'v99'),
            'replicas': kwargs.get('replicas', 4),
        }

        deployment = self.scheduler.deployment.update(namespace, name, 'quay.io/fake/image',
                                                      'sh', 'start', **kwargs)
        data = deployment.json()
        self.assertEqual(deployment.status_code, 200, data)
        return name

    def test_create_failure(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create HorizontalPodAutoscaler doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.create('doesnotexist', 'doesnotexist')

    def test_create(self):
        name = self.create()

        # check the deployment object
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 2, deployment)

        # make sure HPA kicked things from 1 (set by Deployments) to 2 (HPA min)
        labels = {'app': self.namespace, 'type': 'web', 'version': 'v99'}
        pods = self.scheduler.pod.get(self.namespace, labels=labels).json()
        self.assertEqual(len(pods['items']), 2)

    def test_update_horizontalpodautoscaler_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to update HorizontalPodAutoscaler foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.update(self.namespace, 'foo')

    def test_update(self):
        # test success
        name = self.create()

        # check the deployment object
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 2, deployment)

        # make sure HPA kicked things from 1 (set by Deployments) to 2 (HPA min)
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['status']['availableReplicas'], 2)

        # update HPA to 3 replicas minimum
        self.update(self.namespace, name, replicas=3)

        # check the deployment object
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 3, deployment)

        # make sure HPA kicked things from 1 (set by Deployments) to 3 (HPA min)
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['status']['availableReplicas'], 3)

        # scale deployment to 1 (should go back to 3)
        self.update_deployment(self.namespace, name, replicas=1)

        # check the deployment object
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 3, deployment)

        # make sure HPA kicked things from 1 (set by Deployments) to 3 (HPA min)
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['status']['availableReplicas'], 3)

        # scale deployment to 6 (should go back to 4)
        self.update_deployment(self.namespace, name, replicas=6)

        # check the deployment object
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['spec']['replicas'], 4, deployment)

        # make sure HPA kicked things from 6 (set by Deployments) to 4 (HPA min)
        deployment = self.scheduler.deployment.get(self.namespace, name).json()
        self.assertEqual(deployment['status']['availableReplicas'], 4)

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete HorizontalPodAutoscaler foo in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.hpa.delete(self.namespace, 'foo')

    def test_delete(self):
        # test success
        name = self.create()
        response = self.scheduler.hpa.delete(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)

    def test_get_horizontalpodautoscalers(self):
        # test success
        name = self.create()
        response = self.scheduler.hpa.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        self.assertEqual(1, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], name, data)

    def test_get_horizontalpodautoscaler_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get HorizontalPodAutoscaler doesnotexist in Namespace {}: 404 Not Found'.format(self.namespace)  # noqa
        ):
            self.scheduler.hpa.get(self.namespace, 'doesnotexist')

    def test_get_horizontalpodautoscaler(self):
        # test success
        name = self.create()
        response = self.scheduler.hpa.get(self.namespace, name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        if self.scheduler.version() < 1.3:
            self.assertEqual(data['apiVersion'], 'extensions/v1beta1')
        else:
            self.assertEqual(data['apiVersion'], 'autoscaling/v1')
        self.assertEqual(data['kind'], 'HorizontalPodAutoscaler')
        self.assertEqual(data['metadata']['name'], name)
        self.assertDictContainsSubset(
            {
                'app': self.namespace,
                'heritage': 'deis'
            },
            data['metadata']['labels']
        )
