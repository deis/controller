"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from unittest import mock
from datetime import datetime, timedelta
from scheduler import KubeHTTPException, KubeException
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

    def test_liveness_status(self):
        # Missing Ready type means pod has passed liveness check
        pod = {'status': {'conditions': []}}
        self.assertTrue(self.scheduler.pod.liveness_status(pod))

        # fake out a minimal pod structure for success
        pod['status']['conditions'].append({
            'type': 'Ready',
            'status': 'True'
        })
        self.assertTrue(self.scheduler.pod.liveness_status(pod))

        # fake out a minimal pod structure for failure
        pod['status']['conditions'][0]['status'] = 'False'
        self.assertFalse(self.scheduler.pod.liveness_status(pod))

    def test_readiness_status(self):
        # create a pod to then manipulate
        name = self.create()
        pod = self.scheduler.pod.get(self.namespace, name).json()

        # on a newly created pod has an overall "Running" status with ready state on a container
        self.assertEqual(self.scheduler.pod.readiness_status(pod), 'Running')

        # on a newly created pod has been deleted with ready state on a container
        pod['metadata']['deletionTimestamp'] = 'fake'
        self.assertEqual(self.scheduler.pod.readiness_status(pod), 'Terminating')
        del pod['metadata']['deletionTimestamp']

        # now say the app container is not Ready
        container = pod['status']['containerStatuses'][0]
        container['ready'] = False

        # state of the container is Starting when container is not ready but says Running
        self.assertTrue('running' in container['state'].keys())
        self.assertEqual(self.scheduler.pod.readiness_status(pod), 'Starting')

        # verify Terminating status
        del container['state']['running']
        container['state']['terminated'] = 'fake'
        self.assertEqual(self.scheduler.pod.readiness_status(pod), 'Terminating')

        # test metdata terminating
        del container['state']['terminated']
        pod['metadata']['deletionTimestamp'] = 'fake'
        self.assertEqual(self.scheduler.pod.readiness_status(pod), 'Terminating')
        del pod['metadata']['deletionTimestamp']

        # inject fake state
        container['state']['random'] = 'fake'
        self.assertEqual(self.scheduler.pod.readiness_status(pod), 'Unknown')

        # no containers around means Unknown
        pod['status']['containerStatuses'] = []
        self.assertEqual(self.scheduler.pod.readiness_status(pod), 'Unknown')

    def test_ready(self):
        # create a pod to then manipulate
        name = self.create()
        pod = self.scheduler.pod.get(self.namespace, name).json()

        # pod itself shouldn't be ready yet
        self.assertFalse(self.scheduler.pod.ready(pod))

        # only pod but no other probe
        pod['status']['phase'] = 'Running'
        # fake out functions for failure
        with mock.patch('scheduler.resources.pod.Pod.readiness_status') as ready:
            ready.return_value = 'Starting'

            # only readiness is ready so overall ready status is False
            self.assertFalse(self.scheduler.pod.ready(pod))

            with mock.patch('scheduler.resources.pod.Pod.liveness_status') as liveness:
                liveness.return_value = False

                # all things have lined up, go time
                self.assertFalse(self.scheduler.pod.ready(pod))

        # fake out other functions since they are tested by themselves
        with mock.patch('scheduler.resources.pod.Pod.readiness_status') as ready:
            ready.return_value = 'Running'
            with mock.patch('scheduler.resources.pod.Pod.liveness_status') as liveness:
                # keep liveness as failing for now
                liveness.return_value = False

                # only readiness is ready so overall ready status is False
                self.assertFalse(self.scheduler.pod.ready(pod))

                # all things have lined up, go time
                liveness.return_value = True
                self.assertTrue(self.scheduler.pod.ready(pod))

    def test_deleted(self):
        # create a pod to then manipulate
        name = self.create()
        pod = self.scheduler.pod.get(self.namespace, name).json()

        # pod should no be deleted yet
        self.assertFalse(self.scheduler.pod.deleted(pod))

        # set deleted 10 minutes in the past
        ts_deleted = datetime.utcnow() - timedelta(minutes=10)
        pod['metadata']['deletionTimestamp'] = ts_deleted.strftime(self.scheduler.DATETIME_FORMAT)
        self.assertTrue(self.scheduler.pod.deleted(pod))

    def test_limits_failure(self):
        message = generate_random_name()
        self.scheduler.ev.create(self.namespace,
                                 '{}'.format(generate_random_name()),
                                 message, type='Warning')
        with self.assertRaisesRegex(KubeException,
                                    'Message:{}.*'.format(message)):
            self.scheduler.pod._handle_not_ready_pods(self.namespace, {})
