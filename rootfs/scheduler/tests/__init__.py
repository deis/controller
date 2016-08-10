from django.core.cache import cache
from django.test import TestCase as DjangoTestCase

from scheduler import mock
from scheduler.utils import generate_random_name


class TestCase(DjangoTestCase):
    def setUp(self):
        self.scheduler = mock.MockSchedulerClient()
        # have a namespace available at all times
        self.namespace = self.create_namespace()

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def create_namespace(self):
        namespace = generate_random_name()
        response = self.scheduler.create_namespace(namespace)
        self.assertEqual(response.status_code, 201, response.json())
        # assert minimal amount data
        data = response.json()
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'Namespace')
        self.assertDictContainsSubset(
            {
                'name': namespace,
                'labels': {
                    'heritage': 'deis'
                }
            },
            data['metadata']
        )

        return namespace
