"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from django.core.cache import cache
from django.test import TestCase

from scheduler import mock, KubeHTTPException


class NodesTest(TestCase):
    """Tests scheduler node calls"""

    def setUp(self):
        self.scheduler = mock.MockSchedulerClient()

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_get_nodes(self):
        response = self.scheduler.get_nodes()
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        # mock scheduler creates one node
        self.assertEqual(1, len(data['items']))
        # simple verify of data
        self.assertEqual(data['items'][0]['metadata']['name'], '172.17.8.100')

    def test_get_node(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Node doesnotexist in Nodes: 404 Not Found'
        ):
            self.scheduler.get_node('doesnotexist')

        name = '172.17.8.100'
        response = self.scheduler.get_node(name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'Node')
        self.assertEqual(data['metadata']['name'], name)
        self.assertDictContainsSubset({'ssd': 'true'}, data['metadata']['labels'])
