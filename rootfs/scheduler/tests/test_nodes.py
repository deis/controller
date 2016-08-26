"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
from scheduler.tests import TestCase
from scheduler import KubeHTTPException


class NodesTest(TestCase):
    """Tests scheduler node calls"""

    def test_get_nodes(self):
        response = self.scheduler.node.get()
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
            self.scheduler.node.get('doesnotexist')

        name = '172.17.8.100'
        response = self.scheduler.node.get(name)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'Node')
        self.assertEqual(data['metadata']['name'], name)
        self.assertDictContainsSubset({'ssd': 'true'}, data['metadata']['labels'])
