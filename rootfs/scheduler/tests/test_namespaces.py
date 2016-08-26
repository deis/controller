"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler import KubeHTTPException
from scheduler.tests import TestCase


class NamespacesTest(TestCase):
    """Tests scheduler namespace calls"""

    def test_create_namespace(self):
        # subclassed function does all the checking
        self.create_namespace()

    def test_get_namespaces(self):
        response = self.scheduler.ns.get()
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertIn('items', data)
        # mock scheduler already creates deis and duplicate
        self.assertEqual(3, len(data['items']), data['items'])
        # simple verify of data
        self.assertEqual(data['items'][2]['metadata']['name'], self.namespace)

    def test_get_namespace(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to get Namespace doesnotexist: 404 Not Found'
        ):
            self.scheduler.node.get('doesnotexist')

        response = self.scheduler.ns.get(self.namespace)
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['apiVersion'], 'v1')
        self.assertEqual(data['kind'], 'Namespace')
        self.assertDictContainsSubset(
            {
                'name': self.namespace,
                'labels': {
                    'heritage': 'deis'
                }
            },
            data['metadata']
        )

    def test_delete_failure(self):
        # test failure
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to delete Namespace doesnotexist: 404 Not Found'
        ):
            self.scheduler.ns.delete('doesnotexist')

    def test_delete_namespace(self):
        response = self.scheduler.ns.delete(self.namespace)
        self.assertEqual(response.status_code, 200, response.json())
