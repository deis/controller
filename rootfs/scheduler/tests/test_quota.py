"""
Unit tests for the Deis scheduler module.

Run the tests with './manage.py test scheduler'
"""
from scheduler.tests import TestCase
from scheduler import KubeHTTPException


class QuotaTest(TestCase):

    def test_create_quota(self):
        namespace_name = self.create_namespace()
        quota = {
            'spec': {
                'hard': {
                    'cpu': '3',
                    'pods': '10',
                    'secrets': '5'
                }
            }
        }
        self.scheduler.quota.create(namespace_name, 'test1', data=quota)

        response = self.scheduler.quota.get(namespace_name, 'test1')
        data = response.json()
        self.assertEqual(data.get('spec', {}), quota['spec'])
        self.assertEqual(data['metadata']['namespace'], namespace_name)

    def test_create_with_nonexistent_namespace(self):
        with self.assertRaises(
            KubeHTTPException,
            msg='failed to create quota test1 for namespace ghost-namespace: 404 Not Found'
        ):
            self.scheduler.quota.create('ghost-namespace', 'test1', data={})
