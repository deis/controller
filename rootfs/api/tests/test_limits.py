import json
import requests_mock

from django.core.cache import cache
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from api.serializers import MEMLIMIT_MATCH
from api.serializers import CPUSHARE_MATCH
from api.tests import adapter, DeisTransactionTestCase


@requests_mock.Mocker(real_http=True, adapter=adapter)
class TestLimits(DeisTransactionTestCase):
    """Tests setting and updating config values"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_memlimit_regex(self, mock_requests):
        """Tests the regex for unit format used by "deis limits:set --memory=<limit>"."""
        self.assertTrue(MEMLIMIT_MATCH.match("0/100MB"))
        self.assertTrue(MEMLIMIT_MATCH.match("200GB/100MB"))
        self.assertTrue(MEMLIMIT_MATCH.match("20MB"))
        self.assertTrue(MEMLIMIT_MATCH.match("20gb"))
        self.assertTrue(MEMLIMIT_MATCH.match("0m"))
        self.assertFalse(MEMLIMIT_MATCH.match("20MK"))
        self.assertFalse(MEMLIMIT_MATCH.match("10"))
        self.assertFalse(MEMLIMIT_MATCH.match("20gK"))
        self.assertFalse(MEMLIMIT_MATCH.match("mb"))

    def test_cpushare_regex(self, mock_requests):
        """Tests the regex for unit format used by "deis limits:set --cpu=<limit>"."""
        self.assertTrue(CPUSHARE_MATCH.match("0/2"))
        self.assertTrue(CPUSHARE_MATCH.match("500m/600m"))
        self.assertTrue(CPUSHARE_MATCH.match("0.5"))
        self.assertTrue(CPUSHARE_MATCH.match(".123"))
        self.assertTrue(CPUSHARE_MATCH.match("1.123"))
        self.assertTrue(CPUSHARE_MATCH.match("200m"))
        self.assertTrue(CPUSHARE_MATCH.match("0"))
        self.assertFalse(CPUSHARE_MATCH.match("20MK"))
        self.assertFalse(CPUSHARE_MATCH.match("20gK"))
        self.assertFalse(CPUSHARE_MATCH.match("m"))
        self.assertFalse(CPUSHARE_MATCH.match("."))

    def test_request_limit_memory(self, mock_requests):
        """
        Test that limit is auto-created for a new app and that
        limits can be updated using a PATCH
        """
        app_id = self.create_app()
        url = '/v2/apps/{app_id}/config'.format(**locals())

        # check default limit
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('memory', response.data)
        self.assertEqual(response.data['memory'], {})
        # regression test for https://github.com/deis/deis/issues/1563
        self.assertNotIn('"', response.data['memory'])

        # set an initial limit
        mem = {'web': '1G'}
        body = {'memory': json.dumps(mem)}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        limit1 = response.data

        # check memory limits
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('memory', response.data)
        memory = response.data['memory']
        self.assertIn('web', memory)
        self.assertEqual(memory['web'], '1G')

        # set an additional value
        body = {'memory': json.dumps({'worker': '512M'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        limit2 = response.data
        self.assertNotEqual(limit1['uuid'], limit2['uuid'])
        memory = response.data['memory']
        self.assertIn('worker', memory)
        self.assertEqual(memory['worker'], '512M')
        self.assertIn('web', memory)
        self.assertEqual(memory['web'], '1G')

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        limit3 = response.data
        self.assertEqual(limit2, limit3)
        memory = response.data['memory']
        self.assertIn('worker', memory)
        self.assertEqual(memory['worker'], '512M')
        self.assertIn('web', memory)
        self.assertEqual(memory['web'], '1G')

        # regression test for https://github.com/deis/deis/issues/1613
        # ensure that config:set doesn't wipe out previous limits
        body = {'values': json.dumps({'NEW_URL2': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL2', response.data['values'])

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        memory = response.data['memory']
        self.assertIn('worker', memory)
        self.assertEqual(memory['worker'], '512M')
        self.assertIn('web', memory)
        self.assertEqual(memory['web'], '1G')

        # add with requests/limits
        body = {'memory': json.dumps({'db': '1G/2G'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        memory = response.data['memory']
        self.assertIn('worker', memory)
        self.assertEqual(memory['worker'], '512M')
        self.assertIn('web', memory)
        self.assertEqual(memory['web'], '1G')
        self.assertIn('db', memory)
        self.assertEqual(memory['db'], '1G/2G')

        # replace one with requests/limits
        body = {'memory': json.dumps({'web': '3G/4G'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        memory = response.data['memory']
        self.assertIn('worker', memory)
        self.assertEqual(memory['worker'], '512M')
        self.assertIn('web', memory)
        self.assertEqual(memory['web'], '3G/4G')
        self.assertIn('db', memory)
        self.assertEqual(memory['db'], '1G/2G')

        # unset a value
        body = {'memory': json.dumps({'worker': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        limit4 = response.data
        self.assertNotEqual(limit3['uuid'], limit4['uuid'])
        self.assertNotIn('worker', json.dumps(response.data['memory']))

        # bad memory values
        mem = {'web': '1Z'}
        body = {'memory': json.dumps(mem)}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        mem = {'w3&b': '1G'}
        body = {'memory': json.dumps(mem)}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        # disallow put/patch/delete
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405, response.data)
        return limit4

    def test_request_limit_cpu(self, mock_requests):
        """
        Test that CPU requests/limits can be set
        """
        app_id = self.create_app()
        url = '/v2/apps/{app_id}/config'.format(**locals())

        # check default limit
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('cpu', response.data)
        self.assertEqual(response.data['cpu'], {})
        # regression test for https://github.com/deis/deis/issues/1563
        self.assertNotIn('"', response.data['cpu'])

        # set an initial limit
        body = {'cpu': json.dumps({'web': '1024'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        limit1 = response.data

        # check cpu limits
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('cpu', response.data)
        cpu = response.data['cpu']
        self.assertIn('web', cpu)
        self.assertEqual(cpu['web'], '1024')

        # set an additional value
        body = {'cpu': json.dumps({'worker': '512m'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        limit2 = response.data
        self.assertNotEqual(limit1['uuid'], limit2['uuid'])
        cpu = response.data['cpu']
        self.assertIn('worker', cpu)
        self.assertEqual(cpu['worker'], '512m')
        self.assertIn('web', cpu)
        self.assertEqual(cpu['web'], '1024')

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        limit3 = response.data
        self.assertEqual(limit2, limit3)
        cpu = response.data['cpu']
        self.assertIn('worker', cpu)
        self.assertEqual(cpu['worker'], '512m')
        self.assertIn('web', cpu)
        self.assertEqual(cpu['web'], '1024')

        # add with requests/limits
        body = {'cpu': json.dumps({'db': '1/2'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        cpu = response.data['cpu']
        self.assertIn('worker', cpu)
        self.assertEqual(cpu['worker'], '512m')
        self.assertIn('web', cpu)
        self.assertEqual(cpu['web'], '1024')
        self.assertIn('db', cpu)
        self.assertEqual(cpu['db'], '1/2')

        # replace one with requests/limits
        body = {'cpu': json.dumps({'web': '300m/4000m'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # read the limit again
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        cpu = response.data['cpu']
        self.assertIn('worker', cpu)
        self.assertEqual(cpu['worker'], '512m')
        self.assertIn('web', cpu)
        self.assertEqual(cpu['web'], '300m/4000m')
        self.assertIn('db', cpu)
        self.assertEqual(cpu['db'], '1/2')

        # unset a value
        body = {'cpu': json.dumps({'worker': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        limit4 = response.data
        self.assertNotEqual(limit3['uuid'], limit4['uuid'])
        self.assertNotIn('worker', json.dumps(response.data['cpu']))

        # bad cpu values
        mem = {'web': '1G'}
        body = {'cpu': json.dumps(mem)}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        mem = {'w3&b': '1G'}
        body = {'cpu': json.dumps(mem)}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        # disallow put/patch/delete
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.data)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405, response.data)
