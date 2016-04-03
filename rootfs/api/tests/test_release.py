"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""


import json
import uuid

from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.test import APITransactionTestCase
from unittest import mock
from rest_framework.authtoken.models import Token

from api.models import Release
from . import adapter
import requests_mock


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
class ReleaseTest(APITransactionTestCase):

    """Tests push notification from build system"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_release(self, mock_requests):
        """
        Test that a release is created when an app is created, and
        that updating config or build or triggers a new release
        """
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # check that updating config rolls a new release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        self.assertIn('NEW_URL1', response.data['values'])
        # check to see that an initial release was created
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        # account for the config release as well
        self.assertEqual(response.data['count'], 2)
        url = '/v2/apps/{app_id}/releases/v1'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release1 = response.data
        self.assertIn('config', response.data)
        self.assertIn('build', response.data)
        self.assertEqual(release1['version'], 1)
        # check to see that a new release was created
        url = '/v2/apps/{app_id}/releases/v2'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release2 = response.data
        self.assertNotEqual(release1['uuid'], release2['uuid'])
        self.assertNotEqual(release1['config'], release2['config'])
        self.assertEqual(release1['build'], release2['build'])
        self.assertEqual(release2['version'], 2)
        # check that updating the build rolls a new release
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        build_config = json.dumps({'PATH': 'bin:/usr/local/bin:/usr/bin:/bin'})
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['image'], body['image'])
        # check to see that a new release was created
        url = '/v2/apps/{app_id}/releases/v3'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release3 = response.data
        self.assertNotEqual(release2['uuid'], release3['uuid'])
        self.assertNotEqual(release2['build'], release3['build'])
        self.assertEqual(release3['version'], 3)
        # check that we can fetch a previous release
        url = '/v2/apps/{app_id}/releases/v2'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release2 = response.data
        self.assertNotEqual(release2['uuid'], release3['uuid'])
        self.assertNotEqual(release2['build'], release3['build'])
        self.assertEqual(release2['version'], 2)
        # disallow post/put/patch/delete
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 405)
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405)
        return release3

    def test_response_data(self, mock_requests):
        body = {'id': 'test'}
        response = self.client.post('/v2/apps', body,)
        body = {'values': json.dumps({'NEW_URL': 'http://localhost:8080/'})}
        config_response = self.client.post('/v2/apps/test/config', body)
        url = '/v2/apps/test/releases/v2'
        response = self.client.get(url)
        for key in response.data.keys():
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'build', 'config',
                                'summary', 'version'])
        expected = {
            'owner': self.user.username,
            'app': 'test',
            'build': None,
            'config': uuid.UUID(config_response.data['uuid']),
            'summary': '{} added NEW_URL'.format(self.user.username),
            'version': 2
        }
        self.assertDictContainsSubset(expected, response.data)

    def test_release_rollback(self, mock_requests):
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # try to rollback with only 1 release extant, expecting 400
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, {'detail': 'version cannot be below 0'})
        self.assertEqual(response.get('content-type'), 'application/json')
        # update config to roll a new release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        #  todo : edge case that fails becasue version 1 has no build object.
        # update the build to roll a new release
        # url = '/v2/apps/{app_id}/builds'.format(**locals())
        # body = {'image': 'autotest/example'}
        # response = self.client.post(url, body)
        # self.assertEqual(response.status_code, 201)
        # rollback and check to see that a 4th release was created
        # with the build and config of release #2
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 3)
        url = '/v2/apps/{app_id}/releases/v1'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release1 = response.data
        self.assertEqual(release1['version'], 1)
        url = '/v2/apps/{app_id}/releases/v3'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release3 = response.data
        self.assertEqual(release3['version'], 3)
        self.assertNotEqual(release1['uuid'], release3['uuid'])
        self.assertEqual(release1['build'], release3['build'])
        self.assertEqual(release1['config'], release3['config'])
        # rollback explicitly to release #1 and check that a 5th release
        # was created with the build and config of release #1
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        body = {'version': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 4)
        url = '/v2/apps/{app_id}/releases/v1'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release1 = response.data
        url = '/v2/apps/{app_id}/releases/v4'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        release4 = response.data
        self.assertEqual(release4['version'], 4)
        self.assertNotEqual(release1['uuid'], release4['uuid'])
        self.assertEqual(release1['build'], release4['build'])
        self.assertEqual(release1['config'], release4['config'])
        # check to see that the current config is actually the initial one
        url = "/v2/apps/{app_id}/config".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['values'], {})
        # rollback to #2 and see that it has the correct config
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        body = {'version': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        url = "/v2/apps/{app_id}/config".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        values = response.data['values']
        self.assertIn('NEW_URL1', values)
        self.assertEqual('http://localhost:8080/', values['NEW_URL1'])

    def test_release_str(self, mock_requests):
        """Test the text representation of a release."""
        release3 = self.test_release()
        release = Release.objects.get(uuid=release3['uuid'])
        self.assertEqual(str(release), "{}-v3".format(release3['app']))

    def test_release_summary(self, mock_requests):
        """Test the text summary of a release."""
        release3 = self.test_release()
        release = Release.objects.get(uuid=release3['uuid'])
        # check that the release has push and env change messages
        self.assertIn('autotest deployed ', release.summary)

    def test_admin_can_create_release(self, mock_requests):
        """If a non-user creates an app, an admin should be able to create releases."""
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        url = '/v2/apps'
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # check that updating config rolls a new release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        self.assertIn('NEW_URL1', response.data['values'])
        # check to see that an initial release was created
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        # account for the config release as well
        self.assertEqual(response.data['count'], 2)

    def test_unauthorized_user_cannot_modify_release(self, mock_requests):
        """
        An unauthorized user should not be able to modify other releases.

        Since an unauthorized user should not know about the application at all, these
        requests should return a 404.
        """
        app_id = 'autotest'
        base_url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(base_url, body)

        # push a new build
        url = '{base_url}/{app_id}/builds'.format(**locals())
        body = {'image': 'test'}
        response = self.client.post(url, body)

        # update config to roll a new release
        url = '{base_url}/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = Token.objects.get(user=unauthorized_user).key

        # try to rollback
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)
        url = '{base_url}/{app_id}/releases/rollback/'.format(**locals())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 403)
