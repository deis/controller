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

from api.models import App, Release
from scheduler import KubeHTTPException
from . import adapter
from . import mock_port
import requests_mock


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
@mock.patch('api.models.release.docker_get_port', mock_port)
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
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['id']
        # check that updating config rolls a new release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])
        # check to see that an initial release was created
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # account for the config release as well
        self.assertEqual(response.data['count'], 2)
        url = '/v2/apps/{app_id}/releases/v1'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        release1 = response.data
        self.assertIn('config', response.data)
        self.assertIn('build', response.data)
        self.assertEqual(release1['version'], 1)
        # check to see that a new release was created
        url = '/v2/apps/{app_id}/releases/v2'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
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
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])
        # check to see that a new release was created
        url = '/v2/apps/{app_id}/releases/v3'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        release3 = response.data
        self.assertNotEqual(release2['uuid'], release3['uuid'])
        self.assertNotEqual(release2['build'], release3['build'])
        self.assertEqual(release3['version'], 3)
        # check that we can fetch a previous release
        url = '/v2/apps/{app_id}/releases/v2'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        release2 = response.data
        self.assertNotEqual(release2['uuid'], release3['uuid'])
        self.assertNotEqual(release2['build'], release3['build'])
        self.assertEqual(release2['version'], 2)
        # disallow post/put/patch/delete
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405, response.content)
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
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['id']
        app = App.objects.get(id=app_id)
        # try to rollback with only 1 release extant, expecting 400
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'version cannot be below 0'})
        self.assertEqual(response.get('content-type'), 'application/json')
        # update the build to roll a new release
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # update config to roll another release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # create another release with a different build
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        body = {'image': 'autotest/example:canary'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        # rollback and check to see that a 5th release was created
        # with the build and config of release #3
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(Release.objects.count(), 5)
        release1 = Release.objects.get(app=app, version=1)
        release2 = Release.objects.get(app=app, version=2)
        release3 = Release.objects.get(app=app, version=3)
        release4 = Release.objects.get(app=app, version=4)
        release5 = Release.objects.get(app=app, version=5)
        # verify the rollback to v3
        self.assertNotEqual(release5.uuid, release3.uuid)
        self.assertNotEqual(release5.build, release4.build)
        self.assertEqual(release5.build, release3.build)
        self.assertEqual(release5.config.values, release3.config.values)
        # double-check to see that the current build and config is the same as v3
        self.assertEqual(release5.build.image, 'autotest/example')
        self.assertEqual(release5.config.values, {'NEW_URL1': 'http://localhost:8080/'})
        # try to rollback to v1 and verify that the rollback failed
        # (v1 is an initial release with no build)
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        body = {'version': 1}
        response = self.client.post(url, body)
        self.assertContains(response, 'Cannot roll back to initial release.', status_code=400)
        # roll back to v2 so we can verify config gets rolled back too
        url = "/v2/apps/{app_id}/releases/rollback/".format(**locals())
        body = {'version': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(Release.objects.count(), 6)
        release6 = Release.objects.get(app=app, version=6)
        self.assertEqual(release6.build.image, 'autotest/example')
        self.assertEqual(release6.config.values, {})

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
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['id']
        # check that updating config rolls a new release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])
        # check to see that an initial release was created
        url = '/v2/apps/{app_id}/releases'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
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

    def test_release_rollback_failure(self, mock_requests):
        """
        Cause an Exception in app.deploy to cause a release.delete
        """
        body = {'id': 'test'}
        self.client.post('/v2/apps', body)

        # deploy app to get a build
        url = "/v2/apps/test/builds"
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        # update config to roll a new release
        url = '/v2/apps/test/config'
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # update config to roll a new release
        url = '/v2/apps/test/config'
        body = {'values': json.dumps({'NEW_URL2': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # app.deploy exception
        with mock.patch('api.models.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            url = "/v2/apps/test/releases/rollback/"
            body = {'version': 2}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 400, response.data)

        # app.deploy exception followed by a KubeHTTPException of 404
        with mock.patch('api.models.App.deploy') as mock_deploy:
            mock_deploy.side_effect = Exception('Boom!')
            with mock.patch('api.models.Release._delete_release_in_scheduler') as mock_kube:
                # instead of full request mocking, fake it out in a simple way
                class Response(object):
                    def json(self):
                        return '{}'

                response = Response()
                response.status_code = 404
                response.reason = "Not Found"
                kube_exception = KubeHTTPException(response, 'big boom')
                mock_kube.side_effect = kube_exception

                url = "/v2/apps/test/releases/rollback/"
                body = {'version': 2}
                response = self.client.post(url, body)
                self.assertEqual(response.status_code, 400, response.data)

    def test_release_unset_config(self, mock_requests):
        """
        Test that a release is created when an app is created, a config can be
        set and then unset without causing a 409 (conflict)
        """
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['id']

        # check that updating config rolls a new release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'cpu': json.dumps({'cmd': None})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 422, response.data)

    def test_release_no_change(self, mock_requests):
        """
        Test that a release is created when an app is created, and
        then has 2 identical config set, causing a 409 as there was
        no change
        """
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['id']

        # check that updating config rolls a new release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('NEW_URL1', response.data['values'])

        # trigger identical release
        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'NEW_URL1': 'http://localhost:8080/'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 409, response.data)

    def test_release_get_port(self, mock_requests):
        """
        Test that get_port always returns the proper value.
        """
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201, response.data)
        app_id = response.data['id']
        app = App.objects.get(id=app_id)

        url = '/v2/apps/{app_id}/builds'.format(**locals())
        body = {'sha': '123456', 'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()

        # when app is not routable, returns None
        self.assertEqual(release.get_port(), None)

        # when a buildpack type, default to 5000
        self.assertEqual(release.get_port(routable=True), 5000)

        # switch to a dockerfile app or else it'll automatically default to 5000
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        url = '/v2/apps/{app_id}/config'.format(**locals())
        body = {'values': json.dumps({'PORT': '8080'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        release = app.release_set.latest()

        # check that the port number returned is an int, not a string
        self.assertEqual(release.get_port(routable=True), 8080)

        # TODO(bacongobbler): test dockerfile ports
