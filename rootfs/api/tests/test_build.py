"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""


import json

from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.test import APITransactionTestCase
from unittest import mock
from rest_framework.authtoken.models import Token

from api.models import Build

from . import adapter
import requests_mock


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
class BuildTest(APITransactionTestCase):

    """Tests build notification from build system"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_build(self, mock_requests):
        """
        Test that a null build is created and that users can post new builds
        """
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # check to see that no initial build was created
        url = "/v2/apps/{app_id}/builds".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 0)
        # post a new build
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        build_id = str(response.data['uuid'])
        build1 = response.data
        self.assertEqual(response.data['image'], body['image'])
        # read the build
        url = "/v2/apps/{app_id}/builds/{build_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        build2 = response.data
        self.assertEqual(build1, build2)
        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        self.assertIn('deis-release', response._headers)
        build3 = response.data
        self.assertEqual(response.data['image'], body['image'])
        self.assertNotEqual(build2['uuid'], build3['uuid'])
        # disallow put/patch/delete
        response = self.client.put(url)
        self.assertEqual(response.status_code, 405)
        response = self.client.patch(url)
        self.assertEqual(response.status_code, 405)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 405)

    def test_response_data(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        body = {'id': 'test'}
        url = '/v2/apps'
        response = self.client.post(url, body)
        # post an image as a build
        url = "/v2/apps/test/builds".format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)

        for key in response.data:
            self.assertIn(key, ['uuid', 'owner', 'created', 'updated', 'app', 'dockerfile',
                                'image', 'procfile', 'sha'])
        expected = {
            'owner': self.user.username,
            'app': 'test',
            'dockerfile': '',
            'image': 'autotest/example',
            'procfile': {},
            'sha': ''
        }
        self.assertDictContainsSubset(expected, response.data)

    def test_build_default_containers(self, mock_requests):
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # post an image as a build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        url = "/v2/apps/{app_id}/pods/cmd".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'cmd')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-v2-cmd-[a-z0-9]{5}')

        # start with a new app
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # post a new build with procfile
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example',
                'sha': 'a'*40,
                'dockerfile': "FROM scratch"}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        url = "/v2/apps/{app_id}/pods/cmd".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'cmd')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-v2-cmd-[a-z0-9]{5}')

        # start with a new app
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']

        # post a new build with procfile
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example',
                'sha': 'a'*40,
                'dockerfile': "FROM scratch",
                'procfile': {'worker': 'node worker.js'}}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        url = "/v2/apps/{app_id}/pods/cmd".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'cmd')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-v2-cmd-[a-z0-9]{5}')

        # start with a new app
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # post a new build with procfile

        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example',
                'sha': 'a'*40,
                'procfile': json.dumps({'web': 'node server.js',
                                        'worker': 'node worker.js'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        url = "/v2/apps/{app_id}/pods/web".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        container = response.data['results'][0]
        self.assertEqual(container['type'], 'web')
        self.assertEqual(container['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(container['name'], app_id + '-v2-web-[a-z0-9]{5}')

    def test_build_str(self, mock_requests):
        """Test the text representation of a build."""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        build = Build.objects.get(uuid=response.data['uuid'])
        self.assertEqual(str(build), "{}-{}".format(
                         response.data['app'], str(response.data['uuid'])[:7]))

    def test_admin_can_create_builds_on_other_apps(self, mock_requests):
        """If a user creates an application, an administrator should be able
        to push builds.
        """
        # create app as non-admin
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']

        # post a new build as admin
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        build = Build.objects.get(uuid=response.data['uuid'])
        self.assertEqual(str(build), "{}-{}".format(
                         response.data['app'], str(response.data['uuid'])[:7]))

    def test_unauthorized_user_cannot_modify_build(self, mock_requests):
        """
        An unauthorized user should not be able to modify other builds.

        Since an unauthorized user can't access the application, these
        requests should return a 403.
        """
        app_id = 'autotest'
        url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(url, body)

        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = Token.objects.get(user=unauthorized_user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)
        url = '{}/{}/builds'.format(url, app_id)
        body = {'image': 'foo'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

    def test_new_build_does_not_scale_up_automatically(self, mock_requests):
        """
        After the first initial deploy, if the containers are scaled down to zero,
        they should stay that way on a new release.
        """
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': json.dumps({
                'web': 'node server.js',
                'worker': 'node worker.js'
            })
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        url = "/v2/apps/{app_id}/pods/web".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)

        # scale to zero
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 0}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204)

        # post another build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': json.dumps({
                'web': 'node server.js',
                'worker': 'node worker.js'
            })
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        url = "/v2/apps/{app_id}/pods/web".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 0)
