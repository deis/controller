"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
import logging
from unittest import mock
import requests

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token

from api.models import App

from . import adapter
import requests_mock


def mock_none(*args, **kwargs):
    return None


def _mock_run(*args, **kwargs):
    return [0, 'mock']


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
class AppTest(APITestCase):
    """Tests creation of applications"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_app(self, mock_requests):
        """
        Test that a user can create, read, update and delete an application
        """
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']  # noqa
        self.assertIn('id', response.data)
        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        url = '/v2/apps/{app_id}'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        body = {'id': 'new'}
        response = self.client.patch(url, body)
        self.assertEqual(response.status_code, 405)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)

    def test_response_data(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        body = {'id': 'test'}
        response = self.client.post('/v2/apps', body)
        for key in response.data:
            self.assertIn(key, ['uuid', 'created', 'updated', 'id', 'owner', 'structure'])
        expected = {
            'id': 'test',
            'owner': self.user.username,
            'structure': {}
        }
        self.assertDictContainsSubset(expected, response.data)

    def test_app_override_id(self, mock_requests):
        body = {'id': 'myid'}
        response = self.client.post('/v2/apps', body)
        self.assertEqual(response.status_code, 201)
        body = {'id': response.data['id']}
        response = self.client.post('/v2/apps', body)
        self.assertContains(response, 'App with this id already exists.', status_code=400)
        return response

    @mock.patch('requests.get')
    def test_app_actions(self, mock_requests, mock_get):
        url = '/v2/apps'
        body = {'id': 'autotest'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']  # noqa

        # test logs - 204 from deis-logger
        mock_response = mock.Mock()
        mock_response.status_code = 204
        mock_get.return_value = mock_response
        url = "/v2/apps/{app_id}/logs".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 204)

        # test logs - 404 from deis-logger
        mock_response.status_code = 404
        response = self.client.get(url)
        self.assertEqual(response.status_code, 204)

        # test logs - unanticipated status code from deis-logger
        mock_response.status_code = 400
        response = self.client.get(url)
        self.assertContains(
            response,
            "Error accessing logs for {}".format(app_id),
            status_code=500)

        # test logs - success accessing deis-logger
        mock_response.status_code = 200
        mock_response.content = FAKE_LOG_DATA
        response = self.client.get(url)
        self.assertContains(response, FAKE_LOG_DATA, status_code=200)

        # test logs - HTTP request error while accessing deis-logger
        mock_get.side_effect = requests.exceptions.RequestException('Boom!')
        response = self.client.get(url)
        self.assertContains(
            response,
            "Error accessing logs for {}".format(app_id),
            status_code=500)

        # TODO: test run needs an initial build

    @mock.patch('api.models.logger')
    def test_app_release_notes_in_logs(self, mock_requests, mock_logger):
        """Verifies that an app's release summary is dumped into the logs."""
        url = '/v2/apps'
        body = {'id': 'autotest'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        # check app logs
        exp_msg = "autotest created initial release"
        exp_log_call = mock.call(logging.INFO, exp_msg)
        mock_logger.log.has_calls(exp_log_call)

    def test_app_errors(self, mock_requests):
        app_id = 'autotest-errors'
        url = '/v2/apps'
        body = {'id': 'camelCase'}
        response = self.client.post(url, body)
        self.assertContains(
            response,
            'App name can only contain a-z (lowercase), 0-9 and hypens',
            status_code=400
        )
        url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']  # noqa
        url = '/v2/apps/{app_id}'.format(**locals())
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)
        for endpoint in ('containers', 'config', 'releases', 'builds'):
            url = '/v2/apps/{app_id}/{endpoint}'.format(**locals())
            response = self.client.get(url)
            self.assertEqual(response.status_code, 404)

    def test_app_reserved_names(self, mock_requests):
        """Nobody should be able to create applications with names which are reserved."""
        url = '/v2/apps'
        reserved_names = ['foo', 'bar']
        with self.settings(DEIS_RESERVED_NAMES=reserved_names):
            for name in reserved_names:
                body = {'id': name}
                response = self.client.post(url, body)
                self.assertContains(
                    response,
                    '{} is a reserved name.'.format(name),
                    status_code=400)

    def test_app_structure_is_valid_json(self, mock_requests):
        """Application structures should be valid JSON objects."""
        url = '/v2/apps'
        response = self.client.post(url)
        self.assertEqual(response.status_code, 201)
        app_id = response.data['id']
        self.assertIn('structure', response.data)
        self.assertEqual(response.data['structure'], {})
        app = App.objects.get(id=app_id)
        app.structure = {'web': 1}
        app.save()
        url = '/v2/apps/{}'.format(app_id)
        response = self.client.get(url)
        self.assertIn('structure', response.data)
        self.assertEqual(response.data['structure'], {"web": 1})

    @mock.patch('api.models.logger')
    def test_admin_can_manage_other_apps(self, mock_requests, mock_logger):
        """Administrators of Deis should be able to manage all applications.
        """
        # log in as non-admin user and create an app
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        app_id = 'autotest'
        url = '/v2/apps'
        body = {'id': app_id}
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.post(url, body)

        # log in as admin, check to see if they have access
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        url = '/v2/apps/{}'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        # check app logs
        exp_msg = "autotest2 created initial release"
        exp_log_call = mock.call(logging.INFO, exp_msg)
        mock_logger.log.has_calls(exp_log_call)

        # TODO: test run needs an initial build
        # delete the app
        url = '/v2/apps/{}'.format(app_id)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)

    def test_admin_can_see_other_apps(self, mock_requests):
        """If a user creates an application, the administrator should be able
        to see it.
        """
        # log in as non-admin user and create an app
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        app_id = 'autotest'
        url = '/v2/apps'
        body = {'id': app_id}
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.post(url, body)

        # log in as admin
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.get(url)
        self.assertEqual(response.data['count'], 1)

    def test_run_without_release_should_error(self, mock_requests):
        """
        A user should not be able to run a one-off command unless a release
        is present.
        """
        app_id = 'autotest'
        url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(url, body)
        url = '/v2/apps/{}/run'.format(app_id)
        body = {'command': 'ls -al'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, {'detail': 'No build associated with this '
                                                   'release to run this command'})

    @mock.patch('api.models.App.run', _mock_run)
    @mock.patch('api.models.App.deploy', mock_none)
    @mock.patch('api.models.Release.publish', mock_none)
    def test_run(self, mock_requests):
        """
        A user should be able to run a one off command
        """
        app_id = 'autotest'
        url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(url, body)

        # create build
        body = {'image': 'autotest/example'}
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)

        # run command
        url = '/v2/apps/{}/run'.format(app_id)
        body = {'command': 'ls -al'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['rc'], 0)
        self.assertEqual(response.data['output'], 'mock')

    def test_unauthorized_user_cannot_see_app(self, mock_requests):
        """
        An unauthorized user should not be able to access an app's resources.

        Since an unauthorized user can't access the application, these
        tests should return a 403, but currently return a 404. FIXME!
        """
        app_id = 'autotest'
        base_url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(base_url, body)
        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = Token.objects.get(user=unauthorized_user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)

        url = '{}/{}/run'.format(base_url, app_id)
        body = {'command': 'foo'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

        url = '{}/{}/logs'.format(base_url, app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        url = '{}/{}'.format(base_url, app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        response = self.client.delete(url)
        self.assertEqual(response.status_code, 403)

    def test_app_info_not_showing_wrong_app(self, mock_requests):
        app_id = 'autotest'
        base_url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(base_url, body)
        url = '{}/foo'.format(base_url)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_app_transfer(self, mock_requests):
        owner = User.objects.get(username='autotest2')
        owner_token = Token.objects.get(user=owner).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + owner_token)

        app_id = 'autotest'
        base_url = '/v2/apps'
        body = {'id': app_id}
        response = self.client.post(base_url, body)

        # Transfer App
        url = '{}/{}'.format(base_url, app_id)
        new_owner = User.objects.get(username='autotest3')
        new_owner_token = Token.objects.get(user=new_owner).key
        body = {'owner': new_owner.username}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200)

        # Original user can no longer access it
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        # New owner can access it
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + new_owner_token)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['owner'], new_owner.username)

        # Collaborators can't transfer
        body = {'username': owner.username}
        perms_url = url+"/perms/"
        response = self.client.post(perms_url, body)
        self.assertEqual(response.status_code, 201)

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + owner_token)
        body = {'owner': self.user.username}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

        # Admins can transfer
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        body = {'owner': self.user.username}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['owner'], self.user.username)

    def test_app_exists_in_kubernetes(self, mock_requests):
        """
        Create an app that has the same namespace as an existing kubernetes namespace
        """
        body = {'id': 'duplicate'}
        response = self.client.post('/v2/apps', body)
        self.assertContains(
            response,
            'duplicate already exists as a namespace in this kuberenetes setup',
            status_code=409
        )

    def test_app_verify_application_health_success(self, mock_requests):
        """
        Create an application which in turn causes a health check to run against
        the router. Make it succeed on the 6th try
        """
        responses = [
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'OK', 'status_code': 200}
        ]
        hostname = 'http://{}:{}/'.format(settings.ROUTER_HOST, settings.ROUTER_PORT)
        mr = mock_requests.register_uri('GET', hostname, responses)

        # create app
        body = {'id': 'myid'}
        response = self.client.post('/v2/apps', body)
        self.assertEqual(response.status_code, 201)

        # deploy app to get verification
        url = "/v2/apps/myid/builds"
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['image'], body['image'])

        self.assertEqual(mr.called, True)
        self.assertEqual(mr.call_count, 6)

    def test_app_verify_application_health_failure_404(self, mock_requests):
        """
        Create an application which in turn causes a health check to run against
        the router. Make it fail with a 404 after 10 tries
        """
        # function tries to hit router 10 times
        responses = [
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
            {'text': 'Not Found', 'status_code': 404},
        ]
        hostname = 'http://{}:{}/'.format(settings.ROUTER_HOST, settings.ROUTER_PORT)
        mr = mock_requests.register_uri('GET', hostname, responses)

        # create app
        body = {'id': 'myid'}
        response = self.client.post('/v2/apps', body)
        self.assertEqual(response.status_code, 201)

        # deploy app to get verification
        url = "/v2/apps/myid/builds"
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['image'], body['image'])

        self.assertEqual(mr.called, True)
        self.assertEqual(mr.call_count, 10)

    def test_app_verify_application_health_failure_exceptions(self, mock_requests):
        """
        Create an application which in turn causes a health check to run against
        the router. Make it fail with a python-requets exception
        """
        def _raise_exception(request, ctx):
            raise requests.exceptions.RequestException('Boom!')

        # function tries to hit router 10 times
        hostname = 'http://{}:{}/'.format(settings.ROUTER_HOST, settings.ROUTER_PORT)
        mr = mock_requests.register_uri('GET', hostname, text=_raise_exception)

        # create app
        body = {'id': 'myid'}
        response = self.client.post('/v2/apps', body)
        self.assertEqual(response.status_code, 201)

        # deploy app to get verification
        url = "/v2/apps/myid/builds"
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['image'], body['image'])

        # Called 10 times due to the exception
        self.assertEqual(mr.called, True)
        self.assertEqual(mr.call_count, 10)

FAKE_LOG_DATA = """
2013-08-15 12:41:25 [33454] [INFO] Starting gunicorn 17.5
2013-08-15 12:41:25 [33454] [INFO] Listening at: http://0.0.0.0:5000 (33454)
2013-08-15 12:41:25 [33454] [INFO] Using worker: sync
2013-08-15 12:41:25 [33457] [INFO] Booting worker with pid 33457
"""
