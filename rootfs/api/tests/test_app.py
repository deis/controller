"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
import logging
from unittest import mock
import random
import requests

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from api.models import App
from scheduler import KubeException

from api.tests import adapter, mock_port, DeisTestCase
import requests_mock


def mock_none(*args, **kwargs):
    return None


def _mock_run(*args, **kwargs):
    return [0, 'mock']


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
@mock.patch('api.models.release.docker_get_port', mock_port)
class AppTest(DeisTestCase):
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
        app_id = self.create_app()

        response = self.client.get('/v2/apps')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        url = '/v2/apps/{app_id}'.format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        body = {'id': 'new'}
        response = self.client.patch(url, body)
        self.assertEqual(response.status_code, 405, response.content)

        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

    def test_response_data(self, mock_requests):
        """Test that the serialized response contains only relevant data."""
        body = {'id': 'app-{}'.format(random.randrange(1000, 10000))}
        response = self.client.post('/v2/apps', body)
        for key in response.data:
            self.assertIn(key, ['uuid', 'created', 'updated', 'id', 'owner', 'structure'])
        expected = {
            'id': body['id'],
            'owner': self.user.username,
            'structure': {}
        }
        self.assertDictContainsSubset(expected, response.data)

    def test_app_override_id(self, mock_requests):
        app_id = self.create_app()

        response = self.client.post('/v2/apps', {'id': app_id})
        self.assertContains(response, 'Application with this id already exists.', status_code=400)

    @mock.patch('requests.get')
    def test_app_actions(self, mock_requests, mock_get):
        app_id = self.create_app()

        # test logs - 204 from deis-logger
        mock_response = mock.Mock()
        mock_response.status_code = 204
        mock_get.return_value = mock_response
        url = "/v2/apps/{app_id}/logs".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 204, response.content)

        # test logs - 404 from deis-logger
        mock_response.status_code = 404
        response = self.client.get(url)
        self.assertEqual(response.status_code, 204, response.content)

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
        self.create_app()

        # check app logs
        exp_msg = "autotest created initial release"
        exp_log_call = mock.call(logging.INFO, exp_msg)
        mock_logger.log.has_calls(exp_log_call)

    def test_app_errors(self, mock_requests):
        response = self.client.post('/v2/apps', {'id': 'camelCase'})
        self.assertContains(
            response,
            'App name can only contain a-z (lowercase), 0-9 and hyphens',
            status_code=400
        )

        app_id = self.create_app()
        url = '/v2/apps/{app_id}'.format(**locals())
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)
        for endpoint in ('containers', 'config', 'releases', 'builds'):
            url = '/v2/apps/{app_id}/{endpoint}'.format(**locals())
            response = self.client.get(url)
            self.assertEqual(response.status_code, 404)

    def test_app_reserved_names(self, mock_requests):
        """Nobody should be able to create applications with names which are reserved."""
        reserved_names = ['foo', 'bar']
        with self.settings(DEIS_RESERVED_NAMES=reserved_names):
            for name in reserved_names:
                response = self.client.post('/v2/apps', {'id': name})
                self.assertContains(
                    response,
                    '{} is a reserved name.'.format(name),
                    status_code=400)

    def test_app_structure_is_valid_json(self, mock_requests):
        """Application structures should be valid JSON objects."""
        response = self.client.post('/v2/apps')
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn('id', response.data)
        self.assertIn('structure', response.data)
        self.assertEqual(response.data['structure'], {})
        app_id = response.data['id']
        app = App.objects.get(id=app_id)
        app.structure = {'web': 1}
        app.save()

        response = self.client.get('/v2/apps/{}'.format(app_id))
        self.assertIn('structure', response.data)
        self.assertEqual(response.data['structure'], {"web": 1})

    @mock.patch('api.models.logger')
    def test_admin_can_manage_other_apps(self, mock_requests, mock_logger):
        """Administrators of Deis should be able to manage all applications.
        """
        # log in as non-admin user and create an app
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        app_id = self.create_app()

        # log in as admin, check to see if they have access
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        url = '/v2/apps/{}'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # check app logs
        exp_msg = "autotest2 created initial release"
        exp_log_call = mock.call(logging.INFO, exp_msg)
        mock_logger.log.has_calls(exp_log_call)

        # TODO: test run needs an initial build
        # delete the app
        url = '/v2/apps/{}'.format(app_id)
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204, response.data)

    def test_admin_can_see_other_apps(self, mock_requests):
        """If a user creates an application, the administrator should be able
        to see it.
        """
        # log in as non-admin user and create an app
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        self.create_app()

        # log in as admin
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        response = self.client.get('/v2/apps')
        self.assertIn('count', response.data)
        self.assertEqual(response.data['count'], 1, response.data)

    def test_run_without_release_should_error(self, mock_requests):
        """
        A user should not be able to run a one-off command unless a release
        is present.
        """
        app_id = self.create_app()
        url = '/v2/apps/{}/run'.format(app_id)
        body = {'command': 'ls -al'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'No build associated with this '
                                                   'release to run this command'})

    @mock.patch('api.models.App.run', _mock_run)
    @mock.patch('api.models.App.deploy', mock_none)
    @mock.patch('api.models.Release.publish', mock_none)
    def test_run(self, mock_requests):
        """
        A user should be able to run a one off command
        """
        app_id = self.create_app()

        # create build
        body = {'image': 'autotest/example'}
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # cannot run command without body
        url = '/v2/apps/{}/run'.format(app_id)
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'command is a required field'})

        # run command
        body = {'command': 'ls -al'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['exit_code'], 0)
        self.assertEqual(response.data['output'], 'mock')

    def test_run_failure(self, mock_requests):
        """Raise a KubeException via scheduler.run"""
        app_id = self.create_app()

        # create build
        body = {'image': 'autotest/example'}
        url = '/v2/apps/{app_id}/builds'.format(**locals())
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        with mock.patch('scheduler.KubeHTTPClient.run') as kube_run:
            kube_run.side_effect = KubeException('boom!')
            # run command
            url = '/v2/apps/{}/run'.format(app_id)
            body = {'command': 'ls -al'}
            response = self.client.post(url, body)
            self.assertEqual(response.status_code, 503, response.data)

    def test_unauthorized_user_cannot_see_app(self, mock_requests):
        """
        An unauthorized user should not be able to access an app's resources.

        Since an unauthorized user can't access the application, these
        tests should return a 403, but currently return a 404. FIXME!
        """
        app_id = self.create_app()
        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = Token.objects.get(user=unauthorized_user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)

        url = '/v2/apps/{}/run'.format(app_id)
        body = {'command': 'foo'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

        url = '/v2/apps/{}/logs'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        url = '/v2/apps/{}'.format(app_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        response = self.client.delete(url)
        self.assertEqual(response.status_code, 403)

    def test_app_info_not_showing_wrong_app(self, mock_requests):
        self.create_app()
        response = self.client.get('/v2/apps/foo')
        self.assertEqual(response.status_code, 404)

    def test_app_transfer(self, mock_requests):
        owner = User.objects.get(username='autotest2')
        owner_token = Token.objects.get(user=owner).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + owner_token)

        app_id = self.create_app()

        # Transfer App
        url = '/v2/apps/{}'.format(app_id)
        new_owner = User.objects.get(username='autotest3')
        new_owner_token = Token.objects.get(user=new_owner).key
        body = {'owner': new_owner.username}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)

        # Original user can no longer access it
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

        # New owner can access it
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + new_owner_token)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['owner'], new_owner.username)

        # Collaborators can't transfer
        body = {'username': owner.username}
        perms_url = url+"/perms/"
        response = self.client.post(perms_url, body)
        self.assertEqual(response.status_code, 201, response.data)

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + owner_token)
        body = {'owner': self.user.username}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

        # Admins can transfer
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        body = {'owner': self.user.username}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
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

    def test_app_create_failure_kubernetes_create(self, mock_requests):
        """
        Create an app but have scheduler.create_service fail with an exception
        """
        with mock.patch('scheduler.KubeHTTPClient.create_service') as mock_kube:
            mock_kube.side_effect = KubeException('Boom!')
            response = self.client.post('/v2/apps')
            self.assertEqual(response.status_code, 503, response.data)

    def test_app_delete_failure_kubernetes_destroy(self, mock_requests):
        """
        Create an app and then delete but have scheduler.delete_namespace
        fail with an exception
        """
        # create
        app_id = self.create_app()

        with mock.patch('scheduler.KubeHTTPClient.delete_namespace') as mock_kube:
            # delete
            mock_kube.side_effect = KubeException('Boom!')
            response = self.client.delete('/v2/apps/{}'.format(app_id))
            self.assertEqual(response.status_code, 503, response.data)

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
        app_id = self.create_app()

        # deploy app to get verification
        url = "/v2/apps/{}/builds".format(app_id)
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
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
        app_id = self.create_app()

        # deploy app to get verification
        url = "/v2/apps/{}/builds".format(app_id)
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
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
        app_id = self.create_app()

        # deploy app to get verification
        url = "/v2/apps/{}/builds".format(app_id)
        body = {'image': 'autotest/example'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        # Called 10 times due to the exception
        self.assertEqual(mr.called, True)
        self.assertEqual(mr.call_count, 10)

    def test_list_ordering(self, mock_requests):
        """
        Test that a list of apps is sorted by name
        """
        for name in ['zulu', 'tango', 'alpha', 'foxtrot']:
            response = self.client.post('/v2/apps', {'id': name})
            self.assertEqual(response.status_code, 201, response.data)

        response = self.client.get('/v2/apps')
        apps = response.data['results']
        self.assertEqual(apps[0]['id'], 'alpha')
        self.assertEqual(apps[1]['id'], 'foxtrot')
        self.assertEqual(apps[2]['id'], 'tango')
        self.assertEqual(apps[3]['id'], 'zulu')


FAKE_LOG_DATA = """
2013-08-15 12:41:25 [33454] [INFO] Starting gunicorn 17.5
2013-08-15 12:41:25 [33454] [INFO] Listening at: http://0.0.0.0:5000 (33454)
2013-08-15 12:41:25 [33454] [INFO] Using worker: sync
2013-08-15 12:41:25 [33457] [INFO] Booting worker with pid 33457
"""
