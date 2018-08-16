"""
Unit tests for the Deis api app.

Run the tests with "./manage.py test api"
"""
import json

from django.contrib.auth.models import User
from django.core.cache import cache
from unittest import mock
from rest_framework.authtoken.models import Token
from test.support import EnvironmentVarGuard

from api.models import App, Build, Release
from scheduler import KubeException

from api.tests import adapter, mock_port, DeisTransactionTestCase
import requests_mock


@requests_mock.Mocker(real_http=True, adapter=adapter)
@mock.patch('api.models.release.publish_release', lambda *args: None)
@mock.patch('api.models.release.docker_get_port', mock_port)
class PodTest(DeisTransactionTestCase):
    """Tests creation of pods on nodes"""

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = Token.objects.get(user=self.user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_container_api_heroku(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        # test setting one proc type at a time
        body = {'web': 4}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        body = {'worker': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 6)

        url = "/v2/apps/{app_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # ensure the structure field is up-to-date
        self.assertEqual(response.data['structure']['web'], 4)
        self.assertEqual(response.data['structure']['worker'], 2)

        # test listing/retrieving container info
        url = "/v2/apps/{app_id}/pods/web".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['count'], 4)
        self.assertEqual(len(response.data['results']), 4)

        name = response.data['results'][0]['name']
        url = "/v2/apps/{app_id}/pods/web/{name}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['name'], name)

        # scale down
        url = "/v2/apps/{app_id}/scale".format(**locals())
        # test setting two proc types at a time
        body = {'web': 2, 'worker': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 3)

        url = "/v2/apps/{app_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        # ensure the structure field is up-to-date
        self.assertEqual(response.data['structure']['web'], 2)
        self.assertEqual(response.data['structure']['worker'], 1)

        # scale down to 0
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 0, 'worker': 0}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        url = "/v2/apps/{app_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

    def test_container_api_docker(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'dockerfile': "FROM busybox\nCMD /bin/true"
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'cmd': 6}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 6)

        url = "/v2/apps/{app_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        # test listing/retrieving container info
        url = "/v2/apps/{app_id}/pods/cmd".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 6)

        # scale down
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'cmd': 3}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 3)

        url = "/v2/apps/{app_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

        # scale down to 0
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'cmd': 0}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        url = "/v2/apps/{app_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)

    def test_release(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['release'], 'v2')

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        # a web proctype must exist on the second build or else the container will be removed
        body = {
            'image': 'autotest/example',
            'procfile': {
                'web': 'echo hi'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['image'], body['image'])

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['release'], 'v3')

        # post new config
        url = "/v2/apps/{app_id}/config".format(**locals())
        body = {'values': json.dumps({'KEY': 'value'})}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['release'], 'v4')

    def test_container_errors(self, mock_requests):
        app_id = self.create_app()

        # create a release so we can scale
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')
        build = Build.objects.create(owner=user, app=app, image="qwerty")

        # create an initial release
        Release.objects.create(
            version=2,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )

        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 'not_an_int'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': "Invalid scaling format: invalid literal for "
                                                   "int() with base 10: 'not_an_int'"})
        body = {'invalid': 1}
        response = self.client.post(url, body)
        self.assertContains(response, 'Container type invalid', status_code=404)

    def test_container_str(self, mock_requests):
        """Test the text representation of a container."""
        app_id = self.create_app()

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 4, 'worker': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        # should start with zero
        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 6)
        pods = response.data['results']
        for pod in pods:
            self.assertIn(pod['type'], ['web', 'worker'])
            self.assertEqual(pod['release'], 'v2')
            # pod name is auto generated so use regex
            self.assertRegex(pod['name'], app_id + '-(worker|web)-[0-9]{8,10}-[a-z0-9]{5}')

    def test_pod_command_format(self, mock_requests):
        # regression test for https://github.com/deis/deis/pull/1285
        app_id = self.create_app()

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)

        # verify that the app._get_command property got formatted
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        pod = response.data['results'][0]
        self.assertEqual(pod['type'], 'web')
        self.assertEqual(pod['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(pod['name'], app_id + '-web-[0-9]{8,10}-[a-z0-9]{5}')

        # verify commands
        data = App.objects.get(id=app_id)
        self.assertNotIn('{c_type}', data._get_command('web'))

    def test_pod_sidecar_format(self, mock_requests):
        app_id = self.create_app()

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            'sidecarfile': {
                'web': [{'name': 'busybox', 'image': 'busybox:latest'}],
                'worker': [{'name': 'busybox', 'image': 'busybox:latest'}]
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)
        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)

        # verify that the app._get_sidecar property got formatted
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 1)

        pod = response.data['results'][0]
        self.assertEqual(pod['type'], 'web')
        self.assertEqual(pod['release'], 'v2')
        # pod name is auto generated so use regex
        self.assertRegex(pod['name'], app_id + '-web-[0-9]{8,10}-[a-z0-9]{5}')

        # verify sidecars
        data = App.objects.get(id=app_id)
        self.assertEqual([{'name': 'busybox', 'image': 'busybox:latest'}],
                         data._get_sidecars('web'))

    def test_scale_errors(self, mock_requests):
        app_id = self.create_app()

        # should start with zero
        url = "/v2/apps/{app_id}/pods".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data['results']), 0)

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # scale to a negative number
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': -1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {"detail": "Invalid scaling format: "
                                         "['Must be greater than or equal to zero']"})

        # scale to something other than a number
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 'one'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        # scale to something other than a number
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': [1]}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)

        # scale with a non-existent proc type
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'foo': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 404, response.data)

        # scale up to an integer as a sanity check
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 1}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        with mock.patch('scheduler.KubeHTTPClient.scale') as mock_kube:
            mock_kube.side_effect = KubeException('Boom!')
            url = "/v2/apps/{app_id}/scale".format(**locals())
            response = self.client.post(url, {'web': 10})
            self.assertEqual(response.status_code, 503, response.data)

    def test_admin_can_manage_other_pods(self, mock_requests):
        """If a non-admin user creates a container, an administrator should be able to
        manage it.
        """
        user = User.objects.get(username='autotest2')
        token = Token.objects.get(user=user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)

        app_id = self.create_app()

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # login as admin, scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 4, 'worker': 2}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

    def test_scale_without_build_should_error(self, mock_requests):
        """A user should not be able to scale processes unless a build is present."""
        app_id = 'autotest'
        url = '/v2/apps'
        body = {'cluster': 'autotest', 'id': app_id}
        response = self.client.post(url, body)

        url = '/v2/apps/{app_id}/scale'.format(**locals())
        body = {'web': '1'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data, {'detail': 'No build associated with this release'})

    def test_command_good(self, mock_requests):
        """Test the default command for each container workflow"""
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')

        # Heroku Buildpack app
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            sha='african-swallow',
            dockerfile=''
        )

        # create an initial release
        Release.objects.create(
            version=2,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )

        # use `start web` for backwards compatibility with slugrunner
        self.assertEqual(app._get_command('web'), ['start', 'web'])
        self.assertEqual(app._get_command('worker'), ['start', 'worker'])

        # switch to docker image app
        build.sha = ''
        build.save()
        self.assertEqual(app._get_command('web'), ["node server.js"])

        # switch to dockerfile app
        build.sha = 'european-swallow'
        build.dockerfile = 'dockerdockerdocker'
        build.save()
        self.assertEqual(app._get_command('web'), ["node server.js"])
        self.assertEqual(app._get_command('cmd'), [])

        # ensure we can override the cmd process type in a Procfile
        build.procfile['cmd'] = 'node server.js'
        build.save()
        self.assertEqual(app._get_entrypoint('cmd'), [])
        self.assertEqual(app._get_command('cmd'), ["node", "server.js"])
        self.assertEqual(app._get_entrypoint('worker'), ["/bin/bash", "-c"])
        self.assertEqual(app._get_command('worker'), ["node worker.js"])

        # for backwards compatibility if no Procfile is supplied
        build.procfile = {}
        build.save()
        self.assertEqual(app._get_command('worker'), ['start', 'worker'])

    def test_run_command_good(self, mock_requests):
        """Test the run command for each container workflow"""
        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        # dockerfile + procfile worflow
        build = Build.objects.create(
            owner=self.user,
            app=app,
            image="qwerty",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            dockerfile='foo',
            sha='somereallylongsha'
        )

        # create an initial release
        Release.objects.create(
            version=2,
            owner=self.user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )

        # create a run pod
        url = "/v2/apps/{app_id}/run".format(**locals())
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app._get_entrypoint('web'), ['/bin/bash', '-c'])

        # docker image workflow
        build.dockerfile = ''
        build.sha = ''
        build.save()
        url = "/v2/apps/{app_id}/run".format(**locals())
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app._get_entrypoint('cmd'), [])

        # procfile workflow
        build.sha = 'somereallylongsha'
        build.save()
        url = "/v2/apps/{app_id}/run".format(**locals())
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app._get_entrypoint('web'), ['/runner/init'])

    def test_run_not_fail_on_debug(self, mock_requests):
        """
        do a run with DEIS_DEBUG on - https://github.com/deis/controller/issues/583
        """
        env = EnvironmentVarGuard()
        env['DEIS_DEBUG'] = 'true'

        app_id = self.create_app()
        app = App.objects.get(id=app_id)

        # dockerfile + procfile worflow
        build = Build.objects.create(
            owner=self.user,
            app=app,
            image="qwerty",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            dockerfile='foo',
            sha='somereallylongsha'
        )

        # create an initial release
        Release.objects.create(
            version=2,
            owner=self.user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )

        # create a run pod
        url = "/v2/apps/{app_id}/run".format(**locals())
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)
        app = App.objects.get(id=app_id)
        self.assertEqual(app._get_entrypoint('web'), ['/bin/bash', '-c'])

    def test_scaling_does_not_add_run_proctypes_to_structure(self, mock_requests):
        """Test that app info doesn't show transient "run" proctypes."""
        app_id = self.create_app()
        app = App.objects.get(id=app_id)
        user = User.objects.get(username='autotest')

        # dockerfile + procfile worflow
        build = Build.objects.create(
            owner=user,
            app=app,
            image="qwerty",
            procfile={
                'web': 'node server.js',
                'worker': 'node worker.js'
            },
            dockerfile='foo',
            sha='somereallylongsha'
        )

        # create an initial release
        release = Release.objects.create(
            version=2,
            owner=user,
            app=app,
            config=app.config_set.latest(),
            build=build
        )

        # create a run pod
        url = "/v2/apps/{app_id}/run".format(**locals())
        body = {'command': 'echo hi'}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 200, response.data)

        # scale up
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 3}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        # test that "run" proctype isn't in the app info returned
        url = "/v2/apps/{app_id}".format(**locals())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertNotIn('run', response.data['structure'])

    def test_scale_with_unauthorized_user_returns_403(self, mock_requests):
        """An unauthorized user should not be able to access an app's resources.

        If an unauthorized user is trying to scale an app he or she does not have access to, it
        should return a 403.
        """
        app_id = self.create_app()

        # post a new build
        url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {'web': 'node server.js', 'worker': 'node worker.js'}
        }
        response = self.client.post(url, body)
        unauthorized_user = User.objects.get(username='autotest2')
        unauthorized_token = Token.objects.get(user=unauthorized_user).key
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + unauthorized_token)

        # scale up with unauthorized user
        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 4}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 403)

    def test_modified_procfile_from_build_removes_pods(self, mock_requests):
        """
        When a new procfile is posted which removes a certain process type, deis should stop the
        existing pods.
        """
        app_id = self.create_app()

        # post a new build
        build_url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(build_url, body)

        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 4}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(build_url, body)
        self.assertEqual(response.status_code, 201, response.data)

        # make sure no pods are web
        application = App.objects.get(id=app_id)
        pods = application.list_pods(type='web')
        self.assertEqual(len(pods), 0)

    def test_restart_pods(self, mock_requests):
        app_id = self.create_app()

        # post a new build
        build_url = "/v2/apps/{app_id}/builds".format(**locals())
        body = {
            'image': 'autotest/example',
            'sha': 'a'*40,
            'procfile': {
                'web': 'node server.js',
                'worker': 'node worker.js'
            }
        }
        response = self.client.post(build_url, body)

        url = "/v2/apps/{app_id}/scale".format(**locals())
        body = {'web': 4, 'worker': 8}
        response = self.client.post(url, body)
        self.assertEqual(response.status_code, 204, response.data)

        # setup app object
        application = App.objects.get(id=app_id)

        # restart all pods
        response = self.client.post('/v2/apps/{}/pods/restart'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        # Compare restarted pods to all pods
        self.assertEqual(len(response.data), 12)

        # restart only the workers
        response = self.client.post('/v2/apps/{}/pods/worker/restart'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        # Compare restarted pods to only worker pods
        self.assertEqual(len(response.data), 8)

        # restart only the web
        response = self.client.post('/v2/apps/{}/pods/web/restart'.format(app_id))
        self.assertEqual(response.status_code, 200, response.data)
        # Compare restarted pods to only worker pods
        self.assertEqual(len(response.data), 4)

        # restart only one of the web pods
        pods = application.list_pods(type='web')
        self.assertEqual(len(pods), 4)

        pod = pods.pop()
        response = self.client.post('/v2/apps/{}/pods/web/{}/restart'.format(app_id, pod['name']))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['type'], 'web')

        # restart only one web port but using the short name of web-asdfg
        name = 'web-' + pod['name'].split('-').pop()
        response = self.client.post('/v2/apps/{}/pods/web/{}/restart'.format(app_id, name))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['type'], 'web')

    def test_list_pods_failure(self, mock_requests):
        """
        Listing all available pods exceptions
        """

        app_id = self.create_app()

        with mock.patch('scheduler.resources.pod.Pod.get') as kube_pod:
            with mock.patch('scheduler.resources.pod.Pod.get') as kube_pods:
                kube_pod.side_effect = KubeException('boom!')
                kube_pods.side_effect = KubeException('boom!')
                url = "/v2/apps/{app_id}/pods".format(**locals())
                response = self.client.get(url)
                self.assertEqual(response.status_code, 503, response.data)
