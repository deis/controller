"""
Unit tests for the Deis registry app.

Run the tests with "./manage.py test registry"
"""

import unittest
from unittest import mock

from django.conf import settings
from rest_framework.exceptions import PermissionDenied
from registry import publish_release, get_port, RegistryException
from registry.dockerclient import DockerClient


@mock.patch('docker.Client')
class DockerClientTest(unittest.TestCase):
    """Test that the client makes appropriate Docker engine API calls."""

    def setUp(self):
        settings.REGISTRY_HOST, settings.REGISTRY_PORT = 'localhost', 5000

    def test_get_port(self, mock_client):
        self.client = DockerClient()

        # Make sure login is not called when there are no creds
        get_port('ozzy/embryo:git-f2a8020', False)
        self.assertFalse(self.client.client.login.called)

        creds = {
            'username': 'fake',
            'password': 'fake',
            'email': 'fake',
            'registry': 'quay.io'
        }

        client = {}
        client['Status'] = 'Login Succeeded'
        self.client.client.login.return_value = client
        get_port('ozzy/embryo:git-f2a8020', False, creds)
        self.assertTrue(self.client.client.login.called)
        self.assertTrue(self.client.client.pull.called)
        self.assertTrue(self.client.client.inspect_image.called)

    def test_publish_release(self, mock_client):
        self.client = DockerClient()

        # Make sure login is not called when there are no creds
        publish_release('ozzy/embryo:git-f2a8020', 'ozzy/embryo:v4', False)
        self.assertFalse(self.client.client.login.called)

        creds = {
            'username': 'fake',
            'password': 'fake',
            'email': 'fake',
            'registry': 'quay.io'
        }

        client = {}
        client['Status'] = 'Login Succeeded'
        self.client.client.login.return_value = client
        publish_release('ozzy/embryo:git-f2a8020', 'ozzy/embryo:v4', False, creds)
        self.assertTrue(self.client.client.login.called)
        self.assertTrue(self.client.client.pull.called)
        self.assertTrue(self.client.client.tag.called)
        self.assertTrue(self.client.client.push.called)

        publish_release('ozzy/embryo:git-f2a8020', 'ozzy/embryo:v4', True)
        self.assertTrue(self.client.client.pull.called)
        self.assertTrue(self.client.client.tag.called)
        self.assertTrue(self.client.client.push.called)

        # Test that a registry host prefix is replaced with deis-registry for the target
        publish_release('ozzy/embryo:git-f2a8020', 'quay.io/ozzy/embryo:v4', True)
        docker_push = self.client.client.push
        docker_push.assert_called_with(
            'localhost:5000/ozzy/embryo', tag='v4', decode=True, stream=True
        )

        # Test that blacklisted image names can't be published
        with self.assertRaises(PermissionDenied):
            publish_release(
                'deis/controller:v1.11.1', 'deis/controller:v1.11.1', True)
        with self.assertRaises(PermissionDenied):
            publish_release(
                'localhost:5000/deis/controller:v1.11.1', 'deis/controller:v1.11.1', True)

    def test_login(self, mock_client):
        self.client = DockerClient()

        # success
        client = {}
        client['Status'] = 'Login Succeeded'
        self.client.client.login.return_value = client

        creds = {
            'username': 'fake',
            'password': 'fake',
            'email': 'fake',
            'registry': 'quay.io'
        }
        self.client.login('quay.io/deis/foobar', creds)
        docker_login = self.client.client.login
        docker_login.assert_called_with(
            username='fake', password='fake',
            email='fake', registry='quay.io'
        )

        # username matches
        client = {}
        client['username'] = 'fake'
        self.client.client.login.return_value = client

        creds = {
            'username': 'fake',
            'password': 'fake',
            'email': 'fake',
            'registry': 'quay.io'
        }
        self.client.login('quay.io/deis/foobar', creds)
        docker_login = self.client.client.login
        docker_login.assert_called_with(
            username='fake', password='fake',
            email='fake', registry='quay.io'
        )

    def test_login_failed(self, mock_client):
        self.client = DockerClient()

        # failed login
        client = {}
        client['Status'] = 'Login Failed'
        self.client.client.login.return_value = client

        creds = {
            'username': 'fake',
            'password': 'fake',
            'email': 'fake',
            'registry': 'quay.io'
        }

        with self.assertRaises(PermissionDenied):
            self.client.login('quay.io/deis/foobar', creds)
            docker_login = self.client.client.login
            docker_login.assert_called_with(
                username='fake', password='fake',
                email='fake', registry='quay.io'
            )

    def test_login_bad_creds(self, mock_client):
        self.client = DockerClient()

        # missing parts of credentials
        with self.assertRaises(PermissionDenied):
            creds = {
                'username': 'fake',
                'email': 'fake',
                'registry': 'quay.io'
            }
            self.client.login('quay.io/deis/foobar', creds)

        # bad credentials
        with self.assertRaises(PermissionDenied):
            creds = {
                'username': 'fake',
                'password': 'fake',
                'email': 'fake',
                'registry': 'quay.io'
            }
            self.client.login('quay.io/deis/foobar', creds)

    def test_pull(self, mock_client):
        self.client = DockerClient()
        self.client.pull('alpine', '3.2')
        docker_pull = self.client.client.pull
        docker_pull.assert_called_once_with('alpine', tag='3.2', decode=True, stream=True)
        # Test that blacklisted image names can't be pulled
        with self.assertRaises(PermissionDenied):
            self.client.pull('deis/controller', 'v1.11.1')
        with self.assertRaises(PermissionDenied):
            self.client.pull('localhost:5000/deis/controller', 'v1.11.1')

    def test_push(self, mock_client):
        self.client = DockerClient()
        self.client.push('ozzy/embryo', 'v4')
        docker_push = self.client.client.push
        docker_push.assert_called_once_with('ozzy/embryo', tag='v4', decode=True, stream=True)

    def test_tag(self, mock_client):
        self.client = DockerClient()
        self.client.tag('ozzy/embryo:git-f2a8020', 'ozzy/embryo', 'v4')
        docker_tag = self.client.client.tag
        docker_tag.assert_called_once_with(
            'ozzy/embryo:git-f2a8020', 'ozzy/embryo', tag='v4', force=True)

        # fake failed tag
        self.client.client.tag.return_value = False
        with self.assertRaises(RegistryException):
            self.client.tag('foo/bar:latest', 'foo/bar', 'v1.11.1')

        # Test that blacklisted image names can't be tagged
        with self.assertRaises(PermissionDenied):
            self.client.tag('deis/controller:v1.11.1', 'deis/controller', 'v1.11.1')

        with self.assertRaises(PermissionDenied):
            self.client.tag('localhost:5000/deis/controller:v1.11.1', 'deis/controller', 'v1.11.1')
