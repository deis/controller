"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
import json
import requests
import requests_mock
from unittest import mock

from django.conf import settings
from django.test import TestCase

import scheduler
from scheduler import exceptions


def mock_session():
    return requests.Session()


def connection_refused_matcher(request):
    raise requests.ConnectionError("connection refused")


@mock.patch('scheduler.get_session', mock_session)
class KubeHTTPClientTest(TestCase):
    """Tests kubernetes HTTP client calls"""

    def setUp(self):
        self.adapter = requests_mock.Adapter()
        self.path = '/foo'
        self.url = settings.SCHEDULER_URL + self.path
        # use the real scheduler client.
        self.scheduler = scheduler.KubeHTTPClient(settings.SCHEDULER_URL)
        self.scheduler.session.mount(self.url, self.adapter)

    def test_head(self):
        """
        Test that calling .http_head() uses the client session to make a HEAD request.
        """
        self.adapter.register_uri('HEAD', self.url)
        response = self.scheduler.http_head(self.path)
        assert response is not None
        self.assertTrue(self.adapter.called)
        self.assertEqual(self.adapter.call_count, 1)
        # ensure that connection errors get raised as a KubeException
        self.adapter.add_matcher(connection_refused_matcher)
        with self.assertRaises(exceptions.KubeException):
            self.scheduler.http_head(self.path)

    def test_get(self):
        """
        Test that calling .http_get() uses the client session to make a GET request.
        """
        self.adapter.register_uri('GET', self.url)
        response = self.scheduler.http_get(self.path)
        assert response is not None
        self.assertTrue(self.adapter.called)
        self.assertEqual(self.adapter.call_count, 1)
        # ensure that connection errors get raised as a KubeException
        self.adapter.add_matcher(connection_refused_matcher)
        with self.assertRaises(exceptions.KubeException):
            self.scheduler.http_get(self.path)

    def test_post(self):
        """
        Test that calling .http_post() uses the client session to make a POST request.
        """
        self.adapter.register_uri('POST', self.url)
        response = self.scheduler.http_post(self.path, data=json.dumps({'hello': 'world'}))
        assert response is not None
        self.assertTrue(self.adapter.called)
        self.assertEqual(self.adapter.call_count, 1)
        # ensure that connection errors get raised as a KubeException
        self.adapter.add_matcher(connection_refused_matcher)
        with self.assertRaises(exceptions.KubeException):
            self.scheduler.http_post(self.path)

    def test_put(self):
        """
        Test that calling .http_put() uses the client session to make a PUT request.
        """
        self.adapter.register_uri('PUT', self.url)
        response = self.scheduler.http_put(self.path, data=json.dumps({'hello': 'world'}))
        assert response is not None
        self.assertTrue(self.adapter.called)
        self.assertEqual(self.adapter.call_count, 1)
        # ensure that connection errors get raised as a KubeException
        self.adapter.add_matcher(connection_refused_matcher)
        with self.assertRaises(exceptions.KubeException):
            self.scheduler.http_put(self.path)

    def test_delete(self):
        """
        Test that calling .http_delete() uses the client session to make a DELETE request.
        """
        self.adapter.register_uri('DELETE', self.url)
        response = self.scheduler.http_delete(self.path)
        assert response is not None
        self.assertTrue(self.adapter.called)
        self.assertEqual(self.adapter.call_count, 1)
        # ensure that connection errors get raised as a KubeException
        self.adapter.add_matcher(connection_refused_matcher)
        with self.assertRaises(exceptions.KubeException):
            self.scheduler.http_delete(self.path)
