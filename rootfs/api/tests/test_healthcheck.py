
from rest_framework.test import APITestCase


class HealthCheckTest(APITestCase):

    def test_healthcheck_liveness(self):
        # GET and HEAD (no auth required)
        url = '/healthz'
        resp = self.client.get(url)
        self.assertContains(resp, "OK", status_code=200)

        resp = self.client.head(url)
        self.assertEqual(resp.status_code, 200)

    def test_healthcheck_liveness_invalid(self):
        url = '/healthz'
        for method in ('put', 'post', 'patch', 'delete'):
            resp = getattr(self.client, method)(url)
            # method not allowed
            self.assertEqual(resp.status_code, 405)

    def test_healthcheck_readiness(self):
        # GET and HEAD (no auth required)
        url = '/readiness'
        resp = self.client.get(url)
        self.assertContains(resp, "OK", status_code=200)

        resp = self.client.head(url)
        self.assertEqual(resp.status_code, 200)

    def test_healthcheck_readiness_invalid(self):
        url = '/readiness'
        for method in ('put', 'post', 'patch', 'delete'):
            resp = getattr(self.client, method)(url)
            # method not allowed
            self.assertEqual(resp.status_code, 405)
