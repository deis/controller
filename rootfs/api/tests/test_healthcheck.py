
from api.tests import DeisTestCase


class HealthCheckTest(DeisTestCase):

    def test_healthcheck_liveness(self):
        # GET and HEAD (no auth required)
        response = self.client.get('/healthz')
        self.assertContains(response, "OK", status_code=200)

        response = self.client.head('/healthz')
        self.assertEqual(response.status_code, 200)

    def test_healthcheck_liveness_invalid(self):
        for method in ('put', 'post', 'patch', 'delete'):
            response = getattr(self.client, method)('/healthz')
            # method not allowed
            self.assertEqual(response.status_code, 405)

    def test_healthcheck_readiness(self):
        # GET and HEAD (no auth required)
        response = self.client.get('/readiness')
        self.assertContains(response, "OK", status_code=200)

        response = self.client.head('/readiness')
        self.assertEqual(response.status_code, 200)

    def test_healthcheck_readiness_invalid(self):
        for method in ('put', 'post', 'patch', 'delete'):
            response = getattr(self.client, method)('/readiness')
            # method not allowed
            self.assertEqual(response.status_code, 405)
