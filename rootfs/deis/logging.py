import os
from gunicorn.glogging import Logger


class Logging(Logger):
    def access(self, resp, req, environ, request_time):
        # health check endpoints are only logged in debug mode
        if (
            not os.environ.get('DEIS_DEBUG', False) and
            req.path in ['/readiness', '/healthz']
        ):
            return

        Logger.access(self, resp, req, environ, request_time)
