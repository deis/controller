from channels.routing import route_class
from django.conf import settings

from .consumers import PtyConsumer


PTY_PATH = r'^/v2/apps/(?P<app_id>{})/ptys/?$'.format(settings.APP_URL_REGEX)


pty_routing = [
    route_class(PtyConsumer, path=PTY_PATH),
]
