from channels.routing import route
from django.conf import settings

from api.consumers import ws_connect
from api.consumers import ws_disconnect
from api.consumers import ws_message


PTY_PATH = r'^/v2/apps/(?P<app_id>{})/ptys/?$'.format(settings.APP_URL_REGEX)


pty_routing = [
    route("websocket.connect", ws_connect, path=PTY_PATH),
    route("websocket.receive", ws_message, path=PTY_PATH),
    route("websocket.disconnect", ws_disconnect, path=PTY_PATH),
]
