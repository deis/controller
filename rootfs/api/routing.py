from channels.routing import route
from django.conf import settings

from api.consumers import ws_message

pty_routing = [
    route("websocket.receive", ws_message,
        path=r"^apps/(?P<id>{})/ptys/?$".format(settings.APP_URL_REGEX)),
]
