
import logging
from pprint import pformat

from channels.sessions import enforce_ordering
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied

from .authentication import MessageRequest
from .models import App
from .permissions import is_app_user


logger = logging.getLogger(__name__)


@enforce_ordering(slight=True)
def ws_connect(message, app_id):
    logger.debug("ws_connect(\n{}\n)".format(pformat(message.content)))
    request = MessageRequest(message)
    app = get_object_or_404(App, id=app_id)
    # check the user is authorized for this app
    if not is_app_user(request, app):
        raise PermissionDenied()
    # TODO: store the user in a channel session
    # TODO: create the app "run" pod and connect to it
    logger.debug("User: {}\nApp: {}".format(request.user, app))
    # logger.debug("Channel: {}".format(message.reply_channel))


@enforce_ordering(slight=True)
def ws_message(message, app_id):
    logger.debug("ws_message(\n{}\n)".format(pformat(message.content)))
    # TODO: relay message to the app "run" pod
    # ASGI WebSocket packet-received and send-packet message types
    # both have a "text" key for their textual data.
    message.reply_channel.send({
        "text": message.content['text'],
    })
    logger.debug("Channel: {}".format(message.reply_channel))


@enforce_ordering(slight=True)
def ws_disconnect(message, app_id):
    logger.debug("ws_disconnect(\n{}\n)".format(pformat(message.content)))
    # TODO: destroy the app "run" pod
    logger.debug("Channel: {}".format(message.reply_channel))
