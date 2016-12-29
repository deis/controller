
import logging
from pprint import pformat

from channels.exceptions import WebsocketCloseException
from channels.generic.websockets import WebsocketConsumer
from rest_framework.exceptions import PermissionDenied

from .authentication import MessageRequest
from .models import App
from .permissions import is_app_user


logger = logging.getLogger(__name__)


class PtyConsumer(WebsocketConsumer):

    def connect(self, message, **kwargs):
        logger.debug("connect(\n{}\n)".format(pformat(message.content)))
        # call superclass to complete connection setup
        super(PtyConsumer, self).connect(message, **kwargs)
        try:
            app = App.objects.get(id=kwargs.get('app_id'))
            if not is_app_user(MessageRequest(message), app):
                raise PermissionDenied()
        except:
            raise WebsocketCloseException(code=3404)
        # TODO: create the app "run" pod and connect to it
        # command = 'ls'
        # app.run(request.user, command, interactive=True)

    def receive(self, text=None, bytes=None, **kwargs):
        """
        Called when a message is received with either text or bytes
        filled out.
        """
        logger.debug("receive(\n{}\n)".format(text))
        # TODO: relay message to the app "run" pod
        # Just echo back the text sent, for now.
        self.send(text=text, bytes=bytes)

    def disconnect(self, message, **kwargs):
        logger.debug("disconnect(\n{}\n)".format(pformat(message.content)))
        # TODO: destroy the app "run" pod
        logger.debug("Channel: {}".format(message.reply_channel))
