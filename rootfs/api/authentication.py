from django.contrib.auth.models import AnonymousUser
from rest_framework import authentication
from rest_framework.authentication import TokenAuthentication


class AnonymousAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone!
        """
        return AnonymousUser(), None


class AnonymousOrAuthenticatedAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone or if a valid token is provided, a user.
        """
        try:
            return TokenAuthentication.authenticate(TokenAuthentication(), request)
        except:
            return AnonymousUser(), None


class MessageRequest(object):
    """
    Convert a Django channels message back to an object that acts enough like a Django REST
    Framework request that Token-based authentication methods can use it.
    """

    def __init__(self, message):
        headers = dict(message['headers'])
        if b'authorization' in headers:
            headers['HTTP_AUTHORIZATION'] = headers[b'authorization']
        self.META = headers
        user, token = AnonymousOrAuthenticatedAuthentication().authenticate(self)
        self.user = user
