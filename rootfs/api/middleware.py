"""
HTTP middleware for the Deis REST API.

See https://docs.djangoproject.com/en/1.6/topics/http/middleware/
"""

from api import __version__


class APIVersionMiddleware(object):
    """
    Include that REST API version with each response.
    """

    def process_response(self, request, response):
        """
        Include the controller's REST API major and minor version in
        a response header.
        """
        # clients shouldn't care about the patch release
        version = __version__.rsplit('.', 1)[0]
        response['DEIS_API_VERSION'] = version
        response['DEIS_PLATFORM_VERSION'] = __version__
        return response
