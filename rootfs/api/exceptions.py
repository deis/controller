import logging
from rest_framework.compat import set_rollback
from rest_framework.exceptions import APIException, status
from rest_framework.response import Response
from rest_framework.views import exception_handler


class HealthcheckException(APIException):
    """Exception class used for when the application's health check fails"""
    pass


class DeisException(APIException):
    status_code = 400


class AlreadyExists(APIException):
    status_code = 409


class ServiceUnavailable(APIException):
    status_code = 503
    default_detail = 'Service temporarily unavailable, try again later.'


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # No response means DRF couldn't handle it
    # Output a generic 500 in a JSON format
    if response is None:
        logging.exception('Uncaught Exception', exc_info=exc)
        set_rollback()
        return Response({'detail': 'Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response
