class KubeException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class KubeHTTPException(KubeException):
    def __init__(self, response, errmsg, *args, **kwargs):
        self.response = response

        data = response.json()
        message = data['message'] if 'message' in data else ''

        msg = errmsg.format(*args)
        msg = 'failed to {}: {} {} {}'.format(
            msg,
            response.status_code,
            response.reason,
            message
        )
        KubeException.__init__(self, msg, *args, **kwargs)
