class KubeException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class KubeHTTPException(KubeException):
    def __init__(self, response, errmsg, *args, **kwargs):
        self.response = response

        msg = errmsg.format(*args)
        msg = "failed to {}: {} {}".format(
            msg,
            response.status_code,
            response.reason
        )
        KubeException.__init__(self, msg, *args, **kwargs)
