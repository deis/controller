from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Node(Resource):
    short_name = 'no'

    def get(self, name=None, **kwargs):
        """
        Fetch a single Node or a list
        """
        url = '/nodes'
        args = []
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Node "{}" in Nodes'
        else:
            message = 'get Nodes'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response
