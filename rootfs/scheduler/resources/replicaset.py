from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class ReplicaSet(Resource):
    api_prefix = 'apis'
    api_version = 'extensions/v1beta1'
    short_name = 'rs'

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single ReplicaSet or a list
        """
        url = '/namespaces/{}/replicasets'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get ReplicaSet "{}" in Namespace "{}"'
        else:
            message = 'get ReplicaSets in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response
