from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class Namespace(Resource):
    short_name = 'ns'

    def get(self, name=None, **kwargs):
        """
        Fetch a single Namespace or a list
        """
        url = '/namespaces'
        args = []
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Namespace "{}"'
        else:
            message = 'get Namespaces'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def create(self, namespace):
        url = self.api("/namespaces")
        data = {
            "kind": "Namespace",
            "apiVersion": "v1",
            "metadata": {
                "name": namespace,
                "labels": {
                    'heritage': 'deis'
                }
            }
        }

        response = self.http_post(url, json=data)
        if not response.status_code == 201:
            raise KubeHTTPException(response, "create Namespace {}".format(namespace))

        return response

    def delete(self, namespace):
        url = self.api("/namespaces/{}", namespace)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete Namespace "{}"', namespace)

        return response

    def events(self, namespace, **kwargs):
        url = self.api("/namespaces/{}/events", namespace)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, "get Events in Namespace {}", namespace)

        return response
