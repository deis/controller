from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource
from scheduler.utils import dict_merge


class Service(Resource):
    short_name = 'svc'

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single Service or a list
        """
        url = '/namespaces/{}/services'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Service "{}" in Namespace "{}"'
        else:
            message = 'get Services in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def create(self, namespace, name, **kwargs):
        # Ports and app type will be overwritten as required
        manifest = {
            'kind': 'Service',
            'apiVersion': 'v1',
            'metadata': {
                'name': name,
                'labels': {
                    'app': namespace,
                    'heritage': 'deis'
                },
                'annotations': {}
            },
            'spec': {
                'ports': [{
                    'name': 'http',
                    'port': 80,
                    'targetPort': 5000,
                    'protocol': 'TCP'
                }],
                'selector': {
                    'app': namespace,
                    'heritage': 'deis'
                }
            }
        }

        data = dict_merge(manifest, kwargs.get('data', {}))
        url = self.api("/namespaces/{}/services", namespace)
        response = self.http_post(url, json=data)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'create Service "{}" in Namespace "{}"', namespace, namespace
            )

        return response

    def update(self, namespace, name, data):
        url = self.api("/namespaces/{}/services/{}", namespace, name)
        response = self.http_put(url, json=data)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'update Service "{}" in Namespace "{}"', namespace, name
            )

        return response

    def delete(self, namespace, name):
        url = self.api("/namespaces/{}/services/{}", namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete Service "{}" in Namespace "{}"', name, namespace
            )

        return response
