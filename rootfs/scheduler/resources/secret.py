import base64
import json
from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException, KubeException


class Secret(Resource):
    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single Secret or a list
        """
        url = '/namespaces/{}/secrets'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Secret "{}" in Namespace "{}"'
        else:
            message = 'get Secrets in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        # return right away if it is a list
        if name is None:
            return response

        # decode the base64 data
        secrets = response.json()
        for key, value in secrets['data'].items():
            if value is None:
                secrets['data'][key] = ''
                continue

            value = base64.b64decode(value)
            value = value if isinstance(value, bytes) else bytes(str(value), 'UTF-8')
            secrets['data'][key] = value.decode(encoding='UTF-8')

        # tell python-requests it actually hasn't consumed the data
        response._content = bytes(json.dumps(secrets), 'UTF-8')

        return response

    def manifest(self, namespace, name, data, secret_type='Opaque', labels={}):
        secret_types = ['Opaque', 'kubernetes.io/dockerconfigjson']
        if secret_type not in secret_types:
            raise KubeException('{} is not a supported secret type. Use one of the following: '.format(secret_type, ', '.join(secret_types)))  # noqa

        manifest = {
            'kind': 'Secret',
            'apiVersion': 'v1',
            'metadata': {
                'name': name,
                'namespace': namespace,
                'labels': {
                    'app': namespace,
                    'heritage': 'deis'
                }
            },
            'type': secret_type,
            'data': {}
        }

        # add in any additional label info
        manifest['metadata']['labels'].update(labels)

        for key, value in data.items():
            if value is None:
                manifest['data'].update({key: ''})
                continue

            value = value if isinstance(value, bytes) else bytes(str(value), 'UTF-8')
            item = base64.b64encode(value).decode(encoding='UTF-8')
            manifest['data'].update({key: item})

        return manifest

    def create(self, namespace, name, data, secret_type='Opaque', labels={}):
        manifest = self.manifest(namespace, name, data, secret_type, labels)
        url = self.api("/namespaces/{}/secrets", namespace)
        response = self.http_post(url, json=manifest)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'failed to create Secret "{}" in Namespace "{}"', name, namespace
            )

        return response

    def update(self, namespace, name, data, secret_type='Opaque', labels={}):
        manifest = self.manifest(namespace, name, data, secret_type, labels)
        url = self.api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.http_put(url, json=manifest)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'failed to update Secret "{}" in Namespace "{}"',
                name, namespace
            )

        return response

    def delete(self, namespace, name):
        url = self.api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete Secret "{}" in Namespace "{}"', name, namespace
            )

        return response
