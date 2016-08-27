from scheduler.resources import Resource
from scheduler.exceptions import KubeHTTPException


class Scale(Resource):
    def manifest(self, namespace, name, replicas):
        manifest = {
            'kind': 'Scale',
            'apiVersion': self.api_version,
            'metadata': {
                'namespace': namespace,
                'name': name,
            },
            'spec': {
                'replicas': replicas,
            }
        }

        return manifest

    def update(self, namespace, name, replicas, target):
        # use API version and prefix from target use pick the right endpoint
        resource_type = target['kind'].lower() + 's'  # make plural for url
        self.api_version = getattr(self, resource_type).api_version
        self.api_prefix = getattr(self, resource_type).api_prefix

        manifest = self.manifest(namespace, name, replicas)
        url = self.api("/namespaces/{}/{}/{}/scale", namespace, resource_type, name)
        response = self.http_put(url, json=manifest)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'scale {} "{}" in Namespace "{}"', target['kind'], name, namespace
            )
            self.log(namespace, 'template used: {}'.format(json.dumps(manifest, indent=4)), 'DEBUG')  # noqa

        return response
