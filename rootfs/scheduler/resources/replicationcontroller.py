import json
import time
from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource


class ReplicationController(Resource):
    short_name = 'rc'

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single ReplicationController or a list
        """
        url = '/namespaces/{}/replicationcontrollers'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get ReplicationController "{}" in Namespace "{}"'
        else:
            message = 'get ReplicationControllers in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def create(self, namespace, name, image, entrypoint, command, **kwargs):
        manifest = {
            'kind': 'ReplicationController',
            'apiVersion': 'v1',
            'metadata': {
                'name': name,
                'labels': {
                    'app': namespace,
                    'version': kwargs.get('version'),
                    'type': kwargs.get('app_type'),
                    'heritage': 'deis',
                }
            },
            'spec': {
                'replicas': kwargs.get('replicas', 0)
            }
        }

        # tell pod how to execute the process
        kwargs['command'] = entrypoint
        kwargs['args'] = command

        # pod manifest spec
        manifest['spec']['template'] = self.pod.manifest(namespace, name, image, **kwargs)

        url = self.api("/namespaces/{}/replicationcontrollers", namespace)
        resp = self.http_post(url, json=manifest)
        if self.unhealthy(resp.status_code):
            self.log(namespace, 'template: {}'.format(json.dumps(manifest, indent=4)), 'DEBUG')
            raise KubeHTTPException(
                resp,
                'create ReplicationController "{}" in Namespace "{}"', name, namespace
            )

        self.wait_until_updated(namespace, name)

        return resp

    def update(self, namespace, name, data):
        url = self.api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.http_put(url, json=data)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'scale ReplicationController "{}"', name)

        return response

    def delete(self, namespace, name):
        url = self.api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete ReplicationController "{}" in Namespace "{}"', name, namespace
            )

        return response

    def scale(self, namespace, name, desired, timeout):
        rc = self.get(namespace, name).json()

        current = int(rc['spec']['replicas'])
        if desired == current:
            self.log(namespace, "Not scaling RC {} to {} replicas. Already at desired replicas".format(name, desired))  # noqa
            return
        elif desired != rc['spec']['replicas']:  # RC needs new replica count
            self.log(namespace, "scaling RC {} from {} to {} replicas".format(name, current, desired))  # noqa
            self.scales.update(namespace, name, desired, rc)
            self.wait_until_updated(namespace, name)

        # Double check enough pods are in the required state to service the application
        labels = rc['metadata']['labels']
        containers = rc['spec']['template']['spec']['containers']
        self.pods.wait_until_ready(namespace, containers, labels, desired, timeout)

        # if it was a scale down operation, wait until terminating pods are done
        if int(desired) < int(current):
            self.pods.wait_until_terminated(namespace, labels, current, desired)

    def wait_until_updated(self, namespace, name):
        """
        Looks at status/observedGeneration and metadata/generation and
        waits for observedGeneration >= generation to happen, indicates RC is ready

        More information is also available at:
        https://github.com/kubernetes/kubernetes/blob/master/docs/devel/api-conventions.md#metadata
        """
        self.log(namespace, "waiting for ReplicationController {} to get a newer generation (30s timeout)".format(name), 'DEBUG')  # noqa
        for _ in range(30):
            try:
                rc = self.get(namespace, name).json()
                if (
                    "observedGeneration" in rc["status"] and
                    rc["status"]["observedGeneration"] >= rc["metadata"]["generation"]
                ):
                    self.log(namespace, "ReplicationController {} got a newer generation (30s timeout)".format(name), 'DEBUG')  # noqa
                    break

                time.sleep(1)
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    time.sleep(1)
