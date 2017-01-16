from scheduler.exceptions import KubeHTTPException
from scheduler.resources import Resource
from datetime import datetime
import uuid

DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Events(Resource):
    """
    Events resource.
    Warning! Used ONLY for testing purposes
    """
    short_name = 'ev'

    def create(self, namespace, name, message, **kwargs):
        url = self.api('/namespaces/{}/events'.format(namespace))
        data = {
            'kind': 'Event',
            'apiVersion': 'v1',
            'count': kwargs.get('count', 1),
            'metadata': {
                'creationTimestamp': datetime.now().strftime(DATETIME_FORMAT),
                'namespace': namespace,
                'name': name,
                'resourceVersion': kwargs.get('resourceVersion', ''),
                'uid': str(uuid.uuid4()),
            },
            'message': message,
            'type': kwargs.get('type', 'Normal'),
            'firstTimestamp': datetime.now().strftime(DATETIME_FORMAT),
            'lastTimestamp': datetime.now().strftime(DATETIME_FORMAT),
            'reason': kwargs.get('reason', ''),
            'source': {
                'component': kwargs.get('component', ''),
            },
            'involvedObject': kwargs.get('involvedObject', {})
        }

        response = self.http_post(url, json=data)
        if not response.status_code == 201:
            raise KubeHTTPException(response, 'create Event for namespace {}'.format(namespace))  # noqa

        return response


