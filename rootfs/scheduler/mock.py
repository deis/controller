from datetime import datetime
import requests
import requests_mock
from urllib.parse import urlparse, parse_qs
import string
import random
import time

from . import KubeHTTPClient, KubeHTTPException

from django.conf import settings
from django.core.cache import cache

import logging
logger = logging.getLogger(__name__)


resources = [
    'namespaces', 'nodes', 'pods', 'replicationcontrollers',
    'secrets', 'services', 'events'
]


def jitter():
    """Introduce random jitter (sleep)"""
    # 5 second jitter is the highest
    jit = random.randint(1, 50) * 0.1
    time.sleep(jit)


def pod_name(size=5, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def cache_key(key):
    """Unify the way keys are stored"""
    key = key.replace(settings.SCHEDULER_URL, '').replace('/', '_').replace('-', '_').strip('_')
    return key


def get_type(key, pos=-1):
    key = key.strip('/').split('/')
    if key[pos] in resources:
        return key[pos]

    # bad if it gets there
    return 'unknown'


def delete_pods(url, pods, current, desired):
    # remove from namespace scope
    delta = current - desired

    removed = []
    items = cache.get(url, [])
    for _ in range(delta):
        item = pods.pop()
        items.remove(item)
        removed.append(item)
        # Remove individual item
        cache.delete(item)
    # remove from namespace
    cache.set(url, items, None)

    # remove from global scope
    items = cache.get('pods', [])  # global scope
    for item in removed:
        if item in items:
            items.remove(item)
    cache.set('pods', items, None)

    # Remove operation is done. No additions
    return


def create_pods(url, labels, base, new_pods):
    # Start by fetching available pods in the Namespace that fit the profile
    # and prune down if needed, Otherwise go into the addition logic here
    for _ in range(new_pods):
        data = base.copy()
        # creation time
        timestamp = str(datetime.utcnow().strftime(settings.DEIS_DATETIME_FORMAT))
        data['metadata']['creationTimestamp'] = timestamp

        # generate the pod name and combine with RC name
        data['metadata']['name'] = data['metadata']['generateName'] + pod_name()

        timestamp = str(datetime.utcnow().strftime(settings.DEIS_DATETIME_FORMAT))
        data['status'] = {
            'phase': 'Running',
            'startTime': timestamp,
            'conditions': [
                # TODO status can be True or False (string)
                {'type': 'Ready', 'status': 'True'}
            ],
            'containerStatuses': [
                {
                    'name': '{}-{}'.format(labels['app'], labels['type']),
                    # TODO ready can be True / False (boolean)
                    'ready': True,
                    # TODO can be running / terminated or nothing if in pending mode
                    'state': {
                        'running': {
                            'startedAt': timestamp
                        }
                    }
                }
            ],
        }

        # Create the single resource with all its information
        pod_key = cache_key(url + '_' + data['metadata']['name'])
        cache.set(pod_key, data, None)

        # Keep track of what resources are in a given resource type
        items = cache.get('pods', [])  # global scope
        if pod_key not in items:
            items.append(pod_key)
            cache.set('pods', items, None)

        items = cache.get(url, [])  # pods within the namespace
        if pod_key not in items:
            items.append(pod_key)
            cache.set(url, items, None)


def upsert_pods(controller, url):
    # turn RC url into pods one
    url = url.replace(cache_key(controller['metadata']['name']), '')
    url = url.replace('_replicationcontrollers_', '_pods')
    # make sure url only has up to "_pods"
    url = url[0:(url.find("_pods") + 5)]

    # pod is not part of the POST loop
    data = controller['spec']['template'].copy()
    data['metadata']['namespace'] = controller['metadata']['namespace']
    data['metadata']['generateName'] = controller['metadata']['name'] + '-'

    # fetch a list of all the pods given the labels
    items = []
    for item in filter_data({'labels': data['metadata']['labels']}, url):
        # Translate to a cache key since a full object gets passed
        items.append(cache_key(url + '_' + item['metadata']['name']))
    current = len(items)
    desired = controller['spec']['replicas']

    delta = desired - current
    # nothing to do here
    if not delta:
        return

    # If operation is scale down then pods needs to be removed
    if current > desired:
        return delete_pods(url, items, current, desired)

    create_pods(url, data['metadata']['labels'], data, delta)


def filter_data(filters, path):
    data = []
    for item in cache.get(path, []):
        item = cache.get(item)
        if not item:
            # item is broken
            continue

        # check if item has labels
        if 'labels' not in item['metadata']:
            continue

        # Do extra filtering based on labelSelector
        add = True
        for label, value in filters['labels'].items():
            if (
                label not in item['metadata']['labels'] or
                item['metadata']['labels'][label] != value
            ):
                add = False
                continue

        if add:
            data.append(item)

    return data


def fetch_single(request, context):
    url = cache_key(request.url)
    data = cache.get(url)
    if data is None:
        context.status_code = 404
        context.reason = 'Not Found'
        return {}

    return data


def fetch_all(request, context):
    # Figure out if there are any labels to filter on
    url = urlparse(request.url)
    filters = prepare_query_filters(url.query)
    cache_path = cache_key(request.path)

    data = filter_data(filters, cache_path)
    return {'items': data}


def prepare_query_filters(query):
    filters = {'labels': {}}
    if query:
        queries = parse_qs(query)
        if 'labelSelector' in queries:
            for items in queries['labelSelector']:
                for item in items.split(','):
                    key, value = item.split('=')
                    filters['labels'][key] = value

    return filters


def get(request, context):
    """Process a GET request to the kubernetes API"""
    # Figure out if it is a GET operation for a single element or a list
    url = urlparse(request.url)
    if get_type(url.path) in resources:
        return fetch_all(request, context)

    # fetch singular item
    return fetch_single(request, context)


def post(request, context):
    """Process a POST request to the kubernetes API"""
    data = request.json()
    url = cache_key(request.url + '/' + data['metadata']['name'] + '/')
    if cache.get(url) is not None:
        context.status_code = 409
        context.reason = 'Conflict'
        return {}

    resource_type = get_type(request.url)

    # fill in generic data
    timestamp = str(datetime.utcnow().strftime(settings.DEIS_DATETIME_FORMAT))
    data['metadata']['creationTimestamp'] = timestamp
    data['metadata']['resourceVersion'] = 1

    # don't bother adding it to those two resources since they live outside namespace
    if resource_type not in ['nodes', 'namespaces']:
        namespace = request.url.replace(settings.SCHEDULER_URL + '/api/v1/namespaces/',  '')
        namespace = namespace.split('/')[0]
        data['metadata']['namespace'] = namespace

    # deis run is the only thing that creates pods directly
    if resource_type == 'pods':
        # need to make the pod Succeed instead of be just running
        data.update({'status': {'phase': 'Succeeded'}})

    if resource_type == 'replicationcontrollers':
        data['status'] = {
            'observedGeneration': 1
        }
        data['metadata']['generation'] = 1

        upsert_pods(data, url)

    cache.set(url, data, None)

    # Keep track of what resources are in a given resource
    items = cache.get(resource_type, [])
    if url not in items:
        items.append(url)
        cache.set(resource_type, items, None)

    # Keep track of what resources exist under other resources (mostly namespace)
    other = cache_key(request.url)
    items = cache.get(other, [])
    if url not in items:
        items.append(url)
        cache.set(other, items, None)

    context.status_code = 201
    context.reason = 'Created'
    return data


def put(request, context):
    """Process a PUT request to the kubernetes API"""
    url = cache_key(request.url)
    data = cache.get(url)
    if data is None:
        context.status_code = 404
        context.reason = 'Not Found'
        return {}

    data = request.json()

    # type is the second last element
    resource_type = get_type(request.url, -2)

    if resource_type == 'replicationcontrollers':
        data['metadata']['resourceVersion'] += 1
        upsert_pods(data, url)

    # Update the individual resource
    cache.set(url, data, None)

    context.status_code = 200
    context.reason = 'OK'

    return request.json()


def delete(request, context):
    """Process a DELETE request to the kubernetes API"""
    url = cache_key(request.url)
    data = cache.get(url)
    if data is None:
        context.status_code = 404
        context.reason = 'Not Found'
        return {}

    # remove data object from individual cache
    cache.delete(url)

    # remove from the resource type global scope
    resource_type = get_type(request.url, -2)
    items = cache.get(resource_type, [])
    if url in items:
        items.remove(url)
        cache.set(resource_type, items, None)

    # clean everything from a namespace
    if resource_type == 'namespaces':
        for resource in resources:
            items = cache.get(resource, [])
            for item in items:
                if item.startswith(url):
                    # remove individual item
                    cache.delete(item)

                    # remove from the resource collection
                    if item in items:
                        items.remove(item)
                        cache.set(resource, items, None)
    # If a pod belongs to an RC and DELETE operation makes it fall below the
    # minimum replicas count then a new pod comes into service
    elif resource_type == 'pods':
        remove_cache_item(url, resource_type)

        # Try to determine the connected RC to readjust pod count
        # One way is to look at annotations:kubernetes.io/created-by and read
        # the serialized reference but that looks clunky right now
        controllers = filter_data({'labels': data['metadata']['labels']}, 'replicationcontrollers')
        controller = controllers.pop()
        upsert_pods(controller, cache_key(request.path))
    else:
        remove_cache_item(url, resource_type)

    # k8s API uses 200 instead of 204
    context.status_code = 200
    context.reason = 'OK'
    return {}


def remove_cache_item(url, resource_type):
    # remove from namespace specific scope
    namespace, item = url.split('_{}_'.format(resource_type))
    cache_url = '{}_{}'.format(namespace, resource_type)
    items = cache.get(cache_url, [])
    if url in items:
        items.remove(url)
        cache.set(cache_url, items, None)


def mock(request, context):
    # What to do about context
    if request.method == 'POST':
        return post(request, context)
    elif request.method == 'GET':
        return get(request, context)
    elif request.method == 'PUT':
        return put(request, context)
    elif request.method == 'DELETE':
        return delete(request, context)

    # Log if any operation slips through that hasn't been accounted for
    logger.critical('COULD NOT FIND WHAT I AM')
    logger.critical(request.url)
    logger.critical(request.method)


class MockSchedulerClient(KubeHTTPClient):
    def __init__(self):
        self.url = settings.SCHEDULER_URL
        self.registry = settings.REGISTRY_URL

        adapter = requests_mock.Adapter()
        self.session = requests.Session()
        self.session.mount(self.url, adapter)

        # Lets just listen to everything and sort it out ourselves
        adapter.register_uri(
            requests_mock.ANY, requests_mock.ANY,
            json=mock
        )

        # Pre-seed data that is assumed to otherwise be there
        try:
            self._get_namespace('deis')
        except KubeHTTPException:
            self._create_namespace('deis')

        try:
            self._get_secret('deis', 'minio-user')
        except KubeHTTPException:
            secrets = {
                'access-key-id': 'i am a key',
                'access-secret-key': 'i am a secret'
            }
            self._create_secret('deis', 'minio-user', secrets)

        try:
            self._get_namespace('duplicate')
        except KubeHTTPException:
            self._create_namespace('duplicate')

        try:
            self._get_node('172.17.8.100')
        except KubeHTTPException:
            data = {
                "kind": "Node",
                "apiVersion": "v1",
                "metadata": {
                    "name": "172.17.8.100",
                    "selfLink": "/api/v1/nodes/172.17.8.100",
                    "uid": "fbd5f7a4-df2b-11e5-9553-0800279a0a3c",
                    "resourceVersion": "129461",
                    "creationTimestamp": "2016-02-29T21:32:50Z",
                    "labels": {
                        "environ": "dev",
                        "rack": "1",
                        "deis.com/fun": "yes",
                        "kubernetes.io/hostname": "172.17.8.100",
                        "is.valid": "is-also_valid",
                        "host.the-name.com/is.valid": "valid",
                        "ssd": "true"
                    }
                },
                "spec": {
                    "externalID": "172.17.8.100"
                },
                "status": {
                    "capacity": {
                        "cpu": "1",
                        "memory": "2053684Ki",
                        "pods": "40"
                    },
                    "conditions": [
                        {
                            "type": "OutOfDisk",
                            "status": "False",
                            "lastHeartbeatTime": "2016-03-10T23:03:25Z",
                            "lastTransitionTime": "2016-03-09T22:37:05Z",
                            "reason": "KubeletHasSufficientDisk",
                            "message": "kubelet has sufficient disk space available"
                        },
                        {
                            "type": "Ready",
                            "status": "True",
                            "lastHeartbeatTime": "2016-03-10T23:03:25Z",
                            "lastTransitionTime": "2016-03-10T17:48:49Z",
                            "reason": "KubeletReady",
                            "message": "kubelet is posting ready status"
                        }
                    ],
                    "addresses": [
                        {
                            "type": "LegacyHostIP",
                            "address": "172.17.8.100"
                        },
                        {
                            "type": "InternalIP",
                            "address": "172.17.8.100"
                        }
                    ],
                    "daemonEndpoints": {
                        "kubeletEndpoint": {
                            "Port": 10250
                        }
                    },
                    "nodeInfo": {
                        "machineID": "d3e0f7b72e2d4d3689245ccf54b89786",
                        "systemUUID": "F6C94CA8-6DAC-471D-BDA2-4E6C2A015E07",
                        "bootID": "11895587-b7f1-4332-8e33-ec222c147d0b",
                        "kernelVersion": "4.2.2-coreos-r2",
                        "osImage": "CoreOS 835.12.0",
                        "containerRuntimeVersion": "docker://1.8.3",
                        "kubeletVersion": "v1.1.7",
                        "kubeProxyVersion": "v1.1.7"
                    }
                }
            }

            name = 'api_v1_nodes_172.17.8.100'
            cache.set(name, data, None)
            cache.set('api_v1_nodes', [name], None)
        except Exception as e:
            logger.critical(e)

SchedulerClient = MockSchedulerClient


# List of currently used resources in the client
# NI = Not Implemented in the client
# http://kubernetes.io/third_party/swagger-ui/
#
# GET                                       /nodes  # noqa
# PATCH (NI) | PUT (NI) | GET | DELETE (NI) /nodes/{node}  # noqa
# POST | GET                                /namespaces  # noqa
# PATCH (NI) | PUT (NI) | GET | DELETE      /namespaces/{namespace}  # noqa
# GET                                       /namespaces/{namespace}/events  # noqa
# POST | GET                                /namespaces/{namespace}/replicationcontrollers  # noqa
# PATCH (NI) | PUT      | GET | DELETE      /namespaces/{namespace}/replicationcontrollers/{controller}  # noqa
# POST | GET                                /namespaces/{namespace}/secrets  # noqa
# PATCH (NI) | PUT (NI) | GET | DELETE      /namespaces/{namespace}/secrets/{secret}  # noqa
# POST | GET                                /namespaces/{namespace}/services  # noqa
# PATCH (NI) | PUT      | GET | DELETE      /namespaces/{namespace}/services/{service}  # noqa
# POST | GET                                /namespaces/{namespace}/pods  # noqa
# PATCH (NI) | PUT (NI) | GET | DELETE      /namespaces/{namespace}/pods/{pod}  # noqa
# GET                                       /namespaces/{namespace}/pods/{pod}/log  (needs to be special cased)  # noqa

# TODO transitions pod between the various states to emulate real life more
