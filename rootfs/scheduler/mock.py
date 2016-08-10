import copy
from datetime import datetime, timedelta
import json
import random
import re
import requests
import requests_mock
import string
import time
from urllib.parse import urlparse, parse_qs
from zlib import adler32

from . import KubeHTTPClient, KubeHTTPException

from django.conf import settings
from django.core.cache import cache

import logging
logger = logging.getLogger(__name__)


class LockNotAcquiredError(Exception):
    pass


class CacheLock(object):
    def __init__(self, key=None, timeout=60, block=True):
        """
        :param key: unique key for lock (unique through Django cache)
        :param timeout: timeout of lock, in seconds
        :param block: if a lock is blocking
        """
        self.key = key
        self.timeout = timeout
        self.block = block

    # for use with decorator
    def __call__(self, f):
        if not self.key:
            self.key = "%s:%s" % (f.__module__, f.__name__)

        def wrapped(*args, **kargs):
            with self:
                return f(*args, **kargs)

        return wrapped

    def __enter__(self):
        if not type(self.key) == str and self.key == '':
            raise RuntimeError("Key not specified!")

        if not self.acquire(self.block):
            raise LockNotAcquiredError()

        logger.debug("locking with key %s" % self.key)

    def __exit__(self, type, value, traceback):
        logger.debug('releasing lock {}'.format(self.key))
        self.release()

    def acquire(self, block=True):
        while not self._acquire():
            if not block:
                return False

            time.sleep(0.1)

        return True

    def release(self):
        cache.delete(self.key)

    def _acquire(self):
        return cache.add(self.key, 'true', self.timeout)


resources = [
    'namespaces', 'nodes', 'pods', 'replicationcontrollers',
    'secrets', 'services', 'events', 'deployments', 'replicasets',
]


def jit():
    # 2 second jitter is the highest
    return random.randint(1, 20) * 0.1


def jitter():
    """Introduce random jitter (sleep)"""
    time.sleep(jit())


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


@CacheLock()
def pod_state_transitions(pod_url=None):
    """
    Move pods through the various states while maintaining
    how long a pod should stay in a certain state as well

    http://kubernetes.io/docs/user-guide/pod-states/
    """
    pods = cache.get('pods_states', {})
    # Is there a new pod?
    if pod_url:
        state_time = datetime.utcnow() + timedelta(seconds=jit())
        pods[pod_url] = state_time

        # Initial state is Pending
        new_phase = 'Pending'
        pod = cache.get(pod_url)
        pod['status']['phase'] = new_phase
        cache.set(pod_url, pod)

    # Loops through all the pods to see if next phase needs to be done
    for pod_url, state_time in pods.items():
        if datetime.utcnow() < state_time:
            # it is not time yet!
            continue

        # Look at the current phase
        pod = cache.get(pod_url, None)
        if pod is None:
            continue

        # this needs to be done from "most advanced phase" to "earliest phase"

        # Is this Pod part of an RC or not
        if pod['status']['phase'] == 'Running':
            # Try to determine the connected RC / RS to readjust pod count
            # One way is to look at annotations:kubernetes.io/created-by and read
            # the serialized reference but that looks clunky right now

            if 'pod-template-hash' in pod['metadata']['labels']:
                controllers = filter_data({'labels': pod['metadata']['labels']}, 'replicasets')  # noqa
            else:
                controllers = filter_data({'labels': pod['metadata']['labels']}, 'replicationcontrollers')  # noqa

            # If Pod is in an RC then do nothing
            if not controllers:
                # If Pod is not in an RC then it needs to move forward
                pod['status']['phase'] = 'Succeeded'

        # Transition from Pending to Running
        if pod['status']['phase'] == 'Pending':
            pod['status']['phase'] = 'Running'

        cache.set(pod_url, pod)

    cache.set('pods_states', pods)


@CacheLock()
def cleanup_pods():
    """Can be called during any sort of access, it will cleanup pods as needed"""
    pods = cache.get('cleanup_pods', {})
    for pod, timestamp in pods.copy().items():
        if timestamp > datetime.utcnow():
            continue

        del pods[pod]
        remove_cache_item(pod, 'pods')
    cache.set('cleanup_pods', pods)


@CacheLock()
def add_cleanup_pod(url):
    """populate the cleanup pod list"""
    # variance allows a pod to stay alive past grace period
    variance = random.uniform(0.1, 1.5)
    grace = round(settings.KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS * variance)

    # save
    pods = cache.get('cleanup_pods', {})
    pods[url] = (datetime.utcnow() + timedelta(seconds=grace))
    cache.set('cleanup_pods', pods)

    # add grace period timestamp
    pod = cache.get(url)
    grace = settings.KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS
    pd = datetime.utcnow() + timedelta(seconds=grace)
    timestamp = str(pd.strftime(settings.DEIS_DATETIME_FORMAT))
    pod['metadata']['deletionTimestamp'] = timestamp
    cache.set(url, pod)


def delete_pod(url, data, request):
    # Try to determine the connected RC / RS to readjust pod count
    # One way is to look at annotations:kubernetes.io/created-by and read
    # the serialized reference but that looks clunky right now

    # Try RC first and then RS
    if 'pod-template-hash' in data['metadata']['labels']:
        controllers = filter_data({'labels': data['metadata']['labels']}, 'replicasets')
    else:
        controllers = filter_data({'labels': data['metadata']['labels']}, 'replicationcontrollers')

    if controllers:
        controller = controllers.pop()
        upsert_pods(controller, cache_key(request.path))
    else:
        # delete individual item
        delete_pods([url], 1, 0)


def delete_pods(pods, current, desired):
    if not pods:
        return

    delta = current - desired

    removed = []
    while True:
        if len(removed) == delta:
            break

        if not pods:
            break

        item = pods.pop()
        pod = cache.get(item)
        if 'deletionTimestamp' in pod['metadata']:
            continue

        removed.append(item)

    for item in removed:
        add_cleanup_pod(item)


def create_pods(url, labels, base, new_pods):
    # Start by fetching available pods in the Namespace that fit the profile
    # and prune down if needed, Otherwise go into the addition logic here
    for _ in range(new_pods):
        data = base.copy()
        # creation time
        timestamp = str(datetime.utcnow().strftime(settings.DEIS_DATETIME_FORMAT))
        data['metadata']['creationTimestamp'] = timestamp

        # generate the pod name and combine with RC name
        if 'generateName' in data['metadata']:
            data['metadata']['name'] = data['metadata']['generateName'] + pod_name()

        timestamp = str(datetime.utcnow().strftime(settings.DEIS_DATETIME_FORMAT))
        data['status'] = {
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
                    # TODO can be running / terminated / waiting
                    'state': {
                        'running': {
                            'startedAt': timestamp
                        }
                    }
                }
            ],
        }

        # Create the single resource with all its information
        pod_key = url
        if cache_key(data['metadata']['name']) not in url:
            pod_key = cache_key(url + '_' + data['metadata']['name'])

        add_cache_item(pod_key, 'pods', data)

        # set up a fake log for the pod
        log = "I did stuff today"
        pod_log_key = pod_key + '_log'
        cache.set(pod_log_key, log, None)

        # Add it to the transition loop
        pod_state_transitions(pod_key)


def upsert_pods(controller, url):
    # turn RC / RS (which a Deployment creates) url into pods one
    url = url.replace(cache_key(controller['metadata']['name']), '')
    if '_replicasets_' in url:
        url = url.replace('_replicasets_', '_pods').replace('apis_extensions_v1beta1', 'api_v1')  # noqa
    else:
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
        # skip pods being deleted
        if 'deletionTimestamp' in data['metadata']:
            continue

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
        return delete_pods(items, current, desired)

    create_pods(url, data['metadata']['labels'], data, delta)


@CacheLock()
def manage_replicasets(deployment, url):
    """
    Creates a new ReplicaSet, scales up the pods and
    scales down the old ReplicaSet (if applicable) to 0
    and terminates all Pods

    The input data is going to be a Deployment object
    """
    # reset Deployments status
    deployment['status']['replicas'] = deployment['spec']['replicas']
    deployment['status']['unavailableReplicas'] = deployment['spec']['replicas']
    if 'updatedReplicas' in deployment['status']:
        del deployment['status']['updatedReplicas']
    if 'availableReplicas' in deployment['status']:
        del deployment['status']['availableReplicas']
    cache.set(url, deployment, None)

    # hash deployment.spec.template with adler32 to get pod hash
    pod_hash = str(adler32(bytes(json.dumps(deployment['spec']['template'], sort_keys=True), 'UTF-8')))  # noqa

    # fix up url
    rs_url = url.replace('_deployments_', '_replicasets_')

    # create new RS
    rs = copy.deepcopy(deployment)
    rs['kind'] = 'ReplicaSet'
    # fix up the name
    rs['metadata']['name'] = rs['metadata']['name'] + '-' + pod_hash
    rs_url += '_' + pod_hash

    # add the pod-template-hash label
    rs['metadata']['labels'] = rs['spec']['template']['metadata']['labels'].copy()
    rs['metadata']['labels']['pod-template-hash'] = pod_hash
    rs['spec']['template']['metadata']['labels']['pod-template-hash'] = pod_hash

    # deployment only
    del rs['spec']['strategy']

    # save new ReplicaSet to cache
    add_cache_item(rs_url, 'replicasets', rs)

    namespaced_url = rs_url[0:(rs_url.find("_replicasets") + 12)]
    data = cache.get(namespaced_url, [])

    # spin up/down pods for RS
    upsert_pods(rs, rs_url)

    # Scale down older ReplicaSets
    for item in data:
        # skip latest
        if item == rs_url:
            continue

        old_rs = cache.get(item)

        # lame way of seeing if the RSs have the same Deployment parent
        # have to prune of hash as well
        deployment_url = item.replace('_replicasets_', '_deployments_').replace('_' + old_rs['metadata']['labels']['pod-template-hash'], '')  # noqa
        if url != deployment_url:
            continue

        if old_rs['spec']['replicas'] == 0:
            continue

        old_rs['spec']['replicas'] = 0

        upsert_pods(old_rs, item)

    # Fill out deployment.status for success as pods transition to running state
    pod_url = namespaced_url.replace('_replicasets', '_pods').replace('apis_extensions_v1beta1', 'api_v1')  # noqa
    while True:
        # The below needs to be done to emulate Deployment handling things
        # always cleanup pods
        cleanup_pods()
        # always transition pods
        pod_state_transitions()

        current = 0
        for pod in filter_data({'labels': rs['metadata']['labels']}, pod_url):
            # when this is in the Mock class this can be _pod_ready call
            if pod['status']['phase'] == 'Running':
                current += 1

        deployment['status']['updatedReplicas'] = current
        deployment['status']['availableReplicas'] = current
        deployment['status']['unavailableReplicas'] = deployment['spec']['replicas'] - current
        cache.set(url, deployment, None)

        # all ready and matching the intent
        if current == deployment['spec']['replicas']:
            break

        time.sleep(0.5)

    del deployment['status']['unavailableReplicas']
    cache.set(url, deployment, None)


def filter_data(filters, path):
    data = []
    rows = cache.get(path, [])
    for row in rows:
        item = cache.get(row)
        if not item:
            # item is broken
            continue

        # check if item has labels
        if 'labels' not in item['metadata']:
            continue

        # Do extra filtering based on labelSelector
        add = True
        for label, value in filters['labels'].items():
            # set based filter
            if '__' in label:
                label, matcher = label.split('__')
                if matcher == 'in':
                    if (
                        label not in item['metadata']['labels'] or
                        item['metadata']['labels'][label] not in value
                    ):
                        add = False
                        continue
                elif matcher == 'notin':
                    if (
                        label not in item['metadata']['labels'] or
                        item['metadata']['labels'][label] in value
                    ):
                        add = False
                        continue

            elif (
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
    filters = {'labels': {}, 'fields': {}}
    if query:
        # set based regex - does not support only field
        labelRegex = re.compile('^(?P<label>.*) (?P<matcher>notin|in)\s?\((?P<values>.*)\)$')

        queries = parse_qs(query)
        if 'labelSelector' in queries:
            for items in queries['labelSelector']:
                # split on , but not inside ()
                r = re.compile(r'(?:[^,(]|\([^)]*\))+')
                for item in r.findall(items):
                    if '=' in item:
                        # equal based requirement
                        key, value = item.split('=')
                        filters['labels'][key] = value
                    else:
                        # set based requirement
                        matches = labelRegex.match(item)
                        if matches is None:
                            continue

                        # split and strip spaces
                        values = [x.strip() for x in matches.group('values').split(',')]
                        key = matches.group('label') + '__' + matches.group('matcher')
                        filters['labels'][key] = values

        if 'fieldSelector' in queries:
            for items in queries['fieldSelector']:
                for item in items.split(','):
                    key, value = item.split('=')
                    filters['fields'][key] = value

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
    resource_type = get_type(request.url)
    # check if the namespace being posted to exists
    if resource_type != 'namespaces':
        namespace, _ = url.split('_{}_'.format(resource_type))
        namespace = namespace.replace('apis_extensions_v1beta1', 'api_v1')
        if cache.get(namespace) is None:
            context.status_code = 404
            context.reason = 'Not Found'
            return {}

    if cache.get(url) is not None:
        context.status_code = 409
        context.reason = 'Conflict'
        return {}

    # fill in generic data
    timestamp = str(datetime.utcnow().strftime(settings.DEIS_DATETIME_FORMAT))
    data['metadata']['creationTimestamp'] = timestamp
    data['metadata']['resourceVersion'] = 1

    # don't bother adding it to those two resources since they live outside namespace
    if resource_type not in ['nodes', 'namespaces']:
        namespace = request.url.replace(settings.SCHEDULER_URL + '/api/v1/namespaces/',  '')
        namespace = request.url.replace(settings.SCHEDULER_URL + '/apis/extensions/v1beta1/namespaces/',  '')  # noqa
        namespace = namespace.split('/')[0]
        data['metadata']['namespace'] = namespace

    # Handle RC / RS / Deployments
    if resource_type in ['replicationcontrollers', 'replicasets', 'deployments']:
        data['status'] = {
            'observedGeneration': 1
        }
        data['metadata']['generation'] = 1

        if resource_type in ['replicationcontrollers', 'replicasets']:
            upsert_pods(data, url)
        elif resource_type == 'deployments':
            manage_replicasets(data, url)

    # deis run is the only thing that creates pods directly
    if resource_type == 'pods':
        create_pods(url, data['metadata']['labels'], data, 1)
    else:
        add_cache_item(url, resource_type, data)

    context.status_code = 201
    context.reason = 'Created'
    return data


def put(request, context):
    """Process a PUT request to the kubernetes API"""
    url = cache_key(request.url)
    # type is the second last element
    resource_type = get_type(request.url, -2)
    # check if the namespace being posted to exists
    if resource_type != 'namespaces':
        namespace, _ = url.split('_{}_'.format(resource_type))
        namespace = namespace.replace('apis_extensions_v1beta1', 'api_v1')
        if cache.get(namespace) is None:
            context.status_code = 404
            context.reason = 'Not Found'
            return {}

    item = cache.get(url)
    if item is None:
        context.status_code = 404
        context.reason = 'Not Found'
        return {}

    data = request.json()

    # merge new data into old but keep labels separate in case they changed
    labels = data['metadata'].pop('labels')
    item['metadata'].update(data['metadata'])
    data['metadata'] = item['metadata']
    # make sure only new labels are used
    data['metadata']['labels'] = labels

    # split out deployments and replicasets? due to upsert_pods
    if resource_type in ['replicationcontrollers', 'replicasets', 'deployments']:
        if 'status' not in data:
            # just use what was set last time
            data['status'] = {'observedGeneration': item['status']['observedGeneration']}

        data['metadata']['resourceVersion'] += 1
        data['metadata']['generation'] += 1
        data['status']['observedGeneration'] += 1
        if resource_type in ['replicationcontrollers', 'replicasets']:
            upsert_pods(data, url)
        elif resource_type == 'deployments':
            manage_replicasets(data, url)

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

    resource_type = get_type(request.url, -2)
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
        # pods have a graceful termination period, handle pods different
        delete_pod(url, data, request)
    else:
        remove_cache_item(url, resource_type)

    # k8s API uses 200 instead of 204
    context.status_code = 200
    context.reason = 'OK'
    return {}


@CacheLock()
def add_cache_item(url, resource_type, data):
    cache.set(url, data, None)

    # Keep track of what resources are in a given resource
    items = cache.get(resource_type, [])
    if url not in items:
        items.append(url)
        cache.set(resource_type, items, None)

    # Keep track of what resources exist under other resources (mostly namespace)
    namespace, item = url.split('_{}_'.format(resource_type))
    cache_url = '{}_{}'.format(namespace, resource_type)
    items = cache.get(cache_url, [])
    if url not in items:
        items.append(url)
        cache.set(cache_url, items, None)


@CacheLock()
def remove_cache_item(url, resource_type):
    # remove data object from individual cache
    cache.delete(url)
    # get rid of log element as well for pods
    if resource_type == 'pod':
        cache.delete(url + '_log')

    # remove from the resource type global scope
    items = cache.get(resource_type, [])
    if url in items:
        items.remove(url)
        cache.set(resource_type, items, None)

    # remove from namespace specific scope
    namespace, item = url.split('_{}_'.format(resource_type))
    cache_url = '{}_{}'.format(namespace, resource_type)
    items = cache.get(cache_url, [])
    if url in items:
        items.remove(url)
    cache.set(cache_url, items, None)


def mock(request, context):
    # always cleanup pods
    cleanup_pods()
    # always transition pods
    pod_state_transitions()

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
            self.get_namespace('deis')
        except KubeHTTPException:
            self.create_namespace('deis')

        try:
            self.get_secret('deis', 'objectstorage-keyfile')
        except KubeHTTPException:
            secrets = {
                'access-key-id': 'i am a key',
                'access-secret-key': 'i am a secret'
            }
            self.create_secret('deis', 'objectstorage-keyfile', secrets)

        try:
            self.get_secret('deis', 'registry-secret')
        except KubeHTTPException:
            secrets = {
                'username': 'test',
                'password': 'test',
                'hostname': ''
            }
            self.create_secret('deis', 'registry-secret', secrets)

        try:
            self.get_namespace('duplicate')
        except KubeHTTPException:
            self.create_namespace('duplicate')

        try:
            self.get_node('172.17.8.100')
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
# POST (NI) | GET                           /namespaces/{namespace}/deployments  # noqa
# PATCH (NI) | PUT (NI) | GET | DELETE      /namespaces/{namespace}/deployments/{deployment}  # noqa
