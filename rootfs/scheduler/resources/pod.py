from collections import defaultdict
from datetime import datetime, timedelta
import operator
import os
import time

from scheduler.exceptions import KubeException, KubeHTTPException
from scheduler.resources import Resource
from scheduler.states import PodState


class Pod(Resource):
    short_name = 'po'

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single Pod or a list
        """
        url = '/namespaces/{}/pods'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Pod "{}" in Namespace "{}"'
        else:
            message = 'get Pods in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def create(self, namespace, name, image, **kwargs):
        manifest = self.manifest(namespace, name, image, **kwargs)

        url = self.api('/namespaces/{}/pods', namespace)
        response = self.http_post(url, json=manifest)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'create Pod in Namespace "{}"', namespace)

        # wait for all pods to start - use the same function as scale
        labels = manifest['metadata']['labels']
        containers = manifest['spec']['containers']
        self.pods.wait_until_ready(
            namespace,
            containers,
            labels,
            desired=kwargs.get('replicas'),
            timeout=kwargs.get('deploy_timeout')
        )

        return response

    def state(self, pod):
        """
        Resolve Pod state to an internally understandable format and returns a
        PodState object that can be used for comparison or name can get gotten
        via .name

        However if no match is found then a text representation is returned
        """
        # See "Pod Phase" at http://kubernetes.io/docs/user-guide/pod-states/
        if pod is None:
            return PodState.destroyed

        states = {
            'Pending': PodState.initializing,
            'ContainerCreating': PodState.creating,
            'Starting': PodState.starting,
            'Running': PodState.up,
            'Terminating': PodState.terminating,
            'Succeeded': PodState.down,
            'Failed': PodState.crashed,
            'Unknown': PodState.error,
        }

        # being in a Pending/ContainerCreating state can mean different things
        # introspecting app container first
        if pod['status']['phase'] in ['Pending', 'ContainerCreating']:
            pod_state, _ = self.pod.pending_status(pod)
        # being in a running state can mean a pod is starting, actually running or terminating
        elif pod['status']['phase'] == 'Running':
            # is the readiness probe passing?
            pod_state = self.readiness_status(pod)
            if pod_state in ['Starting', 'Terminating']:
                return states[pod_state]
            elif pod_state == 'Running' and self.liveness_status(pod):
                # is the pod ready to serve requests?
                return states[pod_state]
        else:
            # if no match was found for deis mapping then passthrough the real state
            pod_state = pod['status']['phase']

        return states.get(pod_state, pod_state)

    def manifest(self, namespace, name, image, **kwargs):
        app_type = kwargs.get('app_type')
        build_type = kwargs.get('build_type')

        # labels that represent the pod(s)
        labels = {
            'app': namespace,
            'version': kwargs.get('version'),
            'type': app_type,
            'heritage': 'deis',
        }

        # create base pod structure
        manifest = {
            'kind': 'Pod',
            'apiVersion': 'v1',
            'metadata': {
              'name': name,
              'namespace': namespace,
              'labels': labels
            },
            'spec': {}
        }

        # pod manifest spec
        spec = manifest['spec']

        # what should the pod do if it exits
        spec['restartPolicy'] = kwargs.get('restartPolicy', 'Always')

        # apply tags as needed to restrict pod to particular node(s)
        spec['nodeSelector'] = kwargs.get('tags', {'role': 'worker'})

        # How long until a pod is forcefully terminated. 30 is kubernetes default
        spec['terminationGracePeriodSeconds'] = kwargs.get('pod_termination_grace_period_seconds', 30)  # noqa

        # Check if it is a slug builder image.
        if build_type == "buildpack":
            # add the required volume to the top level pod spec
            spec['volumes'] = [{
                'name': 'objectstorage-keyfile',
                'secret': {
                    'secretName': 'objectstorage-keyfile'
                }
            }]

            # added to kwargs to send to the container function
            kwargs['volumeMounts'] = [{
                'name': 'objectstorage-keyfile',
                'mountPath': '/var/run/secrets/deis/objectstore/creds',
                'readOnly': True
            }]

        # create the base container
        container = {}

        # process to call
        if kwargs.get('command', []):
            container['command'] = kwargs.get('command')
        if kwargs.get('args', []):
            container['args'] = kwargs.get('args')

        # set information to the application container
        kwargs['image'] = image
        container_name = namespace + '-' + app_type
        self._set_container(namespace, container_name, container, **kwargs)
        # add image to the mix
        if kwargs.get('image_pull_secret_name', None) is not None:
            # apply image pull secret to a Pod spec
            spec['imagePullSecrets'] = [{'name': kwargs.get('image_pull_secret_name')}]

        spec['containers'] = [container]

        return manifest

    def _set_container(self, namespace, container_name, data, **kwargs):
        """Set app container information (env, healthcheck, etc) on a Pod"""
        env = kwargs.get('envs', {})

        # container name
        data['name'] = container_name
        # set the image to use
        data['image'] = kwargs.get('image')
        # set the image pull policy for the above image
        data['imagePullPolicy'] = kwargs.get('image_pull_policy')
        # add in any volumes that need to be mounted into the container
        data['volumeMounts'] = kwargs.get('volumeMounts', [])

        # create env list if missing
        if 'env' not in data:
            data['env'] = []

        if env:
            # map application configuration (env secret) to env vars
            secret_name = "{}-{}-env".format(namespace, kwargs.get('version'))
            for key in env.keys():
                item = {
                    "name": key,
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": secret_name,
                            # k8s doesn't allow _ so translate to -, see above
                            "key": key.lower().replace('_', '-')
                        }
                    }
                }

                # add value to env hash. Overwrite hardcoded values if need be
                match = next((k for k, e in enumerate(data["env"]) if e['name'] == key), None)
                if match is not None:
                    data["env"][match] = item
                else:
                    data["env"].append(item)

        # Inject debugging if workflow is in debug mode
        if os.environ.get("DEIS_DEBUG", False):
            data["env"].append({
                "name": "DEIS_DEBUG",
                "value": "1"
            })

        # list sorted by dict key name
        data['env'].sort(key=operator.itemgetter('name'))

        self._set_resources(data, kwargs)

        self._set_health_checks(data, env, **kwargs)

    def _set_resources(self, container, kwargs):
        """ Set CPU/memory resource management manifest """
        app_type = kwargs.get("app_type")
        mem = kwargs.get("memory", {}).get(app_type)
        cpu = kwargs.get("cpu", {}).get(app_type)

        if mem or cpu:
            resources = defaultdict(dict)

            if mem:
                if "/" in mem:
                    parts = mem.split("/")
                    resources["requests"]["memory"] = self._format_memory(parts[0])
                    resources["limits"]["memory"] = self._format_memory(parts[1])
                else:
                    resources["limits"]["memory"] = self._format_memory(mem)

            if cpu:
                # CPU needs to be defined as lower case
                if "/" in cpu:
                    parts = cpu.split("/")
                    resources["requests"]["cpu"] = parts[0].lower()
                    resources["limits"]["cpu"] = parts[1].lower()
                else:
                    resources["limits"]["cpu"] = cpu.lower()

            if resources:
                container["resources"] = dict(resources)

    def _format_memory(self, mem):
        """ Format memory limit value """
        if mem[-2:-1].isalpha() and mem[-1].isalpha():
            mem = mem[:-1]

        if mem[-1].isalpha():
            # memory needs to be upper cased (only first char)
            mem = mem.upper() + "i"
        return mem

    def _set_health_checks(self, container, env, **kwargs):
        healthchecks = kwargs.get('healthcheck', None)
        if healthchecks:
            # check if a port is present. if not, auto-populate it
            # TODO: rip this out when we stop supporting deis config:set HEALTHCHECK_URL
            if (
                healthchecks.get('livenessProbe') is not None and
                healthchecks['livenessProbe'].get('httpGet') is not None and
                healthchecks['livenessProbe']['httpGet'].get('port') is None
            ):
                healthchecks['livenessProbe']['httpGet']['port'] = env['PORT']
            container.update(healthchecks)
        elif kwargs.get('routable', False):
            self._default_readiness_probe(container, kwargs.get('build_type'), env.get('PORT', None))  # noqa

    def _default_readiness_probe(self, container, build_type, port=None):
        # Update only the application container with the health check
        if build_type == "buildpack":
            container.update(self._default_buildpack_readiness_probe())
        elif port:
            container.update(self._default_dockerapp_readiness_probe(port))

    """
    Applies exec readiness probe to the slugrunner container.
    http://kubernetes.io/docs/user-guide/pod-states/#container-probes

    /runner/init is the entry point of the slugrunner.
    https://github.com/deis/slugrunner/blob/01eac53f1c5f1d1dfa7570bbd6b9e45c00441fea/rootfs/Dockerfile#L20
    Once it downloads the slug it starts running using `exec` which means the pid 1
    will point to the slug/application command instead of entry point once the application has
    started.
    https://github.com/deis/slugrunner/blob/01eac53f1c5f1d1dfa7570bbd6b9e45c00441fea/rootfs/runner/init#L90

    This should be added only for the build pack apps when a custom liveness probe is not set to
    make sure that the pod is ready only when the slug is downloaded and started running.
    """
    def _default_buildpack_readiness_probe(self, delay=30, timeout=5, period_seconds=5,
                                           success_threshold=1, failure_threshold=1):
        readinessprobe = {
            'readinessProbe': {
                # an exec probe
                'exec': {
                    "command": [
                        "bash",
                        "-c",
                        "[[ '$(ps -p 1 -o args)' != *'bash /runner/init'* ]]"
                    ]
                },
                # length of time to wait for a pod to initialize
                # after pod startup, before applying health checking
                'initialDelaySeconds': delay,
                'timeoutSeconds': timeout,
                'periodSeconds': period_seconds,
                'successThreshold': success_threshold,
                'failureThreshold': failure_threshold,
            },
        }
        return readinessprobe

    def _default_dockerapp_readiness_probe(self, port, delay=5, timeout=5, period_seconds=5,
                                           success_threshold=1, failure_threshold=1):
        """
        Applies tcp socket readiness probe to the docker app container only if some port is exposed
        by the docker image.
        """
        readinessprobe = {
            'readinessProbe': {
                # an exec probe
                'tcpSocket': {
                    "port": int(port)
                },
                # length of time to wait for a pod to initialize
                # after pod startup, before applying health checking
                'initialDelaySeconds': delay,
                'timeoutSeconds': timeout,
                'periodSeconds': period_seconds,
                'successThreshold': success_threshold,
                'failureThreshold': failure_threshold,
            },
        }
        return readinessprobe

    def delete(self, namespace, name):
        # get timeout info from pod
        pod = self.pod.get(namespace, name).json()
        # 30 seconds is the kubernetes default
        timeout = pod['spec'].get('terminationGracePeriodSeconds', 30)

        # delete pod
        url = self.api("/namespaces/{}/pods/{}", namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'delete Pod "{}" in Namespace "{}"', name, namespace)

        # Verify the pod has been deleted
        # Only wait as long as the grace period is - k8s will eventually GC
        for _ in range(timeout):
            try:
                pod = self.pod.get(namespace, name).json()
                # hide pod if it is passed the graceful termination period
                if self.deleted(pod):
                    return
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    break

            time.sleep(1)

        return response

    def logs(self, namespace, name):
        url = self.api("/namespaces/{}/pods/{}/log", namespace, name)
        response = self.http_get(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get logs for Pod "{}" in Namespace "{}"', name, namespace
            )

        return response

    def ready(self, pod):
        """Combines various checks to see if the pod is considered up or not by checking probes"""
        return (
            pod['status']['phase'] == 'Running' and
            # is the readiness probe passing?
            self.readiness_status(pod) == 'Running' and
            # is the pod ready to serve requests?
            self.liveness_status(pod)
        )

    def readiness_status(self, pod):
        """Check if the pod container have passed the readiness probes"""
        name = '{}-{}'.format(pod['metadata']['labels']['app'], pod['metadata']['labels']['type'])
        # find the right container in case there are many on the pod
        container = self.find_container(name, pod['status']['containerStatuses'])
        if container is None:
            # Seems like the most sensible default
            return 'Unknown'

        if not container['ready']:
            if 'running' in container['state'].keys():
                return 'Starting'

            if (
                'terminated' in container['state'].keys() or
                'deletionTimestamp' in pod['metadata']
            ):
                return 'Terminating'
        else:
            # See if k8s is in Terminating state
            if 'deletionTimestamp' in pod['metadata']:
                return 'Terminating'

            return 'Running'

        # Seems like the most sensible default
        return 'Unknown'

    def liveness_status(self, pod):
        """Check if the pods liveness probe status has passed all checks"""
        for condition in pod['status']['conditions']:
            # type = Ready is the only binary type right now
            if condition['type'] == 'Ready' and condition['status'] != 'True':
                return False

        return True

    def deleted(self, pod):
        """Checks if a pod is deleted and past its graceful termination period"""
        # https://github.com/kubernetes/kubernetes/blob/release-1.2/docs/devel/api-conventions.md#metadata
        # http://kubernetes.io/docs/user-guide/pods/#termination-of-pods
        if 'deletionTimestamp' in pod['metadata']:
            # past the graceful deletion period
            deletion = self.parse_date(pod['metadata']['deletionTimestamp'])
            if deletion < datetime.utcnow():
                return True

        return False

    def pending_status(self, pod):
        """Introspect the pod containers when pod is in Pending state"""
        if 'containerStatuses' not in pod['status']:
            return 'Pending', ''

        name = '{}-{}'.format(pod['metadata']['labels']['app'], pod['metadata']['labels']['type'])
        # find the right container in case there are many on the pod
        container = self.pod.find_container(name, pod['status']['containerStatuses'])
        if container is None:
            # Return Pending if nothing else can be found
            return 'Pending', ''

        if 'waiting' in container['state']:
            reason = container['state']['waiting']['reason']
            message = ''
            # message is not always available
            if 'message' in container['state']['waiting']:
                message = container['state']['waiting']['message']

            if reason == 'ContainerCreating':
                # get the last event
                events = self.events(pod)
                if not events:
                    # could not find any events
                    return reason, message

                event = events.pop()
                return event['reason'], event['message']

            return reason, message

        # Return Pending if nothing else can be found
        return 'Pending', ''

    def events(self, pod):
        """Process events for a given Pod to find if Pulling is happening, among other events"""
        # fetch all events for this pod
        fields = {
            'involvedObject.name': pod['metadata']['name'],
            'involvedObject.namespace': pod['metadata']['namespace'],
            'involvedObject.uid': pod['metadata']['uid']
        }
        events = self.ns.events(pod['metadata']['namespace'], fields=fields).json()
        # make sure that events are sorted
        events['items'].sort(key=lambda x: x['lastTimestamp'])
        return events['items']

    def _handle_pod_errors(self, pod, reason, message):
        """
        Handle potential pod errors based on the Pending
        reason passed into the function

        Images, FailedScheduling and others are needed
        """
        # image error reported on the container level
        container_errors = [
            'Pending',  # often an indication of deeper inspection is needed
            'ErrImagePull',
            'ImagePullBackOff',
            'RegistryUnavailable',
            'ErrImageInspect',
        ]
        # Image event reason mapping
        event_errors = {
            "Failed": "FailedToPullImage",
            "InspectFailed": "FailedToInspectImage",
            "ErrImageNeverPull": "ErrImageNeverPullPolicy",
            # Not including this one for now as the message is not useful
            # "BackOff": "BackOffPullImage",
            # FailedScheduling relates limits
            "FailedScheduling": "FailedScheduling",
        }

        # Nicer error than from the event
        # Often this gets to ImageBullBackOff before we can introspect tho
        if reason == 'ErrImagePull':
            raise KubeException(message)

        # collect all error messages of worth
        messages = []
        if reason in container_errors:
            for event in self.events(pod):
                if event['reason'] in event_errors.keys():
                    # only show a given error once
                    event_errors.pop(event['reason'])
                    # strip out whitespaces on either side
                    message = "\n".join([x.strip() for x in event['message'].split("\n")])
                    messages.append(message)

        if messages:
            raise KubeException("\n".join(messages))

    def _handle_long_image_pulling(self, reason, pod):
        """
        If pulling an image is taking long (1 minute) then return how many seconds
        the pod ready state timeout should be extended by

        Return value is an int that represents seconds
        """
        # only apply once
        if getattr(self, '_handle_long_image_pulling_applied', False):
            return 0

        if reason is not 'Pulling':
            return 0

        # last event should be Pulling in this case
        event = self.events(pod).pop()
        # see if pull operation has been happening for over 1 minute
        seconds = 60  # time threshold before padding timeout
        start = self.parse_date(event['firstTimestamp'])
        if (start + timedelta(seconds=seconds)) < datetime.utcnow():
            # make it so function doesn't do processing again
            setattr(self, '_handle_long_image_pulling_applied', True)
            return 600

        return 0

    def _handle_pending_pods(self, namespace, labels):
        """
        Detects if any pod is in the starting phases and handles
        any potential issues around that, and increases timeouts
        or throws errors as needed
        """
        timeout = 0
        pods = self.get(namespace, labels=labels).json()
        for pod in pods['items']:
            # only care about pods that are not starting or in the starting phases
            if pod['status']['phase'] not in ['Pending', 'ContainerCreating']:
                continue

            # Get more information on why a pod is pending
            reason, message = self.pending_status(pod)
            # If pulling an image is taking long then increase the timeout
            timeout += self._handle_long_image_pulling(pod, reason)

            # handle errors and bubble up if need be
            self._handle_pod_errors(pod, reason, message)

        return timeout

    def find_container(self, container_name, containers):
        """
        Locate a container by name in a list of containers
        """
        for container in containers:
            if container['name'] == container_name:
                return container

        return None

    def wait_until_terminated(self, namespace, labels, current, desired):
        """Wait until all the desired pods are terminated"""
        # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_podspec
        # https://github.com/kubernetes/kubernetes/blob/release-1.2/docs/devel/api-conventions.md#metadata
        # http://kubernetes.io/docs/user-guide/pods/#termination-of-pods

        # fetch timeout from the first pod
        pods = self.get(namespace, labels=labels).json()
        if not pods['items']:
            return

        spec = pods['items'][0]['spec']
        # default to 30 since that's kubernetes default
        timeout = spec.get('terminationGracePeriodSeconds', 30)

        delta = current - desired
        self.log(namespace, "waiting for {} pods to be terminated ({}s timeout)".format(delta, timeout))  # noqa
        for waited in range(timeout):
            pods = self.get(namespace, labels=labels).json()
            count = len(pods['items'])

            # see if any pods are past their terminationGracePeriodsSeconds (as in stuck)
            # seems to be a problem in k8s around that:
            # https://github.com/kubernetes/kubernetes/search?q=terminating&type=Issues
            # these will be eventually GC'ed by k8s, ignoring them for now
            for pod in pods['items']:
                # remove pod if it is passed the graceful termination period
                if self.deleted(pod):
                    count -= 1

            # stop when all pods are terminated as expected
            if count == desired:
                break

            if waited > 0 and (waited % 10) == 0:
                self.log(namespace, "waited {}s and {} pods out of {} are fully terminated".format(waited, (delta - count), delta))  # noqa

            time.sleep(1)

        self.log(namespace, "{} pods are terminated".format(delta))

    def wait_until_ready(self, namespace, containers, labels, desired, timeout):  # noqa
        # If desired is 0 then there is no ready state to check on
        if desired == 0:
            return

        timeout = self.deploy_probe_timeout(timeout, namespace, labels, containers)
        self.log(namespace, "waiting for {} pods in {} namespace to be in services ({}s timeout)".format(desired, namespace, timeout))  # noqa

        # Ensure the minimum desired number of pods are available
        waited = 0
        while waited < timeout:
            # figure out if there are any pending pod issues
            additional_timeout = self._handle_pending_pods(namespace, labels)
            if additional_timeout:
                timeout += additional_timeout
                # add 10 minutes to timeout to allow a pull image operation to finish
                self.log(namespace, 'Kubernetes has been pulling the image for {}s'.format(waited))  # noqa
                self.log(namespace, 'Increasing timeout by {}s to allow a pull image operation to finish for pods'.format(additional_timeout))  # noqa

            count = 0  # ready pods
            pods = self.get(namespace, labels=labels).json()
            for pod in pods['items']:
                # now that state is running time to see if probes are passing
                if self.ready(pod):
                    count += 1
                    continue

                # Find out if any pod goes beyond the Running (up) state
                # Allow that to happen to account for very fast `deis run` as
                # an example. Code using this function will account for it
                state = self.state(pod)
                if isinstance(state, PodState) and state > PodState.up:
                    count += 1
                    continue

            if count == desired:
                break

            if waited > 0 and (waited % 10) == 0:
                self.log(namespace, "waited {}s and {} pods are in service".format(waited, count))

            # increase wait time without dealing with jitters from above code
            waited += 1
            time.sleep(1)

        # timed out
        if waited > timeout:
            self.log(namespace, 'timed out ({}s) waiting for pods to come up in namespace {}'.format(timeout, namespace))  # noqa

        self.log(namespace, "{} out of {} pods are in service".format(count, desired))  # noqa

    def _handle_not_ready_pods(self, namespace, labels):
        """
        Detects if any pod is in the Running phase but not Ready and handles
        any potential issues around that mainly failed healthcheks
        """
        pods = self.get(namespace, labels=labels).json()
        for pod in pods['items']:
            # only care about pods that are in running phase
            if pod['status']['phase'] != 'Running':
                continue

            name = '{}-{}'.format(pod['metadata']['labels']['app'], pod['metadata']['labels']['type'])  # noqa
            # find the right container in case there are many on the pod
            container = self.find_container(name, pod['status']['containerStatuses'])
            if container is None or container['ready'] == 'true':
                continue

            for event in self.events(pod):
                if event['reason'] == 'Unhealthy':
                    # strip out whitespaces on either side
                    message = "\n".join([x.strip() for x in event['message'].split("\n")])
                    raise KubeException(message)

        return None

    def deploy_probe_timeout(self, timeout, namespace, labels, containers):
        """
        Added in additional timeouts based on readiness and liveness probe

        Uses the max of the two instead of combining them as the checks are stacked.
        """

        container_name = '{}-{}'.format(labels['app'], labels['type'])
        container = self.pod.find_container(container_name, containers)

        # get health info from container
        added_timeout = []
        if 'readinessProbe' in container:
            # If there is initial delay on the readiness check then timeout needs to be higher
            # this is to account for kubernetes having readiness check report as failure until
            # the initial delay period is up
            added_timeout.append(int(container['readinessProbe'].get('initialDelaySeconds', 50)))

        if 'livenessProbe' in container:
            # If there is initial delay on the readiness check then timeout needs to be higher
            # this is to account for kubernetes having liveness check report as failure until
            # the initial delay period is up
            added_timeout.append(int(container['livenessProbe'].get('initialDelaySeconds', 50)))

        if added_timeout:
            delay = max(added_timeout)
            self.log(namespace, "adding {}s on to the original {}s timeout to account for the initial delay specified in the liveness / readiness probe".format(delay, timeout))  # noqa
            timeout += delay

        return timeout
