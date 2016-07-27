from collections import OrderedDict
from datetime import datetime, timedelta
import json
import logging
import operator
import os
import string
import time
from urllib.parse import urljoin
import base64

from django.conf import settings
from docker.auth import auth as docker_auth
from .states import PodState
import ruamel.yaml
import requests
from requests_toolbelt import user_agent
from .utils import dict_merge

from deis import __version__ as deis_version


logger = logging.getLogger(__name__)

# Ports and app type will be overwritten as required
SERVICE_TEMPLATE = """\
kind: Service
apiVersion: v1
metadata:
  name: $name
  labels:
    app: $name
    heritage: deis
  annotations: {}
spec:
  ports:
    - name: http
      port: 80
      targetPort: 5000
      protocol: TCP
  selector:
    app: $name
    heritage: deis
"""


class KubeException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class KubeHTTPException(KubeException):
    def __init__(self, response, errmsg, *args, **kwargs):
        self.response = response

        msg = errmsg.format(*args)
        msg = "failed to {}: {} {}\n{}".format(
            msg,
            response.status_code,
            response.reason,
            response.json()
        )
        KubeException.__init__(self, msg, *args, **kwargs)


def unhealthy(status_code):
    if not 200 <= status_code <= 299:
        return True

    return False


session = None


def get_session():
    global session
    if session is None:
        with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as token_file:
            token = token_file.read()
        session = requests.Session()
        session.headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'User-Agent': user_agent('Deis Controller', deis_version)
        }
        session.verify = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
    return session


class KubeHTTPClient(object):
    # used as the basis to check if a pod is ready
    deploy_timeout = 120
    apiversion = "v1"

    def __init__(self):
        self.url = settings.SCHEDULER_URL
        self.session = get_session()

    def log(self, namespace, message, level=logging.INFO):
        """Logs a message in the context of this application.

        This prefixes log messages with a namespace "tag".
        When it's seen, the message-- usually an application event of some
        sort like releasing or scaling, will be considered as "belonging" to the application
        instead of the controller and will be handled accordingly.
        """
        logger.log(level, "[{}]: {}".format(namespace, message))

    def deploy(self, namespace, name, image, entrypoint, command, **kwargs):  # noqa
        """Scale RC or Deployment depending on what's requested"""
        self.deploy_timeout = kwargs.get('deploy_timeout')
        if kwargs.get('deployments', False):
            self.deploy_deployment(namespace, name, image, entrypoint, command, **kwargs)
        else:
            self.deploy_rc(namespace, name, image, entrypoint, command, **kwargs)

    def deploy_deployment(self, namespace, name, image, entrypoint, command, **kwargs):  # noqa
        app_type = kwargs.get('app_type')
        routable = kwargs.get('routable', False)
        envs = kwargs.get('envs', {})
        port = envs.get('PORT', None)

        # create a deployment if missing, otherwise update to trigger a release
        try:
            deployment = self.get_deployment(namespace, name).json()
            # labels that represent the pod(s)
            version = kwargs.get('version')
            labels = {
                'app': namespace,
                'version': version,
                'type': app_type,
                'heritage': 'deis',
            }
            # this depends on the deployment object having the latest information
            if deployment['spec']['template']['metadata']['labels'] == labels:
                self.log(namespace, 'Deployment {} with release {} already exists. Stopping deploy'.format(name, version))  # noqa
                return
        except KubeException:
            # create the initial deployment object (and the first revision)
            self.create_deployment(namespace,
                                   name,
                                   image,
                                   entrypoint,
                                   command,
                                   **kwargs)
        else:
            try:
                # kick off a new revision of the deployment
                self.update_deployment(namespace,
                                       name,
                                       image,
                                       entrypoint,
                                       command,
                                       **kwargs)
            except KubeException as e:
                # rollback to the previous Deployment
                kwargs['rollback'] = True
                self.update_deployment(namespace,
                                       name,
                                       image,
                                       entrypoint,
                                       command,
                                       **kwargs)

                raise KubeException(
                    'There was a problem while deploying {} of {}-{}. '
                    'Going back to the previous release'.format(version, namespace, app_type)
                ) from e

        # Make sure the application is routable and uses the correct port
        # Done after the fact to let initial deploy settle before routing
        # traffic to the application
        self._update_application_service(namespace, name, app_type, port, routable)

    def deploy_rc(self, namespace, name, image, entrypoint, command, **kwargs):  # noqa
        app_type = kwargs.get('app_type')
        routable = kwargs.get('routable', False)
        envs = kwargs.get('envs', {})
        port = envs.get('PORT', None)
        timeout = kwargs.get('deploy_timeout')

        # Fetch old RC and create the new one for a release
        old_rc = self.get_old_rc(namespace, app_type)

        # If an RC already exists then stop processing of the deploy
        try:
            self.get_rc(namespace, name)
            self.log(namespace, 'RC {} already exists. Stopping deploy'.format(name))  # noqa
            return
        except KubeHTTPException:
            # make replicas 0 so scaling handles the work
            replicas = kwargs.pop('replicas')
            new_rc = self.create_rc(
                namespace,
                name,
                image,
                entrypoint,
                command,
                replicas=0,
                **kwargs).json()
            kwargs['replicas'] = replicas

        # Get the desired number to scale to
        if old_rc:
            desired = int(old_rc["spec"]["replicas"])
        else:
            desired = kwargs['replicas']
            self.log(namespace, 'No prior RC could be found for {}'.format(app_type))

        # see if application or global deploy batches are defined
        batches = kwargs.get('deploy_batches', None)
        tags = kwargs.get('tags', {})
        steps = self._get_deploy_steps(batches, tags)
        batches = self._get_deploy_batches(steps, desired)

        try:
            count = 0
            new_name = new_rc["metadata"]["name"]
            for batch in batches:
                count += batch
                self.log(namespace, 'scaling release {} to {} out of final {}'.format(
                    new_name, count, desired
                ))
                self._scale_rc(namespace, new_name, count, timeout)

                if old_rc:
                    old_name = old_rc["metadata"]["name"]
                    self.log(namespace, 'scaling old release {} from original {} to {}'.format(
                        old_name, desired, (desired-count))
                    )
                    self._scale_rc(namespace, old_name, (desired-count), timeout)
        except Exception as e:
            # New release is broken. Clean up

            # Remove new release of the RC
            self.cleanup_release(namespace, new_rc, timeout)

            # If there was a previous release then bring that back
            if old_rc:
                self._scale_rc(namespace, old_rc["metadata"]["name"], desired, timeout)

            raise KubeException(
                'Could not scale {} to {}. '
                'Deleting and going back to old release'.format(
                    new_rc["metadata"]["name"], desired
                )
            ) from e

        # New release is live and kicking. Clean up old release
        if old_rc:
            self.cleanup_release(namespace, old_rc, timeout)

        # Make sure the application is routable and uses the correct port
        # Done after the fact to let initial deploy settle before routing
        # traffic to the application
        self._update_application_service(namespace, name, app_type, port, routable)

    def cleanup_release(self, namespace, controller, timeout):
        """
        Cleans up resources related to an application deployment
        """
        # Deployment takes care of this in the API, RC does not
        # Have the RC scale down pods and delete itself
        self._scale_rc(namespace, controller['metadata']['name'], 0, timeout)
        self.delete_rc(namespace, controller['metadata']['name'])

        # Remove stray pods that the scale down will have missed (this can occassionally happen)
        pods = self.get_pods(namespace, labels=controller['metadata']['labels']).json()
        for pod in pods['items']:
            if self.pod_deleted(pod):
                continue

            self.delete_pod(namespace, pod['metadata']['name'])

    def _get_deploy_steps(self, batches, tags):
        # if there is no batch information available default to available nodes for app
        if not batches:
            # figure out how many nodes the application can go on
            steps = len(self.get_nodes(labels=tags).json()['items'])
        else:
            steps = int(batches)

        return steps

    def _get_deploy_batches(self, steps, desired):
        # figure out what kind of batches the deploy is done in - 1 in, 1 out or higher
        if desired < steps:
            # do it all in one go
            batches = [desired]
        else:
            # figure out the stepped deploy count and then see if there is a leftover
            batches = [steps for n in set(range(1, (desired + 1))) if n % steps == 0]
            if desired - sum(batches) > 0:
                batches.append(desired - sum(batches))

        return batches

    def _update_application_service(self, namespace, name, app_type, port, routable=False):
        """Update application service with all the various required information"""
        service = self.get_service(namespace, namespace).json()
        old_service = service.copy()  # in case anything fails for rollback

        try:
            # Update service information
            if routable:
                service['metadata']['labels']['router.deis.io/routable'] = 'true'

            # Set app type if there is not one available
            if 'type' not in service['spec']['selector']:
                service['spec']['selector']['type'] = app_type

            # Find if target port exists already, update / create as required
            if routable:
                for pos, item in enumerate(service['spec']['ports']):
                    if item['port'] == 80 and port != item['targetPort']:
                        # port 80 is the only one we care about right now
                        service['spec']['ports'][pos]['targetPort'] = int(port)

            self.update_service(namespace, namespace, data=service)
        except Exception as e:
            # Fix service to old port and app type
            self.update_service(namespace, namespace, data=old_service)
            raise KubeException(str(e)) from e

    def scale(self, namespace, name, image, entrypoint, command, **kwargs):
        """Scale RC or Deployment depending on what's requested"""
        self.deploy_timeout = kwargs.get('deploy_timeout')
        if kwargs.get('deployments', False):
            self.scale_deployment(namespace, name, image, entrypoint, command, **kwargs)
        else:
            self.scale_rc(namespace, name, image, entrypoint, command, **kwargs)

    def scale_deployment(self, namespace, name, image, entrypoint, command, **kwargs):
        try:
            self.get_deployment(namespace, name)
        except KubeHTTPException as e:
            if e.response.status_code == 404:
                # create missing deployment - deleted if it fails
                try:
                    self.create_deployment(namespace, name, image, entrypoint, command, **kwargs)
                except KubeException:
                    self.delete_deployment(namespace, name)
                    raise

        # let the scale failure bubble up
        self._scale_deployment(namespace, name, image, entrypoint, command, **kwargs)

    def scale_rc(self, namespace, name, image, entrypoint, command, **kwargs):
        replicas = kwargs.pop('replicas')
        try:
            self.get_rc(namespace, name)
        except KubeHTTPException as e:
            if e.response.status_code == 404:
                # add RC if it is missing for the namespace
                try:
                    # Create RC with scale as 0 and then scale to get pod monitoring
                    kwargs['replicas'] = 0
                    self.create_rc(namespace, name, image, entrypoint, command, **kwargs)
                except KubeException:
                    logger.exception("Creating RC {} failed".format(name))
                    raise

        # let the scale failure bubble up
        self._scale_rc(namespace, name, replicas, kwargs.get('deploy_timeout'))

    def _build_pod_manifest(self, namespace, name, image, **kwargs):
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
              'labels': labels
            },
            'spec': {}
        }

        # pod manifest spec
        spec = manifest['spec']

        # what should the pod do if it exits
        spec['restartPolicy'] = kwargs.get('restartPolicy', 'Always')

        # apply tags as needed to restrict pod to particular node(s)
        spec['nodeSelector'] = kwargs.get('tags', {})

        # How long until a pod is forcefully terminated
        spec['terminationGracePeriodSeconds'] = settings.KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS  # noqa

        # set the image pull policy that is associated with the application container
        kwargs['image_pull_policy'] = settings.DOCKER_BUILDER_IMAGE_PULL_POLICY

        # mix in default environment information deis may require
        default_env = {
            'DEIS_APP': namespace,
            'WORKFLOW_RELEASE': kwargs.get("version")
        }

        # Check if it is a slug builder image.
        if build_type == "buildpack":
            # only buildpack apps need access to object storage
            try:
                self.get_secret(namespace, 'objectstorage-keyfile')
            except KubeException:
                secret = self.get_secret('deis', 'objectstorage-keyfile').json()
                self.create_secret(namespace, 'objectstorage-keyfile', secret['data'])

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

            default_env['SLUG_URL'] = image
            default_env['BUILDER_STORAGE'] = os.getenv("APP_STORAGE")
            default_env['DEIS_MINIO_SERVICE_HOST'] = os.getenv("DEIS_MINIO_SERVICE_HOST")
            default_env['DEIS_MINIO_SERVICE_PORT'] = os.getenv("DEIS_MINIO_SERVICE_PORT")

            # overwrite image so slugrunner image is used in the container
            image = settings.SLUGRUNNER_IMAGE
            # slugrunner pull policy
            kwargs['image_pull_policy'] = settings.SLUG_BUILDER_IMAGE_PULL_POLICY

        envs = kwargs.get('envs', {})
        default_env.update(envs)
        kwargs['envs'] = default_env

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
        self._set_image_secret(spec, namespace, **kwargs)

        spec['containers'] = [container]

        return manifest

    def run(self, namespace, name, image, entrypoint, command, **kwargs):
        """Run a one-off command."""
        self.log(namespace, 'run {}, img {}, entrypoint {}, cmd "{}"'.format(
            name, image, entrypoint, command)
        )

        # force the app_type
        kwargs['app_type'] = 'run'
        # run pods never restart
        kwargs['restartPolicy'] = 'Never'
        kwargs['command'] = entrypoint
        kwargs['args'] = command

        manifest = self._build_pod_manifest(namespace, name, image, **kwargs)

        url = self._api("/namespaces/{}/pods", namespace)
        response = self.session.post(url, json=manifest)
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'create Pod in Namespace "{}"', namespace)

        # wait for run pod to start - use the same function as scale
        labels = manifest['metadata']['labels']
        containers = manifest['spec']['containers']
        self._wait_until_pods_are_ready(
            namespace,
            containers,
            labels,
            desired=1,
            timeout=kwargs.get('deploy_timeout')
        )

        try:
            # give pod 20 minutes to execute (after it got into ready state)
            # this is a fairly arbitrary limit but the gunicorn worker / LBs
            # will make this timeout around 20 anyway.
            # TODO: Revisit in the future so it can run longer
            state = 'up'  # pod is still running
            waited = 0
            timeout = 1200  # 20 minutes
            while (state == 'up' and waited < timeout):
                response = self.get_pod(namespace, name)
                pod = response.json()
                state = str(self.pod_state(pod))
                # default data
                exit_code = 0

                waited += 1
                time.sleep(1)

            if state == 'down':  # run finished successfully
                exit_code = 0  # successful run
            elif state == 'crashed':  # run failed
                pod_state = pod['status']['containerStatuses'][0]['state']
                exit_code = pod_state['terminated']['exitCode']

            # timed out!
            if waited == timeout:
                raise KubeException('Timed out (20 mins) while running')

            # check if it is possible to get logs
            state = self.pod_state(self.get_pod(namespace, name).json())
            # States below up do not have logs
            if state < PodState.up:
                return exit_code, 'Could not get logs. Pod is in state {}'.format(str(state))

            # grab log information
            log = self._pod_log(namespace, name)
            log.encoding = 'utf-8'  # defaults to "ISO-8859-1" otherwise...

            return exit_code, log.text
        finally:
            # cleanup
            self.delete_pod(namespace, name)

    def _set_container(self, namespace, container_name, data, **kwargs):  # noqa
        """Set app container information (env, healthcheck, etc) on a Pod"""
        app_type = kwargs.get('app_type')
        mem = kwargs.get('memory', {}).get(app_type)
        cpu = kwargs.get('cpu', {}).get(app_type)
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
            # env vars are stored in secrets and mapped to env in k8s
            try:
                labels = {
                    'version': kwargs.get('version'),
                    'type': 'env'
                }

                # secrets use dns labels for keys, map those properly here
                secrets_env = {}
                for key, value in env.items():
                    secrets_env[key.lower().replace('_', '-')] = str(value)

                # dictionary sorted by key
                secrets_env = OrderedDict(sorted(secrets_env.items(), key=lambda t: t[0]))

                secret_name = "{}-{}-env".format(namespace, kwargs.get('version'))
                self.get_secret(namespace, secret_name)
            except KubeHTTPException:
                self.create_secret(namespace, secret_name, secrets_env, labels=labels)
            else:
                self.update_secret(namespace, secret_name, secrets_env, labels=labels)

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

        if mem or cpu:
            data["resources"] = {"limits": {}}

        if mem:
            if mem[-2:-1].isalpha() and mem[-1].isalpha():
                mem = mem[:-1]

            # memory needs to be upper cased (only first char)
            mem = mem.upper() + "i"
            data["resources"]["limits"]["memory"] = mem

        if cpu:
            # CPU needs to be defined as lower case
            data["resources"]["limits"]["cpu"] = cpu.lower()

        # add in healthchecks
        healthchecks = kwargs.get('healthcheck', None)
        if healthchecks and kwargs.get('routable', False):
            # check if a port is present. if not, auto-populate it
            # TODO: rip this out when we stop supporting deis config:set HEALTHCHECK_URL
            if (
                healthchecks.get('livenessProbe') is not None and
                healthchecks['livenessProbe'].get('httpGet') is not None and
                healthchecks['livenessProbe']['httpGet'].get('port') is None
            ):
                healthchecks['livenessProbe']['httpGet']['port'] = env['PORT']
            data.update(healthchecks)
        else:
            self._default_readiness_probe(data, kwargs.get('build_type'), env.get('PORT', None))

    def _get_private_registry_config(self, registry, image):
        # try to get the hostname information
        hostname = registry.get('hostname', None)
        if not hostname:
            hostname, _ = docker_auth.split_repo_name(image)
        if hostname == docker_auth.INDEX_NAME:
            hostname = "https://index.docker.io/v1/"

        # create / update private registry secret
        auth = bytes('{}:{}'.format(registry.get('username'), registry.get('password')), 'UTF-8')
        # value has to be a base64 encoded JSON
        docker_config = json.dumps({
            "auths": {
                hostname: {
                    "auth": base64.b64encode(auth).decode(encoding='UTF-8')
                }
            }
        })
        return docker_config

    def _set_image_secret(self, data, namespace, **kwargs):
        """
        Take registry information and set as an imagePullSecret for an RC / Deployment
        http://kubernetes.io/docs/user-guide/images/#specifying-imagepullsecrets-on-a-pod
        """
        registry = kwargs.get('registry', {})
        if not registry:
            return
        docker_config = self._get_private_registry_config(registry, kwargs.get('image'))  # noqa
        secret_data = {'.dockerconfigjson': docker_config}

        secret_name = 'private-registry'
        try:
            self.get_secret(namespace, secret_name)
        except KubeHTTPException:
            self.create_secret(
                namespace,
                secret_name,
                secret_data,
                secret_type='kubernetes.io/dockerconfigjson'
            )
        else:
            self.update_secret(
                namespace,
                secret_name,
                secret_data,
                secret_type='kubernetes.io/dockerconfigjson'
            )

        # apply image pull secret to a Pod spec
        data['imagePullSecrets'] = [{'name': secret_name}]

    def pod_state(self, pod):
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
            pod_state, _ = self._pod_pending_status(pod)
        # being in a running state can mean a pod is starting, actually running or terminating
        elif pod['status']['phase'] == 'Running':
            # is the readiness probe passing?
            pod_state = self._pod_readiness_status(pod)
            if pod_state in ['Starting', 'Terminating']:
                return states[pod_state]
            elif pod_state == 'Running' and self._pod_liveness_status(pod):
                # is the pod ready to serve requests?
                return states[pod_state]
        else:
            # if no match was found for deis mapping then passthrough the real state
            pod_state = pod['status']['phase']

        return states.get(pod_state, pod_state)

    def _api(self, tmpl, *args):
        """Return a fully-qualified Kubernetes API URL from a string template with args."""
        # FIXME better way of determining API version based on requested component
        # extensions use apis and not api
        # TODO this needs to be aware that deployments / rs could be top level in future releases
        # https://github.com/deis/controller/issues/875
        prefix = 'api'
        apiversion = 'v1'
        components = tmpl.strip('/').split('/')
        if len(components) > 2:
            component = components[2]
            if component in ['deployments', 'replicasets']:
                prefix = 'apis'
                apiversion = 'extensions/v1beta1'

        url = "/{}/{}".format(prefix, apiversion) + tmpl.format(*args)
        return urljoin(self.url, url)

    def _selectors(self, **kwargs):
        query = {}

        # labels and fields are encoded slightly differently than python-requests can do
        labels = kwargs.get('labels', {})
        if labels:
            selectors = []
            for key, value in labels.items():
                # http://kubernetes.io/docs/user-guide/labels/#set-based-requirement
                if '__notin' in key:
                    key = key.replace('__notin', '')
                    selectors.append('{} notin({})'.format(key, ','.join(value)))
                # list is automagically a in()
                elif '__in' in key or isinstance(value, list):
                    key = key.replace('__in', '')
                    selectors.append('{} in({})'.format(key, ','.join(value)))
                elif value is None:
                    # allowing a check if a label exists (or not) without caring about value
                    selectors.append(key)
                # http://kubernetes.io/docs/user-guide/labels/#equality-based-requirement
                elif isinstance(value, str):
                    selectors.append('{}={}'.format(key, value))

            query['labelSelector'] = ','.join(selectors)

        fields = kwargs.get('fields', {})
        if fields:
            fields = ['{}={}'.format(key, value) for key, value in fields.items()]
            query['fieldSelector'] = ','.join(fields)

        # Which resource version to start from. Otherwise starts from the beginning
        resource_version = kwargs.get('resourceVersion', None)
        if resource_version:
            query['resourceVersion'] = resource_version

        # If output should pretty print, only True / False allowed
        pretty = bool(kwargs.get('pretty', False))
        if pretty:
            query['pretty'] = pretty

        return query

    # NAMESPACE #

    def get_namespace_events(self, namespace, **kwargs):
        url = self._api("/namespaces/{}/events", namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, "get Events in Namespace {}", namespace)

        return response

    def get_namespace(self, namespace):
        url = self._api("/namespaces/{}/", namespace)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Namespace "{}"', namespace)

        return response

    def get_namespaces(self, **kwargs):
        url = self._api("/namespaces")
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Namespaces')

        return response

    def create_namespace(self, namespace):
        url = self._api("/namespaces")
        data = {
            "kind": "Namespace",
            "apiVersion": "v1",
            "metadata": {
                "name": namespace
            }
        }

        response = self.session.post(url, json=data)
        if not response.status_code == 201:
            raise KubeHTTPException(response, "create Namespace {}".format(namespace))

        return response

    def delete_namespace(self, namespace):
        url = self._api("/namespaces/{}", namespace)
        response = self.session.delete(url)
        if response.status_code == 404:
            logger.warn('delete Namespace "{}": not found'.format(namespace))
        elif response.status_code != 200:
            raise KubeHTTPException(response, 'delete Namespace "{}"', namespace)

        return response

    # REPLICATION CONTROLLER #

    def get_old_rc(self, namespace, app_type):
        labels = {
            'app': namespace,
            'type': app_type
        }
        controllers = self.get_rcs(namespace, labels=labels).json()
        if len(controllers['items']) == 0:
            return False

        return controllers['items'][0]

    def get_rc(self, namespace, name):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get ReplicationController "{}" in Namespace "{}"', name, namespace
            )

        return response

    def get_rcs(self, namespace, **kwargs):
        url = self._api("/namespaces/{}/replicationcontrollers", namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get ReplicationControllers in Namespace "{}"', namespace
            )

        return response

    def _wait_until_pods_terminate(self, namespace, labels, current, desired):
        """Wait until all the desired pods are terminated"""
        # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_podspec
        # https://github.com/kubernetes/kubernetes/blob/release-1.2/docs/devel/api-conventions.md#metadata
        # http://kubernetes.io/docs/user-guide/pods/#termination-of-pods

        timeout = settings.KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS
        delta = current - desired
        self.log(namespace, "waiting for {} pods to be terminated ({}s timeout)".format(delta, timeout))  # noqa
        for waited in range(timeout):
            pods = self.get_pods(namespace, labels=labels).json()
            count = len(pods['items'])

            # see if any pods are past their terminationGracePeriodsSeconds (as in stuck)
            # seems to be a problem in k8s around that:
            # https://github.com/kubernetes/kubernetes/search?q=terminating&type=Issues
            # these will be eventually GC'ed by k8s, ignoring them for now
            for pod in pods['items']:
                # remove pod if it is passed the graceful termination period
                if self.pod_deleted(pod):
                    count -= 1

            # stop when all pods are terminated as expected
            if count == desired:
                break

            if waited > 0 and (waited % 10) == 0:
                self.log(namespace, "waited {}s and {} pods out of {} are fully terminated".format(waited, (delta - count), delta))  # noqa

            time.sleep(1)

        self.log(namespace, "{} pods are terminated".format(delta))

    def _deploy_probe_timeout(self, timeout, namespace, labels, containers):
        """
        Added in additional timeouts based on readiness and liveness probe

        Uses the max of the two instead of combining them as the checks are stacked.
        """

        container_name = '{}-{}'.format(labels['app'], labels['type'])
        container = self._find_container(container_name, containers)

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

    def _wait_until_pods_are_ready(self, namespace, containers, labels, desired, timeout):  # noqa
        # If desired is 0 then there is no ready state to check on
        if desired == 0:
            return

        timeout = self._deploy_probe_timeout(timeout, namespace, labels, containers)
        self.log(namespace, "waiting for {} pods in {} namespace to be in services ({}s timeout)".format(desired, namespace, timeout))  # noqa

        # Ensure the minimum desired number of pods are available
        waited = 0
        while waited < timeout:
            count = 0  # ready pods
            pods = self.get_pods(namespace, labels=labels).json()
            for pod in pods['items']:
                # Get more information on why a pod is pending
                if pod['status']['phase'] in ['Pending', 'ContainerCreating']:
                    reason, message = self._pod_pending_status(pod)
                    # If pulling an image is taking long then increase the timeout
                    timeout += self._handle_pod_long_image_pulling(pod, reason)

                    # handle errors and bubble up if need be
                    self._handle_pod_image_errors(pod, reason, message)

                # now that state is running time to see if probes are passing
                if self._pod_ready(pod):
                    count += 1

                # Find out if any pod goes beyond the Running (up) state
                # Allow that to happen to account for very fast `deis run` as
                # an example. Code using this function will account for it
                state = self.pod_state(pod)
                if isinstance(state, PodState) and state > PodState.up:
                    count += 1

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

    def _scale_rc(self, namespace, name, desired, timeout):
        rc = self.get_rc(namespace, name).json()

        current = int(rc['spec']['replicas'])
        if desired == current:
            self.log(namespace, "Not scaling RC {} to {} replicas. Already at desired replicas".format(name, desired))  # noqa
            return
        elif desired != rc['spec']['replicas']:  # RC needs new replica count
            # Set the new desired replica count
            rc['spec']['replicas'] = desired

            self.log(namespace, "scaling RC {} from {} to {} replicas".format(name, current, desired))  # noqa

            self.update_rc(namespace, name, rc)
            self._wait_until_rc_is_updated(namespace, name)

        # Double check enough pods are in the required state to service the application
        labels = rc['metadata']['labels']
        containers = rc['spec']['template']['spec']['containers']
        self._wait_until_pods_are_ready(namespace, containers, labels, desired, timeout)

        # if it was a scale down operation, wait until terminating pods are done
        if int(desired) < int(current):
            self._wait_until_pods_terminate(namespace, labels, current, desired)

    def _find_container(self, container_name, containers):
        """
        Locate a container by name in a list of containers
        """
        for container in containers:
            if container['name'] == container_name:
                return container

        return None

    def create_rc(self, namespace, name, image, entrypoint, command, **kwargs):
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
        manifest['spec']['template'] = self._build_pod_manifest(namespace, name, image, **kwargs)

        url = self._api("/namespaces/{}/replicationcontrollers", namespace)
        resp = self.session.post(url, json=manifest)
        if unhealthy(resp.status_code):
            raise KubeHTTPException(
                resp,
                'create ReplicationController "{}" in Namespace "{}"', name, namespace
            )
            self.log(namespace, 'manifest used: {}'.format(ruamel.yaml.dump(manifest)), logging.DEBUG)  # noqa

        self._wait_until_rc_is_updated(namespace, name)

        return resp

    def _wait_until_rc_is_updated(self, namespace, name):
        """
        Looks at status/observedGeneration and metadata/generation and
        waits for observedGeneration >= generation to happen, indicates RC is ready

        More information is also available at:
        https://github.com/kubernetes/kubernetes/blob/master/docs/devel/api-conventions.md#metadata
        """
        self.log(namespace, "waiting for ReplicationController {} to get a newer generation (30s timeout)".format(name), logging.DEBUG)  # noqa
        for _ in range(30):
            try:
                rc = self.get_rc(namespace, name).json()
                if (
                    "observedGeneration" in rc["status"] and
                    rc["status"]["observedGeneration"] >= rc["metadata"]["generation"]
                ):
                    self.log(namespace, "ReplicationController {} got a newer generation (30s timeout)".format(name), logging.DEBUG)  # noqa
                    break

                time.sleep(1)
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    time.sleep(1)

    def update_rc(self, namespace, name, data):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.session.put(url, json=data)
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'scale ReplicationController "{}"', name)

        return response

    def delete_rc(self, namespace, name):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.session.delete(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete ReplicationController "{}" in Namespace "{}"', name, namespace
            )

        return response

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

    # SECRETS #
    # http://kubernetes.io/docs/api-reference/v1/definitions/#_v1_secret
    def get_secret(self, namespace, name):
        url = self._api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get Secret "{}" in Namespace "{}"', name, namespace
            )

        # decode the base64 data
        secrets = response.json()
        for key, value in secrets['data'].items():
            value = base64.b64decode(value)
            value = value if isinstance(value, bytes) else bytes(value, 'UTF-8')
            secrets['data'][key] = value.decode(encoding='UTF-8')

        # tell python-requests it actually hasn't consumed the data
        response._content = bytes(json.dumps(secrets), 'UTF-8')

        return response

    def get_secrets(self, namespace, **kwargs):
        url = self._api('/namespaces/{}/secrets', namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Secrets in Namespace "{}"', namespace)

        return response

    def _build_secret_manifest(self, namespace, name, data, secret_type='Opaque', labels={}):
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
            value = value if isinstance(value, bytes) else bytes(value, 'UTF-8')
            item = base64.b64encode(value).decode(encoding='UTF-8')
            manifest['data'].update({key: item})

        return manifest

    def create_secret(self, namespace, name, data, secret_type='Opaque', labels={}):
        manifest = self._build_secret_manifest(namespace, name, data, secret_type, labels)
        url = self._api("/namespaces/{}/secrets", namespace)
        response = self.session.post(url, json=manifest)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'failed to create Secret "{}" in Namespace "{}"', name, namespace
            )

        return response

    def update_secret(self, namespace, name, data, secret_type='Opaque', labels={}):
        manifest = self._build_secret_manifest(namespace, name, data, secret_type, labels)
        url = self._api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.session.put(url, json=manifest)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'failed to update Secret "{}" in Namespace "{}"',
                name, namespace
            )

        return response

    def delete_secret(self, namespace, name):
        url = self._api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.session.delete(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete Secret "{}" in Namespace "{}"', name, namespace
            )

        return response

    # SERVICES #

    def get_service(self, namespace, name):
        url = self._api("/namespaces/{}/services/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get Service "{}" in Namespace "{}"', name, namespace
            )

        return response

    def get_services(self, namespace, **kwargs):
        url = self._api('/namespaces/{}/services', namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Services in Namespace "{}"', namespace)

        return response

    def create_service(self, namespace, name, data={}, **kwargs):
        l = {"name": namespace}

        # Merge external data on to the prefined manifest
        manifest = ruamel.yaml.load(string.Template(SERVICE_TEMPLATE).substitute(l))
        data = dict_merge(manifest, data)
        url = self._api("/namespaces/{}/services", namespace)
        response = self.session.post(url, json=data)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'create Service "{}" in Namespace "{}"', namespace, namespace
            )

        return response

    def update_service(self, namespace, name, data):
        url = self._api("/namespaces/{}/services/{}", namespace, name)
        response = self.session.put(url, json=data)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'update Service "{}" in Namespace "{}"', namespace, name
            )

        return response

    def delete_service(self, namespace, name):
        url = self._api("/namespaces/{}/services/{}", namespace, name)
        response = self.session.delete(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete Service "{}" in Namespace "{}"', name, namespace
            )

        return response

    # PODS #

    def get_pod(self, namespace, name):
        url = self._api("/namespaces/{}/pods/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Pod "{}" in Namespace "{}"', name, namespace)

        return response

    def get_pods(self, namespace, **kwargs):
        url = self._api('/namespaces/{}/pods', namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Pods in Namespace "{}"', namespace)

        return response

    def delete_pod(self, namespace, name):
        url = self._api("/namespaces/{}/pods/{}", namespace, name)
        resp = self.session.delete(url)
        if unhealthy(resp.status_code):
            raise KubeHTTPException(resp, 'delete Pod "{}" in Namespace "{}"', name, namespace)

        # Verify the pod has been deleted
        # Only wait as long as the grace period is - k8s will eventually GC
        for _ in range(settings.KUBERNETES_POD_TERMINATION_GRACE_PERIOD_SECONDS):
            try:
                pod = self.get_pod(namespace, name).json()
                # hide pod if it is passed the graceful termination period
                if self.pod_deleted(pod):
                    return
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    break

            time.sleep(1)

    def _pod_log(self, namespace, name):
        url = self._api("/namespaces/{}/pods/{}/log", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get logs for Pod "{}" in Namespace "{}"', name, namespace
            )

        return response

    def _pod_pending_status(self, pod):
        """Introspect the pod containers when pod is in Pending state"""
        if 'containerStatuses' not in pod['status']:
            return 'Pending', ''

        name = '{}-{}'.format(pod['metadata']['labels']['app'], pod['metadata']['labels']['type'])
        # find the right container in case there are many on the pod
        container = self._find_container(name, pod['status']['containerStatuses'])
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
                events = self._pod_events(pod)
                if not events:
                    # could not find any events
                    return reason, message

                event = events.pop()
                return event['reason'], event['message']

            return reason, message

        # Return Pending if nothing else can be found
        return 'Pending', ''

    def _pod_events(self, pod):
        """Process events for a given Pod to find if Pulling is happening, among other events"""
        # fetch all events for this pod
        fields = {
            'involvedObject.name': pod['metadata']['name'],
            'involvedObject.namespace': pod['metadata']['namespace'],
            'involvedObject.uid': pod['metadata']['uid']
        }
        events = self.get_namespace_events(pod['metadata']['namespace'], fields=fields).json()
        # make sure that events are sorted
        events['items'].sort(key=lambda x: x['lastTimestamp'])
        return events['items']

    def _pod_readiness_status(self, pod):
        """Check if the pod container have passed the readiness probes"""
        name = '{}-{}'.format(pod['metadata']['labels']['app'], pod['metadata']['labels']['type'])
        # find the right container in case there are many on the pod
        container = self._find_container(name, pod['status']['containerStatuses'])
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

    def _pod_liveness_status(self, pod):
        """Check if the pods liveness probe status has passed all checks"""
        for condition in pod['status']['conditions']:
            # type = Ready is the only binary type right now
            if condition['type'] == 'Ready' and condition['status'] != 'True':
                return False

        return True

    def _pod_ready(self, pod):
        """Combines various checks to see if the pod is considered up or not by checking probes"""
        return (
            pod['status']['phase'] == 'Running' and
            # is the readiness probe passing?
            self._pod_readiness_status(pod) == 'Running' and
            # is the pod ready to serve requests?
            self._pod_liveness_status(pod)
        )

    def pod_deleted(self, pod):
        """Checks if a pod is deleted and past its graceful termination period"""
        # https://github.com/kubernetes/kubernetes/blob/release-1.2/docs/devel/api-conventions.md#metadata
        # http://kubernetes.io/docs/user-guide/pods/#termination-of-pods
        if 'deletionTimestamp' in pod['metadata']:
            deletion = datetime.strptime(
                pod['metadata']['deletionTimestamp'],
                settings.DEIS_DATETIME_FORMAT
            )

            # past the graceful deletion period
            if deletion < datetime.utcnow():
                return True

        return False

    def _handle_pod_image_errors(self, pod, reason, message):
        """
        Handle potential pod image errors based on the Pending
        reason passed into the function
        """
        # image error reported on the container level
        image_container_errors = [
            'ErrImagePull',
            'ImagePullBackOff',
            'RegistryUnavailable',
            'ErrImageInspect',
        ]
        # Image event reason mapping
        image_event_errors = {
            "Failed": "FailedToPullImage",
            "InspectFailed": "FailedToInspectImage",
            "ErrImageNeverPull": "ErrImageNeverPullPolicy",
            # Not including this one for now as the message is not useful
            # "BackOff": "BackOffPullImage",
        }
        if reason in image_container_errors:
            # Nicer error than from the event
            # Often this gets to ImageBullBackOff before we can introspect tho
            if reason == 'ErrImagePull':
                raise KubeException(message)

            # collect all error messages relevant to images
            messages = []
            for event in self._pod_events(pod):
                if event['reason'] in image_event_errors.keys():
                    # remove new lines and any extra white space
                    message = ' '.join(event['message'].split())
                    messages.append(message)
            raise KubeException("\n".join(messages))

    def _handle_pod_long_image_pulling(self, reason, pod):
        """
        If pulling an image is taking long (1 minute) then return how many seconds
        the pod ready state timeout should be extended by

        Return value is an int that represents seconds
        """
        # only apply once
        if getattr(self, '_handle_pod_long_image_pulling_applied', False):
            return 0

        if reason is not 'Pulling':
            return 0

        # last event should be Pulling in this case
        event = self._pod_events(pod).pop()
        # see if pull operation has been happening for over 1 minute
        start = datetime.strptime(
            event['firstTimestamp'],
            settings.DEIS_DATETIME_FORMAT
        )

        seconds = 60  # time threshold before padding timeout
        if (start + timedelta(seconds=seconds)) < datetime.utcnow():
            # add 10 minutes to timeout to allow a pull image operation to finish
            self.log(namespace, 'Kubernetes has been pulling the image for {} seconds'.format(seconds))  # noqa
            self.log(namespace, 'Increasing timeout by 10 minutes to allow a pull image operation to finish for pods')  # noqa

            # make it so function doesn't do processing again
            setattr(self, '_handle_pod_long_image_pulling_applied', True)
            return 600

        return 0

    # NODES #

    def get_nodes(self, **kwargs):
        url = self._api('/nodes')
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Nodes')

        return response

    def get_node(self, name, **kwargs):
        url = self._api('/nodes/{}'.format(name))
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Node {} in Nodes', name)

        return response

    # DEPLOYMENTS #

    def get_deployment(self, namespace, name):
        url = self._api("/namespaces/{}/deployments/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get Deployment "{}" in Namespace "{}"', name, namespace
            )

        return response

    def get_deployments(self, namespace, **kwargs):
        url = self._api("/namespaces/{}/deployments", namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get Deployments in Namespace "{}"', namespace)

        return response

    def _wait_until_deployment_is_updated(self, namespace, name):
        """
        Looks at status/observedGeneration and metadata/generation and
        waits for observedGeneration >= generation to happen

        http://kubernetes.io/docs/user-guide/deployments/#the-status-of-a-deployment
        More information is also available at:
        https://github.com/kubernetes/kubernetes/blob/master/docs/devel/api-conventions.md#metadata
        """
        self.log(namespace, "waiting for Deployment {} to get a newer generation (30s timeout)".format(name), logging.DEBUG)  # noqa
        for _ in range(30):
            try:
                deploy = self.get_deployment(namespace, name).json()
                if (
                    'observedGeneration' in deploy['status'] and
                    deploy['status']['observedGeneration'] >= deploy['metadata']['generation']
                ):
                    self.log(namespace, "A newer generation was found for Deployment {}".format(name), logging.DEBUG)  # noqa
                    break

                time.sleep(1)
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    time.sleep(1)

    def are_deployment_replicas_ready(self, namespace, name):
        """
        Verify the status of a Deployment and if it is fully deployed
        """
        deployment = self.get_deployment(namespace, name).json()
        desired = deployment['spec']['replicas']
        status = deployment['status']

        # right now updateReplicas is where it is at
        # availableReplicas mean nothing until minReadySeconds is used
        pods = status['updatedReplicas'] if 'updatedReplicas' in status else 0

        # spec/replicas of 0 is a special case as other fields get removed from status
        if desired == 0 and ('replicas' not in status or status['replicas'] == 0):
            return True, pods

        if (
            'unavailableReplicas' in status or
            ('replicas' not in status or status['replicas'] is not desired) or
            ('updatedReplicas' not in status or status['updatedReplicas'] is not desired) or
            ('availableReplicas' not in status or status['availableReplicas'] is not desired)
        ):
            return False, pods

        return True, pods

    def delete_deployment(self, namespace, name):
        url = self._api("/namespaces/{}/deployments/{}", namespace, name)
        response = self.session.delete(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete Deployment "{}" in Namespace "{}"', name, namespace
            )

        return response

    def update_deployment(self, namespace, name, image, entrypoint, command, **kwargs):
        manifest = self._build_deployment_manifest(namespace,
                                                   name,
                                                   image,
                                                   entrypoint,
                                                   command,
                                                   **kwargs)

        url = self._api("/namespaces/{}/deployments/{}", namespace, name)
        response = self.session.put(url, json=manifest)
        if unhealthy(response.status_code):
            self.log(namespace, 'template used: {}'.format(json.dumps(manifest, indent=4)), logging.DEBUG)  # noqa
            raise KubeHTTPException(response, 'update Deployment "{}"', name)

        self._wait_until_deployment_is_updated(namespace, name)
        self._wait_until_deployment_is_ready(namespace, name, **kwargs)

        return response

    def create_deployment(self, namespace, name, image, entrypoint, command, **kwargs):
        manifest = self._build_deployment_manifest(namespace,
                                                   name,
                                                   image,
                                                   entrypoint,
                                                   command,
                                                   **kwargs)

        url = self._api("/namespaces/{}/deployments", namespace)
        response = self.session.post(url, json=manifest)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'create Deployment "{}" in Namespace "{}"', name, namespace
            )
            self.log(namespace, 'template used: {}'.format(json.dumps(manifest, indent=4)), logging.DEBUG)  # noqa

        self._wait_until_deployment_is_updated(namespace, name)
        self._wait_until_deployment_is_ready(namespace, name, **kwargs)

        return response

    def _wait_until_deployment_is_ready(self, namespace, name, **kwargs):
        replicas = int(kwargs.get('replicas', 0))
        # If desired is 0 then there is no ready state to check on
        if replicas == 0:
            return

        current = int(kwargs.get('previous_replicas', 0))
        batches = kwargs.get('deploy_batches', None)
        deploy_timeout = kwargs.get('deploy_timeout', 120)
        tags = kwargs.get('tags', {})
        steps = self._get_deploy_steps(batches, tags)
        batches = self._get_deploy_batches(steps, replicas)

        deployment = self.get_deployment(namespace, name).json()
        labels = deployment['spec']['template']['metadata']['labels']
        containers = deployment['spec']['template']['spec']['containers']

        # if it was a scale down operation, wait until terminating pods are done
        # Deployments say they are ready even when pods are being terminated
        if replicas < current:
            self._wait_until_pods_terminate(namespace, labels, current, replicas)
            return

        # get health info from container
        deploy_timeout = self._deploy_probe_timeout(deploy_timeout, namespace, labels, containers)

        # a rough calculation that figures out an overall timeout
        timeout = len(batches) * deploy_timeout
        self.log(namespace, 'This deployments overall timeout is {}s - batch timout is {}s and there are {} batches to deploy with a total of {} pods'.format(timeout, deploy_timeout, len(batches), replicas))  # noqa

        waited = 0
        while waited < timeout:
            ready, availablePods = self.are_deployment_replicas_ready(namespace, name)
            if ready:
                break

            # check every 10 seconds for pod failures.
            # Depend on Deployment checks for ready pods
            if waited > 0 and (waited % 10) == 0:
                pods = self.get_pods(namespace, labels=labels).json()
                for pod in pods['items']:
                    # Get more information on why a pod is pending
                    if pod['status']['phase'] in ['Pending', 'ContainerCreating']:
                        reason, message = self._pod_pending_status(pod)
                        # If pulling an image is taking long then increase the timeout
                        timeout += self._handle_pod_long_image_pulling(pod, reason)

                        # handle errors and bubble up if need be
                        self._handle_pod_image_errors(pod, reason, message)

                self.log(namespace, "waited {}s and {} pods are in service".format(waited, availablePods))  # noqa

            waited += 1
            time.sleep(1)

    def _build_deployment_manifest(self, namespace, name, image, entrypoint, command, **kwargs):
        replicas = kwargs.get('replicas', 0)
        batches = kwargs.get('deploy_batches', None)
        tags = kwargs.get('tags', {})

        labels = {
            'app': namespace,
            'type': kwargs.get('app_type'),
            'heritage': 'deis',
        }

        manifest = {
            'kind': 'Deployment',
            'apiVersion': 'extensions/v1beta1',
            'metadata': {
                'name': name,
                'labels': labels,
                'annotations': {
                    'kubernetes.io/change-cause': kwargs.get('release_summary', '')
                }
            },
            'spec': {
                'replicas': replicas,
                'selector': {
                    'matchLabels': labels
                }
            }
        }

        # Add in Rollback (if asked for)
        rollback = kwargs.get('rollback', False)
        if rollback:
            # http://kubernetes.io/docs/user-guide/deployments/#rollback-to
            if rollback is True:
                # rollback to the latest known working revision
                revision = 0
            elif isinstance(rollback, int) or isinstance(rollback, str):
                # rollback to a particular revision
                revision = rollback

            # This gets cleared from the template after a rollback is done
            manifest['spec']['rollbackTo'] = {'revision': str(revision)}

        # Add deployment strategy

        # see if application or global deploy batches are defined
        maxSurge = self._get_deploy_steps(batches, tags)
        # if replicas are higher than maxSurge then the old deployment is never scaled down
        # maxSurge can't be 0 when maxUnavailable is 0 and the other way around
        if replicas > 0 and replicas < maxSurge:
            maxSurge = replicas

        # http://kubernetes.io/docs/user-guide/deployments/#strategy
        manifest['spec']['strategy'] = {
            'rollingUpdate': {
                'maxSurge': maxSurge,
                # This is never updated
                'maxUnavailable': 0
            },
            # RollingUpdate or Recreate
            'type': 'RollingUpdate',
        }

        # Add in how many deployment revisions to keep
        if kwargs.get('deployment_revision_history', None) is not None:
            manifest['spec']['revisionHistoryLimit'] = int(kwargs.get('deployment_revision_history'))  # noqa

        # tell pod how to execute the process
        kwargs['command'] = entrypoint
        kwargs['args'] = command

        # pod manifest spec
        manifest['spec']['template'] = self._build_pod_manifest(namespace, name, image, **kwargs)

        return manifest

    def _scale_deployment(self, namespace, name, image, entrypoint, command, **kwargs):
        deployment = self.get_deployment(namespace, name).json()
        desired = int(kwargs.get('replicas'))
        current = int(deployment['spec']['replicas'])
        if desired == current:
            self.log(namespace, "Not scaling Deployment {} to {} replicas. Already at desired replicas".format(name, desired))  # noqa
            return
        elif desired != current:
            # set the previous replicas count so the wait logic can deal with terminating pods
            kwargs['previous_replicas'] = current
            self.log(namespace, "scaling Deployment {} from {} to {} replicas".format(name, current, desired))  # noqa
            self.update_deployment(namespace, name, image, entrypoint, command, **kwargs)

    def get_replicaset(self, namespace, name):
        url = self._api("/namespaces/{}/replicasets/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get ReplicaSet "{}" in Namespace "{}"', name, namespace
            )

        return response

    def get_replicasets(self, namespace, **kwargs):
        url = self._api("/namespaces/{}/replicasets", namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'get ReplicaSets in Namespace "{}"', namespace
            )

        return response

SchedulerClient = KubeHTTPClient
