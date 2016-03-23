import json
import logging
import os
import string
import time
from urllib.parse import urljoin
import base64

from django.conf import settings
from docker import Client
from .states import JobState
import requests
from requests_toolbelt import user_agent
from .utils import dict_merge

from deis import __version__ as deis_version


logger = logging.getLogger(__name__)

# Used for one off command runs on pods
POD_BTEMPLATE = """\
{
  "kind": "Pod",
  "apiVersion": "$version",
  "metadata": {
    "name": "$id"
  },
  "spec": {
    "containers": [
      {
        "name": "$id",
        "image": "$slugimage",
        "env": [
        {
            "name":"PORT",
            "value":"5000"
        },
        {
            "name":"SLUG_URL",
            "value":"$image"
        },
        {
            "name": "DOCKERIMAGE",
            "value":"1"
        }
        ],
        "volumeMounts":[
        {
            "name":"minio-user",
            "mountPath":"/var/run/secrets/object/store",
            "readOnly":true
        }
        ]
      }
    ],
    "volumes":[
    {
        "name":"minio-user",
        "secret":{
        "secretName":"minio-user"
        }
    }
    ],
    "restartPolicy": "Never"
  }
}
"""

POD_TEMPLATE = """\
{
  "kind": "Pod",
  "apiVersion": "$version",
  "metadata": {
    "name": "$id"
  },
  "spec": {
    "containers": [
      {
        "name": "$id",
        "image": "$image"
      }
    ],
    "restartPolicy": "Never"
  }
}
"""

RCD_TEMPLATE = """\
{
  "kind": "ReplicationController",
  "apiVersion": "$version",
  "metadata": {
    "name": "$name",
    "labels": {
      "app": "$id",
      "version": "$appversion",
      "type": "$type",
      "heritage": "deis"
    }
  },
  "spec": {
    "replicas": $replicas,
    "selector": {
      "app": "$id",
      "version": "$appversion",
      "type": "$type",
      "heritage": "deis"
    },
    "template": {
      "metadata": {
        "labels": {
          "app": "$id",
          "version": "$appversion",
          "type": "$type",
          "heritage": "deis"
        }
      },
      "spec": {
        "containers": [
          {
            "name": "$containername",
            "image": "$image",
            "env": [
            {
                "name":"DEIS_APP",
                "value":"$id"
            },
            {
                "name":"DEIS_RELEASE",
                "value":"$appversion"
            }
            ]
          }
        ],
        "nodeSelector": {}
      }
    }
  }
}
"""

RCB_TEMPLATE = """\
{
  "kind": "ReplicationController",
  "apiVersion": "$version",
  "metadata": {
    "name": "$name",
    "labels": {
      "app": "$id",
      "version": "$appversion",
      "type": "$type",
      "heritage": "deis"
    }
  },
  "spec": {
    "replicas": $replicas,
    "selector": {
      "app": "$id",
      "version": "$appversion",
      "type": "$type",
      "heritage": "deis"
    },
    "template": {
      "metadata": {
        "labels": {
          "app": "$id",
          "version": "$appversion",
          "type": "$type",
          "heritage": "deis"
        }
      },
      "spec": {
        "containers": [
          {
            "name": "$containername",
            "image": "$slugimage",
            "imagePullPolicy": "Always",
            "env": [
            {
                "name":"PORT",
                "value":"5000"
            },
            {
                "name":"SLUG_URL",
                "value":"$image"
            },
            {
                "name":"DEIS_APP",
                "value":"$id"
            },
            {
                "name":"DEIS_RELEASE",
                "value":"$appversion"
            },
            {
                "name": "DOCKERIMAGE",
                "value":"1"
            }
            ],
            "volumeMounts":[
            {
                "name":"minio-user",
                "mountPath":"/var/run/secrets/object/store",
                "readOnly":true
            }
            ]
          }
        ],
        "nodeSelector": {},
        "volumes":[
        {
            "name":"minio-user",
            "secret":{
            "secretName":"minio-user"
            }
        }
        ]
      }
    }
  }
}
"""

# Ports and app type will be overwritten as required
SERVICE_TEMPLATE = """\
{
  "kind": "Service",
  "apiVersion": "$version",
  "metadata": {
    "name": "$name",
    "labels": {
      "app": "$name"
    },
    "annotations": {}
  },
  "spec": {
    "ports": [
      {
        "name": "http",
        "port": 80,
        "targetPort": 8080,
        "protocol": "TCP"
      }
    ],
    "selector": {
      "app": "$name",
      "heritage": "deis"
    }
  }
}
"""

SECRET_TEMPLATE = """\
{
  "kind": "Secret",
  "apiVersion": "$version",
  "metadata": {
    "name": "$name",
    "namespace": "$id"
  },
  "type": "Opaque",
  "data": {}
}
"""


class KubeException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class KubeHTTPException(KubeException):
    def __init__(self, *args, **kwargs):
        self.response = kwargs.pop('response', object)
        KubeException.__init__(self, *args, **kwargs)


def error(response, errmsg, *args):
    errmsg = errmsg.format(*args)
    errmsg = "failed to {}: {} {}\n{}".format(
        errmsg,
        response.status_code,
        response.reason,
        response.json()
    )

    raise KubeHTTPException(errmsg, response=response)


def unhealthy(status_code):
    if not 200 <= status_code <= 299:
        return True

    return False


class KubeHTTPClient(object):
    apiversion = "v1"

    def __init__(self):
        self.url = settings.SCHEDULER_URL
        self.registry = settings.REGISTRY_URL

        with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as token_file:
            token = token_file.read()

        session = requests.Session()
        session.headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'User-Agent': user_agent('Deis Controller', deis_version)
        }
        # TODO: accessing the k8s api server by IP address rather than hostname avoids
        # TODO look at https://toolbelt.readthedocs.org/en/latest/adapters.html#fingerprintadapter
        # intermittent DNS errors, but at the price of disabling cert verification.
        # session.verify = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        session.verify = False
        self.session = session

    def deploy(self, namespace, name, image, command, **kwargs):
        logger.debug('deploy {}, img {}, params {}, cmd "{}"'.format(name, image, kwargs, command))
        app_type = kwargs.get('app_type')
        routable = kwargs.get('routable', False)

        # Fetch old RC and create the new one for a release
        old_rc = self._get_old_rc(namespace, app_type)
        new_rc = self._create_rc(namespace, name, image, command, **kwargs)

        # Get the desired number to scale to
        desired = 1
        if old_rc:
            desired = int(old_rc["spec"]["replicas"])

        try:
            count = 1
            while desired >= count:
                logger.debug('scaling release {} to {} out of final {}'.format(
                    new_rc["metadata"]["name"], count, desired
                ))
                self._scale_rc(namespace, new_rc["metadata"]["name"], count)
                logger.debug('scaled up pod number {} for {}'.format(
                    count, new_rc["metadata"]["name"]
                ))

                if old_rc:
                    logger.debug('scaling old release {} from original {} to {}'.format(
                        old_rc["metadata"]["name"], desired, (desired-count))
                    )
                    self._scale_rc(namespace, old_rc["metadata"]["name"], (desired-count))
                    logger.debug('scaled down pod number {} for {}'.format(
                        count, old_rc["metadata"]["name"]
                    ))

                count += 1
        except Exception as e:
            # New release is broken. Clean up
            logger.error('Could not scale {} to {}. Deleting and going back to old release'.format(
                new_rc["metadata"]["name"], desired)
            )

            # Remove old release
            self._scale_rc(namespace, new_rc["metadata"]["name"], 0)
            self._delete_rc(namespace, new_rc["metadata"]["name"])

            # Bring back old release if available
            if old_rc:
                self._scale_rc(namespace, old_rc["metadata"]["name"], desired)

            raise RuntimeError('{} (scheduler::deploy): {}'.format(name, e))

        # New release is live and kicking. Clean up old release
        if old_rc:
            self._delete_rc(namespace, old_rc["metadata"]["name"])

        # Make sure the application is routable and uses the correct port
        # Done after the fact to let initial deploy settle before routing
        # traffic to the application
        self._update_application_service(namespace, name, app_type, image, routable)

    def _update_application_service(self, namespace, name, app_type, image, routable):
        """Update application service with all the various required information"""
        try:
            # Fetch service
            service = self._get_service(namespace, namespace).json()
            old_service = service.copy()  # in case anything fails for rollback

            # Update service information
            if routable:
                service['metadata']['labels']['router.deis.io/routable'] = 'true'

            # Set app type if there is not one available
            if 'type' not in service['spec']['selector']:
                service['spec']['selector']['type'] = app_type

            # Find if target port exists already, update / create as required
            port = self._get_port(image)
            for pos, item in enumerate(service['spec']['ports']):
                if item['port'] == 80 and port != item['targetPort']:
                    # port 80 is the only one we care about right now
                    service['spec']['ports'][pos]['targetPort'] = port

            self._update_service(namespace, namespace, data=service)
        except Exception as e:
            # Fix service to old port and app type
            self._update_service(namespace, namespace, data=old_service)
            raise RuntimeError('{} (scheduler::deploy::service_update): {}'.format(name, e))

    def scale(self, namespace, name, image, command, **kwargs):
        logger.debug('scale {}, img {}, params {}, cmd "{}"'.format(name, image, kwargs, command))
        replicas = kwargs.pop('replicas')
        if unhealthy(self._get_rc_status(namespace, name)):
            # add RC if it is missing for the namespace
            try:
                # Create RC with scale as 0 and then scale to get pod monitoring
                kwargs['replicas'] = 0
                self._create_rc(namespace, name, image, command, **kwargs)
            except KubeException as e:
                logger.debug("Creating RC failed because of: {}".format(str(e)))
                raise RuntimeError('{} (RC): {}'.format(name, e))

        try:
            self._scale_rc(namespace, name, replicas)
        except KubeException as e:
            logger.debug("Scaling failed because of: {}".format(str(e)))
            old = self._get_rc(namespace, name).json()
            self._scale_rc(namespace, name, old['spec']['replicas'])
            raise RuntimeError('{} (Scale): {}'.format(name, e))

    def create(self, namespace, **kwargs):
        """Create a basic structure for an application in k8s"""
        logger.debug('create {}'.format(namespace))
        try:
            # Create essential resources
            try:
                self._get_namespace(namespace)
            except KubeException:
                self._create_namespace(namespace)

            try:
                self._get_secret(namespace, 'minio-user')
            except KubeException:
                self._create_minio_secret(namespace)

            try:
                self._get_service(namespace, namespace)
            except KubeException:
                self._create_service(namespace, namespace)
        except KubeException as e:
            # Blow it all away only if something horrible happens
            logger.debug(e)
            self._delete_namespace(namespace)
            raise

    def destroy(self, namespace):
        """Destroy a application by deleting its namespace."""
        logger.debug("destroy {}".format(namespace))
        self._delete_namespace(namespace)

        # wait 30 seconds for termination
        for _ in range(30):
            try:
                self._get_namespace(namespace).json()
            except KubeException:
                break

    def run(self, namespace, name, image, entrypoint, command, **kwargs):
        """Run a one-off command."""
        logger.debug('run {}, img {}, entrypoint {}, cmd "{}"'.format(
            name, image, entrypoint, command)
        )

        imgurl = self.registry + '/' + image
        POD = POD_TEMPLATE

        l = {
            'id': name,
            'version': self.apiversion,
            'image': imgurl,
        }

        if image.startswith('http://') or image.startswith('https://'):
            POD = POD_BTEMPLATE
            l["image"] = image
            l["slugimage"] = settings.SLUGRUNNER_IMAGE

        template = json.loads(string.Template(POD).substitute(l))

        if command.startswith('-c '):
            args = command.split(' ', 1)
            args[1] = args[1][1:-1]
        else:
            args = [command[1:-1]]

        containers = template['spec']['containers'][0]
        containers['command'] = [entrypoint]
        containers['args'] = args

        self._set_environment(containers, **kwargs)

        url = self._api("/namespaces/{}/pods", namespace)
        response = self.session.post(url, json=template)
        if unhealthy(response.status_code):
            error(response, 'create Pod in Namespace "{}"', namespace)

        data = ''
        duration = 30
        iteration = 1
        while (iteration < duration):
            try:
                response = self._get_pod(namespace, name)
                data = response.text
                pod = response.json()
                if pod['status']['phase'] == 'Succeeded':
                    response = self._pod_log(namespace, name)
                    response.encoding = 'utf-8'  # defaults to "ISO-8859-1" otherwise...
                    log = response.text
                    self._delete_pod(namespace, name)
                    return 0, log

                if pod['status']['phase'] == 'Running':
                    if iteration > 28:
                        duration += 1
            except KubeException:
                break

            iteration += 1
            time.sleep(1)

        if iteration >= duration:
            error(response, 'Pod start took more than 30 seconds', namespace)
            return 0, data

        if pod['status']['phase'] == 'Failed':
            pod_state = pod['status']['containerStatuses'][0]['state']
            err_code = pod_state['terminated']['exitCode']
            self._delete_pod(namespace, name)
            return err_code, data

        return 0, data

    def _set_environment(self, data, **kwargs):
        app_type = kwargs.get('app_type')
        mem = kwargs.get('memory', {}).get(app_type)
        cpu = kwargs.get('cpu', {}).get(app_type)
        env = kwargs.get('envs', {})

        if env:
            for key, value in env.items():
                data["env"].append({
                    "name": key,
                    "value": str(value)
                })

        # Inject debugging if workflow is in debug mode
        if os.environ.get("DEBUG", False):
            data["env"].append({
                "name": "DEBUG",
                "value": "1"
            })

        if mem or cpu:
            data["resources"] = {"limits": {}}

        if mem:
            if mem[-2:-1].isalpha() and mem[-1].isalpha():
                mem = mem[:-1]

            mem = mem + "i"
            data["resources"]["limits"]["memory"] = mem

        if cpu:
            data["resources"]["limits"]["cpu"] = cpu

    def resolve_state(self, pod):
        # See "Pod Phase" at http://kubernetes.io/v1.1/docs/user-guide/pod-states.html
        if pod is None:
            return JobState.destroyed

        states = {
            'Pending': JobState.initialized,
            'Starting': JobState.starting,
            'Running': JobState.up,
            'Terminating': JobState.terminating,
            'Succeeded': JobState.down,
            'Failed': JobState.crashed,
            'Unknown': JobState.error,
        }

        # being in a running state can mean a pod is starting, actually running or terminating
        if pod['status']['phase'] == 'Running':
            # is the readiness probe passing?
            container_status = self._pod_readiness_status(pod)
            if container_status in ['Starting', 'Terminating']:
                return states[container_status]
            elif container_status == 'Running' and self._pod_liveness_status(pod):
                # is the pod ready to serve requests?
                return states[container_status]

        return states[pod['status']['phase']]

    def _get_port(self, image):
        try:
            image = self.registry + '/' + image
            repo = image.split(":")
            # image already includes the tag, so we split it out here
            docker_cli = Client(version="auto")
            docker_cli.pull(repo[0]+":"+repo[1], tag=repo[2], insecure_registry=True)
            image_info = docker_cli.inspect_image(image)
            port = int(list(image_info['Config']['ExposedPorts'].keys())[0].split("/")[0])
        except Exception:
            logger.debug("Failed to find port for Docker image {}, defaulting to 5000".format(image))  # noqa
            port = 5000

        return port

    def _api(self, tmpl, *args):
        """Return a fully-qualified Kubernetes API URL from a string template with args."""
        url = "/api/{}".format(self.apiversion) + tmpl.format(*args)
        return urljoin(self.url, url)

    def _selectors(self, **kwargs):
        query = {}

        # labels and fields are encoded slightly differently than python-requests can do
        labels = kwargs.get('labels', {})
        if labels:
            # http://kubernetes.io/v1.1/docs/user-guide/labels.html#list-and-watch-filtering
            labels = ['{}={}'.format(key, value) for key, value in labels.items()]
            query['labelSelector'] = ','.join(labels)

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

    def _get_namespace_events(self, namespace, **kwargs):
        url = self._api("/namespaces/{}/events", namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, "get Events in Namespace {}", namespace)

        return response

    def _get_namespace(self, namespace):
        url = self._api("/namespaces/{}/", namespace)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get Namespace "{}"', namespace)

        return response

    def _get_namespaces(self, **kwargs):
        url = self._api("/namespaces")
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, 'get Namespaces')

        return response

    def _create_namespace(self, namespace):
        url = self._api("/namespaces")
        data = {
            "kind": "Namespace",
            "apiVersion": self.apiversion,
            "metadata": {
                "name": namespace
            }
        }

        response = self.session.post(url, json=data)
        if not response.status_code == 201:
            error(response, "create Namespace {}".format(namespace))

        return response

    def _delete_namespace(self, namespace):
        url = self._api("/namespaces/{}", namespace)
        response = self.session.delete(url)
        if response.status_code == 404:
            logger.warn('delete Namespace "{}": not found'.format(namespace))
        elif response.status_code != 200:
            error(response, 'delete Namespace "{}"', namespace)

        return response

    # REPLICATION CONTROLLER #

    def _get_old_rc(self, namespace, app_type):
        url = self._api("/namespaces/{}/replicationcontrollers", namespace)
        resp = self.session.get(url)
        if unhealthy(resp.status_code):
            error(resp, 'get ReplicationControllers in Namespace "{}"', namespace)

        exists = False
        prev_rc = []
        for rc in resp.json()['items']:
            if (
                'app' in rc['spec']['selector'] and
                namespace == rc['metadata']['labels']['app'] and
                'type' in rc['spec']['selector'] and
                app_type == rc['spec']['selector']['type']
            ):
                exists = True
                prev_rc = rc
                break
        if exists:
            return prev_rc

        return 0

    def _get_rc_status(self, namespace, name):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        resp = self.session.get(url)
        return resp.status_code

    def _get_rc(self, namespace, name):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get ReplicationController "{}" in Namespace "{}"', name, namespace)

        return response

    def _get_rcs(self, namespace, **kwargs):
        url = self._api("/namespaces/{}/replicationcontrollers", namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, 'get ReplicationControllers in Namespace "{}"', namespace)

        return response

    def _wait_until_pods_terminate(self, namespace, labels, current, desired):
        delta = current - desired

        logger.debug("waiting for {} pods in {} namespace to be terminated (120s timeout)".format(delta, namespace))  # noqa
        for waited in range(120):
            pods = self._get_pods(namespace, labels=labels).json()
            count = len(pods['items'])

            # stop when all pods are terminated as expected
            if count == desired:
                break

            if waited > 0 and (waited % 10) == 0:
                logger.debug("waited {}s and {} pods out of {} are fully terminated".format(waited, (delta - count), delta))  # noqa

            time.sleep(1)

        logger.debug("{} pods in namespace {} are terminated".format(delta, namespace))  # noqa

    def _get_pod_ready_status(self, namespace, labels, desired):
        # If desired is 0 then there is no ready state to check on
        if desired == 0:
            return

        # Ensure the minimum desired number of pods are available
        logger.debug("waiting for {} pods in {} namespace to be in services (120s timeout)".format(desired, namespace))  # noqa
        for waited in range(120):
            count = 0
            pods = self._get_pods(namespace, labels=labels).json()
            for pod in pods['items']:
                # now that state is running time to see if probes are passing
                if (
                    pod['status']['phase'] == 'Running' and
                    # is the readiness probe passing?
                    self._pod_readiness_status(pod) == 'Running' and
                    # is the pod ready to serve requests?
                    self._pod_liveness_status(pod)
                ):
                    count += 1

            if count == desired:
                break

            if waited > 0 and (waited % 10) == 0:
                logger.debug("waited {}s and {} pods are in service".format(waited, count))

            time.sleep(1)

        logger.debug("{} out of {} pods in namespace {} are in service".format(count, desired, namespace))  # noqa

    def _scale_rc(self, namespace, name, desired):
        rc = self._get_rc(namespace, name).json()

        # get the current replica count by querying for pods instead of introspecting RC
        labels = {
            'app': rc['spec']['selector']['app'],
            'type': rc['spec']['selector']['type'],
            'version': rc['spec']['selector']['version']
        }
        current = len(self._get_pods(namespace, labels=labels).json()['items'])

        if desired == current:
            logger.debug("Not scaling RC {} in Namespace {} to {} replicas. Already at desired replicas".format(name, namespace, desired))  # noqa
            return

        # Set the new desired replica count
        rc['spec']['replicas'] = desired

        logger.debug("scaling RC {} in Namespace {} from {} to {} replicas".format(name, namespace, current, desired))  # noqa

        self._update_rc(namespace, name, rc)

        resource_ver = rc['metadata']['resourceVersion']
        logger.debug("waiting for RC {} to get a newer resource version than {} (30s timeout)".format(name, resource_ver))  # noqa
        for waited in range(30):
            js_template = self._get_rc(namespace, name).json()
            if js_template["metadata"]["resourceVersion"] != resource_ver:
                break

            if waited > 0 and (waited % 10) == 0:
                logger.debug("waited {}s so far for a new resource version".format(waited))

            time.sleep(1)

        logger.debug("RC {} has a new resource version {}".format(name, js_template["metadata"]["resourceVersion"]))  # noqa

        # Double check enough pods are in the required state to service the application
        self._get_pod_ready_status(namespace, labels, desired)

        # if it was a scale down operation, wait until terminating pods are done
        if int(desired) < int(current):
            self._wait_until_pods_terminate(namespace, labels, current, desired)

    def _create_rc(self, namespace, name, image, command, **kwargs):  # noqa
        app_type = kwargs.get('app_type')
        container_name = namespace + '-' + app_type
        args = command.split()
        imgurl = self.registry + "/" + image
        TEMPLATE = RCD_TEMPLATE

        l = {
            "name": name,
            "id": namespace,
            "appversion": kwargs.get("version"),
            "version": self.apiversion,
            "image": imgurl,
            "replicas": kwargs.get("replicas", 0),
            "containername": container_name,
            "type": app_type,
        }

        # Check if it is a slug builder image.
        if kwargs.get('build_type') == "buildpack":
            l["image"] = image
            l["slugimage"] = settings.SLUGRUNNER_IMAGE
            TEMPLATE = RCB_TEMPLATE

        template = json.loads(string.Template(TEMPLATE).substitute(l))

        # apply tags as needed
        tags = kwargs.get('tags', {})
        template["spec"]["template"]["spec"]["nodeSelector"] = tags

        # Deal with container information
        container = template["spec"]["template"]["spec"]["containers"][0]
        container['args'] = args

        self._set_environment(container, **kwargs)

        # add in healtchecks
        if kwargs.get('healthcheck'):
            template = self._healthcheck(template, **kwargs['healthcheck'])

        url = self._api("/namespaces/{}/replicationcontrollers", namespace)
        resp = self.session.post(url, json=template)
        if unhealthy(resp.status_code):
            error(resp, 'create ReplicationController "{}" in Namespace "{}"', name, namespace)
            logger.debug('template used: {}'.format(json.dumps(template, indent=4)))

        create = False
        for _ in range(30):
            if not create and self._get_rc_status(namespace, name) == 404:
                time.sleep(1)
                continue

            create = True
            rc = self._get_rc(namespace, name).json()
            # TODO: Does this matter? Is there a better indicator?
            if (
                "observedGeneration" in rc["status"] and
                rc["metadata"]["generation"] == rc["status"]["observedGeneration"]
            ):
                break

            time.sleep(1)

        return resp.json()

    def _update_rc(self, namespace, name, data):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.session.put(url, json=data)
        if unhealthy(response.status_code):
            error(response, 'scale ReplicationController "{}"', name)

        return response

    def _delete_rc(self, namespace, name):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        response = self.session.delete(url)
        if unhealthy(response.status_code):
            error(response, 'delete ReplicationController "{}" in Namespace "{}"',
                  name, namespace)

        return response

    def _healthcheck(self, controller, path='/', port=8080, delay=30, timeout=1):
        # FIXME this logic ideally should live higher up
        app_type = controller['spec']['selector']['type']
        if app_type not in ['web', 'cmd']:
            return controller

        namespace = controller['spec']['selector']['app']
        # Inspect if a PORT env is already defined, make sure that's the port used
        try:
            service = self._get_service(namespace, namespace).json()
            port = service['spec']['ports'][0]['targetPort']
        except:
            pass

        # Only support HTTP checks for now
        # http://kubernetes.io/v1.1/docs/user-guide/pod-states.html#container-probes
        healthcheck = {
            # defines the health checking
            'livenessProbe': {
                # an http probe
                'httpGet': {
                    'path': path,
                    'port': port
                },
                # length of time to wait for a pod to initialize
                # after pod startup, before applying health checking
                'initialDelaySeconds': delay,
                'timeoutSeconds': timeout
            },
            'readinessProbe': {
                # an http probe
                'httpGet': {
                    'path': path,
                    'port': port
                },
                # length of time to wait for a pod to initialize
                # after pod startup, before applying health checking
                'initialDelaySeconds': delay,
                'timeoutSeconds': timeout
            },
        }

        # Update only the application container with the health check
        container_name = '{}-{}'.format(namespace, app_type)
        containers = controller['spec']['template']['spec']['containers']
        for container in containers:
            if container['name'] == container_name:
                container.update(healthcheck)

        return controller

    # SECRETS #
    # http://kubernetes.io/v1.1/docs/api-reference/v1/definitions.html#_v1_secret

    def _create_minio_secret(self, namespace):
        secret = self._get_secret('deis', 'minio-user').json()  # fetch from deis namespace

        data = {
            'access-key-id': base64.b64decode(secret['data']['access-key-id']),
            'access-secret-key': base64.b64decode(secret['data']['access-secret-key'])
        }
        self._create_secret(namespace, 'minio-user', data)

    def _get_secret(self, namespace, name):
        url = self._api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get Secret "{}" in Namespace "{}"', name, namespace)

        # FIXME decode data - can it be done without affecting the response object too much???

        return response

    def _get_secrets(self, namespace, **kwargs):
        url = self._api('/namespaces/{}/secrets', namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, 'get Secrets in Namespace "{}"', namespace)

        return response

    def _create_secret(self, namespace, name, data):
        template = json.loads(string.Template(SECRET_TEMPLATE).substitute({
            "version": self.apiversion,
            "id": namespace,
            "name": name
        }))

        for key, value in data.items():
            value = value if isinstance(value, bytes) else bytes(value, 'UTF-8')
            item = base64.b64encode(value).decode()
            template["data"].update({key: item})

        url = self._api("/namespaces/{}/secrets", namespace)
        response = self.session.post(url, json=template)
        if unhealthy(response.status_code):
            error(response, 'failed to create secret "{}" in Namespace "{}"', name, namespace)

        return response

    def _delete_secret(self, namespace, name):
        url = self._api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.session.delete(url)
        if unhealthy(response.status_code):
            error(response, 'delete Secret "{}" in Namespace "{}"', name, namespace)

        return response

    # SERVICES #

    def _get_service(self, namespace, name):
        url = self._api("/namespaces/{}/services/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get Service "{}" in Namespace "{}"', name, namespace)

        return response

    def _get_services(self, namespace, **kwargs):
        url = self._api('/namespaces/{}/services', namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, 'get Services in Namespace "{}"', namespace)

        return response

    def _create_service(self, namespace, name, data={}, **kwargs):
        l = {
            "version": self.apiversion,
            "name": namespace,
        }

        # Merge external data on to the prefined template
        template = json.loads(string.Template(SERVICE_TEMPLATE).substitute(l))
        data = dict_merge(template, data)
        url = self._api("/namespaces/{}/services", namespace)
        response = self.session.post(url, json=data)
        if unhealthy(response.status_code):
            error(response, 'create Service "{}" in Namespace "{}"', namespace, namespace)

        return response

    def _update_service(self, namespace, name, data):
        url = self._api("/namespaces/{}/services/{}", namespace, name)
        response = self.session.put(url, json=data)
        if unhealthy(response.status_code):
            error(response, 'update Service "{}" in Namespace "{}"', namespace, name)

        return response

    def _delete_service(self, namespace, name):
        url = self._api("/namespaces/{}/services/{}", namespace, name)
        response = self.session.delete(url)
        if unhealthy(response.status_code):
            error(response, 'delete Service "{}" in Namespace "{}"', name, namespace)

        return response

    # PODS #

    def _get_pod(self, namespace, name):
        url = self._api("/namespaces/{}/pods/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get Pod "{}" in Namespace "{}"', name, namespace)

        return response

    def _get_pods(self, namespace, **kwargs):
        url = self._api('/namespaces/{}/pods', namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, 'get Pods in Namespace "{}"', namespace)

        return response

    def _delete_pod(self, namespace, name):
        url = self._api("/namespaces/{}/pods/{}", namespace, name)
        resp = self.session.delete(url)
        if unhealthy(resp.status_code):
            error(resp, 'delete Pod "{}" in Namespace "{}"', name, namespace)

        # Verify the pod has been deleted. Give it 30 seconds.
        for _ in range(30):
            try:
                self._get_pod(namespace, name)
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    break

            time.sleep(1)

        # Pod was not deleted within the grace period.
        try:
            self._get_pod(namespace, name)
        except KubeHTTPException as e:
            if e.response.status_code != 404:
                error(e.response, 'delete Pod "{}" in Namespace "{}"', name, namespace)

    def _pod_log(self, namespace, name):
        url = self._api("/namespaces/{}/pods/{}/log", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get logs for Pod "{}" in Namespace "{}"', name, namespace)

        return response

    def _pod_readiness_status(self, pod):
        """Check if the pod container have passed the readiness probes"""
        name = '{}-{}'.format(pod['metadata']['labels']['app'], pod['metadata']['labels']['type'])
        for container in pod['status']['containerStatuses']:
            # find the right container in case there are many on the pod
            if container['name'] == name:
                if not container['ready']:
                    if 'running' in container['state'].keys():
                        return 'Starting'
                    elif 'terminated' in container['state'].keys():
                        return 'Terminating'
                else:
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

    # NODES #

    def _get_nodes(self, **kwargs):
        url = self._api('/nodes')
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, 'get Nodes')

        return response

    def _get_node(self, name, **kwargs):
        url = self._api('/nodes/{}'.format(name))
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get Node {} in Nodes'.format(name))

        return response


SchedulerClient = KubeHTTPClient
