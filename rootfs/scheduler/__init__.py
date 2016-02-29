import json
import logging
import os
import re
import string
import time
from urllib.parse import urljoin
import base64

from django.conf import settings
from docker import Client
from .states import JobState
from .abstract import AbstractSchedulerClient
import requests
from .utils import dict_merge


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
        "image": "quay.io/deisci/slugrunner:v2-beta",
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
      "heritage": "deis"
    }
  },
  "spec": {
    "replicas": $num,
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
      "heritage": "deis"
    }
  },
  "spec": {
    "replicas": $num,
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
            "image": "quay.io/deisci/slugrunner:v2-beta",
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
        "port": 80,
        "targetPort": $port,
        "protocol": "TCP"
      }
    ],
    "selector": {
      "app": "$name",
      "type": "$type",
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

MATCH = re.compile(
    r'(?P<app>[a-z0-9-]+)_?(?P<version>v[0-9]+)?\.?(?P<c_type>[a-z-_]+)')


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


class KubeHTTPClient(AbstractSchedulerClient):

    def __init__(self, target):
        super(KubeHTTPClient, self).__init__(target)
        self.url = settings.SCHEDULER_URL
        self.registry = settings.REGISTRY_URL
        self.apiversion = "v1"
        with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as token_file:
            token = token_file.read()
        session = requests.Session()
        session.headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
        }
        # TODO: accessing the k8s api server by IP address rather than hostname avoids
        # intermittent DNS errors, but at the price of disabling cert verification.
        # session.verify = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        session.verify = False
        self.session = session

    def deploy(self, name, image, command, **kwargs):
        logger.debug('deploy {}, img {}, params {}, cmd "{}"'.format(name, image, kwargs, command))
        app_name = kwargs.get('aname', {})
        name = name.replace('.', '-').replace('_', '-')
        app_type = name.split('-')[-1]

        # Fetch old RC and create the new one for a release
        old_rc = self._get_old_rc(app_name, app_type)
        new_rc = self._create_rc(name, image, command, **kwargs)

        # Get the desired number to scale to
        if old_rc:
            desired = int(old_rc["spec"]["replicas"])
        else:
            desired = 1

        try:
            count = 1
            while desired >= count:
                logger.debug('scaling release {} to {} out of final {}'.format(
                    new_rc["metadata"]["name"], count, desired
                ))
                self._scale_rc(new_rc["metadata"]["name"], app_name, count)
                logger.debug('scaled up pod number {} for {}'.format(
                    count, new_rc["metadata"]["name"]
                ))

                if old_rc:
                    logger.debug('scaling old release {} from {} to {}'.format(
                        old_rc["metadata"]["name"], desired, (desired-count))
                    )
                    self._scale_rc(old_rc["metadata"]["name"], app_name, (desired-count))
                    logger.debug('scaled down pod number {} for {}'.format(
                        count, old_rc["metadata"]["name"]
                    ))

                count += 1
        except Exception as e:
            logger.error('Could not scale {} to {}. Deleting and going back to old release'.format(
                new_rc["metadata"]["name"], desired)
            )
            self._scale_rc(new_rc["metadata"]["name"], app_name, 0)
            self._delete_rc(app_name, new_rc["metadata"]["name"])
            if old_rc:
                self._scale_rc(old_rc["metadata"]["name"], app_name, desired)

            raise RuntimeError('{} (deploy): {}'.format(name, e))

        if old_rc:
            self._delete_rc(app_name, old_rc["metadata"]["name"])

    def scale(self, name, image, command, **kwargs):
        logger.debug('scale {}, img {}, params {}, cmd "{}"'.format(name, image, kwargs, command))
        app_name = kwargs.get('aname', {})
        rc_name = name.replace('.', '-').replace('_', '-')
        if unhealthy(self._get_rc_status(rc_name, app_name)):
            self.create(name, image, command, **kwargs)
            return

        name = name.replace('.', '-').replace('_', '-')
        num = kwargs.get('num', {})
        js_template = self._get_rc(name, app_name)
        old_replicas = js_template["spec"]["replicas"]
        try:
            self._scale_rc(name, app_name, num)
        except Exception as e:
            logger.debug("Scaling failed because of: {}".format(str(e)))
            self._scale_rc(name, app_name, old_replicas)
            raise RuntimeError('{} (Scale): {}'.format(name, e))

    def create(self, name, image, command, **kwargs):
        """Create a container."""
        logger.debug('create {}, img {}, params {}, cmd "{}"'.format(name, image, kwargs, command))
        name = name.replace('.', '-').replace('_', '-')
        app_type = name.split('-')[-1]
        app_name = kwargs.get('aname', {})
        try:
            # Make sure the router knows what to do with this
            data = {}
            # TODO this should potentially be higher up in the flow
            # see http://docs.deis.io/en/latest/using_deis/process-types/#web-vs-cmd-process-types
            if app_type in ['web', 'cmd']:
                data = {'metadata': {'labels': {'router.deis.io/routable': 'true'}}}
            self._create_namespace(app_name)
            self._create_minio_secret(app_name)
            self._create_service(name, app_name, app_type, data, image=image)

            # Create RC with 0 pods and instead use scale to get polling
            num = kwargs.pop('num')
            kwargs['num'] = 0
            self._create_rc(name, image, command, **kwargs)
            self._scale_rc(name, app_name, num)
        except Exception as e:
            logger.debug(e)
            # TODO check if RC exists first
            self._scale_rc(name, app_name, 0)
            # TODO check if RC exists first
            self._delete_rc(app_name, name)
            raise

    def start(self, name):
        """Start a container."""
        pass

    def stop(self, name):
        """Stop a container."""
        pass

    def destroy(self, name):
        """Destroy a application by deleting its namespace."""
        namespace = name.split("_")[0]
        logger.debug("destroy {}".format(name))
        url = self._api("/namespaces/{}", namespace)
        resp = self.session.delete(url)
        if resp.status_code == 404:
            logger.warn('delete Namespace "{}": not found'.format(namespace))
        elif resp.status_code != 200:
            error(resp, 'delete Namespace "{}"', namespace)

    def run(self, name, image, entrypoint, command):
        """Run a one-off command."""
        logger.debug('run {}, img {}, entrypoint {}, cmd "{}"'.format(
            name, image, entrypoint, command))
        appname = name.split('_')[0]
        name = name.replace('.', '-').replace('_', '-')
        imgurl = self.registry + '/' + image
        POD = POD_TEMPLATE
        if image.startswith('http://') or image.startswith('https://'):
            POD = POD_BTEMPLATE
            imgurl = image
        l = {
            'id': name,
            'version': self.apiversion,
            'image': imgurl,
        }
        template = string.Template(POD).substitute(l)
        if command.startswith('-c '):
            args = command.split(' ', 1)
            args[1] = args[1][1:-1]
        else:
            args = [command[1:-1]]

        js_template = json.loads(template)
        js_template['spec']['containers'][0]['command'] = [entrypoint]
        js_template['spec']['containers'][0]['args'] = args
        url = self._api("/namespaces/{}/pods", appname)
        resp = self.session.post(url, json=js_template)
        if unhealthy(resp.status_code):
            error(resp, 'create Pod in Namespace "{}"', appname)
        parsed_json = {}
        status = 404
        reason = ''
        data = ''
        duration = 30
        iteration = 1
        while(iteration < duration):
            try:
                status, reason, data = self._get_pod(name, appname)
                parsed_json = json.loads(data)
                if parsed_json['status']['phase'] == 'Succeeded':
                    status, data, reason = self._pod_log(name, appname)
                    self._delete_pod(name, appname)
                    return 0, data
                if parsed_json['status']['phase'] == 'Running':
                    if iteration > 28:
                        duration = duration + 1
            except:
                break
            iteration = iteration + 1
            time.sleep(1)

        if iteration >= duration:
            error(resp, 'Pod start took more than 30 seconds', appname)
            return 0, data
        if parsed_json['status']['phase'] == 'Failed':
            pod_state = parsed_json['status']['containerStatuses'][0]['state']
            err_code = pod_state['terminated']['exitCode']
            self._delete_pod(name, appname)
            return err_code, data
        return 0, data

    def state(self, name):
        """Display the state of a container."""
        try:
            appname = name.split('_')[0]
            name = name.split('.')
            name = name[0] + '-' + name[1]
            name = name.replace('_', '-')
            # FIXME fetch a singular pod instead of *all* pods
            pods = self._get_pods(appname)
            parsed_json = pods.json()
            for pod in parsed_json["items"]:
                if pod["metadata"]["generateName"] == name + "-":
                    return self.resolve_state(pod)

            return JobState.destroyed
        except Exception as err:
            logger.warn(err)
            return JobState.error

    def resolve_state(self, pod):
        if pod is None:
            return JobState.destroyed

        # See "Pod Phase" at http://kubernetes.io/v1.1/docs/user-guide/pod-states.html
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

    def _create_namespace(self, app_name):
        url = self._api("/namespaces")
        data = {
            "kind": "Namespace",
            "apiVersion": self.apiversion,
            "metadata": {
                "name": app_name
            }
        }
        resp = self.session.post(url, json=data)
        if not resp.status_code == 201:
            error(resp, "create Namespace {}".format(app_name))

    def _check_status(self, resp, app_name):
        if resp.status_code == 404:
            self._create_namespace(app_name)
        elif resp.status_code != 200:
            error(resp, "locate Namespace {}".format(app_name))

    # REPLICATION CONTROLLER #

    def _get_old_rc(self, name, app_type):
        url = self._api("/namespaces/{}/replicationcontrollers", name)
        resp = self.session.get(url)
        if unhealthy(resp.status_code):
            error(resp, 'get ReplicationControllers in Namespace "{}"', name)

        exists = False
        prev_rc = []
        for rc in resp.json()['items']:
            if('app' in rc['spec']['selector'] and name == rc['metadata']['labels']['app'] and
               'type' in rc['spec']['selector'] and app_type == rc['spec']['selector']['type']):
                exists = True
                prev_rc = rc
                break
        if exists:
            return prev_rc

        return 0

    def _get_rc_status(self, name, namespace):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        resp = self.session.get(url)
        return resp.status_code

    def _get_rc(self, name, namespace):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        resp = self.session.get(url)
        if unhealthy(resp.status_code):
            error(resp, 'get ReplicationController "{}" in Namespace "{}"', name, namespace)

        return resp.json()

    def _get_schedule_status(self, namespace, name, current, desired, resource_version):  # noqa
        if int(desired) > int(current):
            # new pods are going to be scheduled
            component = 'scheduler'
            reason = 'Scheduled'
            # events endpoints will return *all* scheduled pods
            state_count = desired
        else:
            # pods will be deleted
            component = 'kubelet'
            reason = 'Killing'
            # only the delta should be found in a particular state
            state_count = current - desired

        # always get the highest value so all pods are processed
        ready_desired = desired if int(desired) > int(current) else current
        logger.debug("waiting for {} pods to be processed in {} namespace to be known by the k8s api (120s timeout)".format(ready_desired, namespace))  # noqa
        pods = []
        for waited in range(120):
            count = 0
            pods = []
            parsed_json = self._get_pods(namespace).json()
            for pod in parsed_json['items']:
                if pod['metadata']['generateName'] == name+'-':
                    count += 1
                    pods.append(pod['metadata']['name'])

            if count == ready_desired:
                break

            if waited > 0 and (waited % 10) == 0:
                logger.debug("waited {}s and {} pods are found ".format(waited, count))

            time.sleep(1)

        logger.debug("{} out of {} pods to be processed in namespace {} were found".format(count, ready_desired, namespace))  # noqa

        logger.debug("waiting for {} pods to get to state {} in {} namespace (120s timeout)".format(state_count, reason, namespace))  # noqa
        for waited in range(120):
            waiting_pods = []
            # TODO Too many objects returned for this... look for alternative
            events = self._get_namespace_events(namespace, resourceVersion=resource_version).json()
            for event in events['items']:
                if (
                    event['involvedObject']['name'] in pods and
                    event['source']['component'] == component and
                    event['reason'] == reason and
                    event['involvedObject']['name'] not in waiting_pods
                ):
                    # certain reasons, like Killing, can happen many times per pod
                    waiting_pods.append(event['involvedObject']['name'])

            if len(waiting_pods) == state_count:
                break

            if waited > 0 and (waited % 10) == 0:
                logger.debug("waited {}s and {} pods are in state {}".format(waited, len(waiting_pods), reason))  # noqa

            time.sleep(1)

        logger.debug("{} out of {} pods in namespace {} are in state {}".format(len(waiting_pods), state_count, namespace, reason))  # noqa

        # if it was a scale down operation, wait until terminating pods are done
        if reason == 'Killing':
            self._wait_until_pods_terminate(namespace, name, state_count)

    def _wait_until_pods_terminate(self, namespace, name, desired):
        logger.debug("waiting for {} pods in {} namespace to be terminated (120s timeout)".format(desired, namespace))  # noqa
        for waited in range(120):
            count = 0
            pods = self._get_pods(namespace).json()
            for pod in pods['items']:
                # now that state is running time to see if probes are passing
                if (
                    pod['metadata']['generateName'] == name+'-' and
                    pod['status']['phase'] == 'Running' and
                    # is the readiness probe passing?
                    self._pod_readiness_status(pod) == 'Terminating'
                ):
                    count += 1

            # stop when all pods are terminated as expected
            if count == 0:
                break

            if waited > 0 and (waited % 10) == 0:
                logger.debug("waited {}s and {} pods out of {} are fully terminated".format(waited, (desired - count), desired))  # noqa

            time.sleep(1)

        logger.debug("{} pods in namespace {} are terminated".format(desired, namespace))  # noqa

    def _get_pod_ready_status(self, namespace, name, desired):
        # If desired is 0 then there is no ready state to check on
        if desired == 0:
            return

        # Ensure the minimum desired number of pods are available
        logger.debug("waiting for {} pods in {} namespace to be in services (120s timeout)".format(desired, namespace))  # noqa
        for waited in range(120):
            count = 0
            pods = self._get_pods(namespace).json()
            for pod in pods['items']:
                # now that state is running time to see if probes are passing
                if (
                    pod['metadata']['generateName'] == name+'-' and
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

    def _scale_rc(self, name, namespace, desired):
        rc = self._get_rc(name, namespace)

        # get the current replica count by querying for pods instead of introspecting RC
        labels = {
            'app': rc['spec']['selector']['app'],
            'type': rc['spec']['selector']['type'],
            'version': rc['spec']['selector']['version']
        }
        current = len(self._get_pods(namespace, labels=labels).json()['items'])

        # Set the new desired replica count
        rc['spec']['replicas'] = desired

        logger.debug("scaling RC {} in namespace {} from {} to {} replicas".format(name, namespace, current, desired))  # noqa

        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        resp = self.session.put(url, json=rc)
        if unhealthy(resp.status_code):
            error(resp, 'scale ReplicationController "{}"', name)

        resource_ver = rc['metadata']['resourceVersion']
        logger.debug("waiting for RC {} to get a newer resource version than {} (30s timeout)".format(name, resource_ver))  # noqa
        for waited in range(30):
            js_template = self._get_rc(name, namespace)
            if js_template["metadata"]["resourceVersion"] != resource_ver:
                break

            if waited > 0 and (waited % 10) == 0:
                logger.debug("waited {}s so far for a new resource version".format(waited))

            time.sleep(1)

        logger.debug("RC {} has a new resource version {}".format(name, js_template["metadata"]["resourceVersion"]))  # noqa

        # figure out the schedule state
        self._get_schedule_status(
            namespace,
            name,
            current,
            desired,
            js_template['metadata']['resourceVersion']
        )

        # Double check enough pods are in the required state to service the application
        self._get_pod_ready_status(namespace, name, desired)

    def _create_rc(self, name, image, command, **kwargs):  # noqa
        container_fullname = name
        app_name = kwargs.get('aname', {})
        app_type = name.split('-')[-1]
        container_name = app_name + '-' + app_type
        args = command.split()
        num = kwargs.get('num', {})
        imgurl = self.registry + "/" + image
        TEMPLATE = RCD_TEMPLATE

        # Check if it is a slug builder image.
        if kwargs.get('build_type') == "buildpack":
            imgurl = image
            TEMPLATE = RCB_TEMPLATE

        l = {
            "name": name,
            "id": app_name,
            "appversion": kwargs.get("version", {}),
            "version": self.apiversion,
            "image": imgurl,
            "num": kwargs.get("num", {}),
            "containername": container_name,
            "type": app_type,
        }
        template = string.Template(TEMPLATE).substitute(l)
        js_template = json.loads(template)

        # apply tags as needed
        tags = kwargs.get('tags', {})
        js_template["spec"]["template"]["spec"]["nodeSelector"] = tags

        # Deal with container information
        containers = js_template["spec"]["template"]["spec"]["containers"]
        containers[0]['args'] = args
        loc = locals().copy()
        loc.update(re.match(MATCH, container_fullname).groupdict())
        mem = kwargs.get('memory', {}).get(app_type)
        cpu = kwargs.get('cpu', {}).get(app_type)
        env = kwargs.get('envs', {})

        if env:
            for key, value in env.items():
                containers[0]["env"].append({
                    "name": key,
                    "value": str(value)
                })

        # Inject debugging if workflow is in debug mode
        if os.environ.get("DEBUG", False):
            containers[0]["env"].append({
                "name": "DEBUG",
                "value": "1"
            })

        if mem or cpu:
            containers[0]["resources"] = {"limits": {}}

        if mem:
            if mem[-2:-1].isalpha() and mem[-1].isalpha():
                mem = mem[:-1]

            mem = mem+"i"
            containers[0]["resources"]["limits"]["memory"] = mem

        if cpu:
            containers[0]["resources"]["limits"]["cpu"] = cpu

        # add in healtchecks
        if kwargs.get('healthcheck'):
            js_template = self._healthcheck(js_template, **kwargs['healthcheck'])

        url = self._api("/namespaces/{}/replicationcontrollers", app_name)
        resp = self.session.post(url, json=js_template)
        if unhealthy(resp.status_code):
            error(resp, 'create ReplicationController "{}" in Namespace "{}"',
                  name, app_name)
            logger.debug('template used: {}'.format(json.dumps(js_template, indent=4)))

        create = False
        for _ in range(30):
            if not create and self._get_rc_status(name, app_name) == 404:
                time.sleep(1)
                continue

            create = True
            rc = self._get_rc(name, app_name)
            if (
                "observedGeneration" in rc["status"] and
                rc["metadata"]["generation"] == rc["status"]["observedGeneration"]
            ):
                break

            time.sleep(1)
        return resp.json()

    def _update_rc(self, namespace, app, data):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, app)
        return self.session.put(url, json=data)

    def _delete_rc(self, namespace, name):
        url = self._api("/namespaces/{}/replicationcontrollers/{}", namespace, name)
        resp = self.session.delete(url)
        if unhealthy(resp.status_code):
            error(resp, 'delete ReplicationController "{}" in Namespace "{}"',
                  name, namespace)

    def _healthcheck(self, controller, path='/', port=8080, delay=30, timeout=1):
        # FIXME this logic ideally should live higher up
        if controller['spec']['selector']['type'] not in ['web', 'cmd']:
            return controller

        app_name = controller['spec']['selector']['app']
        # Inspect if a PORT env is already defined, make sure that's the port used
        try:
            service = self._get_service(app_name, app_name).json()
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

        # Because it comes from a JSON template, need to hit the first key
        controller['spec']['template']['spec']['containers'][0].update(healthcheck)

        return controller

    # SECRETS #
    # http://kubernetes.io/v1.1/docs/api-reference/v1/definitions.html#_v1_secret

    def _create_minio_secret(self, namespace):
        with open("/var/run/secrets/deis/minio/user/access-key-id", "rb") as the_file:
            secretId = the_file.read()
        with open("/var/run/secrets/deis/minio/user/access-secret-key", "rb") as the_file:
            secretKey = the_file.read()

        data = {
            'access-key-id': secretId,
            'access-secret-key': secretKey
        }
        self._create_secret(namespace, 'minio-user', data)

    def _get_secret(self, namespace, name):
        url = self._api("/namespaces/{}/secrets/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get Secret "{}" in Namespace "{}"', name, namespace)

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

    def _get_service(self, name, namespace):
        url = self._api("/namespaces/{}/services/{}", namespace, name)
        response = self.session.get(url)
        if unhealthy(response.status_code):
            error(response, 'get Service "{}" in Namespace "{}"', name, namespace)

        return response

    def _create_service(self, name, app_name, app_type, data={}, **kwargs):
        docker_cli = Client(version="auto")
        image = kwargs.get('image')
        try:
            image = self.registry + '/' + image
            repo = image.split(":")
            # image already includes the tag, so we split it out here
            docker_cli.pull(repo[0]+":"+repo[1], tag=repo[2], insecure_registry=True)
            image_info = docker_cli.inspect_image(image)
            port = int(list(image_info['Config']['ExposedPorts'].keys())[0].split("/")[0])
        except:
            port = 5000
        l = {
            "version": self.apiversion,
            "port": port,
            "type": app_type,
            "name": app_name,
        }
        # Merge external data on to the prefined template
        template = json.loads(string.Template(SERVICE_TEMPLATE).substitute(l))
        data = dict_merge(template, data)
        url = self._api("/namespaces/{}/services", app_name)
        resp = self.session.post(url, json=data)
        if resp.status_code == 409:
            srv = self._get_service(app_name, app_name).json()
            if srv['spec']['selector']['type'] == 'web':
                return
            srv['spec']['selector']['type'] = app_type
            srv['spec']['ports'][0]['targetPort'] = port
            resp2 = self._update_service(app_name, app_name, srv)
            if unhealthy(resp2.status_code):
                error(resp, 'update Service "{}" in Namespace "{}"', app_name, app_name)
        elif unhealthy(resp.status_code):
            error(resp, 'create Service "{}" in Namespace "{}"', app_name, app_name)

    def _update_service(self, namespace, app, data):
        url = self._api("/namespaces/{}/services/{}", namespace, app)
        return self.session.put(url, json=data)

    # PODS #

    def _get_pod(self, name, namespace, return_response=False):
        url = self._api("/namespaces/{}/pods/{}", namespace, name)
        resp = self.session.get(url)
        if unhealthy(resp.status_code):
            error(resp, 'get Pod "{}" in Namespace "{}"', name, namespace)

        if return_response:
            return resp

        return resp.status_code, resp.reason, resp.text

    def _get_pods(self, namespace, **kwargs):
        url = self._api("/namespaces/{}/pods", namespace)
        response = self.session.get(url, params=self._selectors(**kwargs))
        if unhealthy(response.status_code):
            error(response, 'get Pods in Namespace "{}"', namespace)

        return response

    def _delete_pod(self, name, namespace):
        url = self._api("/namespaces/{}/pods/{}", namespace, name)
        resp = self.session.delete(url)
        if unhealthy(resp.status_code):
            error(resp, 'delete Pod "{}" in Namespace "{}"', name, namespace)

        # Verify the pod has been deleted. Give it 30 seconds.
        for _ in range(30):
            try:
                self._get_pod(name, namespace)
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    break

            time.sleep(1)

        # Pod was not deleted within the grace period.
        try:
            self._get_pod(name, namespace)
        except KubeHTTPException as e:
            if e.response.status_code != 404:
                error(e.response, 'delete Pod "{}" in Namespace "{}"', name, namespace)

    def _pod_log(self, name, namespace):
        url = self._api("/namespaces/{}/pods/{}/log", namespace, name)
        resp = self.session.get(url)
        if unhealthy(resp.status_code):
            error(resp, 'get logs for Pod "{}" in Namespace "{}"', name, namespace)

        return resp.status_code, resp.text, resp.reason

    def _pod_readiness_status(self, pod):
        """Check if the pod container have passed the readiness probes"""
        name = '{}-{}'.format(pod['metadata']['labels']['app'], pod['metadata']['labels']['type'])
        for container in pod['status']['containerStatuses']:
            # find the right container in case there are many on the pod
            if container['name'] == name:
                if not container['ready']:
                    if 'running' in container['state']:
                        return 'Starting'
                    elif 'terminated' in container['state']:
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
        path = '/nodes'
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

        url = self._api(path)
        response = self.session.get(url, params=query)
        if unhealthy(response.status_code):
            error(response, 'get Nodes')

        return response


SchedulerClient = KubeHTTPClient
