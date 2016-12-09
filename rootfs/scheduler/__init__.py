from collections import OrderedDict
from datetime import datetime
import logging
from packaging.version import Version
import requests
import requests.exceptions
from requests_toolbelt import user_agent
import time
from urllib.parse import urljoin

from api import __version__ as deis_version
from scheduler.exceptions import KubeException, KubeHTTPException   # noqa
from scheduler.states import PodState


logger = logging.getLogger(__name__)
session = None
resource_mapping = OrderedDict()


def get_session(k8s_api_verify_tls):
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
        if k8s_api_verify_tls:
            session.verify = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        else:
            session.verify = False
    return session


class KubeHTTPClient(object):
    # ISO-8601 which is used by kubernetes
    DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

    def __init__(self, url, k8s_api_verify_tls=True):
        global resource_mapping
        self.url = url
        self.session = get_session(k8s_api_verify_tls)

        # map the various k8s Resources to an internal property
        from scheduler.resources import Resource  # lazy load
        for res in Resource:
            name = str(res.__name__).lower()  # singular
            component = name + 's'  # make plural
            # check if component has already been processed
            if component in resource_mapping:
                continue

            # get past recursion problems in case of self reference
            resource_mapping[component] = ''
            resource_mapping[component] = res(self.url)
            # map singular Resource name to the plural one
            resource_mapping[name] = component
            if res.short_name is not None:
                # map short name to long name so a resource can be named rs
                # but have the main object live at replicasets
                resource_mapping[str(res.short_name).lower()] = component

    def __getattr__(self, name):
        global resource_mapping
        if name in resource_mapping:
            # resolve to final name if needed
            component = resource_mapping[name]
            if type(component) is not str:
                # already a component object
                return component

            return resource_mapping[component]

        return object.__getattribute__(self, name)

    def version(self):
        """Get Kubernetes version"""
        response = self.http_get('/version')
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'fetching Kubernetes version')

        data = response.json()
        return Version('{}.{}'.format(data['major'], data['minor']))

    @staticmethod
    def parse_date(date):
        return datetime.strptime(date, KubeHTTPClient.DATETIME_FORMAT)

    @staticmethod
    def unhealthy(status_code):
        return not 200 <= status_code <= 299

    @staticmethod
    def query_params(labels=None, fields=None, resource_version=None, pretty=False):
        query = {}

        # labels and fields are encoded slightly differently than python-requests can do
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

        if fields:
            fields = ['{}={}'.format(key, value) for key, value in fields.items()]
            query['fieldSelector'] = ','.join(fields)

        # Which resource version to start from. Otherwise starts from the beginning
        if resource_version:
            query['resourceVersion'] = resource_version

        # If output should pretty print, only True / False allowed
        if pretty:
            query['pretty'] = pretty

        return query

    @staticmethod
    def log(namespace, message, level='INFO'):
        """Logs a message in the context of this application.

        This prefixes log messages with a namespace "tag".
        When it's seen, the message-- usually an application event of some
        sort like releasing or scaling, will be considered as "belonging" to the application
        instead of the controller and will be handled accordingly.
        """
        lvl = getattr(logging, level.upper()) if hasattr(logging, level.upper()) else logging.INFO
        logger.log(lvl, "[{}]: {}".format(namespace, message))

    def http_head(self, path, **kwargs):
        """
        Make a HEAD request to the k8s server.
        """
        try:

            url = urljoin(self.url, path)
            response = self.session.head(url, **kwargs)
        except requests.exceptions.ConnectionError as err:
            # reraise as KubeException, but log stacktrace.
            message = "There was a problem retrieving headers from " \
                "the Kubernetes API server. URL: {}".format(url)
            logger.error(message)
            raise KubeException(message) from err

        return response

    def http_get(self, path, params=None, **kwargs):
        """
        Make a GET request to the k8s server.
        """
        try:
            url = urljoin(self.url, path)
            response = self.session.get(url, params=params, **kwargs)
        except requests.exceptions.ConnectionError as err:
            # reraise as KubeException, but log stacktrace.
            message = "There was a problem retrieving data from " \
                      "the Kubernetes API server. URL: {}, params: {}".format(url, params)
            logger.error(message)
            raise KubeException(message) from err

        return response

    def http_post(self, path, data=None, json=None, **kwargs):
        """
        Make a POST request to the k8s server.
        """
        try:
            url = urljoin(self.url, path)
            response = self.session.post(url, data=data, json=json, **kwargs)
        except requests.exceptions.ConnectionError as err:
            # reraise as KubeException, but log stacktrace.
            message = "There was a problem posting data to " \
                      "the Kubernetes API server. URL: {}, " \
                      "data: {}, json: {}".format(url, data, json)
            logger.error(message)
            raise KubeException(message) from err

        return response

    def http_put(self, path, data=None, **kwargs):
        """
        Make a PUT request to the k8s server.
        """
        try:
            url = urljoin(self.url, path)
            response = self.session.put(url, data=data, **kwargs)
        except requests.exceptions.ConnectionError as err:
            # reraise as KubeException, but log stacktrace.
            message = "There was a problem putting data to " \
                      "the Kubernetes API server. URL: {}, " \
                      "data: {}".format(url, data)
            logger.error(message)
            raise KubeException(message) from err

        return response

    def http_delete(self, path, **kwargs):
        """
        Make a DELETE request to the k8s server.
        """
        try:
            url = urljoin(self.url, path)
            response = self.session.delete(url, **kwargs)
        except requests.exceptions.ConnectionError as err:
            # reraise as KubeException, but log stacktrace.
            message = "There was a problem deleting data from " \
                      "the Kubernetes API server. URL: {}".format(url)
            logger.error(message)
            raise KubeException(message) from err

        return response

    def deploy(self, namespace, name, image, entrypoint, command, **kwargs):  # noqa
        """Deploy Deployment depending on what's requested"""
        app_type = kwargs.get('app_type')
        version = kwargs.get('version')

        # If an RC already exists then stop processing of the deploy
        try:
            # construct old school RC name
            rc_name = '{}-{}-{}'.format(namespace, version, app_type)
            self.rc.get(namespace, rc_name)
            self.log(namespace, 'RC {} already exists. Stopping deploy'.format(rc_name))
            return
        except KubeHTTPException:
            # if RC doesn't exist then let the app continue
            pass

        # create a deployment if missing, otherwise update to trigger a release
        try:
            # labels that represent the pod(s)
            labels = {
                'app': namespace,
                'version': version,
                'type': app_type,
                'heritage': 'deis',
            }
            # this depends on the deployment object having the latest information
            deployment = self.deployment.get(namespace, name).json()
            if deployment['spec']['template']['metadata']['labels'] == labels:
                self.log(namespace, 'Deployment {} with release {} already exists. Stopping deploy'.format(name, version))  # noqa
                return
        except KubeException:
            # create the initial deployment object (and the first revision)
            self.deployment.create(
                namespace, name, image, entrypoint, command, **kwargs
            )
        else:
            try:
                # kick off a new revision of the deployment
                self.deployment.update(
                    namespace, name, image, entrypoint, command, **kwargs
                )
            except KubeException as e:
                raise KubeException(
                    'There was a problem while deploying {} of {}-{}. '
                    "Additional information:\n{}".format(version, namespace, app_type, str(e))
                ) from e

    def scale(self, namespace, name, image, entrypoint, command, **kwargs):
        """Scale Deployment"""
        try:
            self.deployment.get(namespace, name)
        except KubeHTTPException as e:
            if e.response.status_code == 404:
                # create missing deployment - deleted if it fails
                try:
                    self.deployment.create(namespace, name, image, entrypoint, command, **kwargs)
                except KubeException:
                    # see if the deployment got created
                    try:
                        self.deployment.get(namespace, name)
                    except KubeHTTPException as e:
                        if e.response.status_code != 404:
                            self.deployment.delete(namespace, name)

                    raise

        # let the scale failure bubble up
        self.deployment.scale(namespace, name, image, entrypoint, command, **kwargs)

    def run(self, namespace, name, image, entrypoint, command, **kwargs):
        """Run a one-off command."""
        self.log(namespace, 'run {}, img {}, entrypoint {}, cmd "{}"'.format(
            name, image, entrypoint, command)
        )

        # run pods never restart
        kwargs['restartPolicy'] = 'Never'
        kwargs['command'] = entrypoint
        kwargs['args'] = command

        self.pod.create(namespace, name, image, **kwargs)

        try:
            # give pod 20 minutes to execute (after it got into ready state)
            # this is a fairly arbitrary limit but the gunicorn worker / LBs
            # will make this timeout around 20 anyway.
            # TODO: Revisit in the future so it can run longer
            state = 'up'  # pod is still running
            waited = 0
            timeout = 1200  # 20 minutes
            while (state == 'up' and waited < timeout):
                pod = self.pod.get(namespace, name).json()
                state = str(self.pod.state(pod))
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
            state = self.pod.state(self.pod.get(namespace, name).json())
            # States below up do not have logs
            if not isinstance(state, PodState) or state < PodState.up:
                return exit_code, 'Could not get logs. Pod is in state {}'.format(str(state))

            # grab log information
            log = self.pod.logs(namespace, name)
            log.encoding = 'utf-8'  # defaults to "ISO-8859-1" otherwise...

            return exit_code, log.text
        finally:
            # cleanup
            self.pod.delete(namespace, name)


SchedulerClient = KubeHTTPClient
