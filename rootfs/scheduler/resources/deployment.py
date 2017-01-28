from datetime import datetime, timedelta
import json
import time
from scheduler.resources import Resource
from scheduler.exceptions import KubeException, KubeHTTPException


class Deployment(Resource):
    api_prefix = 'apis'
    api_version = 'extensions/v1beta1'

    def get(self, namespace, name=None, **kwargs):
        """
        Fetch a single Deployment or a list
        """
        url = '/namespaces/{}/deployments'
        args = [namespace]
        if name is not None:
            args.append(name)
            url += '/{}'
            message = 'get Deployment "{}" in Namespace "{}"'
        else:
            message = 'get Deployments in Namespace "{}"'

        url = self.api(url, *args)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if self.unhealthy(response.status_code):
            args.reverse()  # error msg is in reverse order
            raise KubeHTTPException(response, message, *args)

        return response

    def manifest(self, namespace, name, image, entrypoint, command, **kwargs):
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
        if kwargs.get('deployment_revision_history_limit', None) is not None:
            manifest['spec']['revisionHistoryLimit'] = int(kwargs.get('deployment_revision_history_limit'))  # noqa

        # tell pod how to execute the process
        kwargs['command'] = entrypoint
        kwargs['args'] = command

        # pod manifest spec
        manifest['spec']['template'] = self.pod.manifest(namespace, name, image, **kwargs)

        return manifest

    def create(self, namespace, name, image, entrypoint, command, **kwargs):
        manifest = self.manifest(namespace, name, image,
                                 entrypoint, command, **kwargs)

        url = self.api("/namespaces/{}/deployments", namespace)
        response = self.http_post(url, json=manifest)
        if self.unhealthy(response.status_code):
            self.log(namespace, 'template: {}'.format(json.dumps(manifest, indent=4)), 'DEBUG')
            raise KubeHTTPException(
                response,
                'create Deployment "{}" in Namespace "{}"', name, namespace
            )

        self.wait_until_updated(namespace, name)
        self.wait_until_ready(namespace, name, **kwargs)

        return response

    def update(self, namespace, name, image, entrypoint, command, **kwargs):
        manifest = self.manifest(namespace, name, image,
                                 entrypoint, command, **kwargs)

        url = self.api("/namespaces/{}/deployments/{}", namespace, name)
        response = self.http_put(url, json=manifest)
        if self.unhealthy(response.status_code):
            self.log(namespace, 'template: {}'.format(json.dumps(manifest, indent=4)), 'DEBUG')
            raise KubeHTTPException(response, 'update Deployment "{}"', name)

        self.wait_until_updated(namespace, name)
        self.wait_until_ready(namespace, name, **kwargs)

        return response

    def delete(self, namespace, name):
        url = self.api("/namespaces/{}/deployments/{}", namespace, name)
        response = self.http_delete(url)
        if self.unhealthy(response.status_code):
            raise KubeHTTPException(
                response,
                'delete Deployment "{}" in Namespace "{}"', name, namespace
            )

        return response

    def scale(self, namespace, name, image, entrypoint, command, **kwargs):
        """
        A convenience wrapper around Deployment update that does a little bit of introspection
        to determine if scale level is already where it needs to be
        """
        deployment = self.deployment.get(namespace, name).json()
        desired = int(kwargs.get('replicas'))
        current = int(deployment['spec']['replicas'])
        if desired == current:
            self.log(namespace, "Not scaling Deployment {} to {} replicas. Already at desired replicas".format(name, desired))  # noqa
            return
        elif desired != current:
            self.log(namespace, "scaling Deployment {} from {} to {} replicas".format(name, current, desired))  # noqa
            self.scales.update(namespace, name, desired, deployment)

            # wait until scaling is done
            self.wait_until_updated(namespace, name)
            # set the previous replicas count so the wait logic can deal with terminating pods
            kwargs['previous_replicas'] = current
            self.wait_until_ready(namespace, name, **kwargs)

    def in_progress(self, namespace, name, timeout, batches, replicas, tags):
        """
        Determine if a Deployment has a deploy in progress

        First is a very basic check to see if replicas are ready.

        If they are not ready then it is time to see if there are problems with any of the pods
        such as image pull issues or similar.

        And then if that is still all okay then it is time to see if the deploy has
        been in progress for longer than the allocated deploy time. Reason to do this
        check is if a client has had a dropped connection.

        Returns 2 booleans, first one is for if the Deployment is in progress or not, second
        one is or if a rollback action is advised while leaving the rollback up to the caller
        """
        self.log(namespace, 'Checking if Deployment {} is in progress'.format(name), level='DEBUG')  # noqa
        try:
            ready, _ = self.are_replicas_ready(namespace, name)
            if ready:
                # nothing more to do - False since it is not in progress
                self.log(namespace, 'All replicas for Deployment {} are ready'.format(name), level='DEBUG')  # noqa
                return False, False
        except KubeHTTPException as e:
            # Deployment doesn't exist
            if e.response.status_code == 404:
                self.log(namespace, 'Deployment {} does not exist yet'.format(name), level='DEBUG')  # noqa
                return False, False

        # get deployment information
        deployment = self.deployment.get(namespace, name).json()
        # get pod template labels since they include the release version
        labels = deployment['spec']['template']['metadata']['labels']
        containers = deployment['spec']['template']['spec']['containers']

        # calculate base deploy timeout
        deploy_timeout = self.pod.deploy_probe_timeout(timeout, namespace, labels, containers)

        # a rough calculation that figures out an overall timeout
        steps = self._get_deploy_steps(batches, tags)
        batches = self._get_deploy_batches(steps, replicas)
        timeout = len(batches) * deploy_timeout

        # is there a slow image pull or image issues
        try:
            timeout += self.pod._handle_pending_pods(namespace, labels)
        except KubeException as e:
            self.log(namespace, 'Deployment {} had stalled due an error and will be rolled back. {}'.format(name, str(e)), level='DEBUG')  # noqa
            return False, True

        # fetch the latest RS for Deployment and use the start time to compare to deploy timeout
        replicasets = self.rs.get(namespace, labels=labels).json()['items']
        # the labels should ensure that only 1 replicaset due to the version label
        if replicasets and len(replicasets) != 1:
            # if more than one then sort by start time to newest is first
            replicasets.sort(key=lambda x: x['metadata']['creationTimestamp'], reverse=True)

        # work with the latest copy
        replica = replicasets.pop()

        # throw an exception if over TTL so error is bubbled up
        start = self.parse_date(replica['metadata']['creationTimestamp'])
        if (start + timedelta(seconds=timeout)) < datetime.utcnow():
            self.log(namespace, 'Deploy operation for Deployment {} in has expired. Rolling back to last good known release'.format(name), level='DEBUG')  # noqa
            return False, True

        return True, False

    def are_replicas_ready(self, namespace, name):
        """
        Verify the status of a Deployment and if it is fully deployed
        """
        deployment = self.get(namespace, name).json()
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

    def wait_until_updated(self, namespace, name):
        """
        Looks at status/observedGeneration and metadata/generation and
        waits for observedGeneration >= generation to happen

        http://kubernetes.io/docs/user-guide/deployments/#the-status-of-a-deployment
        More information is also available at:
        https://github.com/kubernetes/kubernetes/blob/master/docs/devel/api-conventions.md#metadata
        """
        self.log(namespace, "waiting for Deployment {} to get a newer generation (30s timeout)".format(name), 'DEBUG')  # noqa
        for _ in range(30):
            try:
                deploy = self.deployment.get(namespace, name).json()
                if (
                    'observedGeneration' in deploy['status'] and
                    deploy['status']['observedGeneration'] >= deploy['metadata']['generation']
                ):
                    self.log(namespace, "A newer generation was found for Deployment {}".format(name), 'DEBUG')  # noqa
                    break

                time.sleep(1)
            except KubeHTTPException as e:
                if e.response.status_code == 404:
                    time.sleep(1)

    def wait_until_ready(self, namespace, name, **kwargs):
        """
        Wait until the Deployment object has all the replicas ready
        and other factors that play in

        Deals with the wait time, timesout and more
        """
        replicas = int(kwargs.get('replicas', 0))
        # If desired is 0 then there is no ready state to check on
        if replicas == 0:
            return

        current = int(kwargs.get('previous_replicas', 0))
        batches = kwargs.get('deploy_batches', None)
        timeout = kwargs.get('deploy_timeout', 120)
        tags = kwargs.get('tags', {})
        steps = self._get_deploy_steps(batches, tags)
        batches = self._get_deploy_batches(steps, replicas)

        deployment = self.get(namespace, name).json()
        labels = deployment['spec']['template']['metadata']['labels']
        containers = deployment['spec']['template']['spec']['containers']

        # if it was a scale down operation, wait until terminating pods are done
        # Deployments say they are ready even when pods are being terminated
        if replicas < current:
            self.pods.wait_until_terminated(namespace, labels, current, replicas)
            return

        # calculate base deploy timeout
        deploy_timeout = self.pod.deploy_probe_timeout(timeout, namespace, labels, containers)

        # a rough calculation that figures out an overall timeout
        timeout = len(batches) * deploy_timeout
        self.log(namespace, 'This deployments overall timeout is {}s - batch timout is {}s and there are {} batches to deploy with a total of {} pods'.format(timeout, deploy_timeout, len(batches), replicas))  # noqa

        # check for failed events(when quota exceeded for example)
        self._check_for_failed_events(namespace, labels=labels)

        waited = 0
        while waited < timeout:
            ready, availablePods = self.are_replicas_ready(namespace, name)
            if ready:
                break

            # check every 10 seconds for pod failures.
            # Depend on Deployment checks for ready pods
            if waited > 0 and (waited % 10) == 0:
                additional_timeout = self.pod._handle_pending_pods(namespace, labels)
                if additional_timeout:
                    timeout += additional_timeout
                    # add 10 minutes to timeout to allow a pull image operation to finish
                    self.log(namespace, 'Kubernetes has been pulling the image for {}s'.format(waited))  # noqa
                    self.log(namespace, 'Increasing timeout by {}s to allow a pull image operation to finish for pods'.format(additional_timeout))  # noqa

                self.log(namespace, "waited {}s and {} pods are in service".format(waited, availablePods))  # noqa

            waited += 1
            time.sleep(1)

        # check if the replicas are still not ready because of healthcheck failures
        ready, _ = self.are_replicas_ready(namespace, name)
        if not ready:
            self.pod._handle_not_ready_pods(namespace, labels)

    def _check_for_failed_events(self, namespace, labels):
        """
        Request for new ReplicaSet of Deployment and search for failed events involved by that RS
        Raises: KubeException when RS have events with FailedCreate reason
        """
        response = self.rs.get(namespace, labels=labels)
        data = response.json()
        fields = {
            'involvedObject.kind': 'ReplicaSet',
            'involvedObject.name': data['items'][0]['metadata']['name'],
            'involvedObject.namespace': namespace,
            'involvedObject.uid': data['items'][0]['metadata']['uid'],
        }
        events_list = self.ns.events(namespace, fields=fields).json()
        events = events_list.get('items', [])
        if events is not None and len(events) != 0:
            for event in events:
                if event['reason'] == 'FailedCreate':
                    log = self._get_formatted_messages(events)
                    self.log(namespace, log)
                    raise KubeException(log)

    @staticmethod
    def _get_formatted_messages(events):
        """
        Format each event by string and join all events to one string
        """
        message_format = 'Message:{message}, lastTimestamp:{lastTimestamp}, reason: {reason}, count: {count}'  # noqa
        output = []
        for event in events:
            output.append(message_format.format(**event))
        return '\n'.join(output)

    def _get_deploy_steps(self, batches, tags):
        # if there is no batch information available default to available nodes for app
        if not batches:
            # figure out how many nodes the application can go on
            nodes = self.node.get(labels=tags).json()['items']
            steps = len(nodes) if nodes else 0
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
