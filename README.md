# Deis Workflow v2

[![Build Status](https://travis-ci.org/deis/workflow.svg?branch=master)](https://travis-ci.org/deis/workflow)
[![codecov.io](https://codecov.io/github/deis/workflow/coverage.svg?branch=master)](https://codecov.io/github/deis/workflow?branch=master)
[![Docker Repository on Quay](https://quay.io/repository/deisci/controller/status "Docker Repository on Quay")](https://quay.io/repository/deisci/controller)

Deis (pronounced DAY-iss) is an open source PaaS that makes it easy to deploy and manage applications on your own servers. Deis builds on Kubernetes to provide a lightweight, easy and secure way to deploy your code to production.

For more information about the Deis Workflow, please visit the main project page at https://github.com/deis/workflow.

## Beta Status

This Deis component is currently in beta status, and we welcome your input! If you have feedback, please [submit an issue][issues]. If you'd like to participate in development, please read the "Development" section below and [submit a pull request][prs].

The following features are not ready in Beta, but will be coming soon.

- Complete SSL support
- Backup and restore features
- Persistent storage (though it can be manually configured)

# About

The controller is the central API for the entire Deis Platform. Below is a non-exhaustive list of things it can do:

* Create a new application
* Delete an application
* Scale an application
* Configure an application
* Create a new user

# Development

The Deis project welcomes contributions from all developers. The high level process for development matches many other open source projects. See below for an outline.

* Fork this repository
* Make your changes
* [Submit a pull request][prs] (PR) to this repository with your changes, and unit tests whenever possible.
  * If your PR fixes any [issues][issues], make sure you write Fixes #1234 in your PR description (where #1234 is the number of the issue you're closing)
* The Deis core contributors will review your code. After each of them sign off on your code, they'll label your PR with LGTM1 and LGTM2 (respectively). Once that happens, you may merge

## Prerequisities

### Kubernetes

In order to do development on this component, you'll need a working Kubernetes cluster. If you don't have one follow the [installation instructions][install-k8s] and note that Workflow currently targets version 1.1 with the following requirements:

* Docker's `insecure-registry` parameter must include the subnets used by your Kubernetes installation
* If you are testing the logger components, you must enable `DaemonSet` experimental APIs via `--runtime-config=extensions/v1beta1/daemonsets=true`

### Helm

After you have a working Kubernetes cluster, install [helm](http://helm.sh) and run the following commands to add the Deis chart repository and install Deis to your new cluster:

```console
helm repo add deis https://github.com/deis/charts
helm install deis/deis-dev
```

Note that to work off the latest stable release, change the `helm install deis/deis-dev` command to `helm install deis/deis`.

## Testing Your Code

When you've built your new feature or fixed a bug, make sure you've added appropriate unit tests and run `make test` to ensure your code works properly.

Also, since this component is central to the platform, it's recommended that you manually test and verify that your feature or fix works as expected. To do so, ensure the following environment variables are set:

* `DEIS_REGISTRY` - A Docker registry that you have push access to and your Kubernetes cluster can pull from
  * If this is [Docker Hub](https://hub.docker.com/), leave this variable empty
  * Otherwise, ensure it has a trailing `/`. For example, if you're using [Quay.io](https://quay.io), use `quay.io/`
* `IMAGE_PREFIX` - The name of the repository. This defaults to `deis`, but if you don't have access to that repository, set this to a repository that you have push access to.
* `SHORT_NAME` (optional) - The name of the image. This defaults to `controller`
* `VERSION` (optional) - The tag of the Docker image. This defaults to the current Git SHA (the output of `git rev-parse --short HEAD`)

Then, run the following commands to build and push a new Docker image with your changes, and install it on your Kubernetes cluster.

```console
make docker-build docker-push
```

See below for a complete example with appropriate environment variables.

```console
export DEIS_REGISTRY=quay.io/
export IMAGE_PREFIX=arschles
make docker-build docker-push
```

Once the Docker push is complete, edit `$(helm home)/workspace/charts/deis-dev/manifests/deis-controller-rc.yaml` so that the `image:` field has the complete location of your Docker image (for example, the image produced by the previous command would be similar to `quay.io/arschles/controller:bba8eca`.)

Finally, delete and re-create the Deis controller [Replication Controller][repl-controller]:

```console
kubectl delete rc deis-controller --namespace=deis
kubectl create -f $(helm home)/workspace/charts/deis-dev/manifests/deis-controller-rc.yaml
```

Note: if you used the stable release of the Deis chart, the path to the `deis-controller-rc.yaml` will be `Note that if you used the stable release of the Deis chart, the path will be `$(helm home)/workspace/charts/deis/manifests/deis-controller-rc.yaml`.

Once you've re-created the replication controller, a new pod will be launched by it. You'll need to wait until the pod is listed as `Running` and the value in its `Ready` column is `1/1`. Use the following command to check the Pod's status:

```console
kubectl get pod --namespace=deis
```

## License

Copyright 2013, 2014, 2015, 2016 Engine Yard, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


[install-k8s]: http://kubernetes.io/gettingstarted/
[repl-controller]: http://kubernetes.io/docs/user-guide/replication-controller/
[issues]: https://github.com/deis/workflow/issues
[prs]: https://github.com/deis/workflow/pulls
