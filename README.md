# Deis Controller

[![Build Status](https://travis-ci.org/deis/controller.svg?branch=master)](https://travis-ci.org/deis/controller)
[![codecov.io](https://codecov.io/github/deis/controller/coverage.svg?branch=master)](https://codecov.io/github/deis/controller?branch=master)
[![Docker Repository on Quay](https://quay.io/repository/deisci/controller/status "Docker Repository on Quay")](https://quay.io/repository/deisci/controller)
[![Dependency Status](https://www.versioneye.com/user/projects/5728e1dba0ca350034be67be/badge.svg?style=flat)](https://www.versioneye.com/user/projects/5728e1dba0ca350034be67be)

Deis (pronounced DAY-iss) Workflow is an open source Platform as a Service (PaaS) that adds a developer-friendly layer to any [Kubernetes](http://kubernetes.io) cluster, making it easy to deploy and manage applications on your own servers.

For more information about the Deis Workflow, please visit the main project page at https://github.com/deis/workflow.

We welcome your input! If you have feedback, please [submit an issue][issues]. If you'd like to participate in development, please read the "Development" section below and [submit a pull request][prs].

# About

The Controller is the central API server for [Deis Workflow][workflow]. It is installed on a [Kubernetes](http://kubernetes.io) cluster, making it easy to deploy and manage applications on your own cluster. Below is a non-exhaustive list of things it can do:

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
* The Deis core contributors will review your code. After each of them sign off on your code, they'll label your PR with LGTM1 and LGTM2 (respectively). Once that happens, the contributors will merge it

## Prerequisites

### Kubernetes

In order to do development on this component, you'll need a working Kubernetes cluster. If you don't have one, follow the [installation instructions][install-k8s] and note that Controller currently targets version 1.2 and higher.

### Helm Classic

After you have a working Kubernetes cluster, install [helm classic](http://helm.sh) and run the following commands to add the Deis chart repository and install Deis to your new cluster:

```console
helmc repo add deis https://github.com/deis/charts
helmc fetch deis/workflow-dev
helmc generate -x manifests workflow-dev
helmc install workflow-dev
```

### Postgresql

Postgresql can be installed via `homebrew`:

```
brew install postgresql
```

Or via your package manager. For example, on Debian Jessie:

```
apt-get install postgresql libpq-dev
```

### Python

Python 3.5 is a minimum requirement and can be installed via `homebrew`:

```
brew install python3
```

Or via your package manager. For example, on Debian Jessie:

```
apt-get install python3 python3-dev python3-venv
```

With the correct Python in place the quickest way to get up and running is to run `make setup-venv` which will install the Python specific dependencies via [PIP](https://pip.pypa.io/en/stable/) inside an isolated (virtualenv)[https://docs.python.org/3/library/venv.html].
Running `python --version` to verify the correct version is recommend.

Follow the linked documentation to learn about (virtualenv)[https://docs.python.org/3/library/venv.html] and how to `activate` and `deactivate` the environment.

## Testing Your Code

When you've built your new feature or fixed a bug, make sure you've added appropriate unit tests and run `make test` to ensure your code works properly.

Also, since this component is central to the platform, it's recommended that you manually test and verify that your feature or fix works as expected. To do so, ensure the following environment variables are set:

* `DEIS_REGISTRY` - A Docker registry that you have push access to and your Kubernetes cluster can pull from
  * If this is [Docker Hub](https://hub.docker.com/), leave this variable empty
  * Otherwise, ensure it has a trailing `/`. For example, if you're using [Quay.io](https://quay.io), use `quay.io/`
* `IMAGE_PREFIX` - The organization in the Docker repository. This defaults to `deis`, but if you don't have access to that organization, set this to one you have push access to.
* `SHORT_NAME` (optional) - The name of the image. This defaults to `controller`
* `VERSION` (optional) - The tag of the Docker image. This defaults to the current Git SHA (the output of `git rev-parse --short HEAD`)

Then, run `make deploy` to build and push a new Docker image with your changes and replace the existing one with your new one in the Kubernetes cluster. See below for an example with appropriate environment variables.

```console
export DEIS_REGISTRY=quay.io/
export IMAGE_PREFIX=arschles
make deploy
```

After the `make deploy` finishes, a new pod will be launched but may not be running. You'll need to wait until the pod is listed as `Running` and the value in its `Ready` column is `1/1`. Use the following command watch the pod's status:

```console
kubectl get pod --namespace=deis -w | grep deis-controller
```

## License

Copyright 2013, 2014, 2015, 2016 Engine Yard, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


[install-k8s]: http://kubernetes.io/gettingstarted/
[repl-controller]: http://kubernetes.io/docs/user-guide/replication-controller/
[issues]: https://github.com/deis/controller/issues
[prs]: https://github.com/deis/controller/pulls
[workflow]: https://github.com/deis/workflow
