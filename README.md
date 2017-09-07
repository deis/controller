
# Deis Controller

[![Build Status](https://ci.deis.io/job/controller/badge/icon)](https://ci.deis.io/job/controller)
[![codecov.io](https://codecov.io/github/deis/controller/coverage.svg?branch=master)](https://codecov.io/github/deis/controller?branch=master)
[![Docker Repository on Quay](https://quay.io/repository/deisci/controller/status "Docker Repository on Quay")](https://quay.io/repository/deisci/controller)
[![Dependency Status](https://www.versioneye.com/user/projects/5863f1de6f4bf900128fa95a/badge.svg?style=flat)](https://www.versioneye.com/user/projects/5863f1de6f4bf900128fa95a)

Deis (pronounced DAY-iss) Workflow is an open source Platform as a Service (PaaS) that adds a developer-friendly layer to any [Kubernetes](http://kubernetes.io) cluster, making it easy to deploy and manage applications on your own servers.

For more information about the Deis Workflow, please visit the main project page at https://github.com/deisthree/workflow.

We welcome your input! If you have feedback, please [submit an issue][issues]. If you'd like to participate in development, please read the "Development" section below and [submit a pull request][prs].

# About

The Controller is the central API server for [Deis Workflow][workflow]. It is installed on a [Kubernetes](http://kubernetes.io) cluster, making it easy to deploy and manage applications on your own cluster. Below is a non-exhaustive list of things it can do:

* Create a new application
* Delete an application
* Scale an application
* Configure an application
* Create a new user

# Development

The Deis project welcomes contributions from all developers. The high-level process for development matches many other open source projects. See below for an outline.

* Fork this repository
* Make your changes
* [Submit a pull request][prs] (PR) to this repository with your changes, and unit tests whenever possible.
  * If your PR fixes any [issues][issues], make sure you write Fixes #1234 in your PR description (where #1234 is the number of the issue you're closing)
* Deis project maintainers will review your code.
* After two maintainers approve it, they will merge your PR.

## Prerequisites

### Docker

Unit tests and code linters for controller run in a Docker container with your local code directory
mounted in. You need [Docker][] to run `make test`.

### Kubernetes

You'll want to test your code changes interactively in a working Kubernetes cluster. Follow the
[installation instructions][install-k8s] if you need Kubernetes.

### Workflow Installation

After you have a working Kubernetes cluster, you're ready to [install Workflow](https://deis.com/docs/workflow/installing-workflow/).

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

[install-k8s]: https://kubernetes.io/docs/setup/pick-right-solution
[issues]: https://github.com/deisthree/controller/issues
[prs]: https://github.com/deisthree/controller/pulls
[workflow]: https://github.com/deisthree/workflow
[Docker]: https://www.docker.com/
[v2.18]: https://github.com/deisthree/workflow/releases/tag/v2.18.0
