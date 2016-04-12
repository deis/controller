# -*- coding: utf-8 -*-
"""Support the Deis workflow by manipulating and publishing Docker images."""

import logging
import os

from django.conf import settings
from rest_framework.exceptions import PermissionDenied
from simpleflock import SimpleFlock

import docker
import docker.constants
from docker.errors import APIError

logger = logging.getLogger(__name__)


class RegistryException(Exception):
    pass


class DockerClient(object):
    """Use the Docker API to pull, tag, build, and push images to deis-registry."""

    FLOCKFILE = '/tmp/controller-pull'

    def __init__(self):
        timeout = os.environ.get('DOCKER_CLIENT_TIMEOUT', docker.constants.DEFAULT_TIMEOUT_SECONDS)
        self.client = docker.Client(version='auto', timeout=timeout)
        self.registry = settings.REGISTRY_HOST + ':' + str(settings.REGISTRY_PORT)

    def publish_release(self, source, target, deis_registry):
        """Update a source Docker image with environment config and publish it to deis-registry."""
        # get the source repository name and tag
        src_name, src_tag = docker.utils.parse_repository_tag(source)
        # get the target repository name and tag
        name, tag = docker.utils.parse_repository_tag(target)
        # strip any "http://host.domain:port" prefix from the target repository name,
        # since we always publish to the Deis registry
        name = strip_prefix(name)

        # pull the source image from the registry
        # NOTE: this relies on an implementation detail of deis-builder, that
        # the image has been uploaded already to deis-registry
        if deis_registry:
            repo = "{}/{}".format(self.registry, src_name)
        else:
            repo = src_name

        try:
            self.pull(repo, src_tag)

            # tag the image locally without the repository URL
            image = "{}:{}".format(src_name, src_tag)
            self.tag(image, "{}/{}".format(self.registry, name), tag=tag)

            # push the image to deis-registry
            self.push("{}/{}".format(self.registry, name), tag)
        except APIError as e:
            raise RegistryException(str(e))

    def pull(self, repo, tag):
        """Pull a Docker image into the local storage graph."""
        check_blacklist(repo)
        logger.info("Pulling Docker image {}:{}".format(repo, tag))
        with SimpleFlock(self.FLOCKFILE, timeout=1200):
            stream = self.client.pull(repo, tag=tag, stream=True,
                                      decode=True, insecure_registry=True)
            log_output(stream, 'pull', repo, tag)

    def push(self, repo, tag):
        """Push a local Docker image to a registry."""
        logger.info("Pushing Docker image {}:{}".format(repo, tag))
        stream = self.client.push(repo, tag=tag, stream=True, decode=True,
                                  insecure_registry=True)
        log_output(stream, 'push', repo, tag)

    def tag(self, image, repo, tag):
        """Tag a local Docker image with a new name and tag."""
        check_blacklist(repo)
        logger.info("Tagging Docker image {} as {}:{}".format(image, repo, tag))
        if not self.client.tag(image, repo, tag=tag, force=True):
            raise RegistryException('Tagging {} as {}:{} failed'.format(image, repo, tag))


def check_blacklist(repo):
    """Check a Docker repository name for collision with deis/* components."""
    blacklisted = [  # NOTE: keep this list up to date!
        'builder', 'controller', 'database', 'dockerbuilder', 'etcd', 'minio', 'registry',
        'router', 'slugbuilder', 'slugrunner', 'workflow',
    ]
    if any("deis/{}".format(c) in repo for c in blacklisted):
        raise PermissionDenied("Repository name {} is not allowed".format(repo))


def log_output(stream, operation, repo, tag):
    """Log a stream at DEBUG level, and raise RegistryException if it contains an error"""
    for chunk in stream:
        # error handling requires looking at the response body
        if 'error' in chunk:
            stream_error(chunk, operation, repo, tag)


def stream_error(chunk, operation, repo, tag):
    """Translate docker stream errors into a more digestable format"""
    # not all errors provide the code
    if 'code' in chunk['errorDetail']:
        # permission denied on the repo
        if chunk['errorDetail']['code'] == 403:
            message = 'Permission Denied attempting to {} image {}:{}'.format(operation, repo, tag)
    else:
        # grab the generic error and strip the useless Error: portion
        message = chunk['error'].replace('Error: ', '')

    raise RegistryException(message)


def strip_prefix(name):
    """Strip the schema and host:port from a Docker repository name."""
    paths = name.split('/')
    return '/'.join(p for p in paths if p and '.' not in p and ':' not in p)


def publish_release(source, target, deis_registry):
    return DockerClient().publish_release(source, target, deis_registry)
