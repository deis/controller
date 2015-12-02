#!/usr/bin/env bash
#
# Build and push Docker images to Docker Hub and quay.io.
#

cd "$(dirname "$0")" || exit 1

export IMAGE_PREFIX=deisci BUILD_TAG=v2-alpha
docker login -e="$DOCKER_EMAIL" -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"
REGISTRY='' make -C .. docker-build docker-push
docker login -e="$QUAY_EMAIL" -u="$QUAY_USERNAME" -p="$QUAY_PASSWORD" quay.io
REGISTRY=quay.io/ make -C .. docker-build docker-push
