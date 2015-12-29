export GO15VENDOREXPERIMENT=1

SHORT_NAME := deis-e2e

SRC_PATH := /go/src/github.com/deis/workflow/_tests
DEV_IMG := quay.io/deis/go-dev:0.4.0
DEIS_WORKFLOW_SERVICE_HOST ?= deis.172.17.8.100:8080

RUN_CMD := docker run --rm -e DEIS_WORKFLOW_SERVICE_HOST=${DEIS_WORKFLOW_SERVICE_HOST} -v ${CURDIR}:${SRC_PATH} -w ${SRC_PATH} ${DEV_IMG}

DEV_CMD := docker run --rm -e GO15VENDOREXPERIMENT=1 -v ${CURDIR}:${SRC_PATH} -w ${SRC_PATH} ${DEV_IMG}

VERSION ?= git-$(shell git rev-parse --short HEAD)
DEIS_REGISTRY ?= quay.io/
IMAGE_PREFIX ?= deis
IMAGE := ${DEIS_REGISTRY}${IMAGE_PREFIX}/${SHORT_NAME}:${VERSION}

bootstrap:
	${DEV_CMD} glide install

test-integration:
	${RUN_CMD} go test -v .

# Precompile the test suite into a binary "_tests.test"
build:
	${DEV_CMD} ginkgo build -race -r

docker-build: build
	docker build -t ${IMAGE} ${CURDIR}

docker-test-integration:
	docker run -e DEIS_WORKFLOW_SERVICE_HOST=${DEIS_WORKFLOW_SERVICE_HOST} ${IMAGE}
