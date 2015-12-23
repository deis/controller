export GO15VENDOREXPERIMENT=1

SRC_PATH := /go/src/github.com/deis/workflow/_tests
DEV_IMG := quay.io/deis/go-dev:0.3.0
DEIS_WORKFLOW_SERVICE_HOST ?= deis.172.17.8.100:8080
DEV_CMD := docker run --rm -e DEIS_WORKFLOW_SERVICE_HOST=${DEIS_WORKFLOW_SERVICE_HOST} -v ${CURDIR}:${SRC_PATH} -w ${SRC_PATH} ${DEV_IMG}

bootstrap:
	${DEV_CMD} glide install
	# Once the TODO below is complete, this line can be removed
	go get github.com/onsi/ginkgo/ginkgo

test-integration:
	${DEV_CMD} go test -v .

build:
# Precompile the test suite into a binary "_tests.test"
 	# TODO: https://github.com/deis/docker-go-dev/pull/8 is now merged into that repositories master branch.
	# When the repository is tagged as 0.4.0, our CI will build a 'quay.io/deis/go-dev:0.4.0' image that has
	# the ginkgo binary. After that, this command should move to use DEV_CMD. This work is tracked in
	# https://github.com/deis/workflow/issues/139
	ginkgo build -race -r
