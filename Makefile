DEIS_REGISTRY ?= quay.io/
IMAGE_PREFIX ?= deis
COMPONENT ?= controller
SHORT_NAME ?= $(COMPONENT)

include versioning.mk
DEV_IMAGE := ${DEIS_REGISTRY}${IMAGE_PREFIX}/${SHORT_NAME}-dev:${VERSION}

SHELLCHECK_PREFIX := docker run --rm -v ${CURDIR}:/workdir -w /workdir quay.io/deis/shell-dev shellcheck
SHELL_SCRIPTS = $(wildcard rootfs/bin/*) $(shell find "rootfs" -name '*.sh') $(wildcard _scripts/*.sh)

# Test processes used in quick unit testing

TEST_PROCS ?= 4
TEST_FLAGS = --link deispg:deispg -e PGHOST=deispg -e PGPORT=5432 -e PGUSER=postgres -v ${CURDIR}/out:/out

define stop-pg
docker rm -f deispg
endef

check-kubectl:
	@if [ -z $$(which kubectl) ]; then \
	  echo "kubectl binary could not be located"; \
	  exit 2; \
	fi

check-docker:
	@if [ -z $$(which docker) ]; then \
	  echo "Missing \`docker\` client which is required for development"; \
	  exit 2; \
	fi

build: docker-build

docker-build: check-docker
	docker build --rm -t ${IMAGE} .
	docker tag ${IMAGE} ${MUTABLE_IMAGE}

docker-build-dev: check-docker
	docker build --rm -t ${DEV_IMAGE} -f Dockerfile.test .

deploy: check-kubectl docker-build docker-push
	kubectl --namespace=deis patch deployment deis-$(COMPONENT) --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"$(IMAGE)"}]'

clean: check-docker
	docker rmi $(IMAGE)

commit-hook:
	cp _scripts/util/commit-msg .git/hooks/commit-msg

full-clean: check-docker
	docker images -q $(IMAGE_PREFIX)$(COMPONENT) | xargs docker rmi -f

start-postgres:
	docker run -d --name deispg postgres:9.4
	# wait for the database to come up
	sleep 3

stop-postgres:
	$(call stop-pg)

setup-venv:
	@if [ ! -d venv ]; then pyvenv venv && source venv/bin/activate; fi
	pip install --disable-pip-version-check -q -r rootfs/requirements.txt -r rootfs/dev_requirements.txt

test: test-style test-check test-unit test-functional

test-check: docker-build-dev
	docker run --rm ${DEV_IMAGE} python manage.py check

test-style: docker-build-dev
	docker run --rm ${DEV_IMAGE} flake8 --show-pep8 --show-source
	${SHELLCHECK_PREFIX} $(SHELL_SCRIPTS)

test-unit: docker-build-dev start-postgres do-test-unit stop-postgres
do-test-unit:
	docker run ${TEST_FLAGS} --rm ${DEV_IMAGE} sh -c 'coverage run --rcfile=.docker_coveragerc manage.py test --settings=api.settings.testing --noinput registry api scheduler.tests' \
		|| ($(call stop-pg) && false)

test-unit-quick: docker-build-dev start-postgres do-test-unit-quick stop-postgres
do-test-unit-quick:
	docker run ${TEST_FLAGS} --rm ${DEV_IMAGE} sh -c './manage.py test --settings=api.settings.testing --noinput --parallel ${TEST_PROCS} --noinput registry api scheduler.tests' \
	||($(call stop-pg) && false)

test-functional:
	@echo "Implement functional tests in _tests directory"

test-integration:
	@echo "Check https://github.com/deis/workflow-e2e for the complete integration test suite"

.PHONY: build clean commit-hook full-clean postgres setup-venv test test-style test-unit test-functional
