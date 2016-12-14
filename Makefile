# If DEIS_REGISTRY is not set, try to populate it from legacy DEV_REGISTRY
DEIS_REGISTRY ?= $(DEV_REGISTRY)
IMAGE_PREFIX ?= deis
COMPONENT ?= controller
SHORT_NAME ?= $(COMPONENT)

include versioning.mk

SHELLCHECK_PREFIX := docker run --rm -v ${CURDIR}:/workdir -w /workdir quay.io/deis/shell-dev shellcheck
SHELL_SCRIPTS = $(wildcard rootfs/bin/*) $(shell find "rootfs" -name '*.sh') $(wildcard _scripts/*.sh)

# Test processes used in quick unit testing
TEST_PROCS ?= 4

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
	docker build --rm -t ${IMAGE} rootfs
	docker tag ${IMAGE} ${MUTABLE_IMAGE}

deploy: check-kubectl docker-build docker-push
	kubectl --namespace=deis patch deployment deis-$(COMPONENT) --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"$(IMAGE)"}]'

clean: check-docker
	docker rmi $(IMAGE)

commit-hook:
	cp _scripts/util/commit-msg .git/hooks/commit-msg

full-clean: check-docker
	docker images -q $(IMAGE_PREFIX)$(COMPONENT) | xargs docker rmi -f

postgres: check-docker
	docker start postgres || docker run --restart="always" -d -p 5432:5432 --name postgres postgres:9.3
	docker exec postgres createdb -U postgres deis 2>/dev/null || true
	@echo "To use postgres for local development:"
	@echo "    export PGHOST=`docker-machine ip $$(docker-machine active) 2>/dev/null || echo 127.0.0.1`"
	@echo "    export PGPORT=5432"
	@echo "    export PGUSER=postgres"

setup-venv:
	python3 -m venv venv
	venv/bin/pip3 install --disable-pip-version-check -q -r rootfs/requirements.txt -r rootfs/dev_requirements.txt

test: test-style test-check test-unit test-functional

test-check:
	cd rootfs && python manage.py check

test-style:
	cd rootfs && flake8 --show-source
	${SHELLCHECK_PREFIX} $(SHELL_SCRIPTS)

test-unit:
	cd rootfs \
		&& coverage run manage.py test --settings=api.settings.testing --noinput registry api scheduler.tests \
		&& coverage report -m

test-unit-quick:
	cd rootfs \
		&& ./manage.py test --settings=api.settings.testing --noinput --parallel ${TEST_PROCS} registry api scheduler.tests

test-functional:
	@echo "Implement functional tests in _tests directory"

test-integration:
	@echo "Check https://github.com/deis/workflow-e2e for the complete integration test suite"

.PHONY: build clean commit-hook full-clean postgres setup-venv test test-style test-unit test-functional
