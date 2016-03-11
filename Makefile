# If DEIS_REGISTRY is not set, try to populate it from legacy DEV_REGISTRY
DEIS_REGISTRY ?= $(DEV_REGISTRY)
IMAGE_PREFIX ?= deis
COMPONENT ?= controller
SHORT_NAME ?= $(COMPONENT)

include versioning.mk

SHELL_SCRIPTS = $(wildcard rootfs/bin/*) $(shell find "rootfs" -name '*.sh') $(wildcard _scripts/*.sh)

# Get the component informtation to a tmp location and get replica count
KUBE := $(shell which kubectl)
ifdef KUBE
$(shell kubectl get rc deis-$(COMPONENT) --namespace deis -o yaml > /tmp/deis-$(COMPONENT))
DESIRED_REPLICAS=$(shell kubectl get -o template rc/deis-$(COMPONENT) --template={{.status.replicas}} --namespace deis)
endif

check-docker:
	@if [ -z $$(which docker) ]; then \
	  echo "Missing \`docker\` client which is required for development"; \
	  exit 2; \
	fi

build: docker-build

docker-build: check-docker
	docker build --rm -t ${IMAGE} rootfs
	docker tag -f ${IMAGE} ${MUTABLE_IMAGE}

deploy: docker-build docker-push
	sed 's#\(image:\) .*#\1 $(IMAGE)#' /tmp/deis-$(COMPONENT) | kubectl apply --validate=true -f -
	kubectl scale rc deis-workflow --replicas 0 --namespace deis
	kubectl scale rc deis-workflow --replicas $(DESIRED_REPLICAS) --namespace deis

clean: check-docker
	docker rmi $(IMAGE)

commit-hook:
	cp contrib/util/commit-msg .git/hooks/commit-msg

full-clean: check-docker
	docker images -q $(IMAGE_PREFIX)$(COMPONENT) | xargs docker rmi -f

postgres:
	docker start postgres || docker run --restart="always" -d -p 5432:5432 --name postgres postgres:9.3
	docker exec postgres createdb -U postgres deis 2>/dev/null || true
	@echo "To use postgres for local development:"
	@echo "    export PGHOST=`docker-machine ip $$(docker-machine active) 2>/dev/null || echo 127.0.0.1`"
	@echo "    export PGPORT=5432"
	@echo "    export PGUSER=postgres"

setup-venv:
	@if [ ! -d venv ]; then virtualenv venv; fi
	venv/bin/pip install --disable-pip-version-check -q -r rootfs/requirements.txt -r rootfs/dev_requirements.txt

test: test-style test-check test-unit test-functional

test-check:
	cd rootfs && python manage.py check

test-style:
	cd rootfs && flake8 --show-pep8 --show-source
	shellcheck $(SHELL_SCRIPTS)

test-unit:
	cd rootfs \
		&& coverage run manage.py test --noinput registry api \
		&& coverage report -m

test-functional:
	@echo "Implement functional tests in _tests directory"

test-integration:
	@echo "Check https://github.com/deis/workflow-e2e for the complete integration test suite"

.PHONY: build clean commit-hook full-clean postgres setup-venv test test-style test-unit test-functional
