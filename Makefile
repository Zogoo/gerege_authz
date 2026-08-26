# Gerege IdP — MVP
#
#   make up        bring the whole thing up on a local kind cluster
#   make verify    run the assertion suite unattended
#   make demo      walk the scenarios one keypress at a time
#   make down      delete the cluster
#
# `make help` lists everything.

SHELL     := /usr/bin/env bash
CLUSTER   ?= gerege-idp
KCTX      := kind-$(CLUSTER)
IMAGE     ?= gerege/idp-mvp:dev
K         := kubectl --context $(KCTX)

.DEFAULT_GOAL := help
.PHONY: help prereqs hosts unhosts up down reset build load verify demo test schema-test config-test \
        decisions logs sensor status shell-zed reseed open diagram inspect diagram

## ---------------------------------------------------------------------------
## Setup
## ---------------------------------------------------------------------------

help: ## show this help
	@awk 'BEGIN{printf "\n\033[1mGerege IdP — MVP\033[0m\n"} \
	     /^## ---/{next} \
	     /^## /{printf "\n\033[2m%s\033[0m\n", substr($$0,4); next} \
	     /^[a-zA-Z0-9_-]+:.*##/{ \
	         t=substr($$0,1,index($$0,":")-1); \
	         d=substr($$0,index($$0,"##")+3); \
	         printf "  \033[36m%-14s\033[0m %s\n", t, d } \
	     END{print ""}' $(MAKEFILE_LIST)

prereqs: ## install kind, istioctl and zed with Homebrew
	brew install kind istioctl authzed/tap/zed

hosts: ## add the demo hostnames to /etc/hosts (needs sudo)
	@./scripts/hosts.sh

unhosts: ## remove the demo hostnames from /etc/hosts (needs sudo)
	@./scripts/hosts.sh --remove

## ---------------------------------------------------------------------------
## Lifecycle
## ---------------------------------------------------------------------------

up: ## create the cluster and bring up the whole stack (idempotent)
	@./scripts/bootstrap.sh

down: ## delete the kind cluster
	kind delete cluster --name $(CLUSTER)

reset: down up ## delete everything and start again

build: ## rebuild the service image and load it into the cluster
	docker build -t $(IMAGE) services
	kind load docker-image $(IMAGE) --name $(CLUSTER)
	$(K) -n id rollout restart deploy/ext-authz deploy/account-app
	$(K) -n apps rollout restart deploy/profile-app deploy/profile-service deploy/smarthome-service deploy/device-service deploy/agent-runner
	$(K) -n devices rollout restart deploy/telemetry-simulator

reseed: ## reset the demo world — re-apply the schema and seed relationships
	@./scripts/reseed.sh

## ---------------------------------------------------------------------------
## Demonstrate
## ---------------------------------------------------------------------------

verify: ## run the full assertion suite (A1-A13) unattended
	@./scripts/verify.sh

demo: ## walk the scenarios interactively — make demo S="2 3b 5" for a subset
	@./scripts/demo.sh $(S)

open: ## print the demo URLs
	@printf '\n  http://profile.local.test     profile app      alice / alice\n'
	@printf '  http://smarthome.local.test   smart home\n'
	@printf '  http://account.local.test     consent console\n'
	@printf '  http://id.local.test          Keycloak         admin / admin\n\n'

## ---------------------------------------------------------------------------
## Observe
## ---------------------------------------------------------------------------

inspect: ## look inside SpiceDB — schema, facts, and who is authorized for what
	@./scripts/inspect.sh $(A)

decisions: ## show the last authorization decisions, one line each
	@./scripts/decisions.sh

logs: ## follow the raw ext-authz log
	$(K) -n id logs -f deploy/ext-authz

sensor: ## follow the IoT device: one request allowed, three refused, every cycle
	$(K) -n devices logs -f deploy/telemetry-simulator

status: ## show what is running
	@$(K) get pods -n istio-system -n id 2>/dev/null || true
	@echo; $(K) get pods -A -l 'app' --field-selector=status.phase!=Succeeded \
	    -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,READY:.status.containerStatuses[*].ready,NODE:.spec.nodeName \
	    | grep -E 'istio-system|^id|^apps|^devices|NS' || true

shell-zed: ## hold a port-forward to SpiceDB open and print zed recipes
	@./scripts/inspect.sh shell

## ---------------------------------------------------------------------------
## Test — these need no cluster
## ---------------------------------------------------------------------------

test: schema-test config-test ## run every offline test
	cd services && go vet ./... && go test ./...

schema-test: ## run the SpiceDB schema assertion suite
	cd spicedb && zed validate validation.yaml

config-test: ## validate the route configuration and print the match table
	cd services && go run ./cmd/configcheck config/ext-authz.yaml


diagram: ## regenerate docs/architecture.svg and .png
	python3 docs/make-architecture.py
	rsvg-convert -w 3400 -o docs/architecture.png docs/architecture.svg
	@echo "  docs/architecture.svg  ·  docs/architecture.png"
