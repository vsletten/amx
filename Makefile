# M6: `make up MTA_CT=stalwart` runs contoso's mailhost on Stalwart Community (PLAN §5.8). `make up`
# records the choice, so later targets (smoke, logs) default to the MTA the stack is running.
MTA_CT_FILE := deploy/generated/mta_ct
# An empty MTA_CT counts as unset: the recorded choice, else postfix.
override MTA_CT := $(or $(strip $(MTA_CT)),$(strip $(shell cat $(MTA_CT_FILE) 2>/dev/null)),postfix)
COMPOSE_FILES := -f deploy/compose.yaml
ifeq ($(MTA_CT),stalwart)
# compose.stalwart.yaml's !reset/!override tags need Docker Compose 2.24.4 or later.
COMPOSE_FILES += -f deploy/compose.stalwart.yaml
else ifneq ($(MTA_CT),postfix)
ifneq ($(MAKECMDGOALS),down)  # down never reads it, and clears a bad record
$(error MTA_CT must be postfix or stalwart, not $(MTA_CT))
endif
endif
ifneq ($(AMX_SUITE_OVERRIDE),)
COMPOSE_FILES += -f "$(AMX_SUITE_OVERRIDE)"
endif
COMPOSE := docker compose -p amx $(COMPOSE_FILES)
# The gateways run as the invoking user so they can write deploy/generated/state (bind mounts).
export AMX_UID ?= $(shell id -u)
export AMX_GID ?= $(shell id -g)

.PHONY: prepare up down logs smoke scenarios integration suite live-validate selfhost-validate

# Fleet/CI entry point. Low-level targets below are for the locked supervisor;
# never compose an up/scenarios/down sequence in separate worker commands.
suite:
	uv run --group gateway python tools/stack_suite.py suite --mta $(MTA_CT)

prepare:
	./deploy/generate-dev.sh

# Recorded first, so after a failed `up` the logs and smoke targets still use the same files.
up: prepare
	echo $(MTA_CT) > $(MTA_CT_FILE)
	$(COMPOSE) up -d --build --wait

# Whichever MTA the stack runs: the project's containers go with the base file, and the Stalwart
# variant's own volume is removed by name (so a Postfix-only machine never parses the override).
down:
	docker compose -f deploy/compose.yaml down -v --remove-orphans
	docker volume rm -f amx_stalwart-ct >/dev/null
	rm -rf deploy/generated/state $(MTA_CT_FILE)

logs:
	$(COMPOSE) logs -f

smoke: prepare
	$(COMPOSE) run --rm smoke

scenarios:
	$(if $(filter 1,$(SH00_PROBE)),@test "$(MTA_CT)" = stalwart && test -n "$(AMX_SUITE_OVERRIDE)" && test "$(AMX_SUITE_MTA)" = stalwart || { printf '%s\n' 'SH00_PROBE requires make suite MTA_CT=stalwart'; exit 1; })
	$(if $(filter 1,$(SH00_PROBE)),uv run --group gateway python tools/stalwart_probe_fixture.py)
	$(if $(filter 1,$(SH00_PROBE)),$(COMPOSE) run --build --rm --no-deps stalwart-probe)
	uv run --group gateway pytest scenarios -m integration -q -s -p no:cacheprovider

integration: smoke scenarios

# PLAN §11: the live bundle on this machine (project amx-live, 127.0.0.1 ports, fake domain,
# nothing sent outside); leaves the dev stack alone. docs/selfhost-public.md §11.
LIVE_MTA ?= postfix
live-validate:
	uv run --group gateway python tools/stack_suite.py lock -- uv run --group gateway python tools/live_validate.py --mta $(LIVE_MTA)

# SH-26: entire native private server + two agent-host lifecycle under one lease.
selfhost-validate:
	uv run --group gateway python tools/stack_suite.py lock -- uv run --group gateway python tools/selfhost_validate.py
