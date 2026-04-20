# On Windows, use an override so Postgres uses a named volume (avoids bind-mount permission errors).
COMPOSE_FILES := -f etc/services/compose.yml
ifeq ($(OS),Windows_NT)
COMPOSE_FILES += -f etc/services/compose.windows.yml
endif

ifeq ($(OS),Windows_NT)
CURRENT_USER_UID := 1000
CURRENT_USER_GID := 1000
else
CURRENT_USER_UID := $(shell id -u)
CURRENT_USER_GID := $(shell id -g)
endif

help: ## Show this help.
	@grep -F -h "##" $(MAKEFILE_LIST) | grep -v grep | sed -e 's/\\$$//' | sed -e 's/##//'

prepare_services: var/.env
ifeq ($(OS),Windows_NT)
	if not exist var mkdir var
	if not exist var\matrix-synapse-media-store mkdir var\matrix-synapse-media-store
	if not exist var\matrix-synapse-postgres mkdir var\matrix-synapse-postgres
else
	mkdir -p var/matrix-synapse-media-store var/matrix-synapse-postgres
endif

var/.env:
ifeq ($(OS),Windows_NT)
	if not exist var mkdir var
	echo CURRENT_USER_UID=1000> var/.env
	echo CURRENT_USER_GID=1000>> var/.env
else
	mkdir -p var
	echo 'CURRENT_USER_UID='`id -u` > var/.env;
	echo 'CURRENT_USER_GID='`id -g` >> var/.env
endif

services-start: prepare_services ## Starts all services (Postgres, Synapse, Element)
	docker compose --project-directory var --env-file var/.env $(COMPOSE_FILES) -p matrix-lodge up -d

services-stop: prepare_services ## Stops all services (Postgres, Synapse, Element)
	docker compose --project-directory var --env-file var/.env $(COMPOSE_FILES) -p matrix-lodge down

services-tail-logs: prepare_services ## Tails the logs for all running services
	docker compose --project-directory var --env-file var/.env $(COMPOSE_FILES) -p matrix-lodge logs -f

run-postgres-cli: ## Starts a Postgres CLI (psql)
	docker compose --project-directory var --env-file var/.env $(COMPOSE_FILES) -p matrix-lodge \
		exec postgres \
		/bin/sh -c 'PGUSER=synapse PGPASSWORD=synapse-password PGDATABASE=homeserver psql -h postgres'

create-admin-user: prepare_services ## Creates the admin user on the local Synapse instance
	docker compose --project-directory var --env-file var/.env $(COMPOSE_FILES) -p matrix-lodge \
		exec synapse \
		register_new_matrix_user \
		-a \
		-u lev-admin \
		-p admin-password \
		-c /data/homeserver.yaml \
		http://localhost:8008
