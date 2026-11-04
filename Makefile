.PHONY: test lint test-db test-db-stop test-aidb
lint: ; .venv/bin/ruff check src tests
# Needs TEST_DATABASE_URL pointing at a throwaway UTF8 Postgres database (see `make test-db`).
test: ; .venv/bin/pytest -q

# A throwaway UTF-8 cluster (SQL_ASCII breaks the tests), 127.0.0.1 only, no unix socket. Afterwards:
#   export TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:55432/kit_test
APGKIT_PG ?= /tmp/apgkit-pg
APGKIT_PORT ?= 55432
test-db:
	initdb -D $(APGKIT_PG) -U postgres -E UTF8 --auth=trust
	pg_ctl -D $(APGKIT_PG) -o "-p $(APGKIT_PORT) -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" -l $(APGKIT_PG).log -w start
	psql -h 127.0.0.1 -p $(APGKIT_PORT) -U postgres -d postgres -c "CREATE DATABASE kit_test"
	@echo "export TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:$(APGKIT_PORT)/kit_test"
test-db-stop:
	-pg_ctl -D $(APGKIT_PG) -m fast stop
	rm -rf $(APGKIT_PG) $(APGKIT_PG).log

# AIDB tests (marker `aidb`): start a throwaway container from the AIDB image (build it from the ecosystem repo, docker/aidb-postgres),
# run the tests that need it, then stop it (the container is started with the auto-remove flag). AIDB_CALLBACK_HOST must be an address
# of this machine the container can reach (Docker Desktop: 192.168.65.254); the first run downloads small local models from Hugging Face.
AIDB_IMAGE ?= aidb-postgres:17
AIDB_PORT ?= 55462
AIDB_CALLBACK_HOST ?= 192.168.65.254
AIDB_NAME ?= apgkit-aidb-test
test-aidb:
	-docker stop $(AIDB_NAME) >/dev/null 2>&1
	docker run -d --rm --name $(AIDB_NAME) -p 127.0.0.1:$(AIDB_PORT):5432 -e POSTGRES_PASSWORD=postgres $(AIDB_IMAGE) -c aidb.allow_insecure_egress=on >/dev/null
	@for i in $$(seq 1 40); do docker exec $(AIDB_NAME) pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done; sleep 3
	AIDB_TEST_URL=postgresql://postgres:postgres@127.0.0.1:$(AIDB_PORT)/postgres AIDB_TEST_CALLBACK_HOST=$(AIDB_CALLBACK_HOST) .venv/bin/pytest -q -m aidb; rc=$$?; docker stop $(AIDB_NAME) >/dev/null; exit $$rc
