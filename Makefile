.PHONY: test lint test-db test-db-stop
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
