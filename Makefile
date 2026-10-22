.PHONY: test lint
lint: ; .venv/bin/ruff check src tests
# Needs TEST_DATABASE_URL pointing at a throwaway Postgres database.
test: ; .venv/bin/pytest -q
