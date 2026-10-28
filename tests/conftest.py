import os

import pytest

from apgkit.db import Database

TEST_URL = os.environ.get("TEST_DATABASE_URL", "")


def pytest_sessionstart(session):
    """Fail once, clearly, on a SQL_ASCII database (text comes back as bytes and many tests fail cryptically)."""
    if not TEST_URL:
        return
    import psycopg
    try:
        with psycopg.connect(TEST_URL) as c:
            enc = c.execute("SELECT pg_encoding_to_char(encoding) FROM pg_database WHERE datname = current_database()").fetchone()[0]
    except psycopg.Error:
        return                                    # unreachable: the tests report that themselves
    enc = enc.decode() if isinstance(enc, bytes) else enc
    if enc != "UTF8":
        pytest.exit(f"TEST_DATABASE_URL points at a {enc} database; the tests need UTF8. Create the cluster with "
                    "`initdb -E UTF8` (make test-db) or the database with `CREATE DATABASE ... ENCODING 'UTF8' TEMPLATE template0`.",
                    returncode=2)


needs_db = pytest.mark.skipif(not TEST_URL, reason="set TEST_DATABASE_URL to run database tests")


@pytest.fixture
def db(monkeypatch):
    """A fresh, empty schema on the throwaway test database."""
    monkeypatch.setenv("DATABASE_URL", TEST_URL)
    database = Database()
    with database.connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    yield database
    database.close_pool()
