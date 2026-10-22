import os

import pytest

from apgkit.db import Database

TEST_URL = os.environ.get("TEST_DATABASE_URL", "")
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
