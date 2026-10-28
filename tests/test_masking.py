"""Database-enforced masking for the AgentPG read-only group role, proven with real roles on the throwaway Postgres."""
import psycopg
import pytest
from conftest import TEST_URL, needs_db
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from apgkit import masking, migrate

pytestmark = needs_db
LOGIN = "kit_ro_login"
COLUMNS = {"id": "pass", "name": "initial", "email": "email", "card_last4": "last4", "ssn": "redact", "secret": "null", "tag": "hash",
           "domain": "split_part(email, '@', 2)"}


@pytest.fixture
def roles(db):
    with db.connect() as c:
        c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='a1p_readonly') THEN CREATE ROLE a1p_readonly NOLOGIN; END IF; END $$")
        c.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{LOGIN}') THEN CREATE ROLE {LOGIN} LOGIN PASSWORD 'ro-pw-test'; END IF; END $$")
        c.execute(f"GRANT a1p_readonly TO {LOGIN}")
        c.commit()


def _table(db, grant=True):
    with db.connect() as c:
        c.execute("CREATE TABLE customer (id int PRIMARY KEY, name text, email text, card_last4 text, ssn text, secret int, tag text)")
        c.execute("INSERT INTO customer VALUES (1, 'Alice', 'alice@example.com', '4242', '123-45-6789', 7, 'vip')")
        if grant:
            c.execute("GRANT SELECT ON customer TO a1p_readonly")        # what AgentPG's default privileges do for new tables
        c.commit()


def _ro():
    return psycopg.connect(make_conninfo(TEST_URL, user=LOGIN, password="ro-pw-test"), row_factory=dict_row, autocommit=True)


def _mask(c, **kw):
    cols = {k: v for k, v in COLUMNS.items() if k != "domain"} if kw.pop("simple", True) else COLUMNS
    return masking.mask_view(c, "customer", "customer_masked", cols, **kw)


def test_read_only_user_sees_masked_rows_and_not_the_base_table(db, roles):
    _table(db)
    with db.connect() as c:
        c.execute("GRANT USAGE ON SCHEMA public TO a1p_readonly")        # AgentPG has this already; mask_view grants it as well
        c.commit()
    with _ro() as ro:
        assert ro.execute("SELECT name FROM customer").fetchone()["name"] == "Alice"      # before masking: readable
    with db.connect() as c:
        res = masking.mask_view(c, "customer", "customer_masked", COLUMNS)
    assert res == {"applied": True, "reason": "", "base_denied": True, "view_readable": True}
    with _ro() as ro:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            ro.execute("SELECT * FROM customer")
        row = ro.execute("SELECT * FROM customer_masked").fetchone()
        assert row["id"] == 1 and row["name"] == "A***" and row["email"] == "***@example.com" and row["card_last4"] == "**** 4242"
        assert row["ssn"] == "[redacted]" and row["secret"] is None and row["domain"] == "example.com"
        assert len(row["tag"]) == 12 and row["tag"] != "vip"
        for ddl in ("INSERT INTO customer_masked VALUES (1)", "UPDATE customer_masked SET id = 2", "DELETE FROM customer_masked"):
            with pytest.raises(psycopg.Error):
                ro.execute(ddl)
    with db.connect() as c:                                                              # the owner is unaffected
        assert c.execute("SELECT ssn FROM customer").fetchone()["ssn"] == "123-45-6789"


def test_idempotent_and_picks_up_changes(db, roles):
    _table(db)
    with db.connect() as c:
        assert _mask(c)["applied"] and _mask(c)["applied"]
        masking.mask_view(c, "customer", "customer_masked", {"id": "pass", "name": "redact"})     # fewer columns: replace cannot, drop+create can
        assert masking.describe(c, "customer", "customer_masked")["columns"] == ["id", "name"]
    with _ro() as ro:
        assert ro.execute("SELECT name FROM customer_masked").fetchone()["name"] == "[redacted]"


def test_default_privileges_regrant_on_new_tables_so_remask_every_migrate(db, roles, tmp_path):
    (tmp_path / "001.sql").write_text("CREATE TABLE customer (id int, name text, email text, card_last4 text, ssn text, secret int, tag text);"
                                      "INSERT INTO customer VALUES (1,'Alice','a@b.c','4242','x',1,'t');")
    hook = lambda c: masking.mask_view(c, "customer", "customer_masked", {k: v for k, v in COLUMNS.items() if k != "domain"})   # noqa: E731
    assert migrate.run(db, tmp_path, after_migrate=[hook]) == ["001.sql"]
    with db.connect() as c:
        assert not masking.describe(c, "customer", "customer_masked")["base_readable"]
        c.execute("GRANT SELECT ON customer TO a1p_readonly")          # something re-granted it (default privileges, a manual grant)
        c.commit()
        assert masking.describe(c, "customer", "customer_masked")["base_readable"]
    assert migrate.run(db, tmp_path, after_migrate=[hook]) == []       # hooks run even when nothing was applied
    with db.connect() as c:
        assert not masking.describe(c, "customer", "customer_masked")["base_readable"]


def test_missing_role_is_skipped_quietly(db, caplog):
    _table(db, grant=False)
    with db.connect() as c:
        with caplog.at_level("INFO", logger="apgkit.masking"):
            res = masking.mask_view(c, "customer", "customer_masked", {"id": "pass"}, readonly_role="no_such_role_xyz")
        assert res["applied"] is False and "does not exist" in res["reason"]
        assert c.execute("SELECT to_regclass('customer_masked') IS NULL AS gone").fetchone()["gone"]      # nothing was created
        assert masking.unmask(c, "customer", "customer_masked", readonly_role="no_such_role_xyz")["applied"] is False
        assert masking.describe(c, "customer", "customer_masked", readonly_role="no_such_role_xyz")["role_exists"] is False
    assert "skipped" in caplog.text


def test_non_owner_revoke_is_reported_not_assumed(db, roles):
    _table(db)
    with db.connect() as c:
        c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='kit_not_owner') THEN CREATE ROLE kit_not_owner LOGIN PASSWORD 'ro-pw-test'; END IF; END $$")
        c.execute("GRANT USAGE, CREATE ON SCHEMA public TO kit_not_owner")
        c.execute("GRANT SELECT ON customer TO kit_not_owner")
        c.commit()
    with psycopg.connect(make_conninfo(TEST_URL, user="kit_not_owner", password="ro-pw-test"), row_factory=dict_row) as c:
        res = masking.mask_view(c, "customer", "customer_masked", {"id": "pass"})        # can create a view but is not the owner
    assert res["applied"] is False and res["base_denied"] is False and "still readable" in res["reason"]


def test_describe_sample_unmask_and_validation(db, roles):
    _table(db)
    with db.connect() as c:
        d0 = masking.describe(c, "customer", "customer_masked")
        assert d0["base_readable"] and not d0["view_exists"]
        _mask(c)
        d = masking.describe(c, "customer", "customer_masked", sample=1)
        assert d["role_exists"] and not d["base_readable"] and d["view_readable"] and "email" in d["columns"]
        assert d["sample"][0]["email"] == "***@example.com" and d["sample"][0]["name"] == "A***"
        assert masking.unmask(c, "customer", "customer_masked")["applied"]
        d2 = masking.describe(c, "customer", "customer_masked")
        assert d2["base_readable"] and not d2["view_exists"]
        for bad in ("a;b", "x y", 'a"b', "a.b.c"):
            with pytest.raises(ValueError):
                masking.mask_view(c, bad, "v", {"id": "pass"})
        with pytest.raises(ValueError):
            masking.mask_view(c, "customer", "v", {})
        with pytest.raises(ValueError):
            masking.mask_view(c, "customer", "v", {"nope": "null"})


# ---- deny_tables, drift and the re-assert loop ----
import asyncio  # noqa: E402
import logging  # noqa: E402


def test_deny_tables_revokes_skips_missing_and_is_idempotent(db, roles):
    _table(db)
    with db.connect() as c:
        c.execute("CREATE TABLE audit (id int)")
        c.execute("GRANT SELECT ON audit TO a1p_readonly")
        c.execute("GRANT USAGE ON SCHEMA public TO a1p_readonly")
        c.commit()
        r = masking.deny_tables(c, ["customer", "audit", "nope"])
        assert r["applied"] and r["base_denied"] and r["tables"] == {"customer": True, "audit": True} and r["skipped"] == ["nope"]
        assert masking.deny_tables(c, ["customer", "audit"])["applied"]          # idempotent
        with _ro() as ro, pytest.raises(psycopg.errors.InsufficientPrivilege):
            ro.execute("SELECT * FROM audit")
        with pytest.raises(ValueError):
            masking.deny_tables(c, ["bad name;"])


def test_deny_tables_without_the_role_is_skipped(db):
    with db.connect() as c:
        c.execute("DROP ROLE IF EXISTS a1p_readonly_absent")
        r = masking.deny_tables(c, ["customer"], readonly_role="a1p_readonly_absent")
        assert r["applied"] is False and "does not exist" in r["reason"]


def test_reassert_tick_closes_a_regranted_table(db, roles):
    _table(db)
    name = "masking_t1"
    with db.connect() as c:
        _mask(c)
    apply = lambda conn: (_mask(conn), masking.deny_tables(conn, ["customer"]))   # noqa: E731
    assert masking.reassert_tick(db.connect, apply, name=name, deny=["customer"]) is True
    assert masking.status(name)["drift"] == 0 and masking.status(name)["last_ok"]
    with db.connect() as c:                                          # `agentpg db-users create` / default privileges re-grant
        c.execute("GRANT SELECT ON customer TO a1p_readonly")
        c.commit()
        assert masking.describe(c, "customer", "customer_masked")["base_readable"]
    with _ro() as ro:
        assert ro.execute("SELECT ssn FROM customer").fetchone()["ssn"] == "123-45-6789"      # the window the loop closes
    assert masking.reassert_tick(db.connect, apply, name=name, deny=["customer"]) is True
    assert masking.status(name)["drift"] == 1
    with db.connect() as c:
        assert not masking.describe(c, "customer", "customer_masked")["base_readable"]
        assert masking.drift(c, ["customer"]) == []
    with _ro() as ro, pytest.raises(psycopg.errors.InsufficientPrivilege):
        ro.execute("SELECT ssn FROM customer")


def test_reassert_tick_never_raises_and_logs_one_line(db, caplog):
    def boom(conn):
        raise RuntimeError("kaput\nsecond line")
    with caplog.at_level(logging.WARNING, logger="apgkit.masking"):
        assert masking.reassert_tick(db.connect, boom, name="masking_t2") is False
    lines = [r.getMessage() for r in caplog.records if "re-assert failed" in r.getMessage()]
    assert lines == ["masking_t2 re-assert failed: kaput"]
    assert masking.status("masking_t2")["ok"] is False
    assert masking.reassert_tick(lambda: (_ for _ in ()).throw(OSError("down")), boom, name="masking_t2") is False   # connect failure too


def test_reassert_metrics(db, roles):
    from apgkit.metrics import Metrics
    m = Metrics("t", "0")
    _table(db)
    masking.reassert_tick(db.connect, lambda conn: _mask(conn), name="masking", deny=["customer"], metrics=m, clock=lambda: 1234.0)
    masking.reassert_tick(db.connect, lambda conn: _mask(conn), name="masking", deny=["customer"], metrics=m, clock=lambda: 1234.0)
    text = m.render()[0].decode()
    assert "masking_last_ok_timestamp 1234.0" in text and "masking_reapplied_total 2.0" in text and "masking_drift_tables 0.0" in text


def test_reassert_forever_loops_with_fake_sleep_and_survives_errors():
    ticks, sleeps = [], []

    class Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def commit(self): pass

    def apply(conn):
        ticks.append(1)
        if len(ticks) == 2:
            raise RuntimeError("transient")

    async def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) == 3:
            raise asyncio.CancelledError

    async def run():
        with pytest.raises(asyncio.CancelledError):
            await masking.reassert_forever(Conn, apply, every=300, name="masking_t3", sleep=fake_sleep, clock=lambda: 5.0)
    asyncio.run(run())
    assert len(ticks) == 3 and sleeps == [300, 300, 300]          # the failing tick did not stop the loop
    assert masking.status("masking_t3")["ok"] is True
