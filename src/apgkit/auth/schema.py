"""SQL every app that uses the auth blocks needs. Idempotent: it also upgrades the tables of apps created before the kit."""

SQL = """
CREATE TABLE IF NOT EXISTS app_setting (key text PRIMARY KEY, value text NOT NULL);

CREATE TABLE IF NOT EXISTS web_session (
    token_hash text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
ALTER TABLE web_session ADD COLUMN IF NOT EXISTS subject text NOT NULL DEFAULT 'local-admin';
ALTER TABLE web_session ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT '';
ALTER TABLE web_session ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT '';
ALTER TABLE web_session ADD COLUMN IF NOT EXISTS roles jsonb NOT NULL DEFAULT '[]';
ALTER TABLE web_session ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'local';
ALTER TABLE web_session ADD COLUMN IF NOT EXISTS id_token_hint text;

CREATE TABLE IF NOT EXISTS api_token (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    token_hash    text NOT NULL UNIQUE,
    prefix        text NOT NULL,
    scope         text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

CREATE TABLE IF NOT EXISTS oidc_login (
    state       text PRIMARY KEY,
    verifier    text NOT NULL,
    nonce       text NOT NULL,
    return_to   text NOT NULL DEFAULT '/',
    created_at  timestamptz NOT NULL DEFAULT now()
);
"""
