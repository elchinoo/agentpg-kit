CREATE TABLE IF NOT EXISTS note (
    id         bigserial PRIMARY KEY,
    title      text NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
    body       text NOT NULL DEFAULT '',          -- plain text, or a vault token when private
    private    boolean NOT NULL DEFAULT false,
    author     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
