CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL,
  invited_by_uuid UUID REFERENCES users(uuid),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  token_rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS invited_by_uuid UUID REFERENCES users(uuid);

CREATE TABLE IF NOT EXISTS user_invites (
  user_uuid UUID PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  code_prefix TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
