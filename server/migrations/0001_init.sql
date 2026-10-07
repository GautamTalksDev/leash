-- LEASH: credential broker for AI agents. Real keys never leave the vault; agents hold proxy tokens.
CREATE TABLE accounts (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

-- WebAuthn passkeys (the only way to sign in or approve anything irreversible)
CREATE TABLE passkeys (
  cred_id     TEXT PRIMARY KEY,           -- base64url credential id
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  alg         INTEGER NOT NULL,           -- COSE alg: -7 ES256, -257 RS256
  jwk         TEXT NOT NULL,              -- public key as JWK
  sign_count  INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  last_used   INTEGER
);
CREATE INDEX passkeys_by_account ON passkeys(account_id);

-- one-time WebAuthn challenges (5 min)
CREATE TABLE challenges (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL,              -- register | login | approve:<hold> | device:<code>
  account_id  TEXT,
  challenge   TEXT NOT NULL,
  name        TEXT,
  expires_at  INTEGER NOT NULL
);

-- browser sessions (cookie) and CLI sessions (bearer); only hashes are stored
CREATE TABLE sessions (
  hash        TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,              -- web | cli
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

-- CLI sign-in: device authorization (RFC 8628 style)
CREATE TABLE device_codes (
  device_hash TEXT PRIMARY KEY,
  user_code   TEXT NOT NULL UNIQUE,
  account_id  TEXT,
  status      TEXT NOT NULL DEFAULT 'pending', -- pending | approved | used
  expires_at  INTEGER NOT NULL
);

-- the vault: each secret has its own data key, wrapped by the master key (envelope encryption)
CREATE TABLE credentials (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  provider    TEXT NOT NULL,
  label       TEXT NOT NULL,
  hint        TEXT NOT NULL,              -- last 4 chars, so people can tell keys apart
  ct          TEXT NOT NULL,
  iv          TEXT NOT NULL,
  wrapped_dek TEXT NOT NULL,
  dek_iv      TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  last_used   INTEGER
);
CREATE INDEX credentials_by_account ON credentials(account_id);

-- proxy tokens handed to agents
CREATE TABLE tokens (
  id            TEXT PRIMARY KEY,
  account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  hash          TEXT NOT NULL UNIQUE,
  label         TEXT NOT NULL,
  policy        TEXT NOT NULL,            -- JSON
  minted_by     TEXT NOT NULL,            -- passkey | cli
  expires_at    INTEGER NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_used     INTEGER
);
CREATE INDEX tokens_by_account ON tokens(account_id);

-- held irreversible requests; an approved hold lets the exact same request through once, within 10 min
CREATE TABLE holds (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_id    TEXT NOT NULL,
  req_hash    TEXT NOT NULL,
  method      TEXT NOT NULL,
  host        TEXT NOT NULL,
  path        TEXT NOT NULL,
  rule        TEXT NOT NULL,
  why         TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | used | expired
  created_at  INTEGER NOT NULL,
  decided_at  INTEGER,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX holds_lookup ON holds(token_id, req_hash, status);
CREATE INDEX holds_by_account ON holds(account_id, status);

-- append-only audit log, hash-chained per account
CREATE TABLE audit (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id  TEXT NOT NULL,
  at          INTEGER NOT NULL,
  actor       TEXT NOT NULL,              -- token:<id> | web | cli
  action      TEXT NOT NULL,              -- proxy | hold | approve | deny | mint | revoke | add_credential | ...
  detail      TEXT NOT NULL,              -- JSON
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE INDEX audit_by_account ON audit(account_id, seq);

CREATE TABLE ratelimits (
  bucket      TEXT PRIMARY KEY,
  count       INTEGER NOT NULL,
  reset_at    INTEGER NOT NULL
);
