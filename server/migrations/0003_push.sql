-- Devices that get a wake-up when a request is held (Web Push). Endpoints only; no keys, no payload is ever sent.
CREATE TABLE push_subs (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_ok_at INTEGER
);
CREATE INDEX push_subs_account ON push_subs(account_id);
