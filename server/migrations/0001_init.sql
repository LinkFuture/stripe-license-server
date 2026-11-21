-- LinkFuture license server schema. Times are ISO-8601 UTC text.
-- The buyer-facing license key is never stored in plaintext.
-- key_hash is SHA-256 of the canonical key. key_last4 is a display hint.
-- key_enc is AES-GCM ciphertext so recovery email can resend the key.
-- Decrypting key_enc requires the LICENSE_ENCRYPTION_KEY secret.

CREATE TABLE apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  trial_days INTEGER NOT NULL DEFAULT 30 CHECK (trial_days >= 0),
  offline_grace_days INTEGER NOT NULL DEFAULT 30 CHECK (offline_grace_days >= 0),
  inactive_release_days INTEGER NOT NULL DEFAULT 90 CHECK (inactive_release_days >= 0),
  reset_limit INTEGER NOT NULL DEFAULT 5 CHECK (reset_limit >= 0),
  reset_window_days INTEGER NOT NULL DEFAULT 30 CHECK (reset_window_days >= 1),
  mail_from TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id),
  key_hash TEXT NOT NULL UNIQUE,
  key_last4 TEXT NOT NULL,
  key_enc TEXT NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE,
  max_machines INTEGER NOT NULL CHECK (max_machines > 0),
  stripe_session_id TEXT NOT NULL UNIQUE,
  stripe_payment_intent TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  revoked_at TEXT,
  revoke_reason TEXT CHECK (revoke_reason IN ('refund', 'dispute', 'admin')),
  email_sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_licenses_app_email ON licenses(app_id, email);

CREATE TABLE activations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  machine_hash TEXT NOT NULL,
  machine_name TEXT,
  platform TEXT,
  app_version TEXT,
  activated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (license_id, machine_hash)
);

CREATE INDEX idx_activations_machine ON activations(machine_hash);

CREATE TABLE trials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id),
  machine_hash TEXT NOT NULL,
  started_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  platform TEXT,
  app_version TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (app_id, machine_hash)
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER REFERENCES apps(id),
  license_id INTEGER REFERENCES licenses(id),
  type TEXT NOT NULL,
  machine_hash TEXT,
  ip TEXT,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_events_license ON events(license_id, created_at);
CREATE INDEX idx_events_app_type ON events(app_id, type, created_at);

CREATE TABLE email_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id INTEGER NOT NULL REFERENCES apps(id),
  email TEXT NOT NULL COLLATE NOCASE,
  license_id INTEGER REFERENCES licenses(id),
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('recover', 'reset_machines')),
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_email_codes_lookup ON email_codes(app_id, email, purpose, created_at);

CREATE TABLE rate_limits (
  bucket TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (bucket, window_start)
);
