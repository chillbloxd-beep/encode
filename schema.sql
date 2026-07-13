PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vaults (
  id TEXT PRIMARY KEY CHECK (id = 'primary'),
  crypto_version INTEGER NOT NULL CHECK (crypto_version = 1),
  kdf_json TEXT NOT NULL,
  salt_b64 TEXT NOT NULL,
  wrapped_root_b64 TEXT NOT NULL,
  root_nonce_b64 TEXT NOT NULL,
  recovery_wrapped_root_b64 TEXT NOT NULL,
  recovery_nonce_b64 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS upload_sessions (
  id TEXT PRIMARY KEY,
  object_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  expected_chunks INTEGER NOT NULL CHECK (expected_chunks >= 1),
  received_chunks INTEGER NOT NULL DEFAULT 0 CHECK (received_chunks >= 0),
  total_ciphertext_size INTEGER NOT NULL DEFAULT 0 CHECK (total_ciphertext_size >= 0),
  status TEXT NOT NULL CHECK (status IN ('open', 'completed', 'cancelled')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS upload_chunks (
  session_id TEXT NOT NULL,
  chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
  size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
  sha256_b64 TEXT NOT NULL,
  storage_key TEXT NOT NULL,
  PRIMARY KEY (session_id, chunk_index),
  FOREIGN KEY (session_id) REFERENCES upload_sessions(id) ON DELETE CASCADE
) STRICT;

CREATE TABLE IF NOT EXISTS objects (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version >= 1),
  encrypted_manifest_b64 TEXT NOT NULL,
  manifest_nonce_b64 TEXT NOT NULL,
  wrapped_dek_b64 TEXT NOT NULL,
  wrapped_dek_nonce_b64 TEXT NOT NULL,
  stream_header_b64 TEXT NOT NULL,
  chunk_count INTEGER NOT NULL CHECK (chunk_count >= 1),
  ciphertext_size INTEGER NOT NULL CHECK (ciphertext_size > 0),
  previous_version_hash_b64 TEXT,
  version_hash_b64 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'deleted'))
) STRICT;

CREATE TABLE IF NOT EXISTS audit_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  object_id TEXT,
  previous_hash_b64 TEXT,
  entry_hash_b64 TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_objects_status_updated ON objects(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON upload_sessions(status, expires_at);
