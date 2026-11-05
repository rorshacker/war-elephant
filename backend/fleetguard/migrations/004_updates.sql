CREATE TABLE IF NOT EXISTS update_imports (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  stored_path TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  imported_by TEXT NOT NULL,
  authenticity TEXT NOT NULL,
  authenticity_statement TEXT NOT NULL,
  UNIQUE (kind, sha256)
);
