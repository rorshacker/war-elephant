CREATE TABLE IF NOT EXISTS content_scans (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  source_id TEXT NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL,
  observation TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
