ALTER TABLE findings ADD COLUMN risk_json TEXT;

CREATE TABLE IF NOT EXISTS scenario_runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  actor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_imports (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  imported_by TEXT NOT NULL,
  record_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_items (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  description TEXT NOT NULL,
  product_name TEXT NOT NULL,
  version TEXT NOT NULL,
  source_ref TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS package_observations (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  package_name TEXT NOT NULL,
  version TEXT NOT NULL,
  evidence_line TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS container_records (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL,
  name TEXT NOT NULL,
  hostname TEXT NOT NULL,
  image TEXT NOT NULL,
  user_name TEXT NOT NULL,
  privileged INTEGER NOT NULL,
  evidence_line TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_events (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  message TEXT NOT NULL,
  evidence_line TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_rules (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL,
  device_name TEXT NOT NULL,
  action TEXT NOT NULL,
  source TEXT NOT NULL,
  destination TEXT NOT NULL,
  port TEXT NOT NULL,
  evidence_line TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS host_settings (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  setting_key TEXT NOT NULL,
  setting_value TEXT NOT NULL,
  evidence_line TEXT NOT NULL
);
