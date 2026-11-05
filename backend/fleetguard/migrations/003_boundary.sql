ALTER TABLE asset_state ADD COLUMN automation_class TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE assets ADD COLUMN automation_class TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE proposals ADD COLUMN change_type TEXT NOT NULL DEFAULT 'unspecified';

CREATE TABLE IF NOT EXISTS maintenance_authorizations (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  change_type TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  authorized_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS controller_state (
  id TEXT PRIMARY KEY,
  scheduling_halted INTEGER NOT NULL DEFAULT 0,
  halted_by TEXT,
  halted_at TEXT,
  halt_reason TEXT
);

INSERT OR IGNORE INTO controller_state (id, scheduling_halted) VALUES ('local', 0);
