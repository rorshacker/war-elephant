CREATE TABLE IF NOT EXISTS operators (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  operator_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT,
  object_id TEXT,
  correlation_id TEXT,
  outcome TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
  id TEXT PRIMARY KEY,
  head_hash TEXT NOT NULL,
  event_count INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  signature_status TEXT NOT NULL,
  signature TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stig_packages (
  id TEXT PRIMARY KEY,
  original_filename TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  size_bytes INTEGER NOT NULL,
  stored_path TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  imported_by TEXT NOT NULL,
  authenticity TEXT NOT NULL,
  authenticity_statement TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stig_benchmarks (
  id TEXT PRIMARY KEY,
  package_id TEXT NOT NULL,
  benchmark_id TEXT NOT NULL,
  version TEXT NOT NULL,
  release_info TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  xml_sha256 TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  UNIQUE (benchmark_id, version, xml_sha256)
);

CREATE TABLE IF NOT EXISTS stig_rules (
  id TEXT PRIMARY KEY,
  benchmark_row_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  check_text TEXT NOT NULL DEFAULT '',
  fix_text TEXT NOT NULL DEFAULT '',
  source_ref TEXT NOT NULL DEFAULT '',
  UNIQUE (benchmark_row_id, rule_id)
);

CREATE TABLE IF NOT EXISTS inventory_previews (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  worksheet TEXT,
  mapping_json TEXT NOT NULL,
  rows_json TEXT NOT NULL,
  errors_json TEXT NOT NULL,
  duplicates_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  committed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inventory_imports (
  id TEXT PRIMARY KEY,
  preview_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  worksheet TEXT,
  mapping_json TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  imported_by TEXT NOT NULL,
  row_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS inventory_rows (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL,
  row_number INTEGER NOT NULL,
  hostname TEXT,
  ip_address TEXT,
  subnet TEXT,
  device_type TEXT,
  os_name TEXT,
  vlan TEXT,
  enclave TEXT,
  department TEXT,
  owner TEXT,
  mission_function TEXT,
  criticality TEXT,
  maintenance_window TEXT,
  scan_restrictions TEXT,
  raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_computers (
  id TEXT PRIMARY KEY,
  object_guid TEXT NOT NULL UNIQUE,
  computer_name TEXT,
  dns_hostname TEXT,
  enabled INTEGER,
  os_name TEXT,
  os_version TEXT,
  distinguished_name TEXT,
  last_logon_timestamp TEXT,
  observed_at TEXT NOT NULL,
  source_mode TEXT NOT NULL,
  evidence_kind TEXT NOT NULL,
  controller TEXT,
  job_id TEXT
);

CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  port INTEGER,
  status TEXT NOT NULL,
  note TEXT NOT NULL,
  hostname TEXT,
  observed_at TEXT NOT NULL,
  evidence_kind TEXT NOT NULL,
  job_id TEXT
);

CREATE TABLE IF NOT EXISTS discovery_scopes (
  id TEXT PRIMARY KEY,
  domain_name TEXT,
  domain_controller TEXT,
  base_dn TEXT,
  cidrs_json TEXT NOT NULL,
  excluded_json TEXT NOT NULL,
  methods_json TEXT NOT NULL,
  ports_json TEXT NOT NULL,
  rate_limit_per_sec REAL NOT NULL,
  concurrency INTEGER NOT NULL,
  timeout_sec REAL NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL,
  approval_hash TEXT,
  approved_by TEXT,
  approved_at TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discovery_jobs (
  id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  created_by TEXT NOT NULL,
  error TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  detail TEXT
);

CREATE TABLE IF NOT EXISTS asset_state (
  group_key TEXT PRIMARY KEY,
  selected INTEGER NOT NULL DEFAULT 0,
  human_decision TEXT,
  decision_reason TEXT,
  decided_by TEXT,
  decided_at TEXT,
  lab_target_path TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  hostname TEXT,
  ip_address TEXT,
  os_name TEXT,
  os_observations_json TEXT NOT NULL,
  device_type TEXT,
  owner TEXT,
  criticality TEXT,
  match_basis TEXT NOT NULL,
  flags_json TEXT NOT NULL,
  identity_confidence TEXT NOT NULL,
  sources_json TEXT NOT NULL,
  freshness_json TEXT NOT NULL,
  selected INTEGER NOT NULL DEFAULT 0,
  human_decision TEXT,
  decision_reason TEXT,
  decided_by TEXT,
  decided_at TEXT,
  lab_target_path TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS conflicts (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_links (
  id TEXT PRIMARY KEY,
  left_ref TEXT NOT NULL,
  right_ref TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_assignments (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  benchmark_row_id TEXT,
  benchmark_id TEXT,
  version_label TEXT,
  mapping_name TEXT,
  applicability TEXT NOT NULL,
  status TEXT NOT NULL,
  questions_json TEXT NOT NULL,
  override_reason TEXT,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_meta (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  purpose TEXT NOT NULL,
  adapter TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  benchmark_row_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  benchmark_row_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  classification TEXT NOT NULL,
  result TEXT NOT NULL,
  observation TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  check_impl_version TEXT NOT NULL,
  evidence_ref TEXT,
  evidence_kind TEXT NOT NULL,
  rule_source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  supersedes_id TEXT,
  action_type TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  finding_id TEXT,
  execution_id TEXT,
  benchmark_id TEXT NOT NULL,
  benchmark_row_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  target_identity_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  intended_change_json TEXT NOT NULL,
  preconditions_json TEXT NOT NULL,
  expected_start_hash TEXT NOT NULL,
  impact TEXT NOT NULL,
  dependencies TEXT NOT NULL,
  backup_scope TEXT NOT NULL,
  verification_json TEXT NOT NULL,
  rollback_procedure TEXT NOT NULL,
  rollback_capability TEXT NOT NULL,
  connectivity_risk INTEGER NOT NULL,
  adapter_name TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  proposal_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  proposal_hash TEXT NOT NULL,
  actor TEXT NOT NULL,
  decision TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS execution_intents (
  id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  approval_id TEXT NOT NULL UNIQUE,
  asset_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  status TEXT NOT NULL,
  backup_path TEXT,
  prior_hash TEXT,
  post_hash TEXT,
  remote_atomic INTEGER NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  detail TEXT,
  adapter_name TEXT NOT NULL,
  adapter_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_outbox (
  id TEXT PRIMARY KEY,
  origin TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  record_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  acked_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS sync_inbox (
  record_id TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  origin TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  record_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  disposition TEXT NOT NULL,
  PRIMARY KEY (record_id, content_hash)
);
