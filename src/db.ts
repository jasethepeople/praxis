import { Database } from "bun:sqlite";
import { chmodSync, existsSync, lstatSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const schema = `
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA trusted_schema = OFF;
CREATE TABLE IF NOT EXISTS contracts (
  skill_id TEXT PRIMARY KEY,
  contract_hash TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK(state IN ('canonical','deprecated')),
  risk_tier INTEGER NOT NULL CHECK(risk_tier BETWEEN 0 AND 2),
  domain TEXT NOT NULL,
  name TEXT NOT NULL,
  contract_json TEXT NOT NULL,
  signature TEXT NOT NULL,
  signer TEXT NOT NULL,
  promoted_event_id TEXT NOT NULL UNIQUE,
  promoted_event_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  supersedes TEXT REFERENCES contracts(skill_id)
);
CREATE INDEX IF NOT EXISTS contracts_domain_state ON contracts(domain,state);
CREATE TABLE IF NOT EXISTS skill_stats (
  skill_id TEXT PRIMARY KEY REFERENCES contracts(skill_id),
  contract_hash TEXT NOT NULL,
  alpha REAL NOT NULL DEFAULT 1 CHECK(alpha >= 1),
  beta REAL NOT NULL DEFAULT 1 CHECK(beta >= 1),
  uses INTEGER NOT NULL DEFAULT 0 CHECK(uses >= 0),
  blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked >= 0),
  unverified INTEGER NOT NULL DEFAULT 0 CHECK(unverified >= 0),
  last_outcome TEXT,
  last_used_at TEXT,
  last_event_id TEXT
);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  signature TEXT NOT NULL,
  signer TEXT NOT NULL,
  source TEXT NOT NULL,
  prev_hash TEXT,
  event_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS events_type_time ON events(event_type,timestamp);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
CREATE VIRTUAL TABLE IF NOT EXISTS skill_fts USING fts5(skill_id UNINDEXED,name,domain,description,triggers,keywords,tokenize='unicode61 remove_diacritics 2');
CREATE TABLE IF NOT EXISTS embeddings (
  skill_id TEXT NOT NULL REFERENCES contracts(skill_id),
  contract_hash TEXT NOT NULL,
  model TEXT NOT NULL,
  model_sha TEXT NOT NULL,
  dims INTEGER NOT NULL CHECK(dims > 0 AND dims <= 8192),
  vector_json TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)),
  PRIMARY KEY(skill_id,model,model_sha)
);
CREATE INDEX IF NOT EXISTS embeddings_partition ON embeddings(model,model_sha,active);
CREATE TABLE IF NOT EXISTS tool_registry (
  tool_id TEXT PRIMARY KEY,
  risk_tier INTEGER NOT NULL CHECK(risk_tier BETWEEN 0 AND 2),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS molt_source_keys (
  agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id),
  public_key TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  registered_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS molt_source_key_no_change BEFORE UPDATE OF public_key,registered_at ON molt_source_keys BEGIN SELECT RAISE(ABORT,'MOLT source key is immutable'); END;
CREATE TRIGGER IF NOT EXISTS molt_source_key_no_delete BEFORE DELETE ON molt_source_keys BEGIN SELECT RAISE(ABORT,'MOLT source keys are immutable'); END;
CREATE TABLE IF NOT EXISTS molt_local_evidence (
  content_sha256 TEXT PRIMARY KEY,
  room_id TEXT NOT NULL,
  source_agent_id TEXT NOT NULL REFERENCES molt_source_keys(agent_id),
  event_count INTEGER NOT NULL CHECK(event_count > 0),
  ref_json TEXT NOT NULL,
  verified_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS molt_local_evidence_no_update BEFORE UPDATE ON molt_local_evidence BEGIN SELECT RAISE(ABORT,'local evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS molt_local_evidence_no_delete BEFORE DELETE ON molt_local_evidence BEGIN SELECT RAISE(ABORT,'local evidence is immutable'); END;
CREATE TABLE IF NOT EXISTS approval_keys (
  approver_id TEXT PRIMARY KEY,
  public_key_pem TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  contract_hash TEXT NOT NULL,
  approver_id TEXT NOT NULL REFERENCES approval_keys(approver_id),
  decision TEXT NOT NULL CHECK(decision IN ('approve','reject')),
  signed_at TEXT NOT NULL,
  signature TEXT NOT NULL,
  UNIQUE(contract_hash,approver_id)
);
CREATE TRIGGER IF NOT EXISTS approvals_no_update BEFORE UPDATE ON approvals BEGIN SELECT RAISE(ABORT,'approvals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS approvals_no_delete BEFORE DELETE ON approvals BEGIN SELECT RAISE(ABORT,'approvals are append-only'); END;
CREATE TABLE IF NOT EXISTS ingest_records (
  ingest_id TEXT PRIMARY KEY,
  source_agent_id TEXT NOT NULL,
  trajectory_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('draft','quarantined','submitted','rejected')),
  flags_json TEXT NOT NULL,
  sanitized_trajectory TEXT NOT NULL,
  draft_json TEXT,
  created_at TEXT NOT NULL,
  reviewed_by TEXT,
  review_event_id TEXT
);
CREATE INDEX IF NOT EXISTS ingest_state_time ON ingest_records(state,created_at);
CREATE TABLE IF NOT EXISTS molt_rooms (
  room_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS molt_messages (
  message_id TEXT PRIMARY KEY,
  room_id TEXT NOT NULL REFERENCES molt_rooms(room_id),
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  role TEXT NOT NULL CHECK(role IN ('user','assistant','tool')),
  kind TEXT NOT NULL CHECK(kind IN ('message','tool_call','tool_result','evidence')),
  content_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  flags_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS molt_messages_room_time ON molt_messages(room_id,created_at,message_id);
CREATE TABLE IF NOT EXISTS intel_cache (
  cache_key TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  cached_at TEXT NOT NULL,
  response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exploit_db_entries (
  edb_id TEXT PRIMARY KEY,
  file_path TEXT NOT NULL,
  description TEXT NOT NULL,
  date_published TEXT,
  author TEXT,
  exploit_type TEXT,
  platform TEXT,
  port TEXT,
  verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1))
);
CREATE VIRTUAL TABLE IF NOT EXISTS exploit_db_fts USING fts5(edb_id UNINDEXED,description,file_path,author,exploit_type,platform,tokenize='unicode61');
CREATE TABLE IF NOT EXISTS gateway_agents (
  agent_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  url TEXT,
  capabilities_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_runs (
  execution_id TEXT PRIMARY KEY,
  skill_id TEXT NOT NULL REFERENCES contracts(skill_id),
  contract_hash TEXT NOT NULL,
  executor_agent TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('blocked','running','completed','failed')),
  outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','partial','blocked','unverified')),
  created_at TEXT NOT NULL,
  finished_at TEXT,
  output_json TEXT,
  event_id TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS skill_outcomes (
  event_id TEXT PRIMARY KEY REFERENCES events(event_id),
  skill_id TEXT NOT NULL REFERENCES contracts(skill_id),
  executor_agent TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','partial','blocked','unverified')),
  verification_method TEXT NOT NULL CHECK(verification_method IN ('output_spec','eval_replay','human','self_report')),
  applied_weight REAL NOT NULL CHECK(applied_weight >= 0),
  occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS skill_outcomes_recent ON skill_outcomes(skill_id,occurred_at);
CREATE INDEX IF NOT EXISTS skill_outcomes_executor ON skill_outcomes(skill_id,executor_agent);
CREATE TABLE IF NOT EXISTS tier0_audit_queue (
  skill_id TEXT NOT NULL REFERENCES contracts(skill_id),
  contract_hash TEXT NOT NULL,
  queued_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','passed','failed')),
  PRIMARY KEY(skill_id,contract_hash)
);
CREATE TABLE IF NOT EXISTS quarantine_reviews (
  review_id TEXT PRIMARY KEY,
  ledger_event_id TEXT UNIQUE REFERENCES events(event_id),
  ingest_id TEXT NOT NULL REFERENCES ingest_records(ingest_id),
  trajectory_hash TEXT NOT NULL,
  reviewed_trajectory_hash TEXT,
  candidate_hash TEXT,
  original_sanitized_trajectory TEXT NOT NULL,
  reviewed_candidate_json TEXT,
  approver_id TEXT NOT NULL REFERENCES approval_keys(approver_id),
  decision TEXT NOT NULL CHECK(decision IN ('release','reject')),
  notes TEXT NOT NULL,
  signed_at TEXT NOT NULL,
  signature TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS quarantine_reviews_no_update BEFORE UPDATE ON quarantine_reviews BEGIN SELECT RAISE(ABORT,'quarantine reviews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS quarantine_reviews_no_delete BEFORE DELETE ON quarantine_reviews BEGIN SELECT RAISE(ABORT,'quarantine reviews are append-only'); END;
CREATE TABLE IF NOT EXISTS api_audit (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  at TEXT NOT NULL,
  detail_json TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS api_audit_no_update BEFORE UPDATE ON api_audit BEGIN SELECT RAISE(ABORT,'audit records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS api_audit_no_delete BEFORE DELETE ON api_audit BEGIN SELECT RAISE(ABORT,'audit records are append-only'); END;
CREATE TABLE IF NOT EXISTS system_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
`;

export class PraxisDb {
  readonly sqlite: Database;

  constructor(path: string) {
    const directory = dirname(path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (path !== ":memory:") {
      const stat = lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Database directory must be a real directory, not a symlink");
      if ((stat.mode & 0o077) !== 0) throw new Error("Database directory permissions must be 0700 or more restrictive");
      if (existsSync(path)) {
        const dbStat = lstatSync(path);
        if (!dbStat.isFile() || dbStat.isSymbolicLink()) throw new Error("Database path must be a regular file, not a symlink");
      }
    }
    this.sqlite = new Database(path, { create: true, strict: true });
    const current = (this.sqlite.query("PRAGMA user_version").get() as { user_version: number }).user_version;
    if (current > 9) throw new Error(`Database schema ${current} is newer than this application supports`);
    this.sqlite.exec(schema);
    if (current < 2) {
      const columns = this.sqlite.query("PRAGMA table_info(execution_runs)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "idempotency_key")) this.sqlite.exec("ALTER TABLE execution_runs ADD COLUMN idempotency_key TEXT");
      if (!columns.some((column) => column.name === "request_hash")) this.sqlite.exec("ALTER TABLE execution_runs ADD COLUMN request_hash TEXT");
      this.sqlite.exec("CREATE UNIQUE INDEX IF NOT EXISTS execution_runs_idempotency ON execution_runs(idempotency_key)");
    }
    if (current < 3) {
      const columns = this.sqlite.query("PRAGMA table_info(quarantine_reviews)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "reviewed_trajectory_hash")) this.sqlite.exec("ALTER TABLE quarantine_reviews ADD COLUMN reviewed_trajectory_hash TEXT");
    }
    if (current < 4) {
      const columns = this.sqlite.query("PRAGMA table_info(quarantine_reviews)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "candidate_hash")) this.sqlite.exec("ALTER TABLE quarantine_reviews ADD COLUMN candidate_hash TEXT");
      if (!columns.some((column) => column.name === "original_sanitized_trajectory")) this.sqlite.exec("ALTER TABLE quarantine_reviews ADD COLUMN original_sanitized_trajectory TEXT NOT NULL DEFAULT ''");
    }
    if (current < 5) {
      const columns = this.sqlite.query("PRAGMA table_info(quarantine_reviews)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "reviewed_candidate_json")) this.sqlite.exec("ALTER TABLE quarantine_reviews ADD COLUMN reviewed_candidate_json TEXT");
    }
    if (current < 6) {
      const columns = this.sqlite.query("PRAGMA table_info(quarantine_reviews)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "ledger_event_id")) this.sqlite.exec("ALTER TABLE quarantine_reviews ADD COLUMN ledger_event_id TEXT REFERENCES events(event_id)");
    }
    if (current < 9) {
      const columns = this.sqlite.query("PRAGMA table_info(molt_messages)").all() as Array<{ name: string }>;
      if (!columns.some((column) => column.name === "flags_json")) this.sqlite.exec("ALTER TABLE molt_messages ADD COLUMN flags_json TEXT NOT NULL DEFAULT '[]'");
    }
    this.sqlite.exec("PRAGMA user_version = 9");
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.sqlite.exec("PRAGMA optimize;");
  }

  close(): void {
    this.sqlite.close();
  }

  lastEventHash(): string | null {
    return (this.sqlite.query("SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1").get() as { event_hash: string } | null)?.event_hash ?? null;
  }

  audit(requestId: string, actor: string, action: string, detail: Record<string, unknown> = {}): void {
    this.sqlite.query("INSERT INTO api_audit(request_id,actor,action,at,detail_json) VALUES(?,?,?,?,?)")
      .run(requestId, actor.slice(0, 120), action.slice(0, 120), new Date().toISOString(), JSON.stringify(detail));
  }

  closeCheckpoint(): void {
    this.sqlite.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  }
}
