import { createHash, createPublicKey } from "node:crypto";
import { canonicalJson, contractHash, sha256 } from "./canonical";
import { newEventId } from "./ids";
import type { Outcome, SignedEvent, SkillContract, VerificationMethod } from "./types";
import type { PraxisDb } from "./db";
import type { SigningIdentity } from "./security";
import { eventSigningPayload, signEvent, verifySignature } from "./security";

export type LedgerSource = "foundry" | "gateway";

interface EventRow {
  event_id: string;
  event_type: string;
  timestamp: string;
  payload_json: string;
  signature: string;
  signer: string;
  source: LedgerSource;
  prev_hash: string | null;
  event_hash: string;
}

function eventEnvelope(event: SignedEvent): SignedEvent {
  return {
    event_type: event.event_type,
    event_id: event.event_id,
    timestamp: event.timestamp,
    payload: event.payload,
    signature: event.signature,
    signer: event.signer,
  };
}

function eventHash(event: SignedEvent, prevHash: string | null): string {
  return sha256(canonicalJson({ event: eventEnvelope(event), prev_hash: prevHash }));
}

function validIsoTimestamp(value: string): boolean {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

export function makeEvent(identity: SigningIdentity, type: string, payload: Record<string, unknown>, timestamp = new Date().toISOString()): SignedEvent {
  const signedPayload = type === "skill.used" ? { ...payload, timestamp } : payload;
  return signEvent(identity, { event_type: type, event_id: newEventId(), timestamp, payload: signedPayload });
}

export class Ledger {
  constructor(
    private readonly db: PraxisDb,
    private readonly foundry: SigningIdentity,
    private readonly gateway: SigningIdentity,
    private readonly executorWeightCap: number,
  ) {}

  append(event: SignedEvent, source: LedgerSource): { event_hash: string; duplicate: boolean } {
    if (!/^evt_[0-9A-HJKMNP-TV-Z]{26}$/.test(event.event_id) || !validIsoTimestamp(event.timestamp)) throw new Error("Invalid event identity or timestamp");
    if (!event.payload || typeof event.payload !== "object" || Array.isArray(event.payload)) throw new Error("Event payload must be an object");
    if (!new Set(["skill.promoted", "skill.used", "skill.deprecated", "skill.quarantine_reviewed", "approver.registered", "approver.disabled", "tool.policy_set"]).has(event.event_type)) throw new Error("Unsupported ledger event type");
    const identity = source === "foundry" ? this.foundry : this.gateway;
    if (event.signer !== identity.fingerprint || !verifySignature(eventSigningPayload(event), event.signature, createPublicKey(identity.publicKeyPem))) throw new Error("Invalid event signature");
    if ((source === "foundry") !== (event.event_type !== "skill.used")) throw new Error("Event signer is not authorized for this event type");

    const existing = this.db.sqlite.query("SELECT signature,event_type,payload_json,event_hash FROM events WHERE event_id=?").get(event.event_id) as { signature: string; event_type: string; payload_json: string; event_hash: string } | null;
    if (existing) {
      if (existing.signature !== event.signature || existing.event_type !== event.event_type || existing.payload_json !== canonicalJson(event.payload)) throw new Error("Event id was already used for different content");
      return { event_hash: existing.event_hash, duplicate: true };
    }

    const previous = this.db.lastEventHash();
    const hash = eventHash(event, previous);
    this.db.sqlite.query("INSERT INTO events(event_id,event_type,timestamp,payload_json,signature,signer,source,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?,?,?)")
      .run(event.event_id, event.event_type, event.timestamp, canonicalJson(event.payload), event.signature, event.signer, source, previous, hash);
    return { event_hash: hash, duplicate: false };
  }

  promote(contract: SkillContract, contractSignature: string, event: SignedEvent): { event_hash: string; duplicate: boolean } {
    if (event.event_type !== "skill.promoted") throw new Error("Expected skill.promoted event");
    const payload = event.payload;
    if (payload.contract_hash !== contractHash(contract) || payload.contract_signature !== contractSignature) throw new Error("Promotion event does not match the contract");
    if (!verifySignature(contractPayload(contract), contractSignature, createPublicKeyFromIdentity(this.foundry))) throw new Error("Invalid contract signature");
    const outcome = this.db.sqlite.transaction(() => {
      const appended = this.append(event, "foundry");
      const saved = { ...contract, molts_event_hash: appended.event_hash };
      this.db.sqlite.query(`INSERT INTO contracts(skill_id,contract_hash,state,risk_tier,domain,name,contract_json,signature,signer,promoted_event_id,promoted_event_hash,created_at,supersedes)
        VALUES(?,?,'canonical',?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(skill_id) DO NOTHING`)
        .run(contract.id, contractHash(contract), contract.risk_tier, contract.domain, contract.name, canonicalJson(saved), contractSignature, this.foundry.fingerprint, event.event_id, appended.event_hash, event.timestamp, contract.supersedes ?? null);
      const row = this.db.sqlite.query("SELECT contract_hash,promoted_event_id FROM contracts WHERE skill_id=?").get(contract.id) as { contract_hash: string; promoted_event_id: string } | null;
      if (!row || row.contract_hash !== contractHash(contract) || row.promoted_event_id !== event.event_id) throw new Error("Skill id already names a different canonical contract");
      this.db.sqlite.query("INSERT OR IGNORE INTO skill_stats(skill_id,contract_hash) VALUES(?,?)").run(contract.id, contractHash(contract));
      this.indexContract(saved);
      return appended;
    })();
    return outcome;
  }

  deprecate(skillId: string, reason: string, event: SignedEvent): { event_hash: string; duplicate: boolean } {
    if (event.event_type !== "skill.deprecated" || event.payload.skill_id !== skillId) throw new Error("Invalid deprecation event");
    const row = this.db.sqlite.query("SELECT contract_hash,state FROM contracts WHERE skill_id=?").get(skillId) as { contract_hash: string; state: string } | null;
    if (!row || row.state !== "canonical" || event.payload.contract_hash !== row.contract_hash || event.payload.reason !== reason) throw new Error("Skill cannot be deprecated in its current state");
    return this.db.sqlite.transaction(() => {
      const result = this.append(event, "foundry");
      this.db.sqlite.query("UPDATE contracts SET state='deprecated' WHERE skill_id=?").run(skillId);
      this.db.sqlite.query("DELETE FROM skill_fts WHERE skill_id=?").run(skillId);
      return result;
    })();
  }

  recordOutcome(event: SignedEvent): { event_hash: string; duplicate: boolean; applied_weight: number } {
    if (event.event_type !== "skill.used") throw new Error("Expected skill.used event");
    const payload = event.payload;
    const skillId = String(payload.skill_id ?? "");
    const hash = String(payload.contract_hash ?? "");
    const executor = String(payload.executor_agent ?? "");
    const executionId = String(payload.execution_id ?? "");
    const outcome = payload.outcome as Outcome;
    const verification = payload.verification as { method: VerificationMethod; checks_passed?: number; checks_total?: number; verifier?: string };
    const validOutcomes = ["success", "failure", "partial", "blocked", "unverified"];
    const validMethods = ["output_spec", "eval_replay", "human", "self_report"];
    if (!skillId || !/^sha256:[0-9a-f]{64}$/.test(hash) || !/^[A-Za-z0-9._:-]{1,120}$/.test(executor) || !/^exec_[0-9A-HJKMNP-TV-Z]{26}$/.test(executionId) || !verification || !validOutcomes.includes(outcome)) throw new Error("Malformed skill.used event");
    if (!validMethods.includes(String(verification.method))) throw new Error("Invalid verification method");
    if (verification.verifier !== `integration-gateway@${this.gateway.fingerprint}`) throw new Error("Outcome verifier identity is invalid");
    if (!Number.isInteger(verification.checks_passed) || !Number.isInteger(verification.checks_total) || Number(verification.checks_passed) < 0 || Number(verification.checks_total) < Number(verification.checks_passed) || Number(verification.checks_total) > 10000) throw new Error("Invalid output verification counts");
    if (payload.timestamp !== event.timestamp) throw new Error("Outcome payload timestamp must match its signed event");
    if (verification.method === "output_spec" && outcome === "success" && (verification.checks_total === 0 || verification.checks_passed !== verification.checks_total)) throw new Error("A verified success must pass every output_spec check");
    if (verification.method === "output_spec" && outcome === "failure" && verification.checks_passed === verification.checks_total) throw new Error("A failed outcome cannot pass every output_spec check");
    const contract = this.db.sqlite.query("SELECT contract_hash FROM contracts WHERE skill_id=?").get(skillId) as { contract_hash: string } | null;
    if (!contract || contract.contract_hash !== hash) throw new Error("Outcome refers to an unknown contract version");

    return this.db.sqlite.transaction(() => {
      const appended = this.append(event, "gateway");
      if (appended.duplicate) return { ...appended, applied_weight: 0 };
      const stat = this.db.sqlite.query("SELECT alpha,beta,uses,blocked,unverified FROM skill_stats WHERE skill_id=?").get(skillId) as { alpha: number; beta: number; uses: number; blocked: number; unverified: number };
      if (!stat) throw new Error("Skill statistics row is missing");
      const priorWeight = outcome === "blocked" || outcome === "unverified" ? 0 : this.executorWeight(skillId, executor);
      const methodWeight = verification.method === "self_report" ? 0.25 : 1;
      const applied = outcome === "blocked" || outcome === "unverified" ? 0 : Math.max(0, Math.min(methodWeight, this.executorWeightCap - priorWeight));
      this.db.sqlite.query("INSERT INTO skill_outcomes(event_id,skill_id,executor_agent,outcome,verification_method,applied_weight,occurred_at) VALUES(?,?,?,?,?,?,?)")
        .run(event.event_id, skillId, executor, outcome, verification.method, applied, event.timestamp);
      if (outcome === "blocked" || outcome === "unverified") {
        const column = outcome === "blocked" ? "blocked" : "unverified";
        this.db.sqlite.query(`UPDATE skill_stats SET ${column}=${column}+1,last_outcome=?,last_used_at=?,last_event_id=? WHERE skill_id=?`)
          .run(outcome, event.timestamp, event.event_id, skillId);
        return { ...appended, applied_weight: 0 };
      }
      let alpha = stat.alpha;
      let beta = stat.beta;
      if (outcome === "success") alpha += applied;
      else if (outcome === "failure") beta += applied;
      else { alpha += applied * 0.5; beta += applied * 0.5; }
      this.db.sqlite.query("UPDATE skill_stats SET alpha=?,beta=?,uses=uses+?,last_outcome=?,last_used_at=?,last_event_id=? WHERE skill_id=?")
        .run(alpha, beta, applied > 0 ? 1 : 0, outcome, event.timestamp, event.event_id, skillId);
      return { ...appended, applied_weight: applied };
    })();
  }

  verifyLedger(): { valid: boolean; events: number; head_hash: string | null; errors: string[] } {
    const errors: string[] = [];
    const rows = this.db.sqlite.query("SELECT event_id,event_type,timestamp,payload_json,signature,signer,source,prev_hash,event_hash FROM events ORDER BY rowid").all() as EventRow[];
    const expectedStates = new Map<string, "canonical" | "deprecated">();
    let previous: string | null = null;
    for (const row of rows) {
      let payload: Record<string, unknown>;
      try { payload = JSON.parse(row.payload_json); }
      catch { errors.push(`invalid payload JSON: ${row.event_id}`); continue; }
      const event: SignedEvent = { event_type: row.event_type, event_id: row.event_id, timestamp: row.timestamp, payload, signature: row.signature, signer: row.signer };
      const identity = row.source === "foundry" ? this.foundry : row.source === "gateway" ? this.gateway : undefined;
      if (!identity || row.signer !== identity.fingerprint || !verifySignature(eventSigningPayload(event), event.signature, identity ? createPublicKeyFromIdentity(identity) : undefined)) errors.push(`invalid event signature: ${row.event_id}`);
      if (row.prev_hash !== previous) errors.push(`broken previous-hash link: ${row.event_id}`);
      if (!validIsoTimestamp(row.timestamp)) errors.push(`invalid event timestamp: ${row.event_id}`);
      if (row.event_hash !== eventHash(event, previous)) errors.push(`event hash mismatch: ${row.event_id}`);
      if (event.event_type === "skill.promoted") {
        this.checkPromotionEvent(event, row, errors);
        const contract = event.payload.contract as SkillContract | undefined;
        if (contract) {
          if (expectedStates.has(contract.id)) errors.push(`duplicate promotion for skill: ${contract.id}`);
          else expectedStates.set(contract.id, "canonical");
        }
      } else if (event.event_type === "skill.deprecated") {
        const skillId = String(payload.skill_id ?? "");
        const current = expectedStates.get(skillId);
        const saved = this.db.sqlite.query("SELECT contract_hash FROM contracts WHERE skill_id=?").get(skillId) as { contract_hash: string } | null;
        if (!current || current !== "canonical" || !saved || saved.contract_hash !== payload.contract_hash || typeof payload.reason !== "string" || payload.reason.length > 1000) errors.push(`invalid deprecation event: ${row.event_id}`);
        else expectedStates.set(skillId, "deprecated");
      } else if (event.event_type === "skill.used") {
        const skill = this.db.sqlite.query("SELECT contract_hash FROM contracts WHERE skill_id=?").get(String(payload.skill_id)) as { contract_hash: string } | null;
        if (row.source !== "gateway" || !skill || skill.contract_hash !== payload.contract_hash) errors.push(`outcome references a missing or changed contract: ${row.event_id}`);
      } else if (event.event_type === "skill.quarantine_reviewed") {
        const reviewId = String(payload.review_id ?? "");
        const publicPem = typeof payload.approver_public_key_pem === "string" ? payload.approver_public_key_pem : "";
        const signedReview = {
          review_id: payload.review_id,
          ingest_id: payload.ingest_id,
          trajectory_hash: payload.trajectory_hash,
          reviewed_trajectory_hash: payload.reviewed_trajectory_hash,
          candidate_hash: payload.candidate_hash,
          approver_id: payload.approver_id,
          decision: payload.decision,
          notes: payload.notes,
          signed_at: payload.signed_at,
        };
        try {
          const key = createPublicKey(publicPem);
          if (row.source !== "foundry" || !/^review_[0-9A-HJKMNP-TV-Z]{26}$/.test(reviewId) || !["release", "reject"].includes(String(payload.decision)) || !verifySignature(signedReview, String(payload.review_signature), key)) errors.push(`invalid quarantine review event: ${row.event_id}`);
        } catch { errors.push(`invalid quarantine review event: ${row.event_id}`); }
      } else if (event.event_type === "approver.registered") {
        const approverId = String(payload.approver_id ?? "");
        const publicPem = typeof payload.public_key_pem === "string" ? payload.public_key_pem : "";
        try {
          const key = createPublicKey(publicPem);
          const fingerprint = `sha256:${createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex")}`;
          const stored = this.db.sqlite.query("SELECT public_key_pem FROM approval_keys WHERE approver_id=?").get(approverId) as { public_key_pem: string } | null;
          if (row.source !== "foundry" || !approverId || fingerprint !== payload.key_fingerprint || !stored || stored.public_key_pem !== publicPem) errors.push(`invalid approver registration: ${row.event_id}`);
        } catch { errors.push(`invalid approver registration: ${row.event_id}`); }
      } else if (event.event_type === "tool.policy_set") {
        const toolId = String(payload.tool_id ?? "");
        if (row.source !== "foundry" || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$/.test(toolId) || ![0, 1, 2].includes(payload.risk_tier as number) || typeof payload.enabled !== "boolean" || payload.updated_at !== row.timestamp) errors.push(`invalid tool policy event: ${row.event_id}`);
      } else if (event.event_type === "approver.disabled") {
        const approverId = String(payload.approver_id ?? "");
        const publicPem = typeof payload.public_key_pem === "string" ? payload.public_key_pem : "";
        try {
          const key = createPublicKey(publicPem);
          const fingerprint = `sha256:${createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex")}`;
          const registration = this.db.sqlite.query(`SELECT payload_json FROM events
            WHERE event_type='approver.registered' AND json_extract(payload_json,'$.approver_id')=?
            AND rowid<(SELECT rowid FROM events WHERE event_id=?) ORDER BY rowid DESC LIMIT 1`).get(approverId, row.event_id) as { payload_json: string } | null;
          const registered = registration ? JSON.parse(registration.payload_json) as Record<string, unknown> : undefined;
          if (row.source !== "foundry" || !approverId || key.asymmetricKeyType !== "ed25519" || fingerprint !== payload.key_fingerprint || payload.disabled_at !== row.timestamp || registered?.approver_id !== approverId || registered.public_key_pem !== publicPem) errors.push(`invalid approver revocation: ${row.event_id}`);
        } catch { errors.push(`invalid approver revocation: ${row.event_id}`); }
      } else {
        errors.push(`unsupported ledger event type: ${row.event_id}`);
      }
      previous = row.event_hash;
    }
    const contractRows = this.db.sqlite.query("SELECT skill_id,state,contract_hash,contract_json FROM contracts ORDER BY skill_id").all() as Array<{ skill_id: string; state: "canonical" | "deprecated"; contract_hash: string; contract_json: string }>;
    if (contractRows.length !== expectedStates.size) errors.push("canonical contract count differs from promotion ledger");
    for (const contractRow of contractRows) {
      if (expectedStates.get(contractRow.skill_id) !== contractRow.state) errors.push(`contract state differs from signed events: ${contractRow.skill_id}`);
      try {
        const contract = JSON.parse(contractRow.contract_json) as SkillContract;
        if (contractHash(contract) !== contractRow.contract_hash || contract.molts_event_hash !== (this.db.sqlite.query("SELECT promoted_event_hash FROM contracts WHERE skill_id=?").get(contractRow.skill_id) as { promoted_event_hash: string }).promoted_event_hash) errors.push(`contract cache differs from signed contract: ${contractRow.skill_id}`);
      } catch { errors.push(`invalid stored contract: ${contractRow.skill_id}`); }
    }
    const expectedFts = contractRows.filter((row) => row.state === "canonical").map((row) => row.skill_id).sort();
    try {
      const actualFts = (this.db.sqlite.query("SELECT skill_id FROM skill_fts ORDER BY skill_id").all() as Array<{ skill_id: string }>).map((row) => row.skill_id);
      if (expectedFts.length !== actualFts.length || expectedFts.some((id, index) => id !== actualFts[index])) errors.push("derived skill_fts index differs from canonical contracts");
    } catch {
      errors.push("derived skill_fts index is unreadable");
    }
    errors.push(...this.verifyDerivedStats(rows));
    return { valid: errors.length === 0, events: rows.length, head_hash: previous, errors };
  }

  rebuildStats(): void {
    const integrity = this.verifyLedger().errors.filter((error) => !error.startsWith("derived "));
    if (integrity.length) throw new Error("Ledger integrity failed; derived statistics were not rebuilt");
    this.db.sqlite.transaction(() => {
      this.db.sqlite.exec("DELETE FROM skill_outcomes; DELETE FROM skill_stats;");
      this.db.sqlite.query("INSERT INTO skill_stats(skill_id,contract_hash) SELECT skill_id,contract_hash FROM contracts").run();
      const rows = this.db.sqlite.query("SELECT event_id,event_type,timestamp,payload_json FROM events WHERE event_type='skill.used' ORDER BY rowid").all() as Array<{ event_id: string; timestamp: string; payload_json: string }>;
      const balances = new Map<string, { alpha: number; beta: number; uses: number; blocked: number; unverified: number; lastOutcome: string | null; lastAt: string | null; lastEvent: string | null }>();
      const executorWeights = new Map<string, number>();
      for (const contract of this.db.sqlite.query("SELECT skill_id FROM contracts").all() as Array<{ skill_id: string }>) {
        balances.set(contract.skill_id, { alpha: 1, beta: 1, uses: 0, blocked: 0, unverified: 0, lastOutcome: null, lastAt: null, lastEvent: null });
      }
      for (const row of rows) {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        const id = String(payload.skill_id);
        const executor = String(payload.executor_agent);
        const state = balances.get(id);
        if (!state) continue;
        const outcome = payload.outcome as Outcome;
        const method = (payload.verification as { method: VerificationMethod }).method;
        const key = `${id}\u0000${executor}`;
        const prior = executorWeights.get(key) ?? 0;
        const weight = outcome === "blocked" || outcome === "unverified" ? 0 : Math.max(0, Math.min(method === "self_report" ? 0.25 : 1, this.executorWeightCap - prior));
        if (outcome !== "blocked" && outcome !== "unverified") executorWeights.set(key, prior + weight);
        if (outcome === "success") state.alpha += weight;
        else if (outcome === "failure") state.beta += weight;
        else if (outcome === "partial") { state.alpha += weight * 0.5; state.beta += weight * 0.5; }
        else if (outcome === "blocked") state.blocked++;
        else if (outcome === "unverified") state.unverified++;
        if (["success", "failure", "partial"].includes(outcome) && weight > 0) state.uses++;
        state.lastOutcome = outcome;
        state.lastAt = row.timestamp;
        state.lastEvent = row.event_id;
      }
      const update = this.db.sqlite.query("UPDATE skill_stats SET alpha=?,beta=?,uses=?,blocked=?,unverified=?,last_outcome=?,last_used_at=?,last_event_id=? WHERE skill_id=?");
      for (const [skillId, state] of balances) update.run(state.alpha, state.beta, state.uses, state.blocked, state.unverified, state.lastOutcome, state.lastAt, state.lastEvent, skillId);
      this.rebuildOutcomeTable();
    })();
    this.rebuildSearchIndex();
  }

  rebuildSearchIndex(): void {
    this.db.sqlite.transaction(() => {
      this.db.sqlite.exec("DROP TABLE IF EXISTS skill_fts; CREATE VIRTUAL TABLE skill_fts USING fts5(skill_id UNINDEXED,name,domain,description,triggers,keywords,tokenize='unicode61 remove_diacritics 2');");
      const rows = this.db.sqlite.query("SELECT contract_json FROM contracts WHERE state='canonical' ORDER BY skill_id").all() as Array<{ contract_json: string }>;
      for (const row of rows) this.indexContract(JSON.parse(row.contract_json) as SkillContract);
    })();
  }

  private rebuildOutcomeTable(): void {
    this.db.sqlite.exec("DELETE FROM skill_outcomes");
    const rows = this.db.sqlite.query("SELECT event_id,timestamp,payload_json FROM events WHERE event_type='skill.used' ORDER BY rowid").all() as Array<{ event_id: string; timestamp: string; payload_json: string }>;
    const weights = new Map<string, number>();
    const insert = this.db.sqlite.query("INSERT INTO skill_outcomes(event_id,skill_id,executor_agent,outcome,verification_method,applied_weight,occurred_at) VALUES(?,?,?,?,?,?,?)");
    for (const row of rows) {
      const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
      const skillId = String(payload.skill_id);
      const executor = String(payload.executor_agent);
      const outcome = payload.outcome as Outcome;
      const method = (payload.verification as { method: VerificationMethod }).method;
      const key = `${skillId}\u0000${executor}`;
      const prior = weights.get(key) ?? 0;
      const weight = outcome === "blocked" || outcome === "unverified" ? 0 : Math.max(0, Math.min(method === "self_report" ? 0.25 : 1, this.executorWeightCap - prior));
      if (outcome !== "blocked" && outcome !== "unverified") weights.set(key, prior + weight);
      insert.run(row.event_id, skillId, executor, outcome, method, weight, row.timestamp);
    }
  }

  private verifyDerivedStats(rows: EventRow[]): string[] {
    const expected = new Map<string, { alpha: number; beta: number; uses: number; blocked: number; unverified: number; last_outcome: string | null; last_used_at: string | null; last_event_id: string | null }>();
    const weights = new Map<string, number>();
    for (const contract of this.db.sqlite.query("SELECT skill_id FROM contracts").all() as Array<{ skill_id: string }>) {
      expected.set(contract.skill_id, { alpha: 1, beta: 1, uses: 0, blocked: 0, unverified: 0, last_outcome: null, last_used_at: null, last_event_id: null });
    }
    const expectedOutcomes: Array<{ event_id: string; skill_id: string; executor_agent: string; outcome: string; verification_method: string; applied_weight: number; occurred_at: string }> = [];
    for (const row of rows) {
      if (row.event_type !== "skill.used") continue;
      let payload: Record<string, unknown>;
      try { payload = JSON.parse(row.payload_json); } catch { continue; }
      const skillId = String(payload.skill_id);
      const executor = String(payload.executor_agent);
      const state = expected.get(skillId);
      if (!state) continue;
      const outcome = payload.outcome as Outcome;
      const method = (payload.verification as { method?: VerificationMethod } | undefined)?.method;
      if (!method) continue;
      const key = `${skillId}\u0000${executor}`;
      const prior = weights.get(key) ?? 0;
      const applied = outcome === "blocked" || outcome === "unverified" ? 0 : Math.max(0, Math.min(method === "self_report" ? 0.25 : 1, this.executorWeightCap - prior));
      if (outcome !== "blocked" && outcome !== "unverified") weights.set(key, prior + applied);
      if (outcome === "success") state.alpha += applied;
      else if (outcome === "failure") state.beta += applied;
      else if (outcome === "partial") { state.alpha += applied * 0.5; state.beta += applied * 0.5; }
      else if (outcome === "blocked") state.blocked++;
      else if (outcome === "unverified") state.unverified++;
      if (["success", "failure", "partial"].includes(outcome) && applied > 0) state.uses++;
      state.last_outcome = outcome;
      state.last_used_at = row.timestamp;
      state.last_event_id = row.event_id;
      expectedOutcomes.push({ event_id: row.event_id, skill_id: skillId, executor_agent: executor, outcome, verification_method: method, applied_weight: applied, occurred_at: row.timestamp });
    }
    const actual = this.db.sqlite.query("SELECT skill_id,alpha,beta,uses,blocked,unverified,last_outcome,last_used_at,last_event_id FROM skill_stats").all() as Array<{ skill_id: string; alpha: number; beta: number; uses: number; blocked: number; unverified: number; last_outcome: string | null; last_used_at: string | null; last_event_id: string | null }>;
    const errors: string[] = [];
    if (actual.length !== expected.size) errors.push("derived skill_stats row count differs from ledger-derived count");
    for (const row of actual) {
      const want = expected.get(row.skill_id);
      if (!want || Object.keys(want).some((key) => !sameValue(row[key as keyof typeof row], want[key as keyof typeof want]))) errors.push(`derived skill_stats mismatch: ${row.skill_id}`);
    }
    const actualOutcomes = this.db.sqlite.query("SELECT event_id,skill_id,executor_agent,outcome,verification_method,applied_weight,occurred_at FROM skill_outcomes ORDER BY rowid").all() as typeof expectedOutcomes;
    if (actualOutcomes.length !== expectedOutcomes.length) errors.push("derived skill_outcomes row count differs from ledger-derived count");
    for (let i = 0; i < Math.min(actualOutcomes.length, expectedOutcomes.length); i++) {
      const a = actualOutcomes[i];
      const b = expectedOutcomes[i];
      if (a.event_id !== b.event_id || a.skill_id !== b.skill_id || a.executor_agent !== b.executor_agent || a.outcome !== b.outcome || a.verification_method !== b.verification_method || a.occurred_at !== b.occurred_at || !sameValue(a.applied_weight, b.applied_weight)) errors.push(`derived skill_outcomes mismatch: ${a.event_id}`);
    }
    return errors;
  }

  private executorWeight(skillId: string, executor: string): number {
    const row = this.db.sqlite.query("SELECT COALESCE(SUM(applied_weight),0) AS weight FROM skill_outcomes WHERE skill_id=? AND executor_agent=? AND outcome IN ('success','failure','partial')").get(skillId, executor) as { weight: number };
    return Math.min(this.executorWeightCap, row.weight);
  }

  private checkPromotionEvent(event: SignedEvent, row: EventRow, errors: string[]): void {
    const p = event.payload;
    const contract = p.contract as SkillContract | undefined;
    if (!contract || typeof p.contract_signature !== "string" || p.contract_hash !== contractHash(contract)) {
      errors.push(`invalid promoted contract envelope: ${event.event_id}`);
      return;
    }
    if (!verifySignature(contractPayload(contract), p.contract_signature, createPublicKeyFromIdentity(this.foundry))) errors.push(`invalid contract signature: ${event.event_id}`);
    const stored = this.db.sqlite.query("SELECT contract_hash,promoted_event_id,promoted_event_hash FROM contracts WHERE skill_id=?").get(contract.id) as { contract_hash: string; promoted_event_id: string; promoted_event_hash: string } | null;
    if (!stored || stored.contract_hash !== p.contract_hash || stored.promoted_event_id !== event.event_id || stored.promoted_event_hash !== row.event_hash) errors.push(`canonical contract does not match ledger: ${event.event_id}`);
  }

  private indexContract(contract: SkillContract): void {
    this.db.sqlite.query("DELETE FROM skill_fts WHERE skill_id=?").run(contract.id);
    const hints = contract.trigger.lexical_hints.join(" ");
    this.db.sqlite.query("INSERT INTO skill_fts(skill_id,name,domain,description,triggers,keywords) VALUES(?,?,?,?,?,?)")
      .run(contract.id, contract.name, contract.domain, contract.description, contract.trigger.description, hints);
  }
}

function sameValue(a: unknown, b: unknown): boolean {
  if (typeof a === "number" && typeof b === "number") return Math.abs(a - b) < 1e-12;
  return a === b;
}

function contractPayload(contract: SkillContract): Record<string, unknown> {
  const { molts_event_hash: _hash, ...payload } = contract;
  return payload as unknown as Record<string, unknown>;
}

function createPublicKeyFromIdentity(identity: SigningIdentity) {
  return createPublicKey(identity.publicKeyPem);
}
