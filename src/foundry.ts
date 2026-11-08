import { createPublicKey, randomInt } from "node:crypto";
import { canonicalJson, contractHash, sha256 } from "./canonical";
import { newSkillId, newUlid } from "./ids";
import { SANITIZER_VERSION, extractionModelSha, sanitizeTrajectory } from "./sanitizer";
import type { PraxisDb } from "./db";
import type { Config } from "./config";
import type { SigningIdentity } from "./security";
import { verifySignature } from "./security";
import type { SkillContract, SignedEvent, RiskTier } from "./types";
import { Ledger, makeEvent } from "./ledger";
import { lintWorkflow, validateContract, verifyOutputSpec } from "./validation";

const tierTwoWatchlist = [
  /\b(?:send|transfer|wire|withdraw)\b.{0,60}\b(?:money|funds|payment|crypto|currency)\b/i,
  /\b(?:purchase|buy|sell|charge|refund|pay)\b/i,
  /\b(?:delete|erase|purge|destroy)\b.{0,60}\b(?:account|database|records?|files?|production)\b/i,
  /\b(?:external|public)\s+(?:network|internet|api|service)\b/i,
  /\b(?:credential|password|private key|secret|token)\b/i,
];

export interface ApprovalPayload {
  approval_id: string;
  contract_hash: string;
  approver_id: string;
  decision: "approve" | "reject";
  signed_at: string;
}

export interface GraduationReport {
  contract_hash: string;
  suite: string;
  run_id: string;
  passed: boolean;
  case_count: number;
  checks_passed: number;
  checks_total: number;
  timestamp: string;
  signer: string;
  signature: string;
}

interface Fixture {
  output: unknown;
  artifacts?: string[];
}

interface PreparedPromotion {
  ingest_id: string;
  contract: SkillContract;
  contract_hash: string;
  risk_tier: RiskTier;
  audit_sampled: boolean;
  fixtures_hash: string;
  required_approvals: number;
  tool_policy_snapshot: Array<{ tool_id: string; risk_tier: RiskTier; enabled: boolean }>;
  tool_policy_hash: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function approvalSignable(payload: ApprovalPayload): ApprovalPayload {
  return { ...payload };
}

function graduationSignable(report: GraduationReport): Omit<GraduationReport, "signature"> {
  const { signature: _signature, ...payload } = report;
  return payload;
}

function requiredApprovals(tier: RiskTier): number {
  return tier === 0 ? 0 : tier === 1 ? 1 : 2;
}

export class Foundry {
  constructor(
    private readonly db: PraxisDb,
    private readonly ledger: Ledger,
    private readonly identity: SigningIdentity,
    private readonly gatewayIdentity: SigningIdentity,
    private readonly config: Config,
  ) {}

  setToolPolicy(toolId: string, riskTier: RiskTier, enabled = true): void {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$/.test(toolId) || ![0, 1, 2].includes(riskTier) || typeof enabled !== "boolean") throw new Error("Invalid tool policy");
    const updatedAt = new Date().toISOString();
    const event = makeEvent(this.identity, "tool.policy_set", { tool_id: toolId, risk_tier: riskTier, enabled, updated_at: updatedAt });
    this.db.sqlite.transaction(() => {
      this.ledger.append(event, "foundry");
      this.db.sqlite.query(`INSERT INTO tool_registry(tool_id,risk_tier,enabled,updated_at) VALUES(?,?,?,?)
        ON CONFLICT(tool_id) DO UPDATE SET risk_tier=excluded.risk_tier,enabled=excluded.enabled,updated_at=excluded.updated_at`)
        .run(toolId, riskTier, enabled ? 1 : 0, updatedAt);
    })();
  }

  toolPolicies(): Map<string, { risk_tier: RiskTier; enabled: boolean }> {
    const rows = this.db.sqlite.query("SELECT tool_id,risk_tier,enabled FROM tool_registry").all() as Array<{ tool_id: string; risk_tier: RiskTier; enabled: number }>;
    return new Map(rows.map((row) => [row.tool_id, { risk_tier: row.risk_tier, enabled: row.enabled === 1 }]));
  }

  registerApprover(approverId: string, publicKeyPem: string): void {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/.test(approverId)) throw new Error("Invalid approver id");
    if (Buffer.byteLength(publicKeyPem) > 16_384) throw new Error("Approver key is too large");
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") throw new Error("Approver key must be Ed25519");
    const existing = this.db.sqlite.query("SELECT public_key_pem,enabled FROM approval_keys WHERE approver_id=?").get(approverId) as { public_key_pem: string; enabled: number } | null;
    if (existing && existing.public_key_pem !== publicKeyPem) throw new Error("Approver key is immutable; register a new approver id for key rotation");
    if (existing && existing.enabled !== 1) throw new Error("Disabled approver keys cannot be re-enabled; register a new approver id");
    const keyFingerprint = sha256(key.export({ type: "spki", format: "der" }));
    this.db.sqlite.transaction(() => {
      if (!existing) this.db.sqlite.query("INSERT INTO approval_keys(approver_id,public_key_pem,enabled,created_at) VALUES(?,?,1,?)")
        .run(approverId, publicKeyPem, new Date().toISOString());
      const anchored = this.db.sqlite.query("SELECT 1 AS found FROM events WHERE event_type='approver.registered' AND json_extract(payload_json,'$.approver_id')=? LIMIT 1").get(approverId);
      if (!anchored) {
        const event = makeEvent(this.identity, "approver.registered", { approver_id: approverId, public_key_pem: publicKeyPem, key_fingerprint: keyFingerprint });
        this.ledger.append(event, "foundry");
      }
    })();
  }

  listApprovers(): unknown[] {
    return this.db.sqlite.query("SELECT approver_id,public_key_pem,enabled,created_at FROM approval_keys ORDER BY approver_id").all();
  }

  disableApprover(approverId: string): void {
    const row = this.db.sqlite.query("SELECT public_key_pem,enabled FROM approval_keys WHERE approver_id=?").get(approverId) as { public_key_pem: string; enabled: number } | null;
    if (!row) throw new Error("Approver not found");
    if (row.enabled !== 1) return;
    const publicKey = createPublicKey(row.public_key_pem);
    const event = makeEvent(this.identity, "approver.disabled", {
      approver_id: approverId,
      public_key_pem: row.public_key_pem,
      key_fingerprint: sha256(publicKey.export({ type: "spki", format: "der" })),
      disabled_at: new Date().toISOString(),
    });
    this.db.sqlite.transaction(() => {
      this.ledger.append(event, "foundry");
      this.db.sqlite.query("UPDATE approval_keys SET enabled=0 WHERE approver_id=? AND enabled=1").run(approverId);
    })();
  }

  submitApproval(input: unknown): { approval_id: string; contract_hash: string; approver_id: string; decision: string } {
    if (!isRecord(input) || typeof input.approver_id !== "string" || typeof input.approval_id !== "string" || typeof input.contract_hash !== "string" || typeof input.decision !== "string" || typeof input.signed_at !== "string" || typeof input.signature !== "string") throw new Error("Malformed approval");
    if (!/^sha256:[0-9a-f]{64}$/.test(input.contract_hash) || !["approve", "reject"].includes(input.decision) || !validTimestamp(input.signed_at)) throw new Error("Invalid approval fields");
    const age = Date.now() - Date.parse(input.signed_at);
    if (age < -300_000 || age > 7 * 86_400_000) throw new Error("Approval timestamp is outside the allowed window");
    const row = this.db.sqlite.query("SELECT public_key_pem,enabled FROM approval_keys WHERE approver_id=?").get(input.approver_id) as { public_key_pem: string; enabled: number } | null;
    if (!row || row.enabled !== 1) throw new Error("Unknown or disabled approver");
    const approvalId = input.approval_id;
    if (!/^approval_[0-9A-HJKMNP-TV-Z]{26}$/.test(approvalId)) throw new Error("Invalid approval id");
    const payload: ApprovalPayload = { approval_id: approvalId, contract_hash: input.contract_hash, approver_id: input.approver_id, decision: input.decision as "approve" | "reject", signed_at: input.signed_at };
    if (!verifySignature(approvalSignable(payload), input.signature, createPublicKey(row.public_key_pem))) throw new Error("Invalid approver signature");
    const prior = this.db.sqlite.query("SELECT approval_id,decision,signed_at,signature FROM approvals WHERE contract_hash=? AND approver_id=?").get(payload.contract_hash, payload.approver_id) as { approval_id: string; decision: string; signed_at: string; signature: string } | null;
    if (prior) {
      if (prior.approval_id === payload.approval_id && prior.decision === payload.decision && prior.signed_at === payload.signed_at && prior.signature === input.signature) return { approval_id: prior.approval_id, contract_hash: payload.contract_hash, approver_id: payload.approver_id, decision: prior.decision };
      throw new Error("An approver may submit only one immutable decision per contract hash");
    }
    this.db.sqlite.query("INSERT INTO approvals(approval_id,contract_hash,approver_id,decision,signed_at,signature) VALUES(?,?,?,?,?,?)")
      .run(approvalId, payload.contract_hash, payload.approver_id, payload.decision, payload.signed_at, input.signature);
    return { approval_id: approvalId, contract_hash: payload.contract_hash, approver_id: payload.approver_id, decision: payload.decision };
  }

  prepare(ingestId: string, fixtures: Fixture[], approverIds: string[] = []): PreparedPromotion {
    const row = this.db.sqlite.query("SELECT state,flags_json,draft_json,trajectory_hash FROM ingest_records WHERE ingest_id=?").get(ingestId) as { state: string; flags_json: string; draft_json: string | null; trajectory_hash: string } | null;
    if (!row || row.state !== "draft" || !row.draft_json) throw new Error("Ingest record is not an available draft");
    const flags = JSON.parse(row.flags_json) as string[];
    if (flags.length) throw new Error("Draft has unresolved sanitizer flags and is quarantined");
    let contract = JSON.parse(row.draft_json) as SkillContract;
    const initial = validateContract(contract);
    if (!initial.valid) throw new Error(`Draft contract is invalid: ${initial.errors.join("; ")}`);
    if (!contract.provenance.trajectory_hashes.includes(row.trajectory_hash)) throw new Error("Draft provenance does not bind the sanitized trajectory");

    const policies = this.toolPolicies();
    const lint = lintWorkflow(contract.workflow, policies);
    if (!lint.valid) throw new Error(`Workflow lint failed: ${lint.errors.join("; ")}`);
    const toolIds = [...new Set(contract.workflow.map((step) => step.tool_id))].sort();
    const toolPolicySnapshot = toolIds.map((toolId) => {
      const policy = policies.get(toolId);
      if (!policy || !policy.enabled) throw new Error("Workflow tool policy disappeared during promotion");
      return { tool_id: toolId, risk_tier: policy.risk_tier, enabled: policy.enabled };
    });
    const toolPolicyHash = sha256(canonicalJson(toolPolicySnapshot));
    const text = contract.workflow.map((step) => `${step.action} ${JSON.stringify(step.input ?? {})}`).join("\n");
    const forbiddenMatches = contract.forbidden_actions.filter((phrase) => phrase && text.toLowerCase().includes(phrase.toLowerCase()));
    if (forbiddenMatches.length) throw new Error(`Workflow matches forbidden actions: ${forbiddenMatches.join(", ")}`);
    const watchlisted = tierTwoWatchlist.some((pattern) => pattern.test(text));
    const computedTier = Math.max(contract.risk_tier, lint.riskTier, watchlisted ? 2 : 0) as RiskTier;
    const required = requiredApprovals(computedTier);
    const uniqueApprovers = [...new Set(approverIds)].sort();
    if (uniqueApprovers.length !== approverIds.length || uniqueApprovers.length < required || uniqueApprovers.length > 32) throw new Error(`Risk tier ${computedTier} requires ${required} distinct approver(s)`);
    for (const approverId of uniqueApprovers) {
      const approver = this.db.sqlite.query("SELECT enabled FROM approval_keys WHERE approver_id=?").get(approverId) as { enabled: number } | null;
      if (!approver || approver.enabled !== 1) throw new Error(`Unknown or disabled approver: ${approverId}`);
    }
    if (fixtures.length < 1 || fixtures.length > 100) throw new Error("At least one and at most 100 output-spec fixtures are required");
    const fixtureErrors: string[] = [];
    let checkCount = 0;
    fixtures.forEach((fixture, i) => {
      if (!isRecord(fixture) || !Array.isArray(fixture.artifacts ?? [])) {
        fixtureErrors.push(`fixture ${i + 1} is malformed`);
        return;
      }
      const result = verifyOutputSpec(contract.output_spec, fixture.output, (fixture.artifacts ?? []) as string[]);
      checkCount += result.checks_total;
      if (!result.passed) fixtureErrors.push(`fixture ${i + 1}: ${result.errors.join(", ")}`);
    });
    if (checkCount < 1) throw new Error("Output spec must contain at least one machine-checkable check");
    if (fixtureErrors.length) throw new Error(`Evaluation fixtures failed: ${fixtureErrors.join("; ")}`);

    const suites = ["output-spec-fixtures-v1"];
    if (computedTier === 2) suites.push("t340-graduation-v1");
    contract = {
      ...contract,
      agentbook_state: "canonical",
      risk_tier: computedTier,
      provenance: { ...contract.provenance, eval_suites: suites, human_approvers: uniqueApprovers },
    };
    if (contract.supersedes) {
      const superseded = this.db.sqlite.query("SELECT state FROM contracts WHERE skill_id=?").get(contract.supersedes) as { state: string } | null;
      if (!superseded || superseded.state !== "canonical") throw new Error("supersedes must reference a currently canonical skill");
    }
    const validation = validateContract(contract);
    if (!validation.valid) throw new Error(`Prepared contract is invalid: ${validation.errors.join("; ")}`);
    return {
      ingest_id: ingestId,
      contract,
      contract_hash: contractHash(contract),
      risk_tier: computedTier,
      audit_sampled: computedTier === 0 && randomInt(0, 1_000_000) / 1_000_000 < this.config.tier0AuditRate,
      fixtures_hash: sha256(canonicalJson(fixtures)),
      required_approvals: required,
      tool_policy_snapshot: toolPolicySnapshot,
      tool_policy_hash: toolPolicyHash,
    };
  }

  promote(ingestId: string, fixtures: Fixture[], approverIds: string[] = [], graduation?: GraduationReport): { skill_id: string; contract_hash: string; event_hash: string; risk_tier: RiskTier; audit_queued: boolean } {
    const prepared = this.prepare(ingestId, fixtures, approverIds);
    const approvals = this.db.sqlite.query("SELECT approval_id,contract_hash,approver_id,decision,signed_at,signature FROM approvals WHERE contract_hash=? ORDER BY approver_id")
      .all(prepared.contract_hash) as Array<{ approval_id: string; contract_hash: string; approver_id: string; decision: string; signed_at: string; signature: string }>;
    const approvalById = new Map(approvals.map((approval) => [approval.approver_id, approval]));
    for (const approverId of approverIds) {
      const approval = approvalById.get(approverId);
      if (!approval || approval.decision !== "approve") throw new Error(`Missing approval from ${approverId}`);
    }
    if (prepared.risk_tier === 2) this.verifyGraduation(graduation, prepared.contract_hash);

    const approvalEvidence = approvals.filter((approval) => approverIds.includes(approval.approver_id)).map((approval) => {
      const key = this.db.sqlite.query("SELECT public_key_pem,enabled FROM approval_keys WHERE approver_id=?").get(approval.approver_id) as { public_key_pem: string; enabled: number } | null;
      if (!key || key.enabled !== 1) throw new Error(`Approver is disabled: ${approval.approver_id}`);
      return { ...approval, public_key_pem: key.public_key_pem };
    });
    const contractSignature = this.identity.sign(contractPayload(prepared.contract));
    const event = makeEvent(this.identity, "skill.promoted", {
      contract: prepared.contract,
      contract_hash: prepared.contract_hash,
      contract_signature: contractSignature,
      eval_fixtures_hash: prepared.fixtures_hash,
      tool_policy_snapshot: prepared.tool_policy_snapshot,
      tool_policy_hash: prepared.tool_policy_hash,
      approvals: approvalEvidence,
      ...(graduation ? { graduation_report: graduation } : {}),
    });
    const appended = this.ledger.promote(prepared.contract, contractSignature, event);
    this.db.sqlite.query("UPDATE ingest_records SET state='submitted',reviewed_by=COALESCE(reviewed_by,?),review_event_id=COALESCE(review_event_id,?) WHERE ingest_id=? AND state='draft'")
      .run(approverIds.join(",") || "foundry-auto", event.event_id, ingestId);
    if (prepared.audit_sampled) {
      this.db.sqlite.query("INSERT OR IGNORE INTO tier0_audit_queue(skill_id,contract_hash,queued_at,state) VALUES(?,?,?,'pending')")
        .run(prepared.contract.id, prepared.contract_hash, new Date().toISOString());
    }
    return { skill_id: prepared.contract.id, contract_hash: prepared.contract_hash, event_hash: appended.event_hash, risk_tier: prepared.risk_tier, audit_queued: prepared.audit_sampled };
  }

  private toolPolicySnapshot(contract: SkillContract): Array<{ tool_id: string; risk_tier: RiskTier; enabled: boolean }> {
    const policies = this.toolPolicies();
    const toolIds = [...new Set(contract.workflow.map((step) => step.tool_id))].sort();
    return toolIds.map((toolId) => {
      const policy = policies.get(toolId);
      if (!policy) throw new Error("Workflow tool policy disappeared during promotion");
      return { tool_id: toolId, risk_tier: policy.risk_tier, enabled: policy.enabled };
    });
  }

  private verifyGraduation(report: GraduationReport | undefined, expectedHash: string): void {
    if (!report || !report.passed || report.contract_hash !== expectedHash || report.suite !== "t340-graduation-v1" || !Number.isInteger(report.case_count) || report.case_count < 3 || !Number.isInteger(report.checks_total) || report.checks_total < 3 || report.checks_passed !== report.checks_total || !validTimestamp(report.timestamp)) throw new Error("Tier 2 promotion requires a passing signed T340 graduation report with at least three cases");
    if (Date.now() - Date.parse(report.timestamp) > 7 * 86_400_000 || Date.parse(report.timestamp) > Date.now() + 300_000) throw new Error("T340 graduation report is stale");
    if (report.signer !== this.gatewayIdentity.fingerprint || !verifySignature(graduationSignable(report), report.signature, createPublicKey(this.gatewayIdentity.publicKeyPem))) throw new Error("Invalid T340 graduation signature");
  }

  reviewQuarantine(ingestId: string, value: unknown): { review_id: string; event_id: string; event_hash: string; ingest_id: string; decision: "release" | "reject"; state: string; reviewed_trajectory_hash: string | null; candidate_hash: string | null } {
    if (!isRecord(value)) throw new Error("Quarantine review must be an object");
    const row = this.db.sqlite.query("SELECT state,trajectory_hash,sanitized_trajectory FROM ingest_records WHERE ingest_id=?").get(ingestId) as { state: string; trajectory_hash: string; sanitized_trajectory: string } | null;
    if (!row || row.state !== "quarantined") throw new Error("Ingest record is not quarantined");
    const reviewId = typeof value.review_id === "string" ? value.review_id : "";
    const approverId = typeof value.approver_id === "string" ? value.approver_id : "";
    const decision = value.decision;
    const notes = typeof value.notes === "string" ? value.notes : "";
    const signedAt = typeof value.signed_at === "string" ? value.signed_at : "";
    const signature = typeof value.signature === "string" ? value.signature : "";
    if (!/^review_[0-9A-HJKMNP-TV-Z]{26}$/.test(reviewId) || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/.test(approverId) || (decision !== "release" && decision !== "reject") || notes.length > 1000 || !validTimestamp(signedAt)) throw new Error("Invalid quarantine review fields");
    const age = Date.now() - Date.parse(signedAt);
    if (age < -300_000 || age > 7 * 86_400_000) throw new Error("Quarantine review timestamp is outside the allowed window");
    const sanitizedNotes = sanitizeTrajectory(notes, 4096);
    if (sanitizedNotes.redacted || sanitizedNotes.quarantined) throw new Error("Quarantine review notes must not contain secrets, PII, or embedded instructions");
    const approver = this.db.sqlite.query("SELECT public_key_pem,enabled FROM approval_keys WHERE approver_id=?").get(approverId) as { public_key_pem: string; enabled: number } | null;
    if (!approver || approver.enabled !== 1) throw new Error("Unknown or disabled approver");

    let reviewedHash: string | null = null;
    let candidateHash: string | null = null;
    let reviewedTrajectory: string | null = null;
    let reviewedCandidateJson: string | null = null;
    let contract: SkillContract | null = null;
    let reviewFlags: string[] = [];
    const reviewCandidateHash = value.candidate_hash;
    const reviewTrajectoryHash = value.reviewed_trajectory_hash;
    if (decision === "release") {
      if (typeof value.reviewed_trajectory !== "string" || !isRecord(value.candidate)) throw new Error("Release requires a reviewed trajectory and a structured candidate");
      const reviewed = sanitizeTrajectory(value.reviewed_trajectory, this.config.maxBodyBytes);
      if (reviewed.quarantined) throw new Error("Reviewed trajectory still contains flagged instructions");
      reviewFlags = [...reviewed.flags];
      reviewedHash = reviewed.hash;
      reviewedTrajectory = reviewed.content;
      const sanitizedCandidate = sanitizeTrajectory(canonicalJson(value.candidate), this.config.maxBodyBytes);
      if (sanitizedCandidate.quarantined) throw new Error("Reviewed candidate contains flagged instructions");
      reviewedCandidateJson = sanitizedCandidate.content;
      reviewFlags = [...new Set([...reviewFlags, ...sanitizedCandidate.flags])];
      candidateHash = sha256(sanitizedCandidate.content);
      if (reviewTrajectoryHash !== reviewedHash || reviewCandidateHash !== candidateHash) throw new Error("Reviewed hashes do not match the submitted materials");
      const source = JSON.parse(sanitizedCandidate.content) as Record<string, unknown>;
      const sourceProvenance = isRecord(source.provenance) ? source.provenance : {};
      contract = {
        ...source,
        id: newSkillId(),
        schema_version: "skill-contract-v1",
        agentbook_state: "draft",
        risk_tier: source.risk_tier === 1 || source.risk_tier === 2 ? source.risk_tier : 0,
        provenance: {
          trajectory_hashes: [...new Set([row.trajectory_hash, reviewedHash])],
          extraction_model_sha: extractionModelSha(),
          sanitizer_version: SANITIZER_VERSION,
          evidence_refs: Array.isArray(sourceProvenance.evidence_refs) ? sourceProvenance.evidence_refs : [],
          eval_suites: [],
          human_approvers: [],
        },
      } as unknown as SkillContract;
      delete contract.molts_event_hash;
      const validation = validateContract(contract);
      if (!validation.valid) throw new Error(`Reviewed candidate is invalid: ${validation.errors.join("; ")}`);
      const lint = lintWorkflow(contract.workflow, this.toolPolicies(), contract.forbidden_actions);
      if (!lint.valid) throw new Error("Reviewed workflow failed the tool-risk and protected-state checks");
      const workflowText = contract.workflow.map((step) => `${step.action} ${JSON.stringify(step.input ?? {})}`).join("\n");
      const watchlisted = tierTwoWatchlist.some((pattern) => pattern.test(workflowText));
      contract.risk_tier = Math.max(contract.risk_tier, lint.riskTier, watchlisted ? 2 : 0) as RiskTier;
      if (sanitizedCandidate.redacted || reviewed.redacted) contract.provenance.sanitizer_version = SANITIZER_VERSION;
    } else if (reviewTrajectoryHash !== null && reviewTrajectoryHash !== undefined || reviewCandidateHash !== null && reviewCandidateHash !== undefined) {
      throw new Error("Rejected reviews must not include replacement materials");
    }

    const signable = {
      review_id: reviewId,
      ingest_id: ingestId,
      trajectory_hash: row.trajectory_hash,
      reviewed_trajectory_hash: reviewedHash,
      candidate_hash: candidateHash,
      approver_id: approverId,
      decision,
      notes,
      signed_at: signedAt,
    };
    if (!verifySignature(signable, signature, createPublicKey(approver.public_key_pem))) throw new Error("Invalid quarantine-review signature");
    const event = makeEvent(this.identity, "skill.quarantine_reviewed", {
      ...signable,
      review_signature: signature,
      approver_public_key_pem: approver.public_key_pem,
    });
    let ledgerEventHash = "";
    const nextState = decision === "release" ? "draft" : "rejected";
    this.db.sqlite.transaction(() => {
      ledgerEventHash = this.ledger.append(event, "foundry").event_hash;
      this.db.sqlite.query(`INSERT INTO quarantine_reviews(review_id,ledger_event_id,ingest_id,trajectory_hash,reviewed_trajectory_hash,candidate_hash,original_sanitized_trajectory,reviewed_candidate_json,approver_id,decision,notes,signed_at,signature)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(reviewId, event.event_id, ingestId, row.trajectory_hash, reviewedHash, candidateHash, row.sanitized_trajectory, reviewedCandidateJson, approverId, decision, notes, signedAt, signature);
      const update = this.db.sqlite.query("UPDATE ingest_records SET state=?,flags_json=?,sanitized_trajectory=?,draft_json=?,reviewed_by=?,review_event_id=? WHERE ingest_id=? AND state='quarantined'")
        .run(nextState, canonicalJson(reviewFlags), reviewedTrajectory ?? row.sanitized_trajectory, contract ? canonicalJson(contract) : null, approverId, event.event_id, ingestId);
      if (update.changes !== 1) throw new Error("Quarantine state changed while the review was being recorded");
    })();
    return { review_id: reviewId, event_id: event.event_id, event_hash: ledgerEventHash, ingest_id: ingestId, decision, state: nextState, reviewed_trajectory_hash: reviewedHash, candidate_hash: candidateHash };
  }

  deprecate(skillId: string, reason: string): { event_hash: string; duplicate: boolean } {
    const contract = this.db.sqlite.query("SELECT contract_hash,state FROM contracts WHERE skill_id=?").get(skillId) as { contract_hash: string; state: string } | null;
    if (!contract || contract.state !== "canonical") throw new Error("Skill is not canonical");
    const event = makeEvent(this.identity, "skill.deprecated", { skill_id: skillId, contract_hash: contract.contract_hash, reason: reason.slice(0, 1000) });
    return this.ledger.deprecate(skillId, reason.slice(0, 1000), event);
  }

  listDrafts(limit = 100): unknown[] {
    const rows = this.db.sqlite.query("SELECT ingest_id,source_agent_id,trajectory_hash,state,flags_json,draft_json,created_at FROM ingest_records WHERE state='draft' AND draft_json IS NOT NULL ORDER BY created_at DESC LIMIT ?")
      .all(Math.max(1, Math.min(500, limit))) as Array<{ ingest_id: string; source_agent_id: string; trajectory_hash: string; state: string; flags_json: string; draft_json: string; created_at: string }>;
    return rows.map((row) => ({ ...row, flags: JSON.parse(row.flags_json), contract: JSON.parse(row.draft_json) }));
  }

  verify(): ReturnType<Ledger["verifyLedger"]> {
    const base = this.ledger.verifyLedger();
    const errors = [...base.errors];
    const policyRows = this.db.sqlite.query("SELECT event_id,payload_json FROM events WHERE event_type='tool.policy_set' ORDER BY rowid").all() as Array<{ event_id: string; payload_json: string }>;
    const expectedPolicies = new Map<string, { risk_tier: RiskTier; enabled: boolean }>();
    for (const row of policyRows) {
      try {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        if (typeof payload.tool_id !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$/.test(payload.tool_id) || ![0, 1, 2].includes(payload.risk_tier as number) || typeof payload.enabled !== "boolean" || typeof payload.updated_at !== "string" || !validTimestamp(payload.updated_at)) throw new Error("invalid policy");
        expectedPolicies.set(payload.tool_id, { risk_tier: payload.risk_tier as RiskTier, enabled: payload.enabled });
      } catch {
        errors.push(`invalid tool policy event: ${row.event_id}`);
      }
    }
    const actualPolicies = new Map((this.db.sqlite.query("SELECT tool_id,risk_tier,enabled FROM tool_registry").all() as Array<{ tool_id: string; risk_tier: RiskTier; enabled: number }>).map((row) => [row.tool_id, { risk_tier: row.risk_tier, enabled: row.enabled === 1 }]));
    for (const [toolId, policy] of expectedPolicies) {
      const actual = actualPolicies.get(toolId);
      if (!actual || actual.risk_tier !== policy.risk_tier || actual.enabled !== policy.enabled) errors.push(`derived tool registry mismatch: ${toolId}`);
    }
    for (const toolId of actualPolicies.keys()) if (!expectedPolicies.has(toolId)) errors.push(`derived tool registry contains unanchored policy: ${toolId}`);
    const registeredRows = this.db.sqlite.query("SELECT event_id,payload_json FROM events WHERE event_type='approver.registered' ORDER BY rowid").all() as Array<{ event_id: string; payload_json: string }>;
    const registered = new Map<string, string>();
    for (const row of registeredRows) {
      try {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        if (typeof payload.approver_id !== "string" || typeof payload.public_key_pem !== "string" || typeof payload.key_fingerprint !== "string") throw new Error("bad key registration");
        const publicKey = createPublicKey(payload.public_key_pem);
        const fingerprint = sha256(publicKey.export({ type: "spki", format: "der" }));
        const stored = this.db.sqlite.query("SELECT public_key_pem FROM approval_keys WHERE approver_id=?").get(payload.approver_id) as { public_key_pem: string } | null;
        if (publicKey.asymmetricKeyType !== "ed25519" || fingerprint !== payload.key_fingerprint || !stored || stored.public_key_pem !== payload.public_key_pem) throw new Error("key registration mismatch");
        const prior = registered.get(payload.approver_id);
        if (prior && prior !== payload.public_key_pem) throw new Error("approver key changed");
        registered.set(payload.approver_id, payload.public_key_pem);
      } catch {
        errors.push(`invalid approver registration: ${row.event_id}`);
      }
    }
    const revoked = new Set<string>();
    for (const row of this.db.sqlite.query("SELECT event_id,payload_json FROM events WHERE event_type='approver.disabled' ORDER BY rowid").all() as Array<{ event_id: string; payload_json: string }>) {
      try {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        const publicKeyPem = registered.get(String(payload.approver_id));
        const publicKey = createPublicKey(String(payload.public_key_pem));
        const fingerprint = sha256(publicKey.export({ type: "spki", format: "der" }));
        if (!publicKeyPem || publicKeyPem !== payload.public_key_pem || fingerprint !== payload.key_fingerprint || typeof payload.disabled_at !== "string" || !validTimestamp(payload.disabled_at) || revoked.has(String(payload.approver_id))) throw new Error("invalid key revocation");
        revoked.add(String(payload.approver_id));
      } catch {
        errors.push(`invalid approver revocation: ${row.event_id}`);
      }
    }
    for (const [approverId, publicKeyPem] of registered) {
      const stored = this.db.sqlite.query("SELECT public_key_pem,enabled FROM approval_keys WHERE approver_id=?").get(approverId) as { public_key_pem: string; enabled: number } | null;
      if (!stored || stored.public_key_pem !== publicKeyPem || stored.enabled !== (revoked.has(approverId) ? 0 : 1)) errors.push(`derived approval registry mismatch: ${approverId}`);
    }
    for (const row of this.db.sqlite.query("SELECT approver_id,enabled FROM approval_keys").all() as Array<{ approver_id: string; enabled: number }>) {
      if (!registered.has(row.approver_id) && row.enabled !== 0) errors.push(`derived approval registry contains unanchored key: ${row.approver_id}`);
    }
    const eventRows = this.db.sqlite.query("SELECT event_id,event_type,payload_json FROM events WHERE event_type='skill.promoted' ORDER BY rowid").all() as Array<{ event_id: string; event_type: string; payload_json: string }>;
    for (const row of eventRows) {
      try {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        const contract = payload.contract as SkillContract;
        this.verifyPromotionAttestations(payload, contract, row.event_id);
      } catch {
        errors.push(`invalid promotion attestations: ${row.event_id}`);
      }
    }
    const reviews = this.db.sqlite.query(`SELECT review_id,ledger_event_id,ingest_id,trajectory_hash,reviewed_trajectory_hash,candidate_hash,reviewed_candidate_json,original_sanitized_trajectory,approver_id,decision,notes,signed_at,signature
      FROM quarantine_reviews ORDER BY rowid`).all() as Array<Record<string, unknown>>;
    for (const review of reviews) {
      try {
        const source = this.db.sqlite.query("SELECT trajectory_hash,state,sanitized_trajectory,review_event_id FROM ingest_records WHERE ingest_id=?").get(String(review.ingest_id)) as { trajectory_hash: string; state: string; sanitized_trajectory: string; review_event_id: string | null } | null;
        const key = this.db.sqlite.query("SELECT public_key_pem FROM approval_keys WHERE approver_id=?").get(String(review.approver_id)) as { public_key_pem: string } | null;
        const original = sanitizeTrajectory(String(review.original_sanitized_trajectory), this.config.maxBodyBytes);
        const rejected = review.decision === "reject";
        const reviewedHash = rejected ? null : review.reviewed_trajectory_hash;
        const candidateHash = rejected ? null : review.candidate_hash;
        if (!source || !key || !this.hasLedgerApproverKey(String(review.approver_id), key.public_key_pem) || source.trajectory_hash !== review.trajectory_hash || original.hash !== review.trajectory_hash || source.review_event_id !== review.ledger_event_id || (rejected && source.state !== "rejected") || (!rejected && !["draft", "submitted"].includes(source.state))) throw new Error("review source mismatch");
        if (!rejected) {
          const reviewed = sanitizeTrajectory(source.sanitized_trajectory, this.config.maxBodyBytes);
          const candidateJson = String(review.reviewed_candidate_json ?? "");
          const parsedCandidate = JSON.parse(candidateJson);
          if (reviewed.hash !== reviewedHash || sha256(candidateJson) !== candidateHash || canonicalJson(parsedCandidate) !== candidateJson) throw new Error("reviewed content mismatch");
        } else if (review.reviewed_trajectory_hash !== null || review.candidate_hash !== null || review.reviewed_candidate_json !== null) throw new Error("rejected review has replacement material");
        const signable = {
          review_id: review.review_id,
          ingest_id: review.ingest_id,
          trajectory_hash: review.trajectory_hash,
          reviewed_trajectory_hash: reviewedHash,
          candidate_hash: candidateHash,
          approver_id: review.approver_id,
          decision: review.decision,
          notes: review.notes,
          signed_at: review.signed_at,
        };
        const ledgerReview = this.db.sqlite.query("SELECT payload_json FROM events WHERE event_id=? AND event_type='skill.quarantine_reviewed'").get(String(review.ledger_event_id)) as { payload_json: string } | null;
        const expectedLedgerPayload = { ...signable, review_signature: review.signature, approver_public_key_pem: key.public_key_pem };
        if (!ledgerReview || canonicalJson(JSON.parse(ledgerReview.payload_json)) !== canonicalJson(expectedLedgerPayload)) throw new Error("review ledger event mismatch");
        if (!validTimestamp(review.signed_at) || !verifySignature(signable, String(review.signature), createPublicKey(key.public_key_pem))) throw new Error("invalid review signature");
      } catch {
        errors.push(`invalid quarantine review: ${String(review.review_id)}`);
      }
    }
    return { ...base, valid: errors.length === 0, errors };
  }

  private hasLedgerApproverKey(approverId: string, publicKeyPem: string): boolean {
    const rows = this.db.sqlite.query("SELECT payload_json FROM events WHERE event_type='approver.registered' ORDER BY rowid").all() as Array<{ payload_json: string }>;
    return rows.some((row) => {
      try {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        return payload.approver_id === approverId && payload.public_key_pem === publicKeyPem;
      } catch {
        return false;
      }
    });
  }

  private toolPoliciesBefore(eventId: string): Map<string, { risk_tier: RiskTier; enabled: boolean }> {
    const rows = this.db.sqlite.query(`SELECT payload_json FROM events
      WHERE event_type='tool.policy_set' AND rowid<(SELECT rowid FROM events WHERE event_id=?) ORDER BY rowid`).all(eventId) as Array<{ payload_json: string }>;
    const policies = new Map<string, { risk_tier: RiskTier; enabled: boolean }>();
    for (const row of rows) {
      const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
      if (typeof payload.tool_id !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$/.test(payload.tool_id) || ![0, 1, 2].includes(payload.risk_tier as number) || typeof payload.enabled !== "boolean" || typeof payload.updated_at !== "string" || !validTimestamp(payload.updated_at)) throw new Error("Invalid tool policy ledger event");
      policies.set(payload.tool_id, { risk_tier: payload.risk_tier as RiskTier, enabled: payload.enabled });
    }
    return policies;
  }

  private verifyPromotionAttestations(payload: Record<string, unknown>, contract: SkillContract, eventId: string): void {
    const tier = contract.risk_tier;
    const approvals = Array.isArray(payload.approvals) ? payload.approvals : [];
    const expectedApprovers = contract.provenance.human_approvers;
    const seen = new Set<string>();
    for (const raw of approvals) {
      if (!isRecord(raw) || typeof raw.public_key_pem !== "string") throw new Error(`invalid approval in ${eventId}`);
      const approval: ApprovalPayload = {
        approval_id: String(raw.approval_id),
        contract_hash: String(raw.contract_hash),
        approver_id: String(raw.approver_id),
        decision: raw.decision as "approve" | "reject",
        signed_at: String(raw.signed_at),
      };
      if (!/^approval_[0-9A-HJKMNP-TV-Z]{26}$/.test(approval.approval_id) || approval.contract_hash !== contractHash(contract) || approval.decision !== "approve" || !validTimestamp(approval.signed_at) || seen.has(approval.approver_id)) throw new Error(`invalid approval fields in ${eventId}`);
      const publicKey = createPublicKey(raw.public_key_pem);
      if (publicKey.asymmetricKeyType !== "ed25519" || !this.hasLedgerApproverKey(approval.approver_id, raw.public_key_pem) || !verifySignature(approvalSignable(approval), String(raw.signature), publicKey)) throw new Error(`invalid approval signature in ${eventId}`);
      seen.add(approval.approver_id);
    }
    const required = requiredApprovals(tier);
    if (seen.size < required || expectedApprovers.length !== seen.size || expectedApprovers.some((id) => !seen.has(id))) throw new Error(`approval count mismatch in ${eventId}`);
    const snapshot = payload.tool_policy_snapshot;
    if (!Array.isArray(snapshot) || typeof payload.tool_policy_hash !== "string" || sha256(canonicalJson(snapshot)) !== payload.tool_policy_hash) throw new Error(`tool policy commitment missing in ${eventId}`);
    const toolIds = [...new Set(contract.workflow.map((step) => step.tool_id))].sort();
    if (snapshot.length !== toolIds.length) throw new Error(`tool policy snapshot size mismatch in ${eventId}`);
    const historicalPolicies = this.toolPoliciesBefore(eventId);
    let maximumRisk: RiskTier = 0;
    for (let i = 0; i < snapshot.length; i++) {
      const item = snapshot[i];
      if (!isRecord(item) || item.tool_id !== toolIds[i] || ![0, 1, 2].includes(item.risk_tier as number) || item.enabled !== true) throw new Error(`invalid tool policy snapshot in ${eventId}`);
      const historical = historicalPolicies.get(item.tool_id as string);
      if (!historical || !historical.enabled || historical.risk_tier !== item.risk_tier) throw new Error(`tool policy snapshot does not match ledger history in ${eventId}`);
      maximumRisk = Math.max(maximumRisk, historical.risk_tier) as RiskTier;
    }
    const workflowText = contract.workflow.map((step) => `${step.action} ${JSON.stringify(step.input ?? {})}`).join("\n");
    if (contract.forbidden_actions.some((phrase) => phrase && workflowText.toLowerCase().includes(phrase.toLowerCase()))) throw new Error(`forbidden action present in ${eventId}`);
    const watchlisted = tierTwoWatchlist.some((pattern) => pattern.test(workflowText));
    if (contract.risk_tier < Math.max(maximumRisk, watchlisted ? 2 : 0)) throw new Error(`risk tier is below the verified tool policy in ${eventId}`);
    if (tier === 2) this.verifyGraduation(payload.graduation_report as GraduationReport | undefined, contractHash(contract));
    if (typeof payload.eval_fixtures_hash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(payload.eval_fixtures_hash)) throw new Error(`evaluation fixture commitment missing in ${eventId}`);
  }

  rebuild(): void {
    const verification = this.verify();
    const nonDerivedErrors = verification.errors.filter((error) => !error.startsWith("derived "));
    if (nonDerivedErrors.length) throw new Error("Cannot rebuild derived data from an invalid signed ledger");
    const policyRows = this.db.sqlite.query("SELECT payload_json FROM events WHERE event_type='tool.policy_set' ORDER BY rowid").all() as Array<{ payload_json: string }>;
    const policies = new Map<string, { risk_tier: RiskTier; enabled: boolean; updated_at: string }>();
    for (const row of policyRows) {
      const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
      policies.set(String(payload.tool_id), { risk_tier: payload.risk_tier as RiskTier, enabled: payload.enabled as boolean, updated_at: String(payload.updated_at) });
    }
    const registrations = this.db.sqlite.query("SELECT timestamp,payload_json FROM events WHERE event_type='approver.registered' ORDER BY rowid").all() as Array<{ timestamp: string; payload_json: string }>;
    const keys = new Map<string, { public_key_pem: string; created_at: string; enabled: boolean }>();
    for (const row of registrations) {
      const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
      keys.set(String(payload.approver_id), { public_key_pem: String(payload.public_key_pem), created_at: row.timestamp, enabled: true });
    }
    const revocations = this.db.sqlite.query("SELECT payload_json FROM events WHERE event_type='approver.disabled' ORDER BY rowid").all() as Array<{ payload_json: string }>;
    for (const row of revocations) {
      const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
      const key = keys.get(String(payload.approver_id));
      if (key) key.enabled = false;
    }
    this.db.sqlite.transaction(() => {
      this.db.sqlite.query("DELETE FROM tool_registry").run();
      for (const [toolId, policy] of policies) this.db.sqlite.query("INSERT INTO tool_registry(tool_id,risk_tier,enabled,updated_at) VALUES(?,?,?,?)")
        .run(toolId, policy.risk_tier, policy.enabled ? 1 : 0, policy.updated_at);
      for (const [approverId, key] of keys) this.db.sqlite.query(`INSERT INTO approval_keys(approver_id,public_key_pem,enabled,created_at) VALUES(?,?,?,?)
        ON CONFLICT(approver_id) DO UPDATE SET public_key_pem=excluded.public_key_pem,enabled=excluded.enabled,created_at=excluded.created_at`)
        .run(approverId, key.public_key_pem, key.enabled ? 1 : 0, key.created_at);
      this.db.sqlite.query("UPDATE approval_keys SET enabled=0 WHERE approver_id NOT IN (SELECT approver_id FROM events, json_each(events.payload_json) WHERE events.event_type='approver.registered' AND json_each.key='approver_id')").run();
    })();
    this.ledger.rebuildStats();
    const after = this.verify();
    if (!after.valid) throw new Error("Derived data rebuild did not restore a valid state");
  }

}

function contractPayload(contract: SkillContract): Record<string, unknown> {
  const { molts_event_hash: _hash, ...payload } = contract;
  return payload as unknown as Record<string, unknown>;
}
