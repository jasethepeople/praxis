import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical";
import { newUlid, newSkillId } from "./ids";
import type { Config } from "./config";
import type { PraxisDb } from "./db";
import { callMinerSidecar, mineStructuredTrajectory } from "./miner";
import { extractionModelSha, sanitizeTrajectory } from "./sanitizer";
import { lintWorkflow, validateContract } from "./validation";
import type { RiskTier, SkillContract } from "./types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function toolPolicies(db: PraxisDb): Map<string, { risk_tier: RiskTier; enabled: boolean }> {
  const rows = db.sqlite.query("SELECT tool_id,risk_tier,enabled FROM tool_registry").all() as Array<{ tool_id: string; risk_tier: RiskTier; enabled: number }>;
  return new Map(rows.map((row) => [row.tool_id, { risk_tier: row.risk_tier, enabled: row.enabled === 1 }]));
}

function verifiedEvidenceRefs(db: PraxisDb, value: unknown): Array<Record<string, unknown>> | undefined {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > 128 || !value.every(isRecord)) return undefined;
  const allowedSources = new Set(["openalex", "crossref", "unpaywall", "arxiv", "github", "nvd", "exploit_db", "annas_metadata", "local"]);
  const cached = new Map<string, Set<string>>();
  for (const ref of value) {
    if (typeof ref.source !== "string" || !allowedSources.has(ref.source)) return undefined;
    if (ref.source === "local") {
      if (ref.access !== "local" || typeof ref.content_sha256 !== "string" || !/^sha256:[0-9a-f]{64}$/.test(ref.content_sha256) || ref.url !== undefined || ref.doi !== undefined) return undefined;
      const registered = db.sqlite.query("SELECT 1 AS valid FROM molt_local_evidence WHERE content_sha256=? AND ref_json=?").get(ref.content_sha256, canonicalJson(ref));
      if (!registered) return undefined;
      continue;
    }
    if (ref.access === "local" || ref.content_sha256 !== undefined) return undefined;
    if (!cached.has(ref.source)) {
      const rows = db.sqlite.query("SELECT response_json FROM intel_cache WHERE provider=? AND cached_at>=? ORDER BY cached_at DESC LIMIT 1000")
        .all(ref.source, new Date(Date.now() - 7 * 86_400_000).toISOString()) as Array<{ response_json: string }>;
      const serialized = new Set<string>();
      for (const row of rows) {
        try {
          const results = JSON.parse(row.response_json) as unknown;
          if (Array.isArray(results)) for (const result of results) if (isRecord(result)) serialized.add(canonicalJson(result));
        } catch {}
      }
      cached.set(ref.source, serialized);
    }
    if (!cached.get(ref.source)?.has(canonicalJson(ref))) return undefined;
  }
  return value;
}

function contractCandidate(value: unknown, trajectoryHash: string, modelSha: string, evidenceRefs: Array<Record<string, unknown>>): SkillContract {
  if (!isRecord(value) || !isRecord(value.trigger) || !isRecord(value.output_spec) || !Array.isArray(value.workflow)) throw new Error("Miner did not return a skill-contract-v1 object");
  const candidate = structuredClone(value) as unknown as SkillContract;
  candidate.id = newSkillId();
  candidate.schema_version = "skill-contract-v1";
  candidate.agentbook_state = "draft";
  candidate.risk_tier = [0, 1, 2].includes(Number(candidate.risk_tier)) ? Number(candidate.risk_tier) as RiskTier : 0;
  candidate.provenance = {
    trajectory_hashes: [trajectoryHash],
    extraction_model_sha: modelSha,
    sanitizer_version: "praxis-sanitizer/1.0.0",
    evidence_refs: evidenceRefs,
    eval_suites: [],
    human_approvers: [],
  };
  delete candidate.molts_event_hash;
  return candidate;
}

export class PraxisMining {
  constructor(private readonly db: PraxisDb, private readonly config: Config) {}

  async ingest(input: unknown): Promise<{ ingest_id: string; trajectory_hash: string; state: string; flags: string[]; mining_mode: string; skill_id?: string }> {
    if (!isRecord(input) || typeof input.source_agent_id !== "string" || typeof input.trajectory !== "string") throw new Error("source_agent_id and trajectory are required");
    const sourceAgent = input.source_agent_id;
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$/.test(sourceAgent)) throw new Error("Invalid source agent id");
    const raw = input.trajectory;
    const sanitized = sanitizeTrajectory(raw, this.config.maxBodyBytes);
    if (input.trajectory_hash !== undefined && input.trajectory_hash !== sanitized.hash) throw new Error("trajectory_hash does not match the submitted trajectory");
    const flags = new Set(sanitized.flags);
    if (Array.isArray(input.source_flags)) {
      for (const flag of input.source_flags) {
        if (flag === "sensitive_data_redacted" || flag === "prompt_injection_detected") flags.add(flag);
      }
    }
    const evidenceRefs = verifiedEvidenceRefs(this.db, input.evidence_refs);
    if (!evidenceRefs) flags.add("unverified_evidence_reference");
    const agent = this.db.sqlite.query("SELECT enabled FROM agents WHERE agent_id=?").get(sourceAgent) as { enabled: number } | null;
    if (!agent || agent.enabled !== 1) flags.add("source_agent_not_allowlisted");

    let candidate: unknown;
    let miningMode = "structured_stub";
    if (flags.size === 0 && !flags.has("source_agent_not_allowlisted")) {
      if (input.candidate !== undefined) {
        candidate = input.candidate;
        miningMode = "supplied_candidate";
      } else if (this.config.minerUrl && this.config.minerToken && this.config.minerModelSha) {
        candidate = await callMinerSidecar(this.config.minerUrl, this.config.minerToken, sanitized.content, {
          source_agent_id: sourceAgent,
          trajectory_hash: sanitized.hash,
          domain: typeof input.domain === "string" ? input.domain.slice(0, 120) : "general",
        });
        miningMode = "pinned_sidecar";
      } else {
        candidate = mineStructuredTrajectory(sanitized.content, {
          summary: input.summary,
          domain: input.domain,
          output_spec: input.output_spec,
          constraints: input.constraints,
          forbidden_actions: input.forbidden_actions,
          supersedes: input.supersedes,
        });
      }
    }

    let contract: SkillContract | undefined;
    if (candidate !== undefined && candidate !== null && flags.size === 0) {
      const modelSha = this.config.minerModelSha ?? extractionModelSha();
      try {
        const candidateSanitization = sanitizeTrajectory(canonicalJson(candidate), this.config.maxBodyBytes);
        if (candidateSanitization.quarantined || candidateSanitization.redacted) {
          flags.add(candidateSanitization.quarantined ? "miner_output_prompt_injection" : "miner_output_sensitive_data");
        } else {
          contract = contractCandidate(candidate, sanitized.hash, modelSha, evidenceRefs ?? []);
          const validation = validateContract(contract);
          if (!validation.valid) flags.add("miner_output_invalid_contract");
          else {
            const lint = lintWorkflow(contract.workflow, toolPolicies(this.db), contract.forbidden_actions);
            if (!lint.valid) flags.add("workflow_lint_failed");
            else contract.risk_tier = Math.max(contract.risk_tier, lint.riskTier) as RiskTier;
          }
        }
      } catch {
        flags.add("miner_output_invalid_contract");
      }
    }

    const quarantined = flags.size > 0 || (candidate !== undefined && candidate !== null && !contract);
    const state = quarantined ? "quarantined" : "draft";
    const ingestId = `ingest_${newUlid()}`;
    const createdAt = new Date().toISOString();
    this.db.sqlite.query(`INSERT INTO ingest_records(ingest_id,source_agent_id,trajectory_hash,state,flags_json,sanitized_trajectory,draft_json,created_at)
      VALUES(?,?,?,?,?,?,?,?)`)
      .run(ingestId, sourceAgent, sanitized.hash, state, canonicalJson([...flags].sort()), sanitized.content, contract ? canonicalJson(contract) : null, createdAt);
    return {
      ingest_id: ingestId,
      trajectory_hash: sanitized.hash,
      state,
      flags: [...flags].sort(),
      mining_mode: miningMode,
      ...(contract ? { skill_id: contract.id } : {}),
    };
  }

  listQuarantine(limit = 100): unknown[] {
    const rows = this.db.sqlite.query("SELECT ingest_id,source_agent_id,trajectory_hash,flags_json,created_at,review_event_id FROM ingest_records WHERE state='quarantined' ORDER BY created_at DESC LIMIT ?")
      .all(Math.max(1, Math.min(500, limit))) as Array<{ ingest_id: string; source_agent_id: string; trajectory_hash: string; flags_json: string; created_at: string; review_event_id: string | null }>;
    return rows.map((row) => ({ ...row, flags: JSON.parse(row.flags_json) }));
  }

  static trajectoryHash(value: string): string {
    return `sha256:${createHash("sha256").update(value).digest("hex")}`;
  }
}
