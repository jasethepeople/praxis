import { createPublicKey } from "node:crypto";
import { canonicalJson, contractHash, sha256 } from "./canonical";
import { newUlid } from "./ids";
import type { Config } from "./config";
import type { PraxisDb } from "./db";
import type { SigningIdentity } from "./security";
import { verifySignature } from "./security";
import type { SkillContract, SignedEvent, RiskTier } from "./types";
import { Ledger, makeEvent } from "./ledger";
import { lintWorkflow, validateContract, verifyOutputSpec } from "./validation";
import type { GraduationReport } from "./foundry";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function contractPayload(contract: SkillContract): Record<string, unknown> {
  const { molts_event_hash: _hash, ...payload } = contract;
  return payload as unknown as Record<string, unknown>;
}

function safeJson(text: string, maxBytes: number): unknown {
  if (Buffer.byteLength(text) > maxBytes) throw new Error("T340 response exceeds the configured size limit");
  return JSON.parse(text);
}

async function boundedText(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > maxBytes) {
    await response.body?.cancel();
    throw new Error("T340 response exceeds the configured size limit");
  }
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error("T340 response exceeds the configured size limit");
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export interface ExecuteInput {
  skill_id: string;
  executor_agent: string;
  input: unknown;
  idempotency_key: string;
}

export class IntegrationGateway {
  constructor(
    private readonly db: PraxisDb,
    private readonly ledger: Ledger,
    private readonly identity: SigningIdentity,
    private readonly foundryIdentity: SigningIdentity,
    private readonly config: Config,
  ) {}

  registerAgent(input: { agent_id: string; name: string; description: string; url?: string; capabilities?: unknown }): unknown {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$/.test(input.agent_id) || input.name.trim().length < 1 || input.name.length > 120 || input.description.length > 2000) throw new Error("Invalid agent card");
    let url: string | null = null;
    if (input.url) {
      const parsed = new URL(input.url);
      if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hostname === "localhost") throw new Error("Remote agent URLs must use HTTPS without credentials");
      url = parsed.toString();
    }
    const capabilities = input.capabilities ?? [];
    if (!Array.isArray(capabilities) || capabilities.length > 64 || capabilities.some((item) => typeof item !== "string" || item.length > 160)) throw new Error("Agent capabilities must be a short string array");
    const createdAt = new Date().toISOString();
    this.db.sqlite.query(`INSERT INTO gateway_agents(agent_id,name,description,url,capabilities_json,enabled,created_at) VALUES(?,?,?,?,?,1,?)
      ON CONFLICT(agent_id) DO UPDATE SET name=excluded.name,description=excluded.description,url=excluded.url,capabilities_json=excluded.capabilities_json,enabled=1`)
      .run(input.agent_id, input.name.trim(), input.description, url, canonicalJson(capabilities), createdAt);
    this.db.sqlite.query("INSERT INTO agents(agent_id,enabled,created_at) VALUES(?,1,?) ON CONFLICT(agent_id) DO UPDATE SET enabled=1")
      .run(input.agent_id, createdAt);
    return { agent_id: input.agent_id, name: input.name.trim(), description: input.description, url, capabilities, enabled: true, created_at: createdAt };
  }

  ensureDefaultAgent(input: { agent_id: string; name: string; description: string; capabilities?: unknown }): void {
    const existing = this.db.sqlite.query("SELECT 1 AS found FROM gateway_agents WHERE agent_id=?").get(input.agent_id);
    if (!existing) this.registerAgent(input);
    this.db.sqlite.query("INSERT INTO agents(agent_id,enabled,created_at) VALUES(?,1,?) ON CONFLICT(agent_id) DO NOTHING")
      .run(input.agent_id, new Date().toISOString());
  }

  listRegistry(): unknown[] {
    const rows = this.db.sqlite.query("SELECT agent_id,name,description,url,capabilities_json,enabled,created_at FROM gateway_agents ORDER BY name,agent_id")
      .all() as Array<{ agent_id: string; name: string; description: string; url: string | null; capabilities_json: string; enabled: number; created_at: string }>;
    return rows.map((row) => ({ agent_id: row.agent_id, name: row.name, description: row.description, url: row.url, capabilities: JSON.parse(row.capabilities_json), enabled: row.enabled === 1, created_at: row.created_at }));
  }

  disableAgent(agentId: string): void {
    const result = this.db.sqlite.query("UPDATE gateway_agents SET enabled=0 WHERE agent_id=?").run(agentId);
    if (!result.changes) throw new Error("Registered agent not found");
    this.db.sqlite.query("UPDATE agents SET enabled=0 WHERE agent_id=?").run(agentId);
  }


  async execute(input: ExecuteInput): Promise<Record<string, unknown>> {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$/.test(input.executor_agent)) throw new Error("Invalid executor agent");
    if (!/^[a-zA-Z0-9._:-]{16,128}$/.test(input.idempotency_key)) throw new Error("idempotency_key must be 16–128 safe characters");
    const executionInput = input.input ?? null;
    const requestHash = sha256(canonicalJson({ operation: "execute", skill_id: input.skill_id, executor_agent: input.executor_agent, input: executionInput }));
    const existing = this.db.sqlite.query("SELECT execution_id,request_hash,state,outcome,event_id,output_json FROM execution_runs WHERE idempotency_key=?")
      .get(input.idempotency_key) as { execution_id: string; request_hash: string; state: string; outcome: string; event_id: string | null; output_json: string | null } | null;
    if (existing) {
      if (existing.request_hash !== requestHash) throw new Error("Idempotency key was already used for a different request");
      if (existing.state !== "running") return { execution_id: existing.execution_id, state: existing.state, outcome: existing.outcome, event_id: existing.event_id, replayed: true, ...(existing.output_json ? { result: JSON.parse(existing.output_json) } : {}) };
      const recovered = this.recoverExecution(existing.execution_id);
      if (recovered) return recovered;
    }

    const row = this.db.sqlite.query("SELECT contract_json,contract_hash,signature,state,risk_tier FROM contracts WHERE skill_id=?")
      .get(input.skill_id) as { contract_json: string; contract_hash: string; signature: string; state: string; risk_tier: RiskTier } | null;
    if (!row || row.state !== "canonical") throw new Error("Skill is not canonical or has been deprecated");
    const contract = JSON.parse(row.contract_json) as SkillContract;
    if (contractHash(contract) !== row.contract_hash || !verifyContract(contract, row.signature, this.foundryIdentity)) throw new Error("Canonical contract signature verification failed");
    const lint = lintWorkflow(contract.workflow, this.toolPolicies(), contract.forbidden_actions);
    if (!lint.valid || lint.riskTier > row.risk_tier) throw new Error("Workflow is blocked by the current tool-risk registry");
    const agent = this.db.sqlite.query("SELECT enabled FROM gateway_agents WHERE agent_id=?").get(input.executor_agent) as { enabled: number } | null;
    if (!agent || agent.enabled !== 1) throw new Error("Executor agent is not registered and enabled");
    if (Buffer.byteLength(canonicalJson(executionInput)) > 1_000_000) throw new Error("Execution input exceeds 1 MB");

    const executionId = existing?.execution_id ?? `exec_${newUlid()}`;
    if (!existing) {
      const createdAt = new Date().toISOString();
      this.db.sqlite.query(`INSERT INTO execution_runs(execution_id,skill_id,contract_hash,executor_agent,state,outcome,created_at,idempotency_key,request_hash)
        VALUES(?,?,?,?,'running','unverified',?,?,?)`)
        .run(executionId, input.skill_id, row.contract_hash, input.executor_agent, createdAt, input.idempotency_key, requestHash);
    }

    let outcome: "success" | "failure" | "blocked" | "unverified" = "blocked";
    let output: unknown = null;
    let artifacts: string[] = [];
    let checks = { passed: false, checks_passed: 0, checks_total: 0, errors: ["execution backend is disabled"] };
    if (this.config.executionBackend === "t340" && this.config.t340Url && this.config.t340Token) {
      const result = await this.callT340({ execution_id: executionId, contract: contractPayload(contract), contract_hash: row.contract_hash, executor_agent: input.executor_agent, input: executionInput });
      if (result.state === "completed") {
        output = result.output;
        artifacts = result.artifacts;
        checks = verifyOutputSpec(contract.output_spec, output, artifacts);
        outcome = checks.passed && checks.checks_total > 0 ? "success" : "failure";
      } else if (result.state === "failed") {
        outcome = "failure";
        checks = { passed: false, checks_passed: 0, checks_total: 1, errors: ["execution backend reported failure"] };
      } else if (result.state === "unverified") {
        outcome = "unverified";
      }
    }

    const method = "output_spec";
    const event = makeEvent(this.identity, "skill.used", {
      skill_id: input.skill_id,
      contract_hash: row.contract_hash,
      execution_id: executionId,
      outcome,
      verification: { method, checks_passed: checks.checks_passed, checks_total: checks.checks_total, verifier: `integration-gateway@${this.identity.fingerprint}` },
      executor_agent: input.executor_agent,
      timestamp: new Date().toISOString(),
    });
    const applied = this.ledger.recordOutcome(event);
    const finishedAt = new Date().toISOString();
    const outputHash = output === null ? null : sha256(canonicalJson(output));
    const safeResult = output === null ? null : { output_sha256: outputHash, artifacts, checks, output };
    this.db.sqlite.query("UPDATE execution_runs SET state=?,outcome=?,finished_at=?,output_json=?,event_id=? WHERE execution_id=?")
      .run(outcome === "success" ? "completed" : outcome === "failure" ? "failed" : "blocked", outcome, finishedAt,
        safeResult === null ? null : canonicalJson({ output_sha256: outputHash, artifacts, checks }), event.event_id, executionId);
    return { execution_id: executionId, state: outcome === "success" ? "completed" : outcome === "failure" ? "failed" : "blocked", outcome, verification: event.payload.verification, errors: outcome === "failure" ? checks.errors : [], output: safeResult, event, event_hash: applied.event_hash, applied_weight: applied.applied_weight, replayed: false };
  }

  async graduate(input: { contract: SkillContract; fixtures: Array<{ input: unknown; output?: unknown; artifacts?: string[] }>; run_id?: string }): Promise<GraduationReport> {
    if (this.config.executionBackend !== "t340" || !this.config.t340Url || !this.config.t340Token) throw new Error("T340 graduation is unavailable while execution backend is stubbed");
    const validation = validateContract(input.contract);
    if (!validation.valid || input.contract.agentbook_state !== "canonical" || input.contract.risk_tier !== 2) throw new Error("Graduation requires a validated tier-2 promotion candidate");
    if (!Array.isArray(input.fixtures) || input.fixtures.length < 3 || input.fixtures.length > 100) throw new Error("Graduation requires 3–100 fixtures");
    const hash = contractHash(input.contract);
    const runId = input.run_id ?? `grad_${newUlid()}`;
    const response = await fetch(`${this.config.t340Url}/graduate`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.config.t340Token}`, "content-type": "application/json", accept: "application/json", "idempotency-key": runId },
      body: JSON.stringify({ suite: "t340-graduation-v1", run_id: runId, contract: contractPayload(input.contract), contract_hash: hash, fixtures: input.fixtures }),
      redirect: "error",
      signal: AbortSignal.timeout(180_000),
    });
    if (!response.ok) throw new Error(`T340 graduation returned HTTP ${response.status}`);
    const body = safeJson(await boundedText(response, 4_000_000), 4_000_000);
    if (!isRecord(body) || !Array.isArray(body.results) || body.results.length !== input.fixtures.length) throw new Error("T340 graduation returned an invalid result set");
    let checksTotal = 0;
    let checksPassed = 0;
    let passed = true;
    for (const result of body.results) {
      if (!isRecord(result)) throw new Error("T340 graduation result is malformed");
      const verified = verifyOutputSpec(input.contract.output_spec, result.output, Array.isArray(result.artifacts) ? result.artifacts as string[] : []);
      checksTotal += verified.checks_total;
      checksPassed += verified.checks_passed;
      if (!verified.passed || verified.checks_total === 0) passed = false;
    }
    const report: Omit<GraduationReport, "signature"> = {
      contract_hash: hash,
      suite: "t340-graduation-v1",
      run_id: runId,
      passed: passed && checksTotal >= 3,
      case_count: input.fixtures.length,
      checks_passed: checksPassed,
      checks_total: checksTotal,
      timestamp: new Date().toISOString(),
      signer: this.identity.fingerprint,
    };
    return { ...report, signature: this.identity.sign(report) };
  }

  acceptOutcome(value: unknown): { event_hash: string; duplicate: boolean; applied_weight: number } {
    if (!isRecord(value) || value.event_type !== "skill.used" || typeof value.event_id !== "string" || typeof value.timestamp !== "string" || !isRecord(value.payload) || typeof value.signature !== "string" || typeof value.signer !== "string") {
      throw new Error("Malformed signed outcome event");
    }
    return this.ledger.recordOutcome(value as unknown as SignedEvent);
  }

  async selfReport(input: { skill_id: string; executor_agent: string; outcome: "success" | "failure" | "partial"; idempotency_key: string }): Promise<Record<string, unknown>> {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$/.test(input.executor_agent) || !/^[a-zA-Z0-9._:-]{16,128}$/.test(input.idempotency_key)) throw new Error("Invalid self-report identity");
    const agent = this.db.sqlite.query("SELECT enabled FROM gateway_agents WHERE agent_id=?").get(input.executor_agent) as { enabled: number } | null;
    if (!agent || agent.enabled !== 1) throw new Error("Executor agent is not registered and enabled");
    const contract = this.db.sqlite.query("SELECT contract_hash,state FROM contracts WHERE skill_id=?").get(input.skill_id) as { contract_hash: string; state: string } | null;
    if (!contract || contract.state !== "canonical") throw new Error("Skill is not canonical");
    const requestHash = sha256(canonicalJson({ operation: "self-report", skill_id: input.skill_id, executor_agent: input.executor_agent, outcome: input.outcome }));
    const existing = this.db.sqlite.query("SELECT execution_id,request_hash,state,outcome,event_id FROM execution_runs WHERE idempotency_key=?")
      .get(input.idempotency_key) as { execution_id: string; request_hash: string; state: string; outcome: string; event_id: string | null } | null;
    if (existing && existing.request_hash !== requestHash) throw new Error("Idempotency key was already used for a different request");
    if (existing && existing.state !== "running") return { execution_id: existing.execution_id, state: existing.state, outcome: existing.outcome, event_id: existing.event_id, replayed: true };
    const executionId = existing?.execution_id ?? `exec_${newUlid()}`;
    if (!existing) this.db.sqlite.query(`INSERT INTO execution_runs(execution_id,skill_id,contract_hash,executor_agent,state,outcome,created_at,idempotency_key,request_hash)
      VALUES(?,?,?,?,'running','unverified',?,?,?)`).run(executionId, input.skill_id, contract.contract_hash, input.executor_agent, new Date().toISOString(), input.idempotency_key, requestHash);
    const recovered = this.recoverExecution(executionId);
    if (recovered) return recovered;
    const event = makeEvent(this.identity, "skill.used", {
      skill_id: input.skill_id,
      contract_hash: contract.contract_hash,
      execution_id: executionId,
      outcome: input.outcome,
      verification: { method: "self_report", checks_passed: 0, checks_total: 0, verifier: `integration-gateway@${this.identity.fingerprint}` },
      executor_agent: input.executor_agent,
      timestamp: new Date().toISOString(),
    });
    const result = this.ledger.recordOutcome(event);
    const state = input.outcome === "failure" ? "failed" : "completed";
    this.db.sqlite.query("UPDATE execution_runs SET state=?,outcome=?,finished_at=?,event_id=? WHERE execution_id=?")
      .run(state, input.outcome, event.timestamp, event.event_id, executionId);
    return { execution_id: executionId, state, event, event_hash: result.event_hash, applied_weight: result.applied_weight, replayed: false };
  }

  private recoverExecution(executionId: string): Record<string, unknown> | null {
    const row = this.db.sqlite.query(`SELECT event_id,event_type,timestamp,payload_json,signature,signer FROM events
      WHERE event_type='skill.used' AND json_extract(payload_json,'$.execution_id')=? ORDER BY rowid DESC LIMIT 1`).get(executionId) as {
        event_id: string; event_type: string; timestamp: string; payload_json: string; signature: string; signer: string;
      } | null;
    if (!row) return null;
    const event = { event_id: row.event_id, event_type: row.event_type, timestamp: row.timestamp, payload: JSON.parse(row.payload_json), signature: row.signature, signer: row.signer } as SignedEvent;
    const recorded = this.ledger.recordOutcome(event);
    const outcome = event.payload.outcome as "success" | "failure" | "partial" | "blocked" | "unverified";
    const state = outcome === "success" || outcome === "partial" ? "completed" : outcome === "failure" ? "failed" : "blocked";
    this.db.sqlite.query("UPDATE execution_runs SET state=?,outcome=?,finished_at=?,event_id=? WHERE execution_id=? AND state='running'")
      .run(state, outcome, event.timestamp, event.event_id, executionId);
    return { execution_id: executionId, state, outcome, event_id: event.event_id, event_hash: recorded.event_hash, applied_weight: recorded.applied_weight, replayed: true };
  }

  private toolPolicies(): Map<string, { risk_tier: RiskTier; enabled: boolean }> {
    const rows = this.db.sqlite.query("SELECT tool_id,risk_tier,enabled FROM tool_registry").all() as Array<{ tool_id: string; risk_tier: RiskTier; enabled: number }>;
    return new Map(rows.map((row) => [row.tool_id, { risk_tier: row.risk_tier, enabled: row.enabled === 1 }]));
  }

  private async callT340(request: Record<string, unknown>): Promise<{ state: "completed" | "failed" | "blocked" | "unverified"; output?: unknown; artifacts: string[] }> {
    try {
      const response = await fetch(`${this.config.t340Url}/execute`, {
        method: "POST",
        headers: { authorization: `Bearer ${this.config.t340Token}`, "content-type": "application/json", accept: "application/json", "idempotency-key": String(request.execution_id) },
        body: JSON.stringify(request),
        redirect: "error",
        signal: AbortSignal.timeout(180_000),
      });
      if (response.status === 401 || response.status === 403 || response.status === 400 || response.status === 422) return { state: "blocked", artifacts: [] };
      if (!response.ok) return { state: "unverified", artifacts: [] };
      const body = safeJson(await boundedText(response, 4_000_000), 4_000_000);
      if (!isRecord(body) || !["completed", "failed", "blocked"].includes(String(body.state))) return { state: "unverified", artifacts: [] };
      if (body.state === "completed") {
        const artifacts = Array.isArray(body.artifacts) && body.artifacts.every((x) => typeof x === "string" && x.length <= 512) ? body.artifacts as string[] : [];
        return { state: "completed", output: body.output, artifacts };
      }
      return { state: body.state as "failed" | "blocked", artifacts: [] };
    } catch {
      return { state: "unverified", artifacts: [] };
    }
  }
}

function verifyContract(contract: SkillContract, signature: string, identity: SigningIdentity): boolean {
  try {
    return verifySignature(contractPayload(contract), signature, createPublicKey(identity.publicKeyPem));
  } catch {
    return false;
  }
}
