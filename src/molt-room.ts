import { createHash, createPublicKey } from "node:crypto";
import { canonicalJson } from "./canonical";
import { verifyMoltTranscript } from "./molt-import";
import { newUlid } from "./ids";
import { sanitizeTrajectory } from "./sanitizer";
import type { PraxisDb } from "./db";
import type { PraxisMining } from "./mining";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

type ScrubFindings = { redacted: boolean; promptInjection: boolean };

function scrubContent(value: unknown, findings: ScrubFindings, depth = 0, budget = { nodes: 0 }): unknown {
  budget.nodes++;
  if (budget.nodes > 10_000 || depth > 32) throw new Error("Message content exceeds structural limits");
  if (typeof value === "string") {
    const result = sanitizeTrajectory(value, 65_536);
    findings.redacted ||= result.redacted;
    findings.promptInjection ||= result.quarantined;
    return result.content;
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (value.length > 1000) throw new Error("Message arrays are too large");
    return value.map((item) => scrubContent(item, findings, depth + 1, budget));
  }
  if (isRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length > 1000) throw new Error("Message objects are too large");
    const output: Record<string, unknown> = Object.create(null);
    for (let i = 0; i < entries.length; i++) {
      const [key, item] = entries[i];
      const sanitizedKey = sanitizeTrajectory(key, 1024);
      const safeKey = sanitizedKey.redacted || sanitizedKey.quarantined ? `[REDACTED_KEY_${i}]` : sanitizedKey.content;
      if (safeKey !== key) findings.redacted ||= sanitizedKey.redacted;
      findings.promptInjection ||= sanitizedKey.quarantined;
      if (Object.hasOwn(output, safeKey)) throw new Error("Message object keys collide after sanitization");
      if (/(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret|authorization|^token$)/i.test(key)) {
        findings.redacted = true;
        output[safeKey] = "[REDACTED_SECRET]";
      } else if (/^(?:email|e-mail|phone|telephone|mobile|address|ssn|social_security_number)$/i.test(key)) {
        findings.redacted = true;
        output[safeKey] = "[REDACTED_PII]";
      } else output[safeKey] = scrubContent(item, findings, depth + 1, budget);
    }
    return output;
  }
  throw new Error("Message content must contain only JSON values");
}

export class MoltRoom {
  constructor(private readonly db: PraxisDb, private readonly mining: PraxisMining) {}

  registerAgent(agentId: string): { agent_id: string; created: boolean } {
    const id = agentId.trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$/.test(id)) throw new Error("Invalid agent id");
    const old = this.db.sqlite.query("SELECT enabled FROM agents WHERE agent_id=?").get(id) as { enabled: number } | null;
    this.db.sqlite.query("INSERT INTO agents(agent_id,enabled,created_at) VALUES(?,1,?) ON CONFLICT(agent_id) DO UPDATE SET enabled=1")
      .run(id, new Date().toISOString());
    return { agent_id: id, created: !old };
  }

  ensureAgent(agentId: string): void {
    const id = agentId.trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$/.test(id)) throw new Error("Invalid agent id");
    this.db.sqlite.query("INSERT INTO agents(agent_id,enabled,created_at) VALUES(?,1,?) ON CONFLICT(agent_id) DO NOTHING")
      .run(id, new Date().toISOString());
  }

  registerIdentity(input: { agent_id: string; public_key: string }): { agent_id: string; fingerprint: string; created: boolean } {
    if (!/^[0-9a-f]{64}$/.test(input.agent_id) || input.public_key.length > 4096) throw new Error("Invalid MOLT identity");
    const der = Buffer.from(input.public_key, "base64url");
    if (!der.length || der.toString("base64url") !== input.public_key) throw new Error("MOLT public key must be canonical base64url SPKI");
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") throw new Error("MOLT identity must use Ed25519");
    const fingerprint = createHash("sha256").update(der).digest("hex");
    if (fingerprint !== input.agent_id) throw new Error("MOLT agent id must match the public-key fingerprint");
    const existing = this.db.sqlite.query("SELECT public_key FROM molt_source_keys WHERE agent_id=?").get(input.agent_id) as { public_key: string } | null;
    if (existing && existing.public_key !== input.public_key) throw new Error("MOLT identity key cannot be replaced");
    this.db.sqlite.transaction(() => {
      this.registerAgent(input.agent_id);
      this.db.sqlite.query("INSERT INTO molt_source_keys(agent_id,public_key,registered_at) VALUES(?,?,?) ON CONFLICT(agent_id) DO NOTHING")
        .run(input.agent_id, input.public_key, new Date().toISOString());
    })();
    return { agent_id: input.agent_id, fingerprint, created: !existing };
  }

  trustedSourceKey(agentId: string): string | undefined {
    const row = this.db.sqlite.query(`SELECT k.public_key FROM molt_source_keys k JOIN agents a ON a.agent_id=k.agent_id
      WHERE k.agent_id=? AND k.enabled=1 AND a.enabled=1`).get(agentId) as { public_key: string } | null;
    return row?.public_key;
  }

  listIdentities(): Array<{ agent_id: string; public_key: string; enabled: boolean; registered_at: string }> {
    const rows = this.db.sqlite.query("SELECT agent_id,public_key,enabled,registered_at FROM molt_source_keys ORDER BY registered_at,agent_id").all() as Array<{ agent_id: string; public_key: string; enabled: number; registered_at: string }>;
    return rows.map((row) => ({ ...row, enabled: row.enabled === 1 }));
  }

  disableIdentity(agentId: string): void {
    const result = this.db.sqlite.query("UPDATE molt_source_keys SET enabled=0 WHERE agent_id=?").run(agentId);
    if (result.changes !== 1) throw new Error("MOLT identity not found");
  }

  async ingestSignedTranscript(input: unknown): Promise<{ ingest_id: string; trajectory_hash: string; state: string; flags: string[]; mining_mode: string; skill_id?: string }> {
    if (!isRecord(input) || typeof input.source_agent_id !== "string" || typeof input.genesis_json !== "string" || typeof input.transcript_jsonl !== "string") throw new Error("source_agent_id, genesis_json, and transcript_jsonl are required");
    const expectedKey = this.trustedSourceKey(input.source_agent_id);
    if (!expectedKey) throw new Error("MOLT source identity is not registered or enabled");
    const verified = verifyMoltTranscript({ genesis_json: input.genesis_json, transcript_jsonl: input.transcript_jsonl, source_agent_id: input.source_agent_id, expected_source_public_key: expectedKey, seams_markdown: input.seams_markdown, seal_snapshots: input.seal_snapshots });
    const existing = this.db.sqlite.query("SELECT ref_json FROM molt_local_evidence WHERE content_sha256=?").get(String(verified.source_ref.content_sha256)) as { ref_json: string } | null;
    const sourceRef = existing ? JSON.parse(existing.ref_json) as Record<string, unknown> : verified.source_ref;
    this.db.sqlite.query(`INSERT INTO molt_local_evidence(content_sha256,room_id,source_agent_id,event_count,ref_json,verified_at)
      VALUES(?,?,?,?,?,?) ON CONFLICT(content_sha256) DO NOTHING`).run(String(sourceRef.content_sha256), verified.room_id, input.source_agent_id, verified.event_count, canonicalJson(sourceRef), new Date().toISOString());
    return this.mining.ingest({
      source_agent_id: input.source_agent_id,
      trajectory: verified.trajectory,
      candidate: input.candidate,
      summary: input.summary,
      domain: input.domain,
      output_spec: input.output_spec,
      constraints: input.constraints,
      forbidden_actions: input.forbidden_actions,
      supersedes: input.supersedes,
      evidence_refs: [...(Array.isArray(input.evidence_refs) ? input.evidence_refs : []), sourceRef],
    });
  }

  disableAgent(agentId: string): void {
    const result = this.db.sqlite.query("UPDATE agents SET enabled=0 WHERE agent_id=?").run(agentId);
    if (result.changes !== 1) throw new Error("Agent not found");
  }

  listAgents(): Array<{ agent_id: string; enabled: boolean; created_at: string }> {
    const rows = this.db.sqlite.query("SELECT agent_id,enabled,created_at FROM agents ORDER BY agent_id").all() as Array<{ agent_id: string; enabled: number; created_at: string }>;
    return rows.map((row) => ({ ...row, enabled: row.enabled === 1 }));
  }

  createRoom(input: { name: string; created_by: string }): { room_id: string; name: string; created_by: string; created_at: string } {
    const name = input.name.trim();
    if (!name || name.length > 160) throw new Error("Room name must contain 1–160 characters");
    const creator = input.created_by.trim();
    const agent = this.db.sqlite.query("SELECT enabled FROM agents WHERE agent_id=?").get(creator) as { enabled: number } | null;
    if (!name || !agent || agent.enabled !== 1) throw new Error("Room name and an enabled registered creator are required");
    const room = { room_id: `room_${newUlid()}`, name, created_by: creator, created_at: new Date().toISOString() };
    this.db.sqlite.query("INSERT INTO molt_rooms(room_id,name,created_by,created_at) VALUES(?,?,?,?)").run(room.room_id, room.name, room.created_by, room.created_at);
    return room;
  }

  listRooms(limit = 100): unknown[] {
    const rows = this.db.sqlite.query(`SELECT r.room_id,r.name,r.created_by,r.created_at,COUNT(m.message_id) AS message_count
      FROM molt_rooms r LEFT JOIN molt_messages m ON m.room_id=r.room_id
      GROUP BY r.room_id ORDER BY r.created_at DESC LIMIT ?`).all(Math.max(1, Math.min(500, limit)));
    return rows;
  }

  postMessage(input: { room_id: string; agent_id: string; role: string; kind: string; content: unknown }): unknown {
    if (!["user", "assistant", "tool"].includes(input.role) || !["message", "tool_call", "tool_result", "evidence"].includes(input.kind)) throw new Error("Invalid message role or kind");
    const findings: ScrubFindings = { redacted: false, promptInjection: false };
    const content = scrubContent(input.content, findings);
    const flags = [
      ...(findings.redacted ? ["sensitive_data_redacted"] : []),
      ...(findings.promptInjection ? ["prompt_injection_detected"] : []),
    ].sort();
    const contentJson = canonicalJson(content);
    if (Buffer.byteLength(contentJson) > 65_536) throw new Error("Message exceeds 64 KiB");
    const agent = this.db.sqlite.query("SELECT enabled FROM agents WHERE agent_id=?").get(input.agent_id) as { enabled: number } | null;
    const room = this.db.sqlite.query("SELECT 1 AS found FROM molt_rooms WHERE room_id=?").get(input.room_id);
    if (!agent || agent.enabled !== 1 || !room) throw new Error("Unknown room or disabled agent");
    if (input.kind === "tool_call") {
      const value = isRecord(content) ? content : undefined;
      if (!value || typeof value.tool_id !== "string" || typeof value.action !== "string") throw new Error("tool_call content requires tool_id and action");
    }
    const message = {
      message_id: `msg_${newUlid()}`,
      room_id: input.room_id,
      agent_id: input.agent_id,
      role: input.role,
      kind: input.kind,
      content,
      flags,
      created_at: new Date().toISOString(),
    };
    this.db.sqlite.query("INSERT INTO molt_messages(message_id,room_id,agent_id,role,kind,content_json,created_at,flags_json) VALUES(?,?,?,?,?,?,?,?)")
      .run(message.message_id, message.room_id, message.agent_id, message.role, message.kind, contentJson, message.created_at, canonicalJson(flags));
    return message;
  }

  history(roomId: string, before?: string, limit = 100): unknown[] {
    if (before && !Number.isFinite(Date.parse(before))) throw new Error("Invalid before cursor");
    const rows = this.db.sqlite.query(`SELECT message_id,room_id,agent_id,role,kind,content_json,created_at,flags_json
      FROM molt_messages WHERE room_id=? AND (? IS NULL OR created_at<?)
      ORDER BY created_at DESC,message_id DESC LIMIT ?`).all(roomId, before ?? null, before ?? null, Math.max(1, Math.min(500, limit))) as Array<Record<string, unknown> & { content_json: string; flags_json: string }>;
    return rows.reverse().map(({ content_json, flags_json, ...row }) => ({ ...row, content: JSON.parse(content_json), flags: JSON.parse(flags_json) }));
  }

  exportJsonl(roomId: string): string {
    if (!this.db.sqlite.query("SELECT 1 AS found FROM molt_rooms WHERE room_id=?").get(roomId)) throw new Error("Room not found");
    const rows = this.db.sqlite.query(`SELECT message_id,room_id,agent_id,role,kind,content_json,created_at,flags_json FROM molt_messages
      WHERE room_id=? ORDER BY created_at,message_id LIMIT 10001`).all(roomId) as Array<Record<string, unknown> & { content_json: string; flags_json: string }>;
    if (rows.length > 10_000) throw new Error("Room export exceeds 10,000 messages");
    const lines = rows.map(({ content_json, flags_json, ...row }) => canonicalJson({ ...row, content: JSON.parse(content_json), flags: JSON.parse(flags_json) }));
    const output = lines.length ? `${lines.join("\n")}\n` : "";
    if (Buffer.byteLength(output) > 5_000_000) throw new Error("Room export exceeds 5 MB");
    return output;
  }

  async complete(roomId: string, input: {
    source_agent_id: string;
    summary?: unknown;
    domain?: unknown;
    output_spec?: unknown;
    constraints?: unknown;
    forbidden_actions?: unknown;
    supersedes?: unknown;
    evidence_refs?: unknown;
  }): Promise<unknown> {
    const room = this.db.sqlite.query("SELECT room_id FROM molt_rooms WHERE room_id=?").get(roomId);
    if (!room) throw new Error("Room not found");
    const rows = this.db.sqlite.query(`SELECT message_id,agent_id,role,kind,content_json,created_at,flags_json FROM molt_messages
      WHERE room_id=? ORDER BY created_at,message_id LIMIT 10001`).all(roomId) as Array<Record<string, unknown> & { content_json: string; flags_json: string }>;
    if (!rows.length) throw new Error("Cannot complete an empty room");
    if (rows.length > 10_000) throw new Error("Room trajectory exceeds 10,000 messages; split the task before mining");
    const sourceFlags = [...new Set(rows.flatMap((row) => JSON.parse(row.flags_json) as string[]))];
    const trajectory = rows.map(({ content_json, flags_json, ...row }) => JSON.stringify({ ...row, content: JSON.parse(content_json), flags: JSON.parse(flags_json) })).join("\n");
    if (Buffer.byteLength(trajectory) > 1_048_576) throw new Error("Room trajectory exceeds the 1 MiB mining limit");
    return this.mining.ingest({ ...input, trajectory, source_flags: sourceFlags });
  }
}
