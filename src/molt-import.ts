import { createHash, createPublicKey, verify as verifyEd25519 } from "node:crypto";
import { canonicalJson } from "./canonical";

const HASH = /^[0-9a-f]{64}$/;
const ROOM = /^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9a-f]{8}$/;
const THREAD = /^[a-z0-9-]{1,64}$/;
const UUID7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KINDS = new Set(["system", "membership", "turn", "challenge", "verdict", "proposal", "cosign", "canon", "budget", "seam", "seal"]);
const MAX_LINE_BYTES = 65_536;
const MAX_EVENTS = 50_000;
const ZERO_HASH = "0".repeat(64);

type RecordValue = Record<string, unknown>;
type Member = { name: string; role: "human" | "harness-agent"; modelId: string; publicKey: string; fingerprint: string; subscriptions: string[]; budgetTokens: number; tools: string[] };

function isRecord(value: unknown): value is RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: RecordValue, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function assertNoDuplicateKeys(source: string): void {
  let i = 0;
  const whitespace = () => { while (i < source.length && /[\t\n\r ]/.test(source[i]!)) i++; };
  const stringToken = (): string => {
    const start = i++;
    while (i < source.length) {
      const ch = source[i++]!;
      if (ch === "\\") i++;
      else if (ch === "\"") return JSON.parse(source.slice(start, i)) as string;
    }
    throw new Error("unterminated JSON string");
  };
  const value = (depth: number): void => {
    if (depth > 128) throw new Error("JSON nesting limit exceeded");
    whitespace();
    if (source[i] === "\"") { stringToken(); return; }
    if (source[i] === "{") {
      i++;
      whitespace();
      if (source[i] === "}") { i++; return; }
      const keys = new Set<string>();
      while (i < source.length) {
        whitespace();
        if (source[i] !== "\"") throw new Error("invalid JSON object key");
        const key = stringToken();
        if (keys.has(key)) throw new Error(`duplicate JSON property ${key}`);
        keys.add(key);
        whitespace();
        if (source[i++] !== ":") throw new Error("invalid JSON object separator");
        value(depth + 1);
        whitespace();
        const separator = source[i++];
        if (separator === "}") return;
        if (separator !== ",") throw new Error("invalid JSON object delimiter");
      }
      throw new Error("unterminated JSON object");
    }
    if (source[i] === "[") {
      i++;
      whitespace();
      if (source[i] === "]") { i++; return; }
      while (i < source.length) {
        value(depth + 1);
        whitespace();
        const separator = source[i++];
        if (separator === "]") return;
        if (separator !== ",") throw new Error("invalid JSON array delimiter");
      }
      throw new Error("unterminated JSON array");
    }
    const start = i;
    while (i < source.length && !/[\t\n\r ,\]}]/.test(source[i]!)) i++;
    if (i === start) throw new Error("invalid JSON value");
    JSON.parse(source.slice(start, i));
  };
  value(0);
  whitespace();
  if (i !== source.length) throw new Error("trailing JSON data");
}

function hashHex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function integerOnly(value: unknown): boolean {
  if (typeof value === "number") return Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(integerOnly);
  if (isRecord(value)) return Object.values(value).every(integerOnly);
  return true;
}

function validTime(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) return false;
  const zone = match[7]!;
  if (zone !== "Z" && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4, 6)) > 59)) return false;
  return Number.isFinite(Date.parse(value));
}

function validEvidence(value: unknown): boolean {
  if (!isRecord(value) || typeof value.type !== "string") return false;
  if (value.type === "event") return exactKeys(value, ["type", "id"]) && typeof value.id === "string" && UUID7.test(value.id);
  if (value.type === "external") {
    return exactKeys(value, ["type", "url", "sha256"], ["note"]) && typeof value.url === "string" && HASH.test(String(value.sha256)) && (value.note === undefined || typeof value.note === "string");
  }
  return false;
}

function validBody(body: RecordValue): boolean {
  switch (body.kind) {
    case "system": return exactKeys(body, ["kind", "genesisSha256", "templateId", "templateVersion"]) && HASH.test(String(body.genesisSha256)) && typeof body.templateId === "string" && typeof body.templateVersion === "string";
    case "membership": return exactKeys(body, ["kind", "action", "member"]) && ["join", "leave"].includes(String(body.action)) && validateMember(body.member);
    case "turn": return exactKeys(body, ["kind", "text"], ["usage", "artifact"]) && typeof body.text === "string" && body.text.length > 0 && body.text.length <= 250_000 && (body.usage === undefined || (isRecord(body.usage) && exactKeys(body.usage, ["inputTokens", "outputTokens"]) && Number.isSafeInteger(body.usage.inputTokens) && Number.isSafeInteger(body.usage.outputTokens) && Number(body.usage.inputTokens) >= 0 && Number(body.usage.outputTokens) >= 0)) && (body.artifact === undefined || (isRecord(body.artifact) && exactKeys(body.artifact, ["path", "sha256", "bytes"]) && typeof body.artifact.path === "string" && HASH.test(String(body.artifact.sha256)) && Number.isSafeInteger(body.artifact.bytes) && Number(body.artifact.bytes) >= 0));
    case "challenge": return exactKeys(body, ["kind", "targetEventId", "claim", "grounds", "evidence"]) && typeof body.targetEventId === "string" && UUID7.test(body.targetEventId) && typeof body.claim === "string" && ["factual", "procedural", "doctrinal"].includes(String(body.grounds)) && Array.isArray(body.evidence) && body.evidence.every(validEvidence);
    case "verdict": return exactKeys(body, ["kind", "challengeId", "outcome", "evidence", "rationale"]) && typeof body.challengeId === "string" && UUID7.test(body.challengeId) && ["upheld", "refuted", "unproven"].includes(String(body.outcome)) && Array.isArray(body.evidence) && body.evidence.every(validEvidence) && typeof body.rationale === "string";
    case "proposal": return exactKeys(body, ["kind", "statement", "appliesTo"], ["supersedes"]) && typeof body.statement === "string" && (body.appliesTo === "room" || (isRecord(body.appliesTo) && exactKeys(body.appliesTo, ["thread"]) && typeof body.appliesTo.thread === "string" && THREAD.test(body.appliesTo.thread))) && (body.supersedes === undefined || (typeof body.supersedes === "string" && UUID7.test(body.supersedes)));
    case "cosign": return exactKeys(body, ["kind", "proposalId", "stance"]) && typeof body.proposalId === "string" && UUID7.test(body.proposalId) && ["support", "oppose"].includes(String(body.stance));
    case "canon": return exactKeys(body, ["kind", "action", "proposalId", "cosigns", "reason"], ["newRule"]) && ["enact", "demote"].includes(String(body.action)) && typeof body.proposalId === "string" && UUID7.test(body.proposalId) && Array.isArray(body.cosigns) && body.cosigns.every((id) => typeof id === "string" && UUID7.test(id)) && typeof body.reason === "string" && (body.newRule === undefined || (body.action === "enact" && isRecord(body.newRule) && exactKeys(body.newRule, ["id", "minCosigns"]) && typeof body.newRule.id === "string" && Number.isSafeInteger(body.newRule.minCosigns) && Number(body.newRule.minCosigns) >= 0));
    case "budget": return exactKeys(body, ["kind", "member", "state", "reason", "consumedTokens"], ["thread"]) && typeof body.member === "string" && HASH.test(body.member) && ["paused", "resumed"].includes(String(body.state)) && ["exhausted", "human", "rule"].includes(String(body.reason)) && Number.isSafeInteger(body.consumedTokens) && Number(body.consumedTokens) >= 0 && (body.thread === undefined || (typeof body.thread === "string" && THREAD.test(body.thread)));
    case "seam": return exactKeys(body, ["kind", "note", "spans"]) && typeof body.note === "string" && Array.isArray(body.spans) && body.spans.every((span) => isRecord(span) && exactKeys(span, ["fromEventId", "toEventId"]) && typeof span.fromEventId === "string" && UUID7.test(span.fromEventId) && typeof span.toEventId === "string" && UUID7.test(span.toEventId));
    case "seal": return exactKeys(body, ["kind", "chainHead", "eventCount", "seamsSha256"]) && HASH.test(String(body.chainHead)) && Number.isSafeInteger(body.eventCount) && Number(body.eventCount) >= 0 && HASH.test(String(body.seamsSha256));
    default: return false;
  }
}

function parseJson(source: string, maxBytes: number, label: string): unknown {
  if (Buffer.byteLength(source) > maxBytes) throw new Error(`${label} exceeds the size limit`);
  if (source.charCodeAt(0) === 0xfeff) throw new Error(`${label} must not contain a BOM`);
  assertNoDuplicateKeys(source);
  return JSON.parse(source);
}

function validateMember(value: unknown): value is Member {
  if (!isRecord(value) || !exactKeys(value, ["name", "role", "modelId", "publicKey", "fingerprint", "subscriptions", "budgetTokens", "tools"])) return false;
  if (typeof value.name !== "string" || value.name.length > 160 || !["human", "harness-agent"].includes(String(value.role)) || typeof value.modelId !== "string" || typeof value.publicKey !== "string" || typeof value.fingerprint !== "string" || !HASH.test(value.fingerprint) || !Array.isArray(value.subscriptions) || !value.subscriptions.every((x) => typeof x === "string" && THREAD.test(x)) || !Number.isSafeInteger(value.budgetTokens) || (value.budgetTokens as number) < 0 || !Array.isArray(value.tools) || !value.tools.every((x) => typeof x === "string")) return false;
  try {
    const der = Buffer.from(value.publicKey, "base64url");
    if (!der.length || der.toString("base64url") !== value.publicKey || hashHex(der) !== value.fingerprint) return false;
    return createPublicKey({ key: der, format: "der", type: "spki" }).asymmetricKeyType === "ed25519";
  } catch {
    return false;
  }
}

function trajectoryRowsForTurn(event: RecordValue, member: Member, sourceAgentId: string): RecordValue[] {
  const body = event.body as RecordValue;
  const authorRole = member.role === "human" ? "user" : "assistant";
  const text = body.text as string;
  if (event.author === sourceAgentId && member.role === "harness-agent" && text.trimStart().startsWith("{")) {
    let parsed: unknown;
    try { parsed = parseJson(text, MAX_LINE_BYTES, "structured MOLT turn"); } catch { parsed = undefined; }
    if (isRecord(parsed) && parsed.type === "praxis.tool_call") {
      if (!exactKeys(parsed, ["type", "tool_id", "action"], ["input", "failure_policy"]) || typeof parsed.tool_id !== "string" || !member.tools.includes(parsed.tool_id) || typeof parsed.action !== "string" || !parsed.action.trim() || parsed.action.length > 2000 || (parsed.input !== undefined && !isRecord(parsed.input)) || (parsed.failure_policy !== undefined && (typeof parsed.failure_policy !== "string" || parsed.failure_policy.length > 1000))) throw new Error("Signed MOLT tool call is malformed or outside its member's tool allowlist");
      return [{ event_id: event.id, role: "assistant", kind: "tool_call", content: { tool_id: parsed.tool_id, action: parsed.action, ...(isRecord(parsed.input) ? { input: parsed.input } : {}), ...(typeof parsed.failure_policy === "string" ? { failure_policy: parsed.failure_policy } : {}) } }];
    }
  }
  return [{ event_id: event.id, role: authorRole, kind: "message", content: text }];
}

function parseGenesis(source: string): { value: RecordValue; members: Map<string, Member>; threads: Set<string> } {
  const raw = parseJson(source, MAX_LINE_BYTES, "MOLT genesis");
  if (!isRecord(raw) || !exactKeys(raw, ["roomId", "roomName", "createdAt", "templateId", "templateVersion", "canonRule", "threads", "members"]) || typeof raw.roomId !== "string" || !ROOM.test(raw.roomId) || typeof raw.roomName !== "string" || !validTime(raw.createdAt) || typeof raw.templateId !== "string" || typeof raw.templateVersion !== "string" || !isRecord(raw.canonRule) || !exactKeys(raw.canonRule, ["id", "minCosigns"]) || typeof raw.canonRule.id !== "string" || !Number.isSafeInteger(raw.canonRule.minCosigns) || (raw.canonRule.minCosigns as number) < 0 || !Array.isArray(raw.threads) || !Array.isArray(raw.members) || !integerOnly(raw)) throw new Error("MOLT genesis is structurally invalid");
  const threads = new Set<string>();
  for (const item of raw.threads) {
    if (!isRecord(item) || !exactKeys(item, ["id", "title"]) || typeof item.id !== "string" || !THREAD.test(item.id) || typeof item.title !== "string" || item.title.length > 200 || threads.has(item.id)) throw new Error("MOLT genesis has an invalid or duplicate thread");
    threads.add(item.id);
  }
  const members = new Map<string, Member>();
  for (const item of raw.members) {
    if (!validateMember(item) || members.has(item.fingerprint)) throw new Error("MOLT genesis has an invalid or duplicate member");
    members.set(item.fingerprint, item);
  }
  if (!members.size) throw new Error("MOLT genesis must include at least one member");
  canonicalJson(raw);
  return { value: raw, members, threads };
}

function verifyEnvelope(value: unknown, roomId: string, seq: number, previousHash: string, keys: Map<string, Member>, threads: Set<string>): { event: RecordValue; eventHash: string; member: Member } {
  if (!isRecord(value) || !exactKeys(value, ["id", "roomId", "seq", "threadId", "author", "createdAt", "body", "prevHash", "hash", "signature"])) throw new Error(`MOLT event ${seq} has an invalid envelope`);
  if (typeof value.id !== "string" || !UUID7.test(value.id) || value.roomId !== roomId || value.seq !== seq || value.prevHash !== previousHash || !validTime(value.createdAt) || typeof value.author !== "string" || !HASH.test(value.author) || typeof value.hash !== "string" || !HASH.test(value.hash) || typeof value.signature !== "string" || !isRecord(value.body) || typeof value.body.kind !== "string" || !KINDS.has(value.body.kind) || !integerOnly(value)) throw new Error(`MOLT event ${seq} failed structural validation`);
  if (value.threadId !== null && (typeof value.threadId !== "string" || !threads.has(value.threadId))) throw new Error(`MOLT event ${seq} references an unknown thread`);
  if (["system", "seam", "seal"].includes(value.body.kind) && value.threadId !== null) throw new Error(`MOLT event ${seq} must be room-level`);
  if (!validBody(value.body)) throw new Error(`MOLT event ${seq} has an invalid typed body`);
  let member = keys.get(value.author);
  if (value.body.kind === "membership" && value.body.action === "join" && !member && validateMember(value.body.member)) member = value.body.member;
  if (!member) throw new Error(`MOLT event ${seq} has an unknown signer`);
  const payload = { ...value };
  delete payload.hash;
  delete payload.signature;
  const canonical = canonicalJson(payload);
  const digest = hashHex(canonical);
  if (digest !== value.hash) throw new Error(`MOLT event ${seq} hash mismatch`);
  let publicKey;
  try {
    publicKey = createPublicKey({ key: Buffer.from(member.publicKey, "base64url"), format: "der", type: "spki" });
  } catch {
    throw new Error(`MOLT event ${seq} signer key is invalid`);
  }
  const signature = Buffer.from(value.signature as string, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== value.signature || !verifyEd25519(null, Buffer.from(canonical), publicKey, signature)) throw new Error(`MOLT event ${seq} signature mismatch`);
  return { event: value, eventHash: digest, member };
}

export function verifyMoltTranscript(input: { genesis_json: string; transcript_jsonl: string; source_agent_id: string; expected_source_public_key: string; seams_markdown?: unknown; seal_snapshots?: unknown }): { trajectory: string; source_ref: Record<string, unknown>; room_id: string; event_count: number } {
  if (!HASH.test(input.source_agent_id)) throw new Error("source_agent_id must be a registered MOLT member fingerprint");
  if (Buffer.byteLength(input.transcript_jsonl) > 16_000_000) throw new Error("MOLT transcript exceeds 16 MB");
  if (input.transcript_jsonl.includes("\r") || input.transcript_jsonl.charCodeAt(0) === 0xfeff) throw new Error("MOLT transcript must use UTF-8 without BOM or CRLF");
  const genesis = parseGenesis(input.genesis_json);
  if (input.expected_source_public_key.length > 4096 || !/^[A-Za-z0-9_-]+$/.test(input.expected_source_public_key)) throw new Error("Registered MOLT source key is invalid");
  const lines = input.transcript_jsonl === "" ? [] : input.transcript_jsonl.replace(/\n$/, "").split("\n");
  if (!lines.length || lines.length > MAX_EVENTS || lines.some((line) => !line || Buffer.byteLength(line) > MAX_LINE_BYTES)) throw new Error("MOLT transcript line count or size is invalid");
  let previousHash = ZERO_HASH;
  const keys = new Map(genesis.members);
  const active = new Set(genesis.members.keys());
  const seenIds = new Set<string>();
  const priorEvents = new Map<string, { body: RecordValue }>();
  const resolvedChallenges = new Set<string>();
  const cosignedBy = new Set<string>();
  let currentRule = { ...(genesis.value.canonRule as { id: string; minCosigns: number }) };
  const rows: string[] = [];
  let sourceTurnCount = 0;
  let systemCount = 0;
  const seals: Array<{ seq: number; hash: string }> = [];
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    const value = parseJson(line, MAX_LINE_BYTES, `MOLT event ${index + 1}`);
    const verified = verifyEnvelope(value, genesis.value.roomId as string, index + 1, previousHash, keys, genesis.threads);
    const { event, member } = verified;
    if (seenIds.has(event.id as string)) throw new Error(`MOLT event ${index + 1} repeats an event id`);
    seenIds.add(event.id as string);
    const body = event.body as RecordValue;
    const joining = body.kind === "membership" && body.action === "join";
    if (!joining && !active.has(event.author as string)) throw new Error(`MOLT event ${index + 1} was signed by a non-member`);
    if (index === 0 && body.kind !== "system") throw new Error("MOLT transcript must begin with its system event");
    if (index > 0 && body.kind === "system") throw new Error("MOLT system event may appear only once");
    if (event.threadId !== null && !member.subscriptions.includes(event.threadId as string)) throw new Error(`MOLT event ${index + 1} is outside the signer's thread subscription`);
    if (body.kind === "system") {
      systemCount++;
      if (member.role !== "human" || systemCount !== 1 || body.genesisSha256 !== hashHex(canonicalJson(genesis.value)) || body.templateId !== genesis.value.templateId || body.templateVersion !== genesis.value.templateVersion) throw new Error("MOLT system event does not commit to the supplied genesis");
    } else if (body.kind === "membership") {
      const changed = body.member as Member;
      if (body.action === "join") {
        if (changed.fingerprint !== event.author || active.has(changed.fingerprint) || keys.has(changed.fingerprint)) throw new Error(`MOLT membership join ${index + 1} is not self-signed`);
        keys.set(changed.fingerprint, changed);
        active.add(changed.fingerprint);
      } else {
        if (changed.fingerprint !== event.author || changed.publicKey !== member.publicKey || !active.has(changed.fingerprint)) throw new Error(`MOLT membership leave ${index + 1} is invalid`);
        active.delete(changed.fingerprint);
      }
    } else if (body.kind === "challenge") {
      if (!priorEvents.has(String(body.targetEventId))) throw new Error(`MOLT challenge ${index + 1} does not reference an earlier event`);
    } else if (body.kind === "verdict") {
      const challenge = priorEvents.get(String(body.challengeId));
      if (challenge?.body.kind !== "challenge" || resolvedChallenges.has(String(body.challengeId))) throw new Error(`MOLT verdict ${index + 1} does not resolve one earlier challenge`);
      resolvedChallenges.add(String(body.challengeId));
    } else if (body.kind === "proposal") {
      if (isRecord(body.appliesTo) && !genesis.threads.has(String(body.appliesTo.thread))) throw new Error(`MOLT proposal ${index + 1} references an unknown thread`);
      if (body.supersedes !== undefined && priorEvents.get(String(body.supersedes))?.body.kind !== "proposal") throw new Error(`MOLT proposal ${index + 1} supersedes no earlier proposal`);
    } else if (body.kind === "cosign") {
      if (priorEvents.get(String(body.proposalId))?.body.kind !== "proposal") throw new Error(`MOLT cosign ${index + 1} references no earlier proposal`);
      const key = `${body.proposalId}\u0000${event.author}`;
      if (cosignedBy.has(key)) throw new Error(`MOLT member cosigned a proposal twice`);
      cosignedBy.add(key);
    } else if (body.kind === "canon") {
      if (priorEvents.get(String(body.proposalId))?.body.kind !== "proposal") throw new Error(`MOLT canon ${index + 1} references no earlier proposal`);
      let supporting = 0;
      for (const cosignId of body.cosigns as string[]) {
        const cosign = priorEvents.get(cosignId);
        if (cosign?.body.kind !== "cosign" || cosign.body.proposalId !== body.proposalId) throw new Error(`MOLT canon ${index + 1} cites an invalid cosign`);
        if (cosign.body.stance === "support") supporting++;
      }
      if (supporting < currentRule.minCosigns) throw new Error(`MOLT canon ${index + 1} does not meet the active cosign rule`);
      if (isRecord(body.newRule)) currentRule = { id: String(body.newRule.id), minCosigns: Number(body.newRule.minCosigns) };
    } else if (body.kind === "budget") {
      if (!keys.has(String(body.member)) || (typeof body.thread === "string" && !genesis.threads.has(body.thread))) throw new Error(`MOLT budget event ${index + 1} references an unknown member or thread`);
    } else if (body.kind === "seam") {
      if (member.role !== "human") throw new Error("MOLT seam events require a human signer");
      for (const span of body.spans as Array<RecordValue>) if (!priorEvents.has(String(span.fromEventId)) || !priorEvents.has(String(span.toEventId))) throw new Error(`MOLT seam ${index + 1} references an unknown event`);
    } else if (body.kind === "seal") {
      if (member.role !== "human" || body.chainHead !== event.prevHash || body.eventCount !== index) throw new Error(`MOLT seal ${index + 1} is invalid`);
      seals.push({ seq: index + 1, hash: String(body.seamsSha256) });
    } else if (body.kind === "turn") {
      if (event.author === input.source_agent_id && member.role === "harness-agent") sourceTurnCount++;
      rows.push(...trajectoryRowsForTurn(event, member, input.source_agent_id).map((row) => JSON.stringify(row)));
    }
    if (body.kind !== "turn") rows.push(JSON.stringify({ event_id: event.id, role: member.role === "human" ? "user" : "assistant", kind: "message", content: canonicalJson(body) }));
    priorEvents.set(String(event.id), { body });
    previousHash = verified.eventHash;
  }
  if (systemCount !== 1 || sourceTurnCount < 1) throw new Error("MOLT transcript needs one valid system event and a signed turn from the registered source agent");
  if (seals.length) {
    if (typeof input.seams_markdown !== "string" || Buffer.byteLength(input.seams_markdown) > 1_000_000 || hashHex(input.seams_markdown) !== seals.at(-1)!.hash) throw new Error("MOLT latest seal does not match the supplied seams.md");
    const snapshots = input.seal_snapshots;
    if (!isRecord(snapshots) || Object.keys(snapshots).length > 512) throw new Error("MOLT seal snapshots are required for every historical seal");
    let snapshotBytes = 0;
    for (const seal of seals.slice(0, -1)) {
      const snapshot = snapshots[`seams.${seal.seq}.md`];
      if (typeof snapshot !== "string") throw new Error(`MOLT seal snapshot seams.${seal.seq}.md is missing`);
      snapshotBytes += Buffer.byteLength(snapshot);
      if (snapshotBytes > 2_000_000 || hashHex(snapshot) !== seal.hash) throw new Error(`MOLT seal snapshot seams.${seal.seq}.md is invalid`);
    }
  }
  const sourceMember = keys.get(input.source_agent_id);
  const registeredKey = Buffer.from(input.expected_source_public_key, "base64url");
  if (!sourceMember || sourceMember.role !== "harness-agent" || sourceMember.publicKey !== input.expected_source_public_key || registeredKey.toString("base64url") !== input.expected_source_public_key || hashHex(registeredKey) !== input.source_agent_id) throw new Error("MOLT source agent is not the registered harness identity");
  return {
    trajectory: rows.join("\n"),
    source_ref: {
      source: "local",
      access: "local",
      retrieved_at: new Date().toISOString(),
      title: `molt-room ${genesis.value.roomId} signed transcript`,
      content_sha256: `sha256:${hashHex(input.transcript_jsonl)}`,
    },
    room_id: genesis.value.roomId as string,
    event_count: lines.length,
  };
}
