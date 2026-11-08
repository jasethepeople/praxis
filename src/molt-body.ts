export type MOLTBody = Record<string, unknown>;

type RecordValue = Record<string, unknown>;
const UUID7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const THREAD = /^[a-z0-9-]{1,64}$/;

function record(value: unknown): value is RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value: RecordValue, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function text(value: unknown): value is string {
  return typeof value === "string";
}

function uint(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function evidence(value: unknown): boolean {
  if (!record(value) || typeof value.type !== "string") return false;
  if (value.type === "event") return exact(value, ["type", "id"]) && typeof value.id === "string" && UUID7.test(value.id);
  return value.type === "external" && exact(value, ["type", "url", "sha256"], ["note"]) && text(value.url) && typeof value.sha256 === "string" && HASH.test(value.sha256) && (value.note === undefined || text(value.note));
}

function rule(value: unknown): boolean {
  return record(value) && exact(value, ["id", "minCosigns"]) && text(value.id) && uint(value.minCosigns);
}

export function validMoltBody(body: unknown): body is MOLTBody {
  if (!record(body) || typeof body.kind !== "string") return false;
  switch (body.kind) {
    case "system":
      return exact(body, ["kind", "genesisSha256", "templateId", "templateVersion"]) && typeof body.genesisSha256 === "string" && HASH.test(body.genesisSha256) && text(body.templateId) && text(body.templateVersion);
    case "membership":
      return exact(body, ["kind", "action", "member"]) && ["join", "leave"].includes(String(body.action)) && record(body.member);
    case "turn": {
      if (!exact(body, ["kind", "text"], ["usage", "artifact"]) || !text(body.text) || body.text.length === 0 || body.text.length > 250_000) return false;
      if (body.usage !== undefined && (!record(body.usage) || !exact(body.usage, ["inputTokens", "outputTokens"]) || !uint(body.usage.inputTokens) || !uint(body.usage.outputTokens))) return false;
      if (body.artifact !== undefined && (!record(body.artifact) || !exact(body.artifact, ["path", "sha256", "bytes"]) || !text(body.artifact.path) || typeof body.artifact.sha256 !== "string" || !HASH.test(body.artifact.sha256) || !uint(body.artifact.bytes))) return false;
      return true;
    }
    case "challenge":
      return exact(body, ["kind", "targetEventId", "claim", "grounds", "evidence"]) && typeof body.targetEventId === "string" && UUID7.test(body.targetEventId) && text(body.claim) && ["factual", "procedural", "doctrinal"].includes(String(body.grounds)) && Array.isArray(body.evidence) && body.evidence.every(evidence);
    case "verdict":
      return exact(body, ["kind", "challengeId", "outcome", "evidence", "rationale"]) && typeof body.challengeId === "string" && UUID7.test(body.challengeId) && ["upheld", "refuted", "unproven"].includes(String(body.outcome)) && Array.isArray(body.evidence) && body.evidence.every(evidence) && text(body.rationale);
    case "proposal":
      return exact(body, ["kind", "statement", "appliesTo"], ["supersedes"]) && text(body.statement) && (body.appliesTo === "room" || (record(body.appliesTo) && exact(body.appliesTo, ["thread"]) && text(body.appliesTo.thread) && THREAD.test(body.appliesTo.thread))) && (body.supersedes === undefined || (text(body.supersedes) && UUID7.test(body.supersedes)));
    case "cosign":
      return exact(body, ["kind", "proposalId", "stance"]) && text(body.proposalId) && UUID7.test(body.proposalId) && ["support", "oppose"].includes(String(body.stance));
    case "canon":
      return exact(body, ["kind", "action", "proposalId", "cosigns", "reason"], ["newRule"]) && ["enact", "demote"].includes(String(body.action)) && text(body.proposalId) && UUID7.test(body.proposalId) && Array.isArray(body.cosigns) && body.cosigns.every((id) => text(id) && UUID7.test(id)) && text(body.reason) && (body.newRule === undefined || (body.action === "enact" && rule(body.newRule)));
    case "budget":
      return exact(body, ["kind", "member", "state", "reason", "consumedTokens"], ["thread"]) && typeof body.member === "string" && HASH.test(body.member) && ["paused", "resumed"].includes(String(body.state)) && ["exhausted", "human", "rule"].includes(String(body.reason)) && uint(body.consumedTokens) && (body.thread === undefined || (text(body.thread) && THREAD.test(body.thread)));
    case "seam":
      return exact(body, ["kind", "note", "spans"]) && text(body.note) && Array.isArray(body.spans) && body.spans.every((span) => record(span) && exact(span, ["fromEventId", "toEventId"]) && text(span.fromEventId) && UUID7.test(span.fromEventId) && text(span.toEventId) && UUID7.test(span.toEventId));
    case "seal":
      return exact(body, ["kind", "chainHead", "eventCount", "seamsSha256"]) && typeof body.chainHead === "string" && HASH.test(body.chainHead) && uint(body.eventCount) && typeof body.seamsSha256 === "string" && HASH.test(body.seamsSha256);
    default:
      return false;
  }
}
