import { randomUUID } from "node:crypto";
import type { Config } from "./config";
import type { PraxisDb } from "./db";
import { constantTimeEqual } from "./security";
import { IntegrityError } from "./errors";
import { sanitizeTrajectory } from "./sanitizer";
import { validateInputComplexity } from "./validation";
import type { SigningIdentity } from "./security";
import type { PraxisService } from "./praxis";
import type { PraxisMining } from "./mining";
import type { MoltRoom } from "./molt-room";
import type { Foundry } from "./foundry";
import type { IntegrationGateway } from "./gateway";
import type { IntelHub } from "./intel";

export interface AppServices {
  config: Config;
  db: PraxisDb;
  praxis: PraxisService;
  mining: PraxisMining;
  molt: MoltRoom;
  foundry: Foundry;
  gateway: IntegrationGateway;
  intel: IntelHub;
  foundryIdentity: SigningIdentity;
  gatewayIdentity: SigningIdentity;
  startedAt: number;
}

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

interface RateWindow {
  count: number;
  resetAt: number;
}

type HeaderResponse = Response & { withHeaders(headers: HeadersInit): Response };

function json(data: unknown, status = 200, requestId = ""): HeaderResponse {
  const response = new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "cross-origin-resource-policy": "same-origin",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      ...(requestId ? { "x-request-id": requestId } : {}),
    },
  });
  Object.defineProperty(response, "withHeaders", { value: (headers: HeadersInit) => mergeHeaders(response, headers) });
  return response as HeaderResponse;
}

function text(body: string, status = 200, requestId = "", extraHeaders: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "cross-origin-resource-policy": "same-origin",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      ...(requestId ? { "x-request-id": requestId } : {}),
      ...extraHeaders,
    },
  });
}

function errorResponse(error: unknown, requestId: string): Response {
  if (error instanceof IntegrityError) return json({ type: "about:blank", title: "integrity_failure", status: 500, detail: "Signed data failed integrity verification.", request_id: requestId }, 500, requestId);
  if (error instanceof HttpError) {
    return json({ type: "about:blank", title: error.code, status: error.status, detail: error.message, request_id: requestId }, error.status, requestId);
  }
  if (error instanceof SyntaxError) {
    return json({ type: "about:blank", title: "invalid_json", status: 400, detail: "Request body must be valid JSON.", request_id: requestId }, 400, requestId);
  }
  return json({ type: "about:blank", title: "internal_error", status: 500, detail: "The request could not be completed.", request_id: requestId }, 500, requestId);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requiredString(value: unknown, name: string, max = 4096): string {
  if (typeof value !== "string" || !value.trim() || Buffer.byteLength(value) > max) throw new HttpError(422, "invalid_request", `${name} must be a non-empty string up to ${max} bytes.`);
  return value;
}

function arrayOfRecords(value: unknown, name: string, max: number): Record<string, unknown>[] {
  if (!Array.isArray(value) || value.length > max || !value.every(isRecord)) throw new HttpError(422, "invalid_request", `${name} must be an array of at most ${max} objects.`);
  return value;
}

async function readJson(request: Request, maxBytes: number): Promise<unknown> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpError(415, "unsupported_media_type", "Send application/json.");
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (declaredLength > maxBytes) throw new HttpError(413, "payload_too_large", "Request body exceeds the configured size limit.");
  if (!request.body) throw new HttpError(400, "empty_body", "Request body is required.");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new HttpError(413, "payload_too_large", "Request body exceeds the configured size limit.");
      }
      chunks.push(item.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new HttpError(400, "invalid_json", "Request body must be valid UTF-8 JSON."); }
  const value = JSON.parse(text) as unknown;
  if (!validateInputComplexity(value, maxBytes)) throw new HttpError(413, "request_too_complex", "Request JSON exceeds structural limits.");
  return value;
}

function bearerToken(request: Request): string | undefined {
  const header = request.headers.get("authorization");
  if (!header || !header.startsWith("Bearer ") || header.length > 8192) return undefined;
  return header.slice(7);
}

function authorize(request: Request, roles: Array<"control" | "foundry" | "gateway">, config: Config): string {
  const token = bearerToken(request);
  if (!token) throw new HttpError(401, "unauthorized", "A valid bearer token is required.");
  const candidates: Array<["control" | "foundry" | "gateway", string]> = [
    ["control", config.controlToken],
    ["foundry", config.foundryToken],
    ["gateway", config.gatewayToken],
  ];
  let actor = "";
  for (const [role, key] of candidates) {
    const equal = constantTimeEqual(token, key);
    if (equal && roles.includes(role)) actor = role;
  }
  if (!actor) throw new HttpError(401, "unauthorized", "The bearer token is not authorized for this operation.");
  return actor;
}

function makeRateLimiter() {
  const windows = new Map<string, RateWindow>();
  let sweeps = 0;
  return (key: string, limit: number): void => {
    const now = Date.now();
    let window = windows.get(key);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + 60_000 };
      windows.set(key, window);
      if (windows.size > 10_000) {
        const oldest = windows.keys().next().value;
        if (oldest !== undefined) windows.delete(oldest);
      }
    }
    window.count++;
    if (++sweeps % 1024 === 0) for (const [id, value] of windows) if (value.resetAt <= now) windows.delete(id);
    if (window.count > limit) throw new HttpError(429, "rate_limit_exceeded", "Too many requests; retry after the current minute.");
  };
}

function publicBase(config: Config, request: Request): string {
  if (config.publicUrl) return config.publicUrl;
  return `http://127.0.0.1:${config.port}`;
}

function extractA2AText(value: unknown): string {
  if (!isRecord(value) || !isRecord(value.message) || !Array.isArray(value.message.parts)) throw new HttpError(422, "invalid_a2a_message", "A2A message.parts is required.");
  const text = value.message.parts.filter((part) => isRecord(part) && (part.kind === "text" || part.type === "text") && typeof part.text === "string").map((part) => String(part.text)).join("\n");
  return requiredString(text, "message text", 4096);
}

const mcpTools = [
  { name: "skill_recommend", description: "Find ranked, signed Praxis skills for a task. Retrieval is read-only.", inputSchema: { type: "object", properties: { query: { type: "string", minLength: 1, maxLength: 4096 }, k: { type: "integer", minimum: 1, maximum: 20 }, deterministic: { type: "boolean" }, include_tier2: { type: "boolean" } }, required: ["query"], additionalProperties: false } },
  { name: "skill_get", description: "Fetch a canonical signed skill contract and its derived statistics.", inputSchema: { type: "object", properties: { skill_id: { type: "string", pattern: "^skill_[0-9A-HJKMNP-TV-Z]{26}$" }, include_tier2: { type: "boolean" } }, required: ["skill_id"], additionalProperties: false } },
  { name: "intel_search", description: "Search legal metadata sources and return evidence references; no full text is downloaded.", inputSchema: { type: "object", properties: { query: { type: "string", minLength: 1, maxLength: 500 }, sources: { type: "array", items: { type: "string" }, maxItems: 8 }, doi: { type: "string", maxLength: 300 }, include_security: { type: "boolean" } }, required: ["query"], additionalProperties: false } },
];

async function handleMcp(request: Request, services: AppServices, requestId: string): Promise<Response> {
  const body = await readJson(request, services.config.maxBodyBytes);
  if (!isRecord(body) || body.jsonrpc !== "2.0" || typeof body.method !== "string") throw new HttpError(400, "invalid_json_rpc", "Invalid JSON-RPC request.");
  const id = body.id;
  let selectedProtocol = "2025-03-26";
  const responseHeaders = { "MCP-Protocol-Version": selectedProtocol };
  if (body.method === "notifications/initialized" || (body.id === undefined && body.method.startsWith("notifications/"))) return new Response(null, { status: 202, headers: responseHeaders });
  if (body.method === "initialize") {
    const params = isRecord(body.params) ? body.params : {};
    const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : "2025-03-26";
    const supported = new Set(["2025-03-26", "2025-06-18", "2024-11-05"]);
    const protocolVersion = supported.has(requested) ? requested : "2025-03-26";
    selectedProtocol = protocolVersion;
    responseHeaders["MCP-Protocol-Version"] = selectedProtocol;
    return json({ jsonrpc: "2.0", id, result: { protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: { name: "praxis-stack", version: "1.0.0" } } }, 200, requestId).withHeaders(responseHeaders);
  }
  if (body.method === "ping") return json({ jsonrpc: "2.0", id, result: {} }, 200, requestId).withHeaders(responseHeaders);
  if (body.method === "tools/list") return json({ jsonrpc: "2.0", id, result: { tools: mcpTools } }, 200, requestId).withHeaders(responseHeaders);
  if (body.method !== "tools/call") return json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } }, 200, requestId).withHeaders(responseHeaders);
  const params = isRecord(body.params) ? body.params : {};
  const name = params.name;
  const args = isRecord(params.arguments) ? params.arguments : {};
  try {
    let result: unknown;
    if (name === "skill_recommend") {
      const includeTier2 = args.include_tier2 === true;
      if (includeTier2) authorize(request, ["control"], services.config);
      result = await services.praxis.recommend({ query: requiredString(args.query, "query", 4096), k: typeof args.k === "number" ? args.k : undefined, deterministic: args.deterministic === true, include_tier2: includeTier2 });
    } else if (name === "skill_get") {
      const includeTier2 = args.include_tier2 === true;
      if (includeTier2) authorize(request, ["control"], services.config);
      const skill = services.praxis.getSkill(requiredString(args.skill_id, "skill_id", 64));
      result = skill && (skill.contract.risk_tier < 2 || includeTier2) ? skill : { error: "skill_not_found" };
    } else if (name === "intel_search") {
      result = await services.intel.search({ query: requiredString(args.query, "query", 2000), sources: Array.isArray(args.sources) ? args.sources as string[] : undefined, doi: typeof args.doi === "string" ? args.doi : undefined, include_security: args.include_security === true });
    } else {
      return json({ jsonrpc: "2.0", id, error: { code: -32602, message: "Unknown tool" } }, 200, requestId).withHeaders(responseHeaders);
    }
    const text = JSON.stringify(result);
    return json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }], structuredContent: result, isError: false } }, 200, requestId).withHeaders(responseHeaders);
  } catch (error) {
    const raw = error instanceof Error ? error.message : "Tool call failed";
    const safe = Buffer.byteLength(raw) <= 2048 ? sanitizeTrajectory(raw, 2048) : undefined;
    const detail = !safe || safe.quarantined ? "Tool call rejected by validation or policy." : safe.content.slice(0, 500);
    return json({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: detail }], isError: true } }, 200, requestId).withHeaders(responseHeaders);
  }
}

function mergeHeaders(response: Response, headers: HeadersInit): Response {
  const merged = new Headers(response.headers);
  for (const [name, value] of new Headers(headers)) merged.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: merged });
}

export function createHandler(services: AppServices) {
  const rateLimit = makeRateLimiter();
  const app = async (request: Request, server?: Bun.Server<unknown>): Promise<Response> => {
    const requestId = randomUUID();
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const client = server?.requestIP(request)?.address ?? "local";
    const write = method !== "GET" && method !== "HEAD";
    try {
      if (path === "/healthz" && method === "GET") return json({ status: "ok", uptime_seconds: Math.floor((Date.now() - services.startedAt) / 1000) }, 200, requestId);
      if (path === "/readyz" && method === "GET") {
        const check = services.db.sqlite.query("PRAGMA quick_check").get() as Record<string, string>;
        if (!check || Object.values(check)[0] !== "ok") throw new HttpError(503, "not_ready", "Database integrity check failed.");
        return json({ status: "ready", database: "ok", execution_backend: services.config.executionBackend }, 200, requestId);
      }
      rateLimit(`${client}:${path}`, write ? 60 : 120);

      if ((path === "/.well-known/agent.json" || path === "/.well-known/agent-card.json") && method === "GET") {
        const base = publicBase(services.config, request);
        return json({ protocolVersion: "0.3.0", name: "Praxis", description: "Signed, risk-gated skill retrieval and execution.", url: `${base}/api/v1/a2a`, preferredTransport: "JSONRPC", version: "1.0.0", capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: true }, defaultInputModes: ["text/plain", "application/json"], defaultOutputModes: ["application/json", "text/plain"], skills: [{ id: "skill_recommend", name: "Recommend skills", description: "Find relevant, signed skills by task description.", tags: ["skills", "retrieval"] }, { id: "intel_search", name: "Search evidence", description: "Search legal metadata sources.", tags: ["evidence", "research"] }] }, 200, requestId);
      }
      if (path === "/api/v1/keys" && method === "GET") return json({ foundry: { fingerprint: services.foundryIdentity.fingerprint, public_key_pem: services.foundryIdentity.publicKeyPem }, gateway: { fingerprint: services.gatewayIdentity.fingerprint, public_key_pem: services.gatewayIdentity.publicKeyPem } }, 200, requestId);
      if (path === "/openapi.json" && method === "GET") return json(openApiDocument, 200, requestId);
      if (path === "/mcp" && method === "POST") return handleMcp(request, services, requestId);
      if (path === "/api/v1/a2a" && method === "POST") {
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body) || body.jsonrpc !== "2.0" || body.method !== "message/send") throw new HttpError(400, "invalid_a2a_request", "Only A2A message/send is supported.");
        const params = isRecord(body.params) ? body.params : {};
        const query = extractA2AText(params);
        const result = await services.praxis.recommend({ query, k: 5 });
        return json({ jsonrpc: "2.0", id: body.id ?? null, result: { id: `task_${randomUUID()}`, status: { state: "completed" }, artifacts: [{ name: "praxis-recommendations", parts: [{ kind: "data", data: result }] }] } }, 200, requestId);
      }

      if (path === "/api/v1/praxis/recommend" && method === "POST") {
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const includeTier2 = body.include_tier2 === true;
        if (includeTier2) authorize(request, ["control"], services.config);
        return json(await services.praxis.recommend({ query: requiredString(body.query, "query", 4096), k: typeof body.k === "number" ? body.k : undefined, deterministic: body.deterministic === true, include_tier2: includeTier2, query_embeddings: body.query_embeddings }), 200, requestId);
      }
      const skillMatch = path.match(/^\/api\/v1\/praxis\/skills\/(skill_[0-9A-HJKMNP-TV-Z]{26})$/);
      if (skillMatch && method === "GET") {
        const includeTier2 = url.searchParams.get("include_tier2") === "true";
        if (includeTier2) authorize(request, ["control"], services.config);
        const skill = services.praxis.getSkill(skillMatch[1]);
        if (!skill || (skill.contract.risk_tier === 2 && !includeTier2)) throw new HttpError(404, "skill_not_found", "No canonical skill matches this id.");
        return json(skill, 200, requestId);
      }
      if (path === "/api/v1/praxis/embeddings" && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body) || typeof body.skill_id !== "string" || typeof body.contract_hash !== "string" || typeof body.model !== "string" || typeof body.model_sha !== "string") throw new HttpError(422, "invalid_request", "skill_id, contract_hash, model, and model_sha are required.");
        const result = services.praxis.addEmbedding({ skill_id: body.skill_id, contract_hash: body.contract_hash, model: body.model, model_sha: body.model_sha, vector: body.vector, activate: body.activate === true });
        services.db.audit(requestId, actor, "embedding.upsert", { skill_id: body.skill_id, model: body.model, model_sha: body.model_sha });
        return json(result, 201, requestId);
      }
      if (path === "/api/v1/praxis/ingest" && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = await services.mining.ingest(body);
        services.db.audit(requestId, actor, "trajectory.ingest", { ingest_id: result.ingest_id, state: result.state, flags: result.flags });
        return json(result, 201, requestId);
      }

      if (path === "/api/v1/intel/search" && method === "POST") {
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        return json(await services.intel.search({ query: requiredString(body.query, "query", 2000), sources: Array.isArray(body.sources) ? body.sources as string[] : undefined, doi: typeof body.doi === "string" ? body.doi : undefined, include_security: body.include_security === true }), 200, requestId);
      }
      if (path === "/api/v1/intel/exploit-db/refresh" && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const result = await services.intel.refreshExploitDb();
        services.db.audit(requestId, actor, "intel.exploit_db.refresh", { records: result.records, refreshed_at: result.refreshed_at });
        return json(result, 200, requestId);
      }
      if (path === "/api/v1/molt/agents" && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = services.molt.registerAgent(requiredString(body.agent_id, "agent_id", 120));
        services.db.audit(requestId, actor, "molt.agent.register", { agent_id: body.agent_id });
        return json(result, 201, requestId);
      }
      if (path === "/api/v1/molt/agents" && method === "GET") {
        authorize(request, ["control"], services.config);
        return json(services.molt.listAgents(), 200, requestId);
      }
      if (path === "/api/v1/molt/identities" && method === "GET") {
        authorize(request, ["control"], services.config);
        return json(services.molt.listIdentities(), 200, requestId);
      }
      if (path === "/api/v1/molt/identities" && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = services.molt.registerIdentity({ agent_id: requiredString(body.agent_id, "agent_id", 64), public_key: requiredString(body.public_key, "public_key", 4096) });
        services.db.audit(requestId, actor, "molt.identity.register", { agent_id: result.agent_id, fingerprint: result.fingerprint });
        return json(result, 201, requestId);
      }
      const identityMatch = path.match(/^\/api\/v1\/molt\/identities\/([0-9a-f]{64})$/);
      if (identityMatch && method === "DELETE") {
        const actor = authorize(request, ["control"], services.config);
        services.molt.disableIdentity(identityMatch[1]);
        services.db.audit(requestId, actor, "molt.identity.disable", { agent_id: identityMatch[1] });
        return json({ agent_id: identityMatch[1], enabled: false }, 200, requestId);
      }
      if (path === "/api/v1/molt/import" && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxMoltImportBytes);
        const result = await services.molt.ingestSignedTranscript(body);
        services.db.audit(requestId, actor, "molt.transcript.import", { ingest_id: result.ingest_id, state: result.state, flags: result.flags });
        return json(result, 201, requestId);
      }
      const agentMatch = path.match(/^\/api\/v1\/molt\/agents\/([a-zA-Z0-9][a-zA-Z0-9._:-]{0,119})$/);
      if (agentMatch && method === "DELETE") {
        const actor = authorize(request, ["control"], services.config);
        services.molt.disableAgent(decodeURIComponent(agentMatch[1]));
        services.db.audit(requestId, actor, "molt.agent.disable", { agent_id: agentMatch[1] });
        return json({ agent_id: agentMatch[1], enabled: false }, 200, requestId);
      }
      if (path === "/api/v1/molt/rooms" && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = services.molt.createRoom({ name: requiredString(body.name, "name", 160), created_by: requiredString(body.created_by, "created_by", 120) });
        services.db.audit(requestId, actor, "molt.room.create", { room_id: result.room_id });
        return json(result, 201, requestId);
      }
      if (path === "/api/v1/molt/rooms" && method === "GET") {
        authorize(request, ["control"], services.config);
        return json(services.molt.listRooms(Number(url.searchParams.get("limit") ?? 100)), 200, requestId);
      }
      const roomMessages = path.match(/^\/api\/v1\/molt\/rooms\/(room_[0-9A-HJKMNP-TV-Z]{26})\/messages$/);
      if (roomMessages && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = services.molt.postMessage({ room_id: roomMessages[1], agent_id: requiredString(body.agent_id, "agent_id", 120), role: requiredString(body.role, "role", 12), kind: requiredString(body.kind, "kind", 24), content: body.content });
        let praxisReply: unknown = null;
        const storedContent = isRecord(result) ? result.content : undefined;
        const messageText = typeof storedContent === "string" ? storedContent : isRecord(storedContent) && typeof storedContent.text === "string" ? storedContent.text : "";
        const mention = messageText.match(/^\s*@praxis\s+([\s\S]{1,4096})$/i);
        if (body.role === "user" && mention) {
          const recommendations = await services.praxis.recommend({ query: mention[1].trim(), k: 5 });
          const reviewAlerts = recommendations.results.filter(isRecord).filter((result) => result.needs_review === true).map((result) => ({ skill_id: isRecord(result.skill) ? result.skill.id : undefined, drift: result.drift }));
          praxisReply = services.molt.postMessage({ room_id: roomMessages[1], agent_id: "praxis", role: "assistant", kind: "message", content: { type: "skill_recommendations", query: mention[1].trim(), recommendations, review_alerts: reviewAlerts } });
        }
        services.db.audit(requestId, actor, "molt.message.add", { room_id: roomMessages[1] });
        return json(praxisReply ? { message: result, praxis_reply: praxisReply } : result, 201, requestId);
      }
      if (roomMessages && method === "GET") {
        authorize(request, ["control"], services.config);
        return json(services.molt.history(roomMessages[1], url.searchParams.get("before") ?? undefined, Number(url.searchParams.get("limit") ?? 100)), 200, requestId);
      }
      const roomExport = path.match(/^\/api\/v1\/molt\/rooms\/(room_[0-9A-HJKMNP-TV-Z]{26})\/export\.jsonl$/);
      if (roomExport && method === "GET") {
        authorize(request, ["control"], services.config);
        return text(services.molt.exportJsonl(roomExport[1]), 200, requestId, { "content-disposition": `attachment; filename=\"${roomExport[1]}.jsonl\"` });
      }
      const roomComplete = path.match(/^\/api\/v1\/molt\/rooms\/(room_[0-9A-HJKMNP-TV-Z]{26})\/complete$/);
      if (roomComplete && method === "POST") {
        const actor = authorize(request, ["control"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = await services.molt.complete(roomComplete[1], {
          source_agent_id: requiredString(body.source_agent_id, "source_agent_id", 120), summary: body.summary, domain: body.domain,
          output_spec: body.output_spec, constraints: body.constraints, forbidden_actions: body.forbidden_actions, supersedes: body.supersedes, evidence_refs: body.evidence_refs,
        });
        services.db.audit(requestId, actor, "molt.task.complete", { room_id: roomComplete[1], ingest_id: isRecord(result) ? result.ingest_id : undefined });
        return json(result, 201, requestId);
      }

      if (path === "/api/v1/foundry/tools" && method === "GET") {
        authorize(request, ["foundry"], services.config);
        const rows = services.db.sqlite.query("SELECT tool_id,risk_tier,enabled,updated_at FROM tool_registry ORDER BY tool_id").all();
        return json(rows, 200, requestId);
      }
      if (path === "/api/v1/foundry/tools" && method === "POST") {
        const actor = authorize(request, ["foundry"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body) || typeof body.tool_id !== "string" || ![0, 1, 2].includes(Number(body.risk_tier))) throw new HttpError(422, "invalid_request", "tool_id and risk_tier 0, 1, or 2 are required.");
        services.foundry.setToolPolicy(body.tool_id, Number(body.risk_tier) as 0 | 1 | 2, body.enabled !== false);
        services.db.audit(requestId, actor, "foundry.tool_policy.set", { tool_id: body.tool_id, risk_tier: body.risk_tier, enabled: body.enabled !== false });
        return json({ tool_id: body.tool_id, risk_tier: body.risk_tier, enabled: body.enabled !== false }, 200, requestId);
      }
      if (path === "/api/v1/foundry/approvers" && method === "POST") {
        const actor = authorize(request, ["foundry"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const approver = requiredString(body.approver_id, "approver_id", 80);
        const key = requiredString(body.public_key_pem, "public_key_pem", 16_384);
        services.foundry.registerApprover(approver, key);
        services.db.audit(requestId, actor, "foundry.approver.register", { approver_id: approver });
        return json({ approver_id: approver, registered: true }, 201, requestId);
      }
      if (path === "/api/v1/foundry/approvers" && method === "GET") {
        authorize(request, ["foundry"], services.config);
        return json(services.foundry.listApprovers(), 200, requestId);
      }
      const approverMatch = path.match(/^\/api\/v1\/foundry\/approvers\/([a-zA-Z0-9][a-zA-Z0-9._-]{0,79})$/);
      if (approverMatch && method === "DELETE") {
        const actor = authorize(request, ["foundry"], services.config);
        services.foundry.disableApprover(approverMatch[1]);
        services.db.audit(requestId, actor, "foundry.approver.disable", { approver_id: approverMatch[1] });
        return json({ approver_id: approverMatch[1], enabled: false }, 200, requestId);
      }
      if (path === "/api/v1/foundry/approvals" && method === "POST") {
        const body = await readJson(request, services.config.maxBodyBytes);
        return json(services.foundry.submitApproval(body), 201, requestId);
      }
      if (path === "/api/v1/foundry/drafts" && method === "GET") {
        authorize(request, ["foundry"], services.config);
        return json(services.foundry.listDrafts(Number(url.searchParams.get("limit") ?? 100)), 200, requestId);
      }
      if (path === "/api/v1/foundry/quarantine" && method === "GET") {
        authorize(request, ["foundry"], services.config);
        return json(services.mining.listQuarantine(Number(url.searchParams.get("limit") ?? 100)), 200, requestId);
      }
      if (path === "/api/v1/foundry/drift" && method === "GET") {
        authorize(request, ["foundry"], services.config);
        return json(services.praxis.listNeedsReview(Number(url.searchParams.get("limit") ?? 100)), 200, requestId);
      }
      if (path === "/api/v1/foundry/prepare" && method === "POST") {
        const actor = authorize(request, ["foundry"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const fixtures = arrayOfRecords(body.fixtures, "fixtures", 100) as never[];
        const approvers = Array.isArray(body.approver_ids) && body.approver_ids.every((item) => typeof item === "string") ? body.approver_ids as string[] : [];
        const prepared = services.foundry.prepare(requiredString(body.ingest_id, "ingest_id", 64), fixtures, approvers);
        services.db.audit(requestId, actor, "foundry.skill.prepare", { ingest_id: body.ingest_id, risk_tier: prepared.risk_tier, contract_hash: prepared.contract_hash });
        return json(prepared, 200, requestId);
      }
      if (path === "/api/v1/foundry/promote" && method === "POST") {
        const actor = authorize(request, ["foundry"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const fixtures = arrayOfRecords(body.fixtures, "fixtures", 100) as never[];
        const approvers = Array.isArray(body.approver_ids) && body.approver_ids.every((item) => typeof item === "string") ? body.approver_ids as string[] : [];
        const result = services.foundry.promote(requiredString(body.ingest_id, "ingest_id", 64), fixtures, approvers, isRecord(body.graduation_report) ? body.graduation_report as never : undefined);
        services.db.audit(requestId, actor, "foundry.skill.promote", { skill_id: result.skill_id, risk_tier: result.risk_tier, event_hash: result.event_hash });
        return json(result, 201, requestId);
      }
      const quarantineReview = path.match(/^\/api\/v1\/foundry\/quarantine\/([A-Za-z0-9_-]{1,64})\/review$/);
      if (quarantineReview && method === "POST") {
        const actor = authorize(request, ["foundry"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = services.foundry.reviewQuarantine(quarantineReview[1], body);
        services.db.audit(requestId, actor, "foundry.quarantine.review", { ingest_id: quarantineReview[1], decision: result.decision });
        return json(result, 201, requestId);
      }
      if (path === "/api/v1/foundry/deprecate" && method === "POST") {
        const actor = authorize(request, ["foundry"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = services.foundry.deprecate(requiredString(body.skill_id, "skill_id", 64), requiredString(body.reason, "reason", 1000));
        services.db.audit(requestId, actor, "foundry.skill.deprecate", { skill_id: body.skill_id, event_hash: result.event_hash });
        return json(result, 200, requestId);
      }
      if (path === "/api/v1/foundry/verify" && method === "GET") {
        authorize(request, ["foundry"], services.config);
        return json(services.foundry.verify(), 200, requestId);
      }
      if (path === "/api/v1/foundry/rebuild" && method === "POST") {
        const actor = authorize(request, ["foundry"], services.config);
        const before = services.foundry.verify();
        if (before.errors.some((item) => !item.startsWith("derived "))) throw new HttpError(409, "ledger_integrity_failure", "Signed ledger verification failed; derived caches were not rebuilt.");
        services.foundry.rebuild();
        const after = services.foundry.verify();
        services.db.audit(requestId, actor, "foundry.stats.rebuild", { valid: after.valid, head_hash: after.head_hash });
        return json(after, after.valid ? 200 : 500, requestId);
      }

      if (path === "/api/v1/gateway/agents" && method === "POST") {
        const actor = authorize(request, ["gateway"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = services.gateway.registerAgent({ agent_id: requiredString(body.agent_id, "agent_id", 120), name: requiredString(body.name, "name", 120), description: typeof body.description === "string" ? body.description : "", url: typeof body.url === "string" ? body.url : undefined, capabilities: body.capabilities });
        services.db.audit(requestId, actor, "gateway.agent.register", { agent_id: body.agent_id });
        return json(result, 201, requestId);
      }
      const gatewayAgentMatch = path.match(/^\/api\/v1\/gateway\/agents\/([a-zA-Z0-9][a-zA-Z0-9._:-]{0,119})$/);
      if (gatewayAgentMatch && method === "DELETE") {
        const actor = authorize(request, ["gateway"], services.config);
        services.gateway.disableAgent(gatewayAgentMatch[1]);
        services.db.audit(requestId, actor, "gateway.agent.disable", { agent_id: gatewayAgentMatch[1] });
        return json({ agent_id: gatewayAgentMatch[1], enabled: false }, 200, requestId);
      }
      if (path === "/api/v1/gateway/registry" && method === "GET") return json(services.gateway.listRegistry(), 200, requestId);
      if (path === "/api/v1/gateway/execute" && method === "POST") {
        const actor = authorize(request, ["gateway"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be an object.");
        const result = await services.gateway.execute({ skill_id: requiredString(body.skill_id, "skill_id", 64), executor_agent: requiredString(body.executor_agent, "executor_agent", 120), input: body.input, idempotency_key: requiredString(body.idempotency_key, "idempotency_key", 128) });
        services.db.audit(requestId, actor, "gateway.skill.execute", { skill_id: body.skill_id, execution_id: result.execution_id, outcome: result.outcome });
        return json(result, 200, requestId);
      }
      if (path === "/api/v1/gateway/self-report" && method === "POST") {
        const actor = authorize(request, ["gateway"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body) || !["success", "failure", "partial"].includes(String(body.outcome))) throw new HttpError(422, "invalid_request", "A self-report outcome is required.");
        const result = await services.gateway.selfReport({ skill_id: requiredString(body.skill_id, "skill_id", 64), executor_agent: requiredString(body.executor_agent, "executor_agent", 120), outcome: body.outcome as "success" | "failure" | "partial", idempotency_key: requiredString(body.idempotency_key, "idempotency_key", 128) });
        services.db.audit(requestId, actor, "gateway.skill.self_report", { skill_id: body.skill_id, event_id: isRecord(result.event) ? result.event.event_id : undefined });
        return json(result, 201, requestId);
      }
      if (path === "/api/v1/gateway/graduation" && method === "POST") {
        authorize(request, ["gateway"], services.config);
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body) || !isRecord(body.contract)) throw new HttpError(422, "invalid_request", "contract is required.");
        const result = await services.gateway.graduate({ contract: body.contract as never, fixtures: arrayOfRecords(body.fixtures, "fixtures", 100) as never[], run_id: typeof body.run_id === "string" ? body.run_id : undefined });
        return json(result, 201, requestId);
      }
      if (path === "/api/v1/outcomes" && method === "POST") {
        const body = await readJson(request, services.config.maxBodyBytes);
        if (!isRecord(body)) throw new HttpError(422, "invalid_request", "Body must be a signed event.");
        const result = services.gateway.acceptOutcome(body as never);
        return json(result, 201, requestId);
      }

      if (path === "/api/v1/metrics" && method === "GET") {
        authorize(request, ["control", "foundry", "gateway"], services.config);
        const counts = services.db.sqlite.query(`SELECT (SELECT COUNT(*) FROM contracts WHERE state='canonical') AS canonical_skills,
          (SELECT COUNT(*) FROM contracts WHERE state='deprecated') AS deprecated_skills,
          (SELECT COUNT(*) FROM ingest_records WHERE state='quarantined') AS quarantined_trajectories,
          (SELECT COUNT(*) FROM events) AS ledger_events,
          (SELECT COUNT(*) FROM gateway_agents WHERE enabled=1) AS registered_agents`).get();
        return json({ ...counts as Record<string, number>, execution_backend: services.config.executionBackend }, 200, requestId);
      }

      if (path.startsWith("/api/") || path === "/mcp") throw new HttpError(404, "not_found", "No route matches this path.");
      return json({ type: "about:blank", title: "not_found", status: 404, detail: "No route matches this path.", request_id: requestId }, 404, requestId);
    } catch (error) {
      if (error instanceof HttpError) return errorResponse(error, requestId);
      if (error instanceof IntegrityError || (error instanceof Error && error.name !== "Error" && !(error instanceof SyntaxError))) {
        console.error(JSON.stringify({ level: "error", request_id: requestId, path, error_name: error.name }));
        return errorResponse(error, requestId);
      }
      if (error instanceof Error && !(error instanceof SyntaxError)) {
        const raw = error.message;
        const safe = Buffer.byteLength(raw) <= 2048 ? sanitizeTrajectory(raw, 2048) : undefined;
        const detail = !safe || safe.quarantined ? "Request rejected by validation or policy." : safe.content;
        return errorResponse(new HttpError(422, "request_rejected", detail.slice(0, 500)), requestId);
      }
      console.error(JSON.stringify({ level: "error", request_id: requestId, path, error_name: "unknown" }));
      return errorResponse(error, requestId);
    }
  };
  return app;
}

const openApiDocument = {
  openapi: "3.1.0",
  info: { title: "Praxis Stack API", version: "1.0.0", description: "Local-first, cryptographically auditable skill lifecycle." },
  servers: [{ url: "http://127.0.0.1:8787" }],
  paths: {
    "/api/v1/praxis/recommend": { post: { summary: "Hybrid skill retrieval", requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["query"], properties: { query: { type: "string", maxLength: 4096 }, k: { type: "integer", minimum: 1, maximum: 20 }, deterministic: { type: "boolean" } } } } } }, responses: { "200": { description: "Ranked canonical skills" } } } },
    "/api/v1/praxis/ingest": { post: { summary: "Sanitize and mine a trajectory", security: [{ bearerAuth: [] }], responses: { "201": { description: "Draft or quarantined trajectory" } } } },
    "/api/v1/foundry/promote": { post: { summary: "Evaluate and risk-gate a draft", security: [{ bearerAuth: [] }], responses: { "201": { description: "Signed canonical contract" } } } },
    "/api/v1/foundry/drift": { get: { summary: "List canonical skills whose recent outcomes indicate review is warranted", security: [{ bearerAuth: [] }], responses: { "200": { description: "Derived drift signals" } } } },
    "/api/v1/gateway/execute": { post: { summary: "Execute a canonical skill", security: [{ bearerAuth: [] }], responses: { "200": { description: "Execution result and signed outcome event" } } } },
    "/api/v1/intel/search": { post: { summary: "Search legal evidence metadata", responses: { "200": { description: "Evidence references" } } } },
    "/api/v1/intel/exploit-db/refresh": { post: { summary: "Refresh the metadata-only Exploit-DB index", security: [{ bearerAuth: [] }], responses: { "200": { description: "Indexed metadata row count" } } } },
    "/mcp": { post: { summary: "Stateless MCP JSON-RPC endpoint", responses: { "200": { description: "MCP response" } } } },
    "/api/v1/a2a": { post: { summary: "A2A message/send endpoint", responses: { "200": { description: "Completed retrieval task" } } } },
  },
  components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
};
