import { createHash, timingSafeEqual } from "node:crypto";
import { createReadStream, lstatSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

function envString(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} must be set`);
  return value.trim();
}

export interface EmbedderSidecarEnv {
  port: number;
  token: string;
  model: string;
  modelSha: string;
  dims?: number;
  cacheDir: string;
}

export function loadEmbedderEnv(env: NodeJS.ProcessEnv = process.env): EmbedderSidecarEnv {
  const port = Number(env.EMBEDDER_SIDECAR_PORT ?? "8792");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("EMBEDDER_SIDECAR_PORT must be an integer between 1 and 65535");
  const token = envString("EMBEDDER_SIDECAR_TOKEN");
  if (Buffer.byteLength(token) < 32) throw new Error("EMBEDDER_SIDECAR_TOKEN must contain at least 32 bytes");
  const model = envString("EMBEDDER_SIDECAR_MODEL", "Xenova/all-MiniLM-L6-v2");
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(model)) throw new Error("EMBEDDER_SIDECAR_MODEL must be a plain Hugging Face model id");
  const modelSha = (env.EMBEDDER_SIDECAR_MODEL_SHA ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(modelSha)) throw new Error("EMBEDDER_SIDECAR_MODEL_SHA must be the full 64-hex sha256 digest of the pinned ONNX weights");
  const dimsRaw = env.EMBEDDER_SIDECAR_DIMS;
  const dims = dimsRaw === undefined ? undefined : Number(dimsRaw);
  if (dims !== undefined && (!Number.isInteger(dims) || dims < 1 || dims > 8192)) throw new Error("EMBEDDER_SIDECAR_DIMS must be an integer between 1 and 8192");
  const cacheDir = resolve(envString("EMBEDDER_SIDECAR_CACHE_DIR", "./data/embedder-cache"));
  return { port, token, model, modelSha, dims, cacheDir };
}

export function largestOnnxFile(dir: string, depth = 0): { path: string; size: number } | undefined {
  if (depth > 6) return undefined;
  let entries: string[];
  try {
    if (!lstatSync(dir).isDirectory()) return undefined;
    entries = readdirSync(dir);
  } catch {
    return undefined;
  }
  let best: { path: string; size: number } | undefined;
  for (const entry of entries) {
    const path = join(dir, entry);
    let stat;
    try {
      stat = lstatSync(path);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      const nested = largestOnnxFile(path, depth + 1);
      if (nested && (!best || nested.size > best.size)) best = nested;
    } else if (entry.toLowerCase().endsWith(".onnx") && stat.isFile() && (!best || stat.size > best.size)) {
      best = { path, size: stat.size };
    }
  }
  return best;
}

async function fileSha256(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

type Extractor = (texts: string[], options: { pooling: string; normalize: boolean }) => Promise<{ data: Float32Array }>;

let extractor: Extractor | undefined;

async function loadExtractor(env: EmbedderSidecarEnv): Promise<Extractor> {
  if (extractor) return extractor;
  let pipeline: (task: string, model: string, options?: Record<string, unknown>) => Promise<unknown>;
  try {
    const transformers = await import("@huggingface/transformers");
    pipeline = transformers.pipeline as typeof pipeline;
  } catch {
    throw new Error("The embedder runtime is not installed; run `cd sidecar && bun install --frozen-lockfile` and restart the sidecar.");
  }
  const loaded = (await pipeline("feature-extraction", env.model, { dtype: "q8", cache_dir: env.cacheDir })) as unknown as Extractor;
  const largest = largestOnnxFile(env.cacheDir);
  if (!largest) throw new Error("No local ONNX weights were found in the configured cache; refusing to use unverified model files.");
  const digest = await fileSha256(largest.path);
  if (digest !== env.modelSha) throw new Error(`Embedding model digest mismatch: disk reports ${digest}, configured ${env.modelSha}.`);
  extractor = loaded;
  return loaded;
}

export async function embedTexts(env: EmbedderSidecarEnv, texts: string[]): Promise<number[][]> {
  const model = await loadExtractor(env);
  const output = await model(texts, { pooling: "mean", normalize: true });
  const data = output.data;
  const dims = data.length / texts.length;
  if (!Number.isInteger(dims) || dims < 1 || dims > 8192) throw new Error(`Embedding backend returned an impossible dimensionality: ${dims}`);
  if (env.dims !== undefined && dims !== env.dims) throw new Error(`Embedding backend returned ${dims} dimensions; ${env.dims} were configured.`);
  const vectors: number[][] = [];
  for (let i = 0; i < texts.length; i++) {
    const vector: number[] = [];
    for (let j = 0; j < dims; j++) vector.push(data[i * dims + j]);
    vectors.push(vector);
  }
  return vectors;
}

async function readBoundedBody(request: Request, maxBytes: number): Promise<string> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") throw new HttpFailure(415, "Send application/json.");
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > maxBytes) throw new HttpFailure(413, "Request body exceeds the size limit.");
  const reader = request.body?.getReader();
  if (!reader) throw new HttpFailure(400, "Request body is required.");
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new HttpFailure(413, "Request body exceeds the size limit.");
    }
    chunks.push(value);
  }
  reader.releaseLock();
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

class HttpFailure extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export function createEmbedderServer(env: EmbedderSidecarEnv): ReturnType<typeof Bun.serve> {
  return Bun.serve({
    port: env.port,
    hostname: "127.0.0.1",
    reusePort: false,
    async fetch(request) {
      const started = performance.now();
      const url = new URL(request.url);
      try {
        if (request.method === "GET" && url.pathname === "/healthz") {
          return Response.json({ status: "ok", model: env.model, model_sha: env.modelSha, loaded: extractor !== undefined });
        }
        if (request.method !== "POST" || url.pathname !== "/embed") throw new HttpFailure(404, "Only POST /embed is served.");
        const authorization = request.headers.get("authorization");
        if (!authorization?.startsWith("Bearer ") || !safeEqual(authorization.slice(7), env.token)) throw new HttpFailure(401, "A valid bearer token is required.");
        const body = JSON.parse(await readBoundedBody(request, 262_144)) as Record<string, unknown>;
        if (body === null || typeof body !== "object") throw new HttpFailure(400, "Body must be a JSON object.");
        if (body.model !== env.model || String(body.model_sha ?? "").toLowerCase() !== env.modelSha) throw new HttpFailure(400, "model and model_sha must match the configured embedding model.");
        const texts = body.texts;
        if (!Array.isArray(texts) || texts.length < 1 || texts.length > 16 || !texts.every((item) => typeof item === "string" && item.length > 0 && item.length <= 8192)) {
          throw new HttpFailure(400, "texts must contain 1-16 non-empty strings of at most 8192 characters.");
        }
        const vectors = await embedTexts(env, texts as string[]);
        console.log(JSON.stringify({ level: "info", event: "embed", texts: texts.length, dims: vectors[0]?.length ?? 0, duration_ms: Math.round(performance.now() - started) }));
        return Response.json({ model: env.model, model_sha: env.modelSha, vectors });
      } catch (error) {
        if (error instanceof HttpFailure) return Response.json({ error: error.message }, { status: error.status });
        if (error instanceof SyntaxError) return Response.json({ error: "Request body must be valid JSON." }, { status: 400 });
        const kind = error instanceof Error ? error.name : "UnknownError";
        console.log(JSON.stringify({ level: "error", event: "embed_failed", kind }));
        return Response.json({ error: "The embedding request failed or the pinned model could not be verified." }, { status: 503 });
      }
    },
  });
  console.log(JSON.stringify({ level: "info", event: "listening", port: env.port, model: env.model }));
}

if (import.meta.main) {
  createEmbedderServer(loadEmbedderEnv());
}
