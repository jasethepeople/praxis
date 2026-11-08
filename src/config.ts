import { homedir } from "node:os";
import { isAbsolute, relative, resolve, sep } from "node:path";

export interface Config {
  bindHost: string;
  port: number;
  publicUrl?: string;
  controlToken: string;
  foundryToken: string;
  gatewayToken: string;
  dataDir: string;
  dbPath: string;
  foundrySigningKeyPath: string;
  gatewaySigningKeyPath: string;
  foundryPublicKeyPath?: string;
  gatewayPublicKeyPath?: string;
  approverRegistryPath?: string;
  embedderUrl?: string;
  embedderModel?: string;
  embedderModelSha?: string;
  minerUrl?: string;
  minerToken?: string;
  minerModelSha?: string;
  executionBackend: "stub" | "t340";
  t340Url?: string;
  t340Token?: string;
  unpaywallEmail?: string;
  githubToken?: string;
  nvdApiKey?: string;
  maxBodyBytes: number;
  maxMoltImportBytes: number;
  maxQueryCandidates: number;
  halfLifeDays: number;
  executorWeightCap: number;
  tier0AuditRate: number;
}

function required(name: string, value: string | undefined): string {
  if (!value) throw new Error(`${name} must be set`);
  if (Buffer.byteLength(value) < 32) throw new Error(`${name} must contain at least 32 bytes`);
  return value;
}

function loopbackServiceUrl(name: string, raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const url = new URL(raw);
  if (!["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname) || url.protocol !== "http:" || url.username || url.password) {
    throw new Error(`${name} must use plain HTTP on loopback only, without embedded credentials`);
  }
  return url.toString().replace(/\/$/, "");
}

function boundedNumber(name: string, value: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(value ?? fallback);
  if (!Number.isFinite(n) || n < min || n > max) throw new Error(`${name} must be between ${min} and ${max}`);
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const port = boundedNumber("PORT", env.PORT ?? env.PRAXIS_PORT, 8787, 1, 65535);
  const controlToken = required("PRAXIS_CONTROL_TOKEN", env.PRAXIS_CONTROL_TOKEN);
  const foundryToken = required("FOUNDRY_CONTROL_TOKEN", env.FOUNDRY_CONTROL_TOKEN);
  const gatewayToken = required("INTEGRATION_GATEWAY_TOKEN", env.INTEGRATION_GATEWAY_TOKEN);
  if (new Set([controlToken, foundryToken, gatewayToken]).size !== 3) throw new Error("Control tokens must be distinct");

  let publicUrl: string | undefined;
  if (env.PRAXIS_PUBLIC_URL) {
    const parsed = new URL(env.PRAXIS_PUBLIC_URL);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("PRAXIS_PUBLIC_URL must be a clean HTTPS origin or base path");
    publicUrl = parsed.toString().replace(/\/$/, "");
  }

  const bindHost = env.PRAXIS_BIND_HOST ?? "127.0.0.1";
  if (!["127.0.0.1", "localhost", "::1", "0.0.0.0"].includes(bindHost)) throw new Error("PRAXIS_BIND_HOST is not allowed");
  if (bindHost === "0.0.0.0" && env.PRAXIS_PUBLIC_BEHIND_TLS !== "true") {
    throw new Error("Binding to 0.0.0.0 requires PRAXIS_PUBLIC_BEHIND_TLS=true and a trusted TLS reverse proxy");
  }

  const model = env.PRAXIS_EMBEDDER_MODEL;
  const modelSha = env.PRAXIS_EMBEDDER_MODEL_SHA;
  if ((model && !modelSha) || (!model && modelSha)) throw new Error("PRAXIS_EMBEDDER_MODEL and PRAXIS_EMBEDDER_MODEL_SHA must be set together");
  if (modelSha && !/^[0-9a-f]{40}$/i.test(modelSha)) throw new Error("PRAXIS_EMBEDDER_MODEL_SHA must be a 40-character SHA");

  const executionBackend = env.PRAXIS_EXECUTION_BACKEND ?? "stub";
  if (executionBackend !== "stub" && executionBackend !== "t340") throw new Error("PRAXIS_EXECUTION_BACKEND must be stub or t340");
  const minerUrl = loopbackServiceUrl("PRAXIS_MINER_URL", env.PRAXIS_MINER_URL);
  const minerModelSha = env.PRAXIS_MINER_MODEL_SHA?.toLowerCase();
  if (minerUrl && (!env.PRAXIS_MINER_TOKEN || Buffer.byteLength(env.PRAXIS_MINER_TOKEN) < 32 || !minerModelSha || !/^[0-9a-f]{40}$/.test(minerModelSha))) throw new Error("PRAXIS_MINER_URL requires PRAXIS_MINER_TOKEN (32+ bytes) and PRAXIS_MINER_MODEL_SHA (40 hex characters)");

  const t340Url = loopbackServiceUrl("PRAXIS_T340_URL", env.PRAXIS_T340_URL);
  if (executionBackend === "t340" && (!t340Url || !env.PRAXIS_T340_TOKEN || Buffer.byteLength(env.PRAXIS_T340_TOKEN) < 32)) {
    throw new Error("T340 mode requires loopback PRAXIS_T340_URL and a PRAXIS_T340_TOKEN of at least 32 bytes");
  }

  const dataDir = resolve(env.PRAXIS_DATA_DIR ?? "./data");
  if ([resolve("/"), resolve(homedir()), resolve(process.cwd())].includes(dataDir)) throw new Error("PRAXIS_DATA_DIR must be a dedicated subdirectory, not a shared workspace or home directory");
  const dbPath = resolve(env.PRAXIS_DB_PATH ?? `${dataDir}/praxis.sqlite`);
  const foundrySigningKeyPath = resolve(env.FOUNDRY_SIGNING_KEY_PATH ?? `${dataDir}/foundry-ed25519.pem`);
  const gatewaySigningKeyPath = resolve(env.GATEWAY_SIGNING_KEY_PATH ?? `${dataDir}/gateway-ed25519.pem`);
  for (const path of [dbPath, foundrySigningKeyPath, gatewaySigningKeyPath]) {
    const rel = relative(dataDir, path);
    if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("Database and signing-key paths must stay inside PRAXIS_DATA_DIR");
  }
  return {
    bindHost,
    port,
    publicUrl,
    controlToken,
    foundryToken,
    gatewayToken,
    dataDir,
    dbPath,
    foundrySigningKeyPath,
    gatewaySigningKeyPath,
    foundryPublicKeyPath: env.FOUNDRY_PUBLIC_KEY_PATH ? resolve(env.FOUNDRY_PUBLIC_KEY_PATH) : undefined,
    gatewayPublicKeyPath: env.GATEWAY_PUBLIC_KEY_PATH ? resolve(env.GATEWAY_PUBLIC_KEY_PATH) : undefined,
    approverRegistryPath: env.PRAXIS_APPROVER_REGISTRY_PATH ? resolve(env.PRAXIS_APPROVER_REGISTRY_PATH) : undefined,
    embedderUrl: loopbackServiceUrl("PRAXIS_EMBEDDER_URL", env.PRAXIS_EMBEDDER_URL),
    embedderModel: model,
    embedderModelSha: modelSha?.toLowerCase(),
    minerUrl,
    minerToken: env.PRAXIS_MINER_TOKEN,
    minerModelSha,
    executionBackend,
    t340Url,
    t340Token: env.PRAXIS_T340_TOKEN,
    unpaywallEmail: env.UNPAYWALL_EMAIL,
    githubToken: env.GITHUB_TOKEN,
    nvdApiKey: env.NVD_API_KEY,
    maxBodyBytes: boundedNumber("PRAXIS_MAX_BODY_BYTES", env.PRAXIS_MAX_BODY_BYTES, 1_048_576, 1024, 16_777_216),
    maxMoltImportBytes: boundedNumber("PRAXIS_MAX_MOLT_IMPORT_BYTES", env.PRAXIS_MAX_MOLT_IMPORT_BYTES, 24_000_000, 1_048_576, 32_000_000),
    maxQueryCandidates: boundedNumber("PRAXIS_MAX_QUERY_CANDIDATES", env.PRAXIS_MAX_QUERY_CANDIDATES, 200, 10, 1000),
    halfLifeDays: boundedNumber("PRAXIS_STATS_HALF_LIFE_DAYS", env.PRAXIS_STATS_HALF_LIFE_DAYS, 90, 1, 3650),
    executorWeightCap: boundedNumber("PRAXIS_EXECUTOR_WEIGHT_CAP", env.PRAXIS_EXECUTOR_WEIGHT_CAP, 5, 1, 1000),
    tier0AuditRate: boundedNumber("FOUNDRY_TIER0_AUDIT_RATE", env.FOUNDRY_TIER0_AUDIT_RATE, 0.1, 0, 1),
  };
}
