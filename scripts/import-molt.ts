import { lstatSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

function usage(): never {
  console.log("Usage: bun scripts/import-molt.ts --room <room-id> --source-agent <fingerprint> --output-spec <json-file> [--summary TEXT] [--domain NAME] [--api URL] [--home PATH] [--register-source]");
  console.log("Reads the signed MOLT Room genesis/transcript and submits them to Praxis. PRAXIS_CONTROL_TOKEN must be set in the environment.");
  process.exit(0);
}

function options(args: string[]): Map<string, string | true> {
  const result = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const key = args[i]!;
    if (key === "--help" || key === "-h") usage();
    if (key === "--register-source") {
      if (result.has(key)) throw new Error(`${key} was specified more than once`);
      result.set(key, true);
      continue;
    }
    if (!new Set(["--room", "--source-agent", "--output-spec", "--summary", "--domain", "--api", "--home"]).has(key) || result.has(key)) throw new Error(`Unknown or duplicate option: ${key}`);
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error(`${key} requires a value`);
    result.set(key, value);
  }
  return result;
}

function readPrivateFile(path: string, maxBytes: number): string {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes || (stat.mode & 0o077) !== 0) throw new Error(`Refusing non-private, non-regular, or oversized file: ${path}`);
  return readFileSync(path, "utf8");
}

async function boundedJson(response: Response, maxBytes = 1_000_000): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Praxis returned an empty response");
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("Praxis response exceeds the size limit");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function safeApiUrl(value: string): string {
  const url = new URL(value);
  const loopback = url.hostname === "localhost" || url.hostname === "::1" || /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
  if (url.username || url.password || url.search || url.hash || !((url.protocol === "https:" && url.hostname) || (url.protocol === "http:" && loopback))) throw new Error("Praxis URL must be HTTPS or loopback HTTP, without credentials or query parameters");
  return url.toString().replace(/\/$/, "");
}

async function post(api: string, token: string, path: string, body: unknown): Promise<unknown> {
  const response = await fetch(`${api}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
  });
  const result = await boundedJson(response);
  if (!response.ok) throw new Error(`Praxis ${path} failed with HTTP ${response.status}: ${JSON.stringify(result).slice(0, 1000)}`);
  return result;
}

async function main() {
  const parsed = options(process.argv.slice(2));
  const roomId = parsed.get("--room");
  const sourceAgentId = parsed.get("--source-agent");
  const outputSpecPath = parsed.get("--output-spec");
  if (typeof roomId !== "string" || typeof sourceAgentId !== "string" || typeof outputSpecPath !== "string") usage();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9a-f]{8}$/.test(roomId) || !/^[0-9a-f]{64}$/.test(sourceAgentId)) throw new Error("Invalid room id or source-agent fingerprint");
  const token = process.env.PRAXIS_CONTROL_TOKEN;
  if (!token || Buffer.byteLength(token) < 32) throw new Error("PRAXIS_CONTROL_TOKEN must be set to the Praxis control token");
  const api = safeApiUrl(typeof parsed.get("--api") === "string" ? parsed.get("--api") as string : process.env.PRAXIS_URL ?? "http://127.0.0.1:8787");
  const configuredHome = typeof parsed.get("--home") === "string" ? parsed.get("--home") as string : process.env.ROOM_HOME ?? join(homedir(), ".the-room");
  const home = resolve(isAbsolute(configuredHome) ? configuredHome : join(process.cwd(), configuredHome));
  const room = resolve(home, "rooms", roomId);
  const relativeRoom = relative(home, room);
  if (!relativeRoom || relativeRoom.startsWith(`..${sep}`) || relativeRoom === "..") throw new Error("Room path escapes MOLT home");
  for (const path of [home, join(home, "rooms"), room]) {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("MOLT home, rooms, and room paths must be real directories, not symlinks");
  }
  const genesisJson = readPrivateFile(join(room, "genesis.json"), 65_536);
  const transcriptJsonl = readPrivateFile(join(room, "transcript.jsonl"), 16_000_000);
  let seamsMarkdown: string | undefined;
  try {
    seamsMarkdown = readPrivateFile(join(room, "seams.md"), 1_000_000);
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes("ENOENT")) throw error;
  }
  const genesis = JSON.parse(genesisJson) as { members?: Array<{ fingerprint?: string; publicKey?: string }> };
  const transcriptEvents = transcriptJsonl.trimEnd().split("\n").map((line) => JSON.parse(line) as { body?: { kind?: string; action?: string; member?: { fingerprint?: string; publicKey?: string } } });
  let source = genesis.members?.find((member) => member.fingerprint === sourceAgentId);
  for (const event of transcriptEvents) {
    if (event.body?.kind === "membership" && event.body.action === "join" && event.body.member?.fingerprint === sourceAgentId) source = event.body.member;
  }
  if (!source || typeof source.publicKey !== "string") throw new Error("Source agent must appear in the room genesis or a signed membership join");
  const seals = transcriptEvents.flatMap((event, index) => event.body?.kind === "seal" ? [index + 1] : []);
  const sealSnapshots: Record<string, string> = {};
  for (const sequence of seals.slice(0, -1)) sealSnapshots[`seams.${sequence}.md`] = readPrivateFile(join(room, `seams.${sequence}.md`), 1_000_000);
  const outputSpec = JSON.parse(readPrivateFile(resolve(outputSpecPath), 1_000_000)) as unknown;
  if (outputSpec === null || typeof outputSpec !== "object" || Array.isArray(outputSpec)) throw new Error("Output specification must be a JSON object");
  if (parsed.has("--register-source")) await post(api, token, "/api/v1/molt/identities", { agent_id: sourceAgentId, public_key: source.publicKey });
  const result = await post(api, token, "/api/v1/molt/import", {
    source_agent_id: sourceAgentId,
    genesis_json: genesisJson,
    transcript_jsonl: transcriptJsonl,
    summary: typeof parsed.get("--summary") === "string" ? parsed.get("--summary") : "Imported MOLT workflow",
    domain: typeof parsed.get("--domain") === "string" ? parsed.get("--domain") : "general",
    output_spec: outputSpec,
    ...(seamsMarkdown !== undefined ? { seams_markdown: seamsMarkdown } : {}),
    ...(seals.length ? { seal_snapshots: sealSnapshots } : {}),
  });
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "MOLT import failed";
  console.error(message.slice(0, 1200));
  process.exitCode = 1;
});
