import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../src/config";
import { PraxisDb } from "../src/db";
import { Foundry } from "../src/foundry";
import { Ledger } from "../src/ledger";
import { PraxisMining } from "../src/mining";
import { PraxisService } from "../src/praxis";
import { loadOrCreateSigningIdentity } from "../src/security";
import type { SkillContract } from "../src/types";
import { createHash } from "node:crypto";

const help = `Usage: bun run eval
Retrieval accuracy and latency benchmark over a synthetic bank with known-correct skills.
Embeddings use a deterministic hashing vector (384-dim), a stand-in for MiniLM that measures
the retrieval plumbing (FTS + cosine + RRF + Thompson ranking), not MiniLM quality.`;

if (process.argv.includes("-h") || process.argv.includes("--help")) {
  console.log(help);
  process.exit(0);
}

const TOPICS = [
  { domain: "documentation", name: "Read document metadata", hints: ["document", "metadata", "read", "summary"], action: "Read the document metadata and summarize fields" },
  { domain: "data-quality", name: "Validate JSON schema", hints: ["json", "schema", "validate", "parse"], action: "Parse the JSON document and validate its schema" },
  { domain: "research", name: "Verify citation metadata", hints: ["citation", "doi", "metadata", "verify"], action: "Compare citation fields and flag missing identifiers" },
  { domain: "security", name: "Triage vulnerability advisory", hints: ["vulnerability", "advisory", "cve", "triage"], action: "Look up the advisory and summarize affected versions" },
  { domain: "operations", name: "Rotate log archive", hints: ["log", "archive", "rotate", "compress"], action: "Compress the log archive and record the checksum" },
  { domain: "documentation", name: "Diff document revisions", hints: ["document", "diff", "revision", "compare"], action: "Compare two document revisions and list changes" },
  { domain: "data-quality", name: "Deduplicate records", hints: ["records", "duplicate", "dedupe", "clean"], action: "Find duplicate records and keep the newest" },
  { domain: "research", name: "Expand search keywords", hints: ["search", "keywords", "expand", "query"], action: "Expand the query with synonyms and rank by novelty" },
];

const root = mkdtempSync(join(tmpdir(), "praxis-eval-"));
const secrets = [crypto.randomUUID() + crypto.randomUUID(), crypto.randomUUID() + crypto.randomUUID(), crypto.randomUUID() + crypto.randomUUID()];
const sha64 = createHash("sha256").update("eval-embedder").digest("hex");
const config = loadConfig({
  PRAXIS_CONTROL_TOKEN: secrets[0],
  FOUNDRY_CONTROL_TOKEN: secrets[1],
  INTEGRATION_GATEWAY_TOKEN: secrets[2],
  PRAXIS_DATA_DIR: join(root, "data"),
  PRAXIS_EMBEDDER_TIMEOUT_MS: "2000",
});
const db = new PraxisDb(":memory:");
const identity = loadOrCreateSigningIdentity(config.foundrySigningKeyPath);
const gatewayIdentity = loadOrCreateSigningIdentity(config.gatewaySigningKeyPath);
const ledger = new Ledger(db, identity, gatewayIdentity, config.executorWeightCap);
const foundry = new Foundry(db, ledger, identity, gatewayIdentity, config);
const mining = new PraxisMining(db, config);
const praxis = new PraxisService(db, config, identity);
foundry.setToolPolicy("docs.read", 0, true);
db.sqlite.query("INSERT INTO agents(agent_id,enabled,created_at) VALUES('eval-agent',1,?) ON CONFLICT(agent_id) DO NOTHING").run(new Date().toISOString());

function hashingVector(text: string, dims = 384): number[] {
  const vector = new Array<number>(dims).fill(0);
  for (const token of new Set(text.toLowerCase().match(/[a-z0-9]{3,}/g) ?? [])) {
    const digest = createHash("sha256").update(token).digest();
    const index = ((digest[0] | (digest[1] << 8)) % dims + dims) % dims;
    vector[index] += digest[2] % 2 === 0 ? 1 : -1;
  }
  const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
  return norm > 0 ? vector.map((value) => value / norm) : vector;
}

const model = "Xenova/all-MiniLM-L6-v2";
const embedderServer = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch: async (request) => {
    const body = JSON.parse(await request.text()) as { model: string; model_sha: string; texts: string[] };
    if (body.model !== model || body.model_sha !== sha64) return Response.json({ error: "model identity mismatch" }, { status: 400 });
    return Response.json({ model: body.model, model_sha: body.model_sha, vectors: body.texts.map((text) => hashingVector(text)) });
  },
});

function contractFor(topicIndex: number, variant: number): SkillContract {
  const topic = TOPICS[topicIndex];
  const name = `${topic.name} (variant ${variant})`;
  return {
    id: "",
    schema_version: "skill-contract-v1",
    agentbook_state: "draft",
    risk_tier: 0,
    domain: topic.domain,
    name,
    description: `${topic.name}: ${topic.action}. Variant ${variant} of the same known-correct procedure.`,
    trigger: { description: `When a task needs ${topic.name.toLowerCase()}`, lexical_hints: topic.hints },
    workflow: [{ tool_id: "docs.read", action: topic.action, failure_policy: "stop", input: { variant } }],
    constraints: ["Read-only"],
    forbidden_actions: ["delete files"],
    output_spec: { assertions: [{ path: "$.ok", op: "equals", expected: true }] },
    provenance: {
      trajectory_hashes: ["sha256:" + createHash("sha256").update(`${topicIndex}-${variant}`).digest("hex")],
      extraction_model_sha: sha64,
      sanitizer_version: "praxis-sanitizer/1.0.0",
      evidence_refs: [],
      eval_suites: ["output-spec-fixtures-v1"],
      human_approvers: [],
    },
  };
}

const VARIANTS = 5;
const expected: string[][] = [];
let seeded = 0;
try {
  for (let topicIndex = 0; topicIndex < TOPICS.length; topicIndex++) {
    const correct: string[] = [];
    for (let variant = 0; variant < VARIANTS; variant++) {
      const result = await mining.ingest({
        source_agent_id: "eval-agent",
        trajectory: JSON.stringify([{ role: "assistant", kind: "tool_call", tool_id: "docs.read", action: TOPICS[topicIndex].action }]),
        candidate: contractFor(topicIndex, variant),
        domain: TOPICS[topicIndex].domain,
      });
      if (result.state !== "draft" || !result.skill_id) throw new Error(`seed failed: topic ${topicIndex} variant ${variant}`);
      const promoted = foundry.promote(result.ingest_id, [{ output: { ok: true } }]);
      correct.push(promoted.skill_id);
      const contractHash = (db.sqlite.query("SELECT contract_hash FROM contracts WHERE skill_id=?").get(promoted.skill_id) as { contract_hash: string }).contract_hash;
      praxis.addEmbedding({ skill_id: promoted.skill_id, contract_hash: contractHash, model, model_sha: sha64, vector: hashingVector(`${TOPICS[topicIndex].name} ${TOPICS[topicIndex].hints.join(" ")} variant ${variant}`) });
      seeded++;
    }
    expected.push(correct);
  }

  const latencies: number[] = [];
  let top1 = 0;
  let top5 = 0;
  let queries = 0;
  for (let topicIndex = 0; topicIndex < TOPICS.length; topicIndex++) {
    const query = `${TOPICS[topicIndex].name} ${TOPICS[topicIndex].hints.join(" ")}`;
    const started = performance.now();
    const result = await praxis.recommend({ query, k: 5, deterministic: true });
    latencies.push(performance.now() - started);
    queries++;
    const returned = result.results.map((entry) => (entry as { skill: { id: string } }).skill.id);
    if (returned.length && expected[topicIndex].includes(returned[0])) top1++;
    if (returned.some((id) => expected[topicIndex].includes(id))) top5++;
  }
  latencies.sort((a, b) => a - b);
  const p = (quantile: number) => Number(latencies[Math.min(latencies.length - 1, Math.ceil(latencies.length * quantile) - 1)].toFixed(3));
  const report = {
    skills: seeded,
    queries,
    recall_at_1: Number((top1 / queries).toFixed(3)),
    recall_at_5: Number((top5 / queries).toFixed(3)),
    latency_including_query_embedding_ms: { median: p(0.5), p95: p(0.95) },
    retrieval_mode: "hybrid",
    note: "Embeddings are deterministic hashing vectors; recall measures retrieval plumbing, not MiniLM quality.",
  };
  console.log(JSON.stringify(report, null, 2));
  if (report.recall_at_1 < 0.75 || report.recall_at_5 < 1) process.exitCode = 1;
} finally {
  embedderServer.stop(true);
  db.closeCheckpoint();
  db.close();
  rmSync(root, { recursive: true, force: true });
}
