import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../src/config";
import { canonicalJson, contractHash, sha256 } from "../src/canonical";
import { PraxisDb } from "../src/db";
import { makeEvent, Ledger } from "../src/ledger";
import { newSkillId } from "../src/ids";
import { loadOrCreateSigningIdentity } from "../src/security";
import { PraxisService } from "../src/praxis";
import type { SkillContract } from "../src/types";

const root = mkdtempSync(join(tmpdir(), "praxis-benchmark-"));
const secrets = [crypto.randomUUID() + crypto.randomUUID(), crypto.randomUUID() + crypto.randomUUID(), crypto.randomUUID() + crypto.randomUUID()];
const config = loadConfig({
  PRAXIS_CONTROL_TOKEN: secrets[0],
  FOUNDRY_CONTROL_TOKEN: secrets[1],
  INTEGRATION_GATEWAY_TOKEN: secrets[2],
  PRAXIS_DATA_DIR: join(root, "data"),
});
const db = new PraxisDb(join(config.dataDir, "praxis.sqlite"));
const identity = loadOrCreateSigningIdentity(config.foundrySigningKeyPath);
const gatewayIdentity = loadOrCreateSigningIdentity(config.gatewaySigningKeyPath);
const ledger = new Ledger(db, identity, gatewayIdentity, config.executorWeightCap);
const praxis = new PraxisService(db, config, identity);

function contract(index: number): SkillContract {
  const title = `Document workflow ${index}`;
  return {
    id: newSkillId(),
    schema_version: "skill-contract-v1",
    agentbook_state: "canonical",
    risk_tier: 0,
    domain: "documentation",
    name: title,
    description: `Read and summarize document metadata for benchmark ${index}.`,
    trigger: { description: `When a document ${index} needs review`, lexical_hints: ["document", "review", `case${index}`] },
    workflow: [{ tool_id: "docs.read", action: `Read document metadata ${index}`, failure_policy: "stop", input: { record: String(index) } }],
    constraints: ["Do not write files"],
    forbidden_actions: ["delete files"],
    output_spec: { assertions: [{ path: "$.ok", op: "equals", expected: true }] },
    provenance: {
      trajectory_hashes: [sha256(`trajectory-${index}`)],
      extraction_model_sha: "a".repeat(40),
      sanitizer_version: "praxis-sanitizer/1.0.0",
      evidence_refs: [],
      eval_suites: ["output-spec-fixtures-v1"],
      human_approvers: [],
    },
  };
}

try {
  db.sqlite.query("INSERT INTO tool_registry(tool_id,risk_tier,enabled,updated_at) VALUES('docs.read',0,1,?)").run(new Date().toISOString());
  const snapshot = [{ tool_id: "docs.read", risk_tier: 0, enabled: true }];
  for (let index = 0; index < 1000; index++) {
    const value = contract(index);
    const hash = contractHash(value);
    const { molts_event_hash: _hash, ...payload } = value;
    const signature = identity.sign(payload);
    const event = makeEvent(identity, "skill.promoted", {
      contract: value,
      contract_hash: hash,
      contract_signature: signature,
      eval_fixtures_hash: sha256(canonicalJson([{ output: { ok: true } }])),
      tool_policy_snapshot: snapshot,
      tool_policy_hash: sha256(canonicalJson(snapshot)),
      approvals: [],
    });
    ledger.promote(value, signature, event);
  }

  const measurements: number[] = [];
  for (let index = 0; index < 50; index++) {
    const start = performance.now();
    const result = await praxis.recommend({ query: `document review case${index * 7}`, k: 5, deterministic: true });
    measurements.push(performance.now() - start);
    if (result.results.length === 0) throw new Error("Benchmark query returned no skills");
  }
  measurements.sort((a, b) => a - b);
  const p95 = measurements[Math.ceil(measurements.length * 0.95) - 1];
  const median = measurements[Math.floor(measurements.length / 2)];
  console.log(JSON.stringify({ skills: 1000, queries: measurements.length, retrieval_mode: "lexical", median_ms: Number(median.toFixed(3)), p95_ms: Number(p95.toFixed(3)), target_p95_ms: 5 }));
  if (p95 > 5) process.exitCode = 1;
} finally {
  db.close();
  rmSync(root, { recursive: true, force: true });
}
