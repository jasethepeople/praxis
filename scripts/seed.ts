import { loadConfig } from "../src/config";
import { PraxisDb } from "../src/db";
import { Foundry } from "../src/foundry";
import { Ledger } from "../src/ledger";
import { PraxisMining } from "../src/mining";
import { loadOrCreateSigningIdentity } from "../src/security";

const help = "Usage: bun run seed\nSeeds three signed tier-0 demonstration skills into an empty Praxis database.";
const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  console.log(help);
  process.exit(0);
}
if (args.length) {
  console.error(help);
  process.exit(2);
}

const config = loadConfig();
const db = new PraxisDb(config.dbPath);
try {
  const foundryIdentity = loadOrCreateSigningIdentity(config.foundrySigningKeyPath);
  const gatewayIdentity = loadOrCreateSigningIdentity(config.gatewaySigningKeyPath);
  const ledger = new Ledger(db, foundryIdentity, gatewayIdentity, config.executorWeightCap);
  const foundry = new Foundry(db, ledger, foundryIdentity, gatewayIdentity, config);
  if (!foundry.verify().valid) throw new Error("Existing Praxis state is invalid; seed refused.");
  const existing = db.sqlite.query("SELECT (SELECT COUNT(*) FROM contracts) AS contracts,(SELECT COUNT(*) FROM events) AS events,(SELECT COUNT(*) FROM ingest_records) AS ingests").get() as { contracts: number; events: number; ingests: number };
  if (existing.contracts || existing.events || existing.ingests) throw new Error("Seeding is allowed only on a completely empty Praxis database.");
  const mining = new PraxisMining(db, config);
  const agentId = "praxis-seed";
  db.sqlite.query("INSERT INTO agents(agent_id,enabled,created_at) VALUES(?,1,?) ON CONFLICT(agent_id) DO NOTHING")
    .run(agentId, new Date().toISOString());

  const samples = [
    {
      tool_id: "json.validate",
      domain: "data-quality",
      name: "Validate a JSON document",
      description: "Check that a JSON document parses and matches a supplied schema.",
      trigger: { description: "When a JSON document needs schema validation", lexical_hints: ["json", "schema", "validate", "parse"] },
      action: "Parse the JSON document and validate it against the supplied schema",
      output_spec: { assertions: [{ path: "$.valid", op: "equals", expected: true }] },
    },
    {
      tool_id: "documents.metadata.read",
      domain: "document-workflows",
      name: "Check document metadata",
      description: "Read a document's metadata and confirm required fields without changing the file.",
      trigger: { description: "When a document needs a read-only metadata check", lexical_hints: ["document", "metadata", "read-only", "fields"] },
      action: "Read the document metadata and report which required fields are present",
      output_spec: { assertions: [{ path: "$.complete", op: "equals", expected: true }] },
    },
    {
      tool_id: "citations.metadata.verify",
      domain: "research",
      name: "Verify citation metadata",
      description: "Compare citation metadata fields and flag missing identifiers without downloading full text.",
      trigger: { description: "When research citations need metadata verification", lexical_hints: ["citation", "doi", "metadata", "research"] },
      action: "Compare the available citation fields and list missing identifiers",
      output_spec: { assertions: [{ path: "$.verified", op: "equals", expected: true }] },
    },
  ];

  const created: string[] = [];
  for (const sample of samples) {
    foundry.setToolPolicy(sample.tool_id, 0, true);
    const draft = await mining.ingest({
      source_agent_id: agentId,
      trajectory: JSON.stringify([{ role: "assistant", kind: "tool_call", tool_id: sample.tool_id, action: sample.action }]),
      summary: sample.description,
      domain: sample.domain,
      candidate: {
        risk_tier: 0,
        domain: sample.domain,
        name: sample.name,
        description: sample.description,
        trigger: sample.trigger,
        workflow: [{ tool_id: sample.tool_id, action: sample.action, input: { read_only: true }, failure_policy: "stop" }],
        constraints: ["Do not modify files or call external services."],
        forbidden_actions: ["write files", "send money", "delete data"],
        output_spec: sample.output_spec,
      },
    });
    if (draft.state !== "draft" || !draft.skill_id) throw new Error(`Seed skill did not pass mining validation: ${sample.name}`);
    const promoted = foundry.promote(draft.ingest_id, [{ output: Object.fromEntries(sample.output_spec.assertions.map((item) => [item.path.slice(2), item.expected])) }]);
    created.push(promoted.skill_id);
  }
  const result = foundry.verify();
  if (!result.valid) throw new Error("Seeded ledger failed verification.");
  console.log(JSON.stringify({ seeded: created.length, skill_ids: created, ledger_head: result.head_hash }, null, 2));
} finally {
  db.closeCheckpoint();
  db.close();
}
