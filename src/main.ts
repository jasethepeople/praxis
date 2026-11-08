import { createHandler } from "./app";
import { loadConfig } from "./config";
import { PraxisDb } from "./db";
import { Foundry } from "./foundry";
import { IntegrationGateway } from "./gateway";
import { IntelHub } from "./intel";
import { Ledger } from "./ledger";
import { PraxisMining } from "./mining";
import { MoltRoom } from "./molt-room";
import { PraxisService } from "./praxis";
import { loadOrCreateSigningIdentity } from "./security";

const config = loadConfig();
const db = new PraxisDb(config.dbPath);
const foundryIdentity = loadOrCreateSigningIdentity(config.foundrySigningKeyPath);
const gatewayIdentity = loadOrCreateSigningIdentity(config.gatewaySigningKeyPath);
const ledger = new Ledger(db, foundryIdentity, gatewayIdentity, config.executorWeightCap);
const praxis = new PraxisService(db, config, foundryIdentity);
const mining = new PraxisMining(db, config);
const molt = new MoltRoom(db, mining);
const foundry = new Foundry(db, ledger, foundryIdentity, gatewayIdentity, config);
const gateway = new IntegrationGateway(db, ledger, gatewayIdentity, foundryIdentity, config);
const intel = new IntelHub(db, config);

molt.ensureAgent("praxis");
gateway.ensureDefaultAgent({
  agent_id: "praxis",
  name: "Praxis",
  description: "Signed, risk-gated skill retrieval and execution.",
  capabilities: ["skill_recommend", "skill_get", "intel_search"],
});

const startupVerification = foundry.verify();
if (!startupVerification.valid) {
  if (startupVerification.errors.every((error) => error.startsWith("derived "))) {
    foundry.rebuild();
    console.log(JSON.stringify({ level: "warn", event: "praxis.derived_state_rebuilt", errors: startupVerification.errors.length }));
  } else {
    db.closeCheckpoint();
    db.close();
    throw new Error("Signed ledger integrity check failed; refusing to serve requests");
  }
}
if (!foundry.verify().valid) {
  db.closeCheckpoint();
  db.close();
  throw new Error("Praxis startup integrity check failed; refusing to serve requests");
}

const startedAt = Date.now();
const handler = createHandler({ config, db, praxis, mining, molt, foundry, gateway, intel, foundryIdentity, gatewayIdentity, startedAt });
const server = Bun.serve({
  hostname: config.bindHost,
  port: config.port,
  maxRequestBodySize: Math.max(config.maxBodyBytes, config.maxMoltImportBytes),
  idleTimeout: 30,
  fetch: handler,
});

console.log(JSON.stringify({ level: "info", event: "praxis.started", host: config.bindHost, port: server.port, execution_backend: config.executionBackend, foundry_key: foundryIdentity.fingerprint, gateway_key: gatewayIdentity.fingerprint }));

let closing = false;
function shutdown(signal: string) {
  if (closing) return;
  closing = true;
  console.log(JSON.stringify({ level: "info", event: "praxis.stopping", signal }));
  server.stop(true);
  try {
    db.closeCheckpoint();
    db.close();
  } finally {
    process.exit(0);
  }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
