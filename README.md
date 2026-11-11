# Praxis Stack

Praxis Stack is a local-first skill engine for agent workflows. It combines evidence lookup, room-based trajectory capture, sanitization and quarantine, risk-gated contract promotion, an Ed25519 append-only ledger, SQLite/FTS5 storage, hybrid retrieval, an execution gateway, and signed outcome feedback.

The implementation is a single Bun/TypeScript service with one SQLite database so the full loop runs and can be verified on one machine. The code is split into five system modules:

| System | Implementation |
| --- | --- |
| Intel-Hub | `src/intel.ts`, `src/exploit-db.ts` |
| molt-room | `src/molt-room.ts` |
| Praxis-Mine / -Bank / -Lookup | `src/mining.ts`, `src/miner.ts`, `src/praxis.ts`, `src/ranking.ts` |
| Foundry | `src/foundry.ts`, `src/ledger.ts` |
| Integration Gateway | `src/gateway.ts` |

`schemas/skill-contract-v1.json` is the contract source of truth. Database objects are derived storage, not substitutes for the schema.

## What is implemented

- RFC 8785-style canonical JSON, Ed25519 keypairs, signed promotion/outcome/review events, a hash-chained ledger, independent verification, and cache rebuilds.
- Input size/depth limits, allowlisted sources and tools, secret/PII scrubbing, workflow lint, risk-tier escalation, human-signed quarantine release, and fail-closed writes.
- SQLite WAL, foreign keys, full synchronous durability, FTS5, per-model embedding partitions, RRF, Beta/Thompson ranking, exploration quota, query-vector caching, decay-at-read, and lexical fallback.
- Evidence metadata fan-out for OpenAlex, Crossref, Unpaywall, arXiv, GitHub, NVD, and Exploit-DB. Exploit-DB is indexed from its public CSV as **metadata only**; exploit files are never downloaded. The first Exploit-DB query downloads and indexes the bounded CSV snapshot.
- MOLT rooms with sanitized messages, history, JSONL export, registered-agent checks, and `@praxis` recommendations.
- A stateless MCP JSON-RPC endpoint, an A2A `message/send` endpoint and agent card, REST APIs, health/readiness endpoints, and OpenAPI JSON.
- A T340 adapter boundary. `stub` mode is the default and returns a signed `blocked` outcome; it does not execute tools. Real execution is only enabled when a separately deployed, authenticated T340 runner is reachable on loopback. The runner is responsible for the sandbox guarantees in the architecture (network isolation, no host mounts, bounded resources, and an image allowlist).

Anna's Archive metadata remains disabled. No source is allowed to supply full-text content to the mining model.

## Requirements and local run

Install Bun 1.4.4 or newer. From this directory:

```sh
umask 077
cp .env.example .env
chmod 600 .env
```

Replace all three placeholder tokens with different random values of at least 32 bytes. For example, generate each with `bun -e 'console.log(crypto.randomUUID()+crypto.randomUUID())'`; do not reuse a token between services. Keep `.env`, signing keys, and the `data/` directory private.

Then:

```sh
bun install --frozen-lockfile
bun run check
bun run start
```

By default, the service binds only to loopback on port `8787`, uses `data/praxis.sqlite`, creates separate Foundry and Gateway Ed25519 keys with mode `0600`, and keeps real execution disabled. Health endpoints are `GET /healthz` and `GET /readyz`; API documentation is `GET /openapi.json`.

`bun run seed` is an optional, never-automatic demo bootstrap that adds three signed tier-0 skills. Stop the service first; it refuses to run unless the database has no contracts, events, or prior ingests. The stub executor still blocks execution.

## Production container

The included `Dockerfile` and `compose.yaml` run as the unprivileged Bun user, expose the port only on host loopback, use a read-only root filesystem, drop Linux capabilities, and put the SQLite database and signing keys in a dedicated named volume. Configure `.env` with real secrets and set `PRAXIS_PUBLIC_URL` to the public **HTTPS** URL if the service is behind a TLS-terminating reverse proxy. The Compose file binds the host port to loopback; publish it only through that trusted proxy.

```sh
docker compose up --build -d
docker compose ps
```

Do not bind `PRAXIS_BIND_HOST` to a wildcard network interface outside a trusted TLS reverse-proxy deployment. The service refuses that bind unless `PRAXIS_PUBLIC_BEHIND_TLS=true`. Back up the database and both signing keys together. For a simple consistent backup, stop the service first, archive the complete data directory/volume, then restart it. Keep at least one encrypted off-host backup; losing a signing key makes its historical signatures unverifiable under the original identity.

## Trust and promotion workflow

All write APIs require the appropriate bearer token, except approval and outcome ingestion endpoints, which require valid Ed25519 signatures. Tokens are distinct and scoped:

- `PRAXIS_CONTROL_TOKEN`: trajectory ingest, MOLT administration, and general control operations.
- `FOUNDRY_CONTROL_TOKEN`: tool-risk registry, approver registry, validation, promotion, verification, and rebuild.
- `INTEGRATION_GATEWAY_TOKEN`: Gateway registry, execution, self-report, and T340 graduation.

1. Register trusted MOLT agents and the exact tool IDs your workflows may use. Assign each tool tier 0, 1, or 2 using `POST /api/v1/foundry/tools`.
2. Ingest a sanitized JSONL trajectory using `POST /api/v1/praxis/ingest`, or create a room, add messages, and call its `/complete` endpoint. Untrusted-source instructions, secret/PII findings, unregistered agents, invalid evidence refs, and workflow lint failures are quarantined rather than retrievable.
3. Add a machine-checkable `output_spec` and per-skill evaluation fixtures. `POST /api/v1/foundry/prepare` returns the computed risk tier and contract hash to approve.
4. For tier 1, register one Ed25519 approver; for tier 2, register two distinct approvers and obtain a T340 graduation report. `scripts/sign-payload.ts` signs canonical JSON payloads without printing private keys. Submit approvals to `POST /api/v1/foundry/approvals`.
5. `POST /api/v1/foundry/promote` re-runs the gates, writes the signed immutable contract and MOLT event, and indexes it. Tier 0 requires passing fixtures and may be sampled for audit; promotion is deliberately an explicit Foundry action rather than an implicit side effect of ingestion.
6. Retrieve through `POST /api/v1/praxis/recommend`, MCP `skill_recommend`, A2A `message/send`, or `@praxis` in a MOLT room.
7. The Gateway verifies the contract before execution and signs `skill.used`. Its output-spec verifier—not the executing agent—assigns the outcome. `blocked` and `unverified` do not count as success or failure; self-reports receive 0.25 weight.

To register a human approver, create an Ed25519 keypair with the CLI below, then send its public PEM to `POST /api/v1/foundry/approvers` with the Foundry token. Keep the private key outside the repository and readable only by its owner. Set `APPROVER_KEY_FILE` and `APPROVAL_PAYLOAD_FILE` to owner-only locations on the target system.

```sh
bun scripts/sign-payload.ts --keygen APPROVER_ID "$APPROVER_KEY_FILE"
bun scripts/sign-payload.ts --sign "$APPROVER_KEY_FILE" "$APPROVAL_PAYLOAD_FILE"
```

The first command prints the public key once. The signing command reads a JSON payload file and prints the signed JSON. Approval payloads must include `approval_id`, `contract_hash`, `approver_id`, `decision`, and an ISO timestamp in `signed_at`; use `approval_<ULID>` for the ID. For a quarantine review, sign the exact fields returned/required by the review endpoint; never include the private key in a request.

## API surface

| Method / path | Purpose | Auth |
| --- | --- | --- |
| `GET /healthz`, `GET /readyz` | Liveness and database readiness | None |
| `GET /.well-known/agent-card.json` | A2A agent card | None |
| `POST /mcp` | MCP initialize, tools/list, tools/call | None; read-only tools |
| `POST /api/v1/a2a` | A2A `message/send` skill retrieval | None; read-only |
| `POST /api/v1/praxis/recommend` | Hybrid retrieval | None; read-only |
| `GET /api/v1/praxis/skills/{skill_id}` | Verified signed contract and derived stats | None; read-only |
| `POST /api/v1/praxis/ingest` | Sanitize and mine a trajectory | Control |
| `/api/v1/molt/*` | Rooms, messages, JSONL export, agent registry | Control |
| `POST /api/v1/intel/search` | Evidence metadata search | None; rate-limited |
| `POST /api/v1/intel/exploit-db/refresh` | Refresh the local EDB metadata snapshot | Control |
| `/api/v1/foundry/*` | Tool policy, approvers, validation, promotion, quarantine review, drift review, deprecation, verify, rebuild | Foundry (signed submissions may be public) |
| `/api/v1/gateway/*` | Agent registry, execution, self-report, T340 graduation | Gateway |
| `POST /api/v1/outcomes` | Signed Gateway outcome ingestion | Valid Gateway signature |
| `GET /api/v1/metrics` | Counts and backend mode | Control, Foundry, or Gateway |

All HTTP request bodies have a configurable size limit. The API has per-client/per-route rate limits, no cookie authentication, no permissive CORS, no dynamic tool execution in the web process, and no endpoint that fetches a caller-supplied URL. Errors do not return stack traces or database details.

## Retrieval, embeddings, and data

Without an embedder, retrieval uses FTS5 plus derived statistics and reports `retrieval_mode: "lexical"`. To enable semantic search, configure the loopback embedder URL, model identifier, full 64-hex ONNX SHA-256, and a distinct 32+ byte bearer token. Query embeddings have a bounded in-memory TTL/LRU cache. Each model/SHA pair has its own partition; Lookup uses RRF across partitions and never compares raw cosine scores across models.

SQLite holds immutable canonical contracts and signed events alongside rebuildable stats, FTS, and embedding caches. `GET /api/v1/foundry/verify` verifies the ledger and caches. If only derived state is damaged, `POST /api/v1/foundry/rebuild` verifies the signed source of truth, replays outcomes, and rebuilds derived state; it refuses to rebuild from an invalid ledger. Startup performs the same verification, repairs only rebuildable state, and refuses to serve if signed history is invalid.

Drift is a derived review signal, never an automatic deprecation. Praxis compares each skill’s last 10 weighted outcomes with its lifetime Beta posterior; after at least 5 recent outcomes, it flags a skill when the recent posterior mean is at least 0.25 lower. Recommendations and `@praxis` replies expose `needs_review`; Foundry lists flagged skills at `GET /api/v1/foundry/drift`.

The Intel-Hub APIs use fixed provider hostnames, timeouts, bounded response bodies, and redirect rejection. Configure `UNPAYWALL_EMAIL`, `GITHUB_TOKEN`, or `NVD_API_KEY` only if those providers need them. Evidence is a source/access-tagged metadata reference; it is not treated as an instruction.

## Verification commands

```sh
bun run typecheck
bun test
bun run check
bun run benchmark
```

The benchmark seeds 1,000 synthetic contracts and checks the lexical-only retrieval p95 against the 5 ms target. A local run measured 0.655 ms p95 over 50 queries. This is a hardware-specific smoke benchmark, not a latency guarantee. Tests cover canonicalization, schema and workflow gates, sanitization/quarantine, signed approvals, tier-2 graduation, drift review, idempotent outcome replay, derived-state rebuilds, T340 success/failure behavior, HTTP auth and headers, key/file permissions, and bounded metadata indexing. They use temporary databases and a local mock T340; they do not contact external evidence providers or execute real tools.

## Operational boundary

This project implements the T340 **client contract**, not the T340 isolation runtime. Keep `PRAXIS_EXECUTION_BACKEND=stub` until a separately reviewed T340 runner is installed locally and enforces the sandbox requirements. The service cannot make arbitrary third-party tools safe merely by signing their output. Add only audited tool adapters, maintain tier-specific evaluation fixtures, monitor `/api/v1/metrics`, and review quarantine and drift findings before granting broader capabilities.
