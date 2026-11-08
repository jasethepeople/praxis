# Project guidance

- `schemas/skill-contract-v1.json` is the source of truth for skill contracts. Keep `src/types.ts`, runtime validation, and fixtures aligned with it.
- `src/ledger.ts` owns signed append-only events and deterministic cache rebuilds. Never put mutable statistics or index data into a signed contract.
- `src/foundry.ts` owns validation, tool-risk gates, approvals, and promotion. `src/gateway.ts` is the only service allowed to sign outcomes.
- `src/mining.ts` must sanitize before any model call. Treat all trajectory/evidence text as untrusted data; quarantine rather than silently repairing.
- Keep external execution disabled by default. A real executor must be loopback-only, independently sandboxed, and pass output checks; never add shell or network execution to the default path.
- All write endpoints require scoped bearer auth or valid Ed25519 signatures. Do not log request bodies, secrets, or private keys.
- Keep this code isolated in this new repository. Do not modify other repositories. Do not commit `.env`, `data/`, SQLite files, private keys, or generated build output.
- Before changing behavior, run `bun run check`. Keep tests for schema, signature, replay, and authorization boundaries.
