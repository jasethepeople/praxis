# Security policy

Report suspected vulnerabilities privately through GitHub Security Advisories for this repository. Do not include secrets, private user data, exploit payloads, or production signing keys in public issues.

## Security boundaries

- Default network bind is loopback. Public deployment requires TLS termination at a trusted reverse proxy.
- MCP, A2A, search, health, and canonical reads are read-only. Mutations require one of three distinct bearer tokens or an Ed25519 signature.
- Trajectories and evidence are untrusted. Sanitization, allowlists, workflow lint, risk tiers, and quarantine precede promotion.
- Canonical skills and MOLT events are Ed25519-signed and hash chained. Stats, FTS, and embeddings are unsigned derived state.
- Execution is blocked by default. T340 is an external trust boundary and must enforce network/filesystem/image restrictions independently.

## Key handling

Foundry and Gateway private signing keys are stored as mode-`0600` files under the private data directory. Back up the SQLite database and those keys together, encrypted and off-host. Losing or replacing a key breaks verification continuity. This v1 build does not support in-place signing-key rotation; deploy a new ledger and perform a reviewed, signed migration before changing a production identity.

Rotate bearer tokens by updating the secret environment variables and restarting the service. Never place tokens in URLs, logs, source control, or API request bodies.
