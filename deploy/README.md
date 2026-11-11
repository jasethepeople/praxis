# Deployment guides

These guides use generic host roles and runtime variables. They contain no host-specific addresses, account names, or machine paths.

| Role | Responsibility | Guide |
|---|---|---|
| Development host | Praxis API; optional local embedder | [development-host.md](development-host.md) |
| Miner host | Optional Ollama-backed mining sidecar | [miner-host.md](miner-host.md) |
| Always-on host | Praxis API, with optional private tailnet access | [always-on-host.md](always-on-host.md) |
| Mobile client | Access from an authenticated terminal app | [mobile-client.md](mobile-client.md) |

## Deployment defaults

- Run Praxis and its sidecars as an unprivileged user service. Keep the data directory and environment file owner-only.
- Praxis, the miner, and the embedder bind to loopback. Keep them there unless a separately secured TLS proxy is intentionally configured.
- The execution backend remains `stub`. Do not enable real execution until an independently sandboxed T340 runner is available and verified.
- The miner refuses to start unless the configured model digest matches the local Ollama model. Use the full 64-hex digest; do not truncate it.
- The embedder uses a dedicated model cache. Pin the full 64-hex SHA-256 of its ONNX weights before enabling it.
- `deploy/gen-secrets.sh` prints unique tokens to stdout. Redirect it only to an owner-only environment file; never paste its output into chat or commit it.
- The checked-in systemd units are generic templates. The installers render deployment-specific values only on the target host; never commit rendered units or environment files.

## Private remote access

For private remote access, keep the service bound to loopback and use an authenticated tailnet Serve proxy. Do not forward the Praxis port directly to the public internet. A publicly reachable reverse proxy requires TLS, a narrowly scoped firewall, and strong authentication for every write endpoint.
