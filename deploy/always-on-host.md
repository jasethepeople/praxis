# Always-on host

Install the API with `bash deploy/install-praxis.sh`. The service runs as an unprivileged systemd user unit, binds to loopback, and stores SQLite state and signing keys in the private state directory. Keep the systemd user manager alive across logout using the host's supported linger mechanism.

For private remote access, place an authenticated tailnet Serve proxy in front of the loopback service:

```bash
tailscale serve --bg --https=443 http://localhost:8787
```

Use the authenticated HTTPS service address assigned by the tailnet in clients. Do not publish the underlying port, place tokens in proxy URLs, or disable bearer authentication. Confirm the host firewall blocks direct inbound access to Praxis and both sidecar ports.

The service starts with the stub executor. Keep `PRAXIS_EXECUTION_BACKEND=stub`; this deployment does not itself provide a safe T340 sandbox. Back up the SQLite database and signing keys together using encrypted, access-controlled storage. Periodically verify the ledger and test restoration from a backup.
