# Mobile client

A mobile device is a client only; it does not host Praxis or the sidecars. Install a terminal client and the tailnet client, authenticate to the approved tailnet, then use the private HTTPS address assigned to the Praxis service.

Keep `PRAXIS_CONTROL_TOKEN` in a password manager. Do not place it in a URL, a shared shell profile, a clipboard-sync service, or command history. For a one-off request, enter the token without echoing it and send it in the authorization header:

```bash
read -r -s -p 'Praxis token: ' PRAXIS_TOKEN
printf '\n'
curl --fail --silent --show-error \
  -H "Authorization: Bearer $PRAXIS_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{"query":"find a canonical skill for this task","k":5,"deterministic":true}' \
  "$PRAXIS_URL/api/v1/praxis/recommend"
unset PRAXIS_TOKEN
```

Set `PRAXIS_URL` to the authenticated HTTPS service address in the terminal session; do not commit it to the repository. The service should expose no public write endpoint. A mobile client should never receive Foundry or Gateway signing keys.
