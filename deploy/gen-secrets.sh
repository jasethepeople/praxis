#!/usr/bin/env bash
# Generate the three distinct control tokens for one machine.
# Output is meant to be pasted into the machine's EnvironmentFile. Never commit it.
set -euo pipefail
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi
echo "PRAXIS_CONTROL_TOKEN=$(openssl rand -hex 24)"
echo "FOUNDRY_CONTROL_TOKEN=$(openssl rand -hex 24)"
echo "INTEGRATION_GATEWAY_TOKEN=$(openssl rand -hex 24)"
echo "PRAXIS_MINER_TOKEN=$(openssl rand -hex 24)"
echo "PRAXIS_EMBEDDER_TOKEN=$(openssl rand -hex 24)"
