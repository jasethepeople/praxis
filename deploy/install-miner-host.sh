#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/praxis"
ENV_FILE="${PRAXIS_ENV_FILE:-$CONFIG_DIR/env}"
SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
BUN_BIN="$(command -v bun || true)"
MODEL="${OLLAMA_MODEL:-}"

if [[ -z "$BUN_BIN" || ! -f "$REPO_DIR/package.json" ]]; then
  echo "Install Bun and set REPO_DIR to the Praxis checkout." >&2
  exit 1
fi
if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama must be installed and running on this host." >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Run deploy/install-praxis.sh first to create private Praxis configuration." >&2
  exit 1
fi
chmod 600 "$ENV_FILE"

if [[ -z "$MODEL" ]]; then
  ollama list
  read -r -p "Exact Ollama model tag to pin: " MODEL
fi
if [[ ! "$MODEL" =~ ^[A-Za-z0-9._:/-]{1,200}$ ]]; then
  echo "Invalid model tag." >&2
  exit 1
fi
DIGEST="$(OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}" bash "$REPO_DIR/deploy/ollama-digest.sh" "$MODEL")"
MINER_TOKEN="$(awk -F= '$1=="PRAXIS_MINER_TOKEN" {print substr($0,index($0,"=")+1)}' "$ENV_FILE")"
if [[ -z "$MINER_TOKEN" || ${#MINER_TOKEN} -lt 32 ]]; then
  echo "The environment file must contain a valid PRAXIS_MINER_TOKEN." >&2
  exit 1
fi
if grep -q '^PRAXIS_MINER_URL=' "$ENV_FILE" || grep -q '^MINER_SIDECAR_MODEL=' "$ENV_FILE"; then
  echo "Miner settings already exist. Review them manually; refusing to overwrite deployment configuration." >&2
  exit 1
fi

umask 077
cat >> "$ENV_FILE" <<EOF
PRAXIS_MINER_URL=http://localhost:8791
PRAXIS_MINER_MODEL_SHA=$DIGEST
MINER_SIDECAR_PORT=8791
MINER_SIDECAR_TOKEN=$MINER_TOKEN
MINER_SIDECAR_MODEL=$MODEL
MINER_SIDECAR_MODEL_SHA=$DIGEST
MINER_SIDECAR_OLLAMA_URL=${OLLAMA_URL:-http://localhost:11434}
EOF
chmod 600 "$ENV_FILE"

cd "$REPO_DIR"
bun install --frozen-lockfile
bun run check
cat > "$SERVICE_DIR/praxis-miner.service" <<EOF
[Unit]
Description=Praxis miner sidecar
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
EnvironmentFile=$ENV_FILE
Environment=PATH=$(dirname "$BUN_BIN"):/usr/local/bin:/usr/bin:/bin
ExecStart=$BUN_BIN run sidecar:miner
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$REPO_DIR

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now praxis-miner.service
systemctl --user restart praxis.service
sleep 2
curl --fail --silent --show-error http://localhost:8791/healthz
printf '\nMiner sidecar is running on loopback.\n'
