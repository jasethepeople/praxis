#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
STATE_DIR="${PRAXIS_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/praxis}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/praxis"
ENV_FILE="${PRAXIS_ENV_FILE:-$CONFIG_DIR/env}"
SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
BUN_BIN="$(command -v bun || true)"

if [[ -z "$BUN_BIN" ]]; then
  echo "Bun is required; install it using the official instructions for this operating system." >&2
  exit 1
fi
if [[ ! -f "$REPO_DIR/package.json" || ! -f "$REPO_DIR/bun.lock" ]]; then
  echo "REPO_DIR must point to the Praxis checkout containing package.json and bun.lock." >&2
  exit 1
fi

cd "$REPO_DIR"
bun install --frozen-lockfile
bun run check
mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$SERVICE_DIR"
chmod 700 "$STATE_DIR" "$CONFIG_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  umask 077
  {
    printf 'PRAXIS_DATA_DIR=%s\n' "$STATE_DIR"
    printf 'PRAXIS_BIND_HOST=localhost\nPORT=8787\n'
    printf 'PRAXIS_EXECUTION_BACKEND=stub\nPRAXIS_PUBLIC_BEHIND_TLS=false\n'
    bash "$REPO_DIR/deploy/gen-secrets.sh"
  } > "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

cat > "$SERVICE_DIR/praxis.service" <<EOF
[Unit]
Description=Praxis Stack
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
EnvironmentFile=$ENV_FILE
Environment=PATH=$(dirname "$BUN_BIN"):/usr/local/bin:/usr/bin:/bin
Environment=PRAXIS_DATA_DIR=$STATE_DIR
ExecStart=$BUN_BIN run start
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE_DIR

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now praxis.service
if command -v loginctl >/dev/null 2>&1; then
  loginctl enable-linger "$USER" 2>/dev/null || true
fi
sleep 2
curl --fail --silent --show-error http://localhost:8787/healthz
printf '\nPraxis is running as a loopback-only user service.\n'
