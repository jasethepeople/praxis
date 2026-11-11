#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/apps/praxis}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/praxis"
SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/praxis"
ENV_FILE="${PRAXIS_ENV_FILE:-$CONFIG_DIR/env}"

command -v bun >/dev/null 2>&1 || { echo "Install Bun before continuing." >&2; exit 1; }
[ -d "$REPO_DIR/.git" ] || { echo "Set REPO_DIR to an existing repository checkout." >&2; exit 1; }

mkdir -p "$STATE_DIR" "$CONFIG_DIR" "$SERVICE_DIR"
chmod 700 "$STATE_DIR" "$CONFIG_DIR"
cd "$REPO_DIR"
bun install --frozen-lockfile
bun run check

if [ ! -f "$ENV_FILE" ]; then
  umask 077
  {
    printf 'PRAXIS_DATA_DIR=%s\nPRAXIS_BIND_HOST=localhost\nPORT=8787\nPRAXIS_EXECUTION_BACKEND=stub\n' "$STATE_DIR"
    bash "$REPO_DIR/deploy/gen-secrets.sh"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "Created a private environment file; review it before enabling the service."
fi

cat > "$SERVICE_DIR/praxis.service" <<EOF
[Unit]
Description=Praxis Stack
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory="$REPO_DIR"
EnvironmentFile="$ENV_FILE"
Environment=PATH=%h/.bun/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/bin/env bun run start
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths="$STATE_DIR"

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now praxis.service
loginctl enable-linger "$USER" 2>/dev/null || true
sleep 2
systemctl --user is-active --quiet praxis.service
curl -fsS http://localhost:8787/healthz >/dev/null
curl -fsS http://localhost:8787/readyz >/dev/null
echo "Praxis is active and its health/readiness checks pass."
