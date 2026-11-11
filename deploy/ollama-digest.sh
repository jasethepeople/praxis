#!/usr/bin/env bash
# Resolve the full 64-hex sha256 digest Ollama reports for a model.
# Refuses to truncate or guess; exits 1 when the model is unknown.
set -euo pipefail
MODEL="${1:-}"
if [ -z "$MODEL" ]; then
  echo "Usage: $0 <model-name>  (e.g. llama3.1:8b)" >&2
  exit 2
fi
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
DIGEST="$(curl -fsSL "$OLLAMA_URL/api/tags" | bun -e '
const body = await Bun.stdin.json();
const wanted = process.argv[2].toLowerCase();
const hit = (body.models ?? []).find((m) => [m.name?.toLowerCase(), m.model?.toLowerCase()].includes(wanted) || m.name?.toLowerCase() === `${wanted}:latest`);
if (!hit || typeof hit.digest !== "string" || !/^[0-9a-f]{64}$/.test(hit.digest)) process.exit(1);
console.log(hit.digest);
' "$MODEL")" || {
  echo "Ollama does not report a 64-hex digest for '$MODEL' at $OLLAMA_URL" >&2
  exit 1
}
echo "$DIGEST"
