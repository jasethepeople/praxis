#!/usr/bin/env bash
# Print the 64-hex sha256 of the largest cached ONNX weight file for the embedder sidecar.
# Run after the embedder sidecar has started once (the model downloads on first start),
# or after a manual warm-up: bun sidecar/embedder-sidecar.ts (it will fail to serve, but downloads).
set -euo pipefail
CACHE="${EMBEDDER_SIDECAR_CACHE_DIR:-$HOME/.local/state/praxis/embedder-cache}"
FILE=$(find "$CACHE" -name '*.onnx' -type f -printf '%s %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
if [ -z "$FILE" ]; then
  echo "No .onnx file under $CACHE yet; start the embedder sidecar once first." >&2
  exit 1
fi
echo "sha256: $FILE"
openssl dgst -sha256 "$FILE" | awk '{print $2}'
