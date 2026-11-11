# Embedding host

The optional Transformers.js sidecar provides local semantic embeddings. It binds to loopback, requires its own bearer token, checks the configured model digest, and degrades retrieval to lexical mode if unavailable.

## Install and pin

1. From the repository checkout, install the sidecar's locked runtime dependencies with `cd sidecar && bun install --frozen-lockfile`.
2. Choose a supported embedding model and a private persistent cache directory outside the repository. Set `EMBEDDER_SIDECAR_MODEL`, `EMBEDDER_SIDECAR_CACHE_DIR`, `EMBEDDER_SIDECAR_PORT=8792`, and a generated `EMBEDDER_SIDECAR_TOKEN` in a mode-`0600` environment file.
3. Start the sidecar locally and make one authorized `/embed` request to populate the cache. Do not expose the service while its model is unpinned.
4. Run `EMBEDDER_SIDECAR_CACHE_DIR=<private-cache> bash deploy/embedder-pin.sh` to print the full SHA-256 digest of the cached ONNX weights. Set that value as `EMBEDDER_SIDECAR_MODEL_SHA` and `PRAXIS_EMBEDDER_MODEL_SHA`; set `PRAXIS_EMBEDDER_MODEL` to the same model identifier and `PRAXIS_EMBEDDER_TOKEN` to the same sidecar token.
5. Restart the sidecar and Praxis. Make an authorized request, confirm the expected model identity and vector dimensions, then run the retrieval evaluation.

The digest helper reports a value; it does not download or verify a model for you. Keep the cache and environment file private. A model or digest mismatch must remain a hard sidecar error, not a reason to disable verification.
