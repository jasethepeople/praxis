# Development host

This role runs the Praxis API and may also run the optional embedding sidecar. It does not require a public network interface.

## Install Praxis

From the repository checkout, run:

```bash
bash deploy/install-praxis.sh
```

The installer checks the lockfile, typechecks the code, runs the tests and build, creates owner-only configuration and state directories, generates distinct tokens if no environment file exists, and installs a loopback-only systemd user service. Set `REPO_DIR`, `PRAXIS_STATE_DIR`, or `PRAXIS_ENV_FILE` before running it if the checkout or private state should use a different location.

The generated environment defaults to `PRAXIS_EXECUTION_BACKEND=stub` and loopback-only binding. Keep those defaults unless a separately secured deployment design has been reviewed. Do not put tokens in shell history or commit the generated environment file.

## Optional embedder

Install the sidecar runtime from its lockfile:

```bash
cd sidecar && bun install --frozen-lockfile
```

Configure `EMBEDDER_SIDECAR_TOKEN`, `EMBEDDER_SIDECAR_MODEL`, `EMBEDDER_SIDECAR_MODEL_SHA`, and `EMBEDDER_SIDECAR_CACHE_DIR` in the owner-only environment file. Use a cache dedicated to the selected model, warm the model from a trusted network, compute its full ONNX digest with `bash deploy/embedder-pin.sh`, and set the matching `PRAXIS_EMBEDDER_URL`, `PRAXIS_EMBEDDER_MODEL`, `PRAXIS_EMBEDDER_MODEL_SHA`, and `PRAXIS_EMBEDDER_TOKEN` in Praxis configuration. Restart both services and verify `/healthz` and `/readyz` before using semantic retrieval.

The first model acquisition may require network access. Do not expose the sidecar during initial model acquisition or before the digest has been checked. Retrieval falls back to lexical mode if the embedder is unavailable.
