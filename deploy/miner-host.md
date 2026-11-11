# Miner host

Use this role when Ollama runs on a separate Linux host. Keep Ollama and the Praxis miner sidecar on loopback; the Praxis API should reach the sidecar through a private, authenticated connection. The current configuration accepts loopback sidecar URLs only, so a remote miner requires a reviewed private-tunnel design rather than a direct network URL.

For a miner on the same host as Praxis, first run `bash deploy/install-praxis.sh`, make sure Ollama is running, and then run:

```bash
bash deploy/install-miner-host.sh
```

The installer asks for the exact local Ollama model tag if `OLLAMA_MODEL` is unset. It records the full digest, reuses the generated miner token, refuses to overwrite existing miner settings, and installs a loopback-only user service. It does not start a shell, execute generated code, or enable the real execution backend.

Verify the sidecar health endpoint and Praxis readiness after installation. Keep the environment file and Ollama model cache private. To update the model, deliberately select a new tag, regenerate the digest, and update both service configurations together; never change a model in place while retaining its old digest.
