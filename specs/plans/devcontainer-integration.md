# Devcontainer Integration Plan

Use the ai-sandbox Docker Compose stack (proxy, traffic control, credential injection) inside repos that already have a devcontainer setup.

## Approach

Extend an existing devcontainer with the proxy as a sidecar service (Approach 2). This layers the proxy network on top of whatever devcontainer setup already exists, without requiring a rebuild of the entire dev environment around this sandbox's Dockerfile.

## Credential Injection

### Problem

Today, `scripts/start.sh` runs on the macOS host and:

1. Extracts credentials from macOS Keychain via `security find-generic-password`
2. Pipes real credentials into the proxy container via `docker exec` at `~/.config/proxy/secrets/claude.json`
3. Pipes sanitized credentials (fake tokens, real metadata) into the Claude container at `~/.claude/.credentials.json`

With a devcontainer, VS Code / the devcontainer CLI manages the `docker compose up` lifecycle. There is no natural place for the host-side Keychain extraction and `docker exec` piping.

### Solution: `initializeCommand` + volume mount

Replace runtime injection with a file that's ready at container start.

1. **`initializeCommand`** in `devcontainer.json` runs a script on the host that extracts credentials from Keychain and writes them to `.devcontainer/.secrets/claude.json` (gitignored).
2. **Volume mount** in `docker-compose.proxy.yml` mounts that file into the proxy container at `/root/.config/proxy/secrets/claude.json:ro`. Credentials are available at container start with no post-start injection needed.
3. **`postStartCommand`** runs inside the devcontainer to wait for the mitmproxy CA cert, install it into the system trust store, and write sanitized fake-token credentials to `~/.claude/.credentials.json` so Claude CLI thinks it's logged in.

### Advantages over the `docker exec` approach

- Credentials available at container start, not after a separate injection step
- Survives proxy container restarts (file persists on host, re-mounted)
- Integrated into the devcontainer lifecycle — no wrapper script needed

## Files to Create in the Target Repo

### `.devcontainer/devcontainer.json`

```jsonc
{
  "dockerComposeFile": [
    "docker-compose.yml",
    "docker-compose.proxy.yml"
  ],
  "service": "devcontainer",
  "workspaceFolder": "/workspace",

  // Runs on the HOST before docker compose up
  "initializeCommand": ".devcontainer/extract-credentials.sh",

  // Runs inside the devcontainer after start
  "postStartCommand": ".devcontainer/setup-claude-creds.sh"
}
```

### `.devcontainer/docker-compose.proxy.yml`

```yaml
services:
  proxy:
    build: ./path-to-ai-sandbox/proxy
    volumes:
      - shared-certs:/shared-certs
      - ./.devcontainer/.secrets/claude.json:/root/.config/proxy/secrets/claude.json:ro
    networks:
      internal_only:
        aliases:
          - proxy.local
      public: {}

  devcontainer:
    environment:
      - HTTP_PROXY=http://proxy.local:8080
      - HTTPS_PROXY=http://proxy.local:8080
      - NODE_EXTRA_CA_CERTS=/shared-certs/mitmproxy-ca-cert.pem
    volumes:
      - shared-certs:/shared-certs:ro
    networks:
      - internal_only
    depends_on:
      - proxy

networks:
  internal_only:
    internal: true
  public: {}

volumes:
  shared-certs:
```

### `.devcontainer/extract-credentials.sh`

Runs on the host (macOS) before containers start.

```bash
#!/bin/bash
set -euo pipefail

SECRETS_DIR="$(cd "$(dirname "$0")" && pwd)/.secrets"
mkdir -p "$SECRETS_DIR"

CREDS_JSON="$(security find-generic-password \
  -s "Claude Code-credentials" -a "$(whoami)" -w 2>/dev/null)" || true

if [ -z "${CREDS_JSON:-}" ]; then
  echo "Warning: No Claude Code credentials found in Keychain." >&2
  echo "Run 'claude login' on the host first." >&2
  echo '{}' > "$SECRETS_DIR/claude.json"
else
  printf '%s' "$CREDS_JSON" > "$SECRETS_DIR/claude.json"
  echo "Credentials extracted for proxy." >&2
fi
```

### `.devcontainer/setup-claude-creds.sh`

Runs inside the devcontainer after start.

```bash
#!/bin/bash
set -euo pipefail

# Wait for mitmproxy CA cert from shared volume
echo "Waiting for mitmproxy CA certificate..."
for i in $(seq 1 30); do
  [ -f /shared-certs/mitmproxy-ca-cert.pem ] && break
  sleep 1
done

if [ ! -f /shared-certs/mitmproxy-ca-cert.pem ]; then
  echo "Warning: mitmproxy CA cert not found after 30s" >&2
  exit 1
fi

# Install CA cert for system trust
sudo cp /shared-certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates

# Write sanitized credentials so Claude CLI thinks it's logged in
mkdir -p ~/.claude
cat > ~/.claude/.credentials.json << 'EOF'
{
  "claudeAiOauth": {
    "accessToken": "proxy-injected-accessToken",
    "refreshToken": "proxy-injected-refreshToken",
    "expiresAt": 0
  }
}
EOF
```

### `.devcontainer/.gitignore`

```
.secrets/
```

## Open Questions

- How to reference the ai-sandbox proxy build context from the target repo (git submodule, vendored copy, or published image).
- Whether the devcontainer base image has `sudo` and `update-ca-certificates` available, or if the CA setup needs to be handled differently.
- Traffic control rules in `proxy/traffic_control.py` will likely need adjustment per-project.
