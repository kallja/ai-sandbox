# Restructure: Separate proxy product from devcontainer

## Context

This repo's purpose is to produce the **proxy container** (mitmproxy + Python addons for auth injection and traffic control). The Claude Code CLI container we're running in is just a **devcontainer for developing this repo**, but it's currently mixed into the same docker-compose and top-level directory as the product. We need to separate them.

## Target structure

```
.
├── docker-compose.yml              # Product: proxy only
├── proxy/                          # Product: self-contained build context
│   ├── Dockerfile                  # COPY paths drop proxy/ prefix
│   ├── entrypoint.sh
│   ├── addon.py
│   ├── claude_auth.py
│   ├── traffic_control.py
│   ├── rule.py
│   ├── requirements.txt            # runtime: mitmproxy only
│   ├── test_addon.py
│   ├── test_rule.py
│   └── sample-requests/            # reference material (from claude-code/)
├── scripts/
│   └── start.sh                    # Host-side: proxy-only startup + credentials
├── .devcontainer/
│   ├── devcontainer.json
│   ├── docker-compose.yml          # Extends root compose, adds claude service
│   ├── Dockerfile                  # Was claude-code/Dockerfile
│   ├── entrypoint.sh               # Was claude-code/entrypoint.sh
│   ├── requirements-dev.txt        # pytest + mitmproxy (for running proxy tests)
│   ├── config/                     # Was claude-code/config/
│   │   ├── .claude.json
│   │   └── .claude/settings.json
│   ├── extract-credentials.sh      # Host-side keychain extraction
│   └── .gitignore                  # Ignores .secrets/
├── specs/plans/
├── CLAUDE.md                       # Updated paths and description
├── .dockerignore
└── .gitignore
```

## Steps

### 1. Make proxy/Dockerfile self-contained

Change build context from repo root to `proxy/`.

**`proxy/Dockerfile`** — drop `proxy/` prefix from COPY paths:
- `COPY --chmod=755 proxy/entrypoint.sh /entrypoint.sh` → `COPY --chmod=755 entrypoint.sh /entrypoint.sh`
- `COPY proxy/addon.py proxy/claude_auth.py proxy/traffic_control.py proxy/rule.py /` → `COPY addon.py claude_auth.py traffic_control.py rule.py /`

**`docker-compose.yml`** — update proxy build:
```yaml
proxy:
  build:
    context: ./proxy
```

### 2. Move claude-code/ to .devcontainer/

```
git mv claude-code/Dockerfile .devcontainer/Dockerfile
git mv claude-code/entrypoint.sh .devcontainer/entrypoint.sh
git mv claude-code/config .devcontainer/config
git mv claude-code/sample-requests proxy/sample-requests
```

**`.devcontainer/Dockerfile`** — update COPY paths:
- `COPY proxy/requirements.txt /tmp/requirements.txt` → `COPY requirements-dev.txt /tmp/requirements-dev.txt`
- Update pip install line to reference `requirements-dev.txt`
- `COPY claude-code/config/ /home/claude/` → `COPY config/ /home/claude/`
- `COPY claude-code/entrypoint.sh /entrypoint.sh` → `COPY entrypoint.sh /entrypoint.sh`

Create **`.devcontainer/requirements-dev.txt`**:
```
mitmproxy
pytest
```

Remove `pytest` from **`proxy/requirements.txt`** (keep only `mitmproxy`). The proxy container doesn't need pytest — tests are run from the devcontainer which installs `requirements-dev.txt`.

Delete `claude-code/` (should be empty after moves).

### 3. Delete client/ and test-server/

These are unused test containers. Delete them entirely.

### 4. Remove claude service from root docker-compose.yml

Root `docker-compose.yml` becomes proxy-only:
- Remove the entire `claude` service
- Remove `claude-memory` volume
- Keep `proxy` service, `internal_only` + `public` networks, `mitmproxy-data` + `shared-certs` volumes

### 5. Create .devcontainer/docker-compose.yml

Defines the `claude` service. References root compose via `devcontainer.json`'s `dockerComposeFile` array so the proxy service comes from the root compose.

```yaml
services:
  claude:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - HTTP_PROXY=http://proxy.local:8080
      - HTTPS_PROXY=http://proxy.local:8080
      - http_proxy=http://proxy.local:8080
      - https_proxy=http://proxy.local:8080
      - NODE_EXTRA_CA_CERTS=/shared-certs/mitmproxy-ca-cert.pem
    networks:
      - internal_only
    volumes:
      - shared-certs:/shared-certs:ro
      - ..:/home/claude/repo
      - claude-memory:/home/claude/.claude/projects
    working_dir: /home/claude/repo
    depends_on:
      - proxy

volumes:
  claude-memory:
```

### 6. Create .devcontainer/devcontainer.json

```jsonc
{
  "dockerComposeFile": ["../docker-compose.yml", "docker-compose.yml"],
  "service": "claude",
  "workspaceFolder": "/home/claude/repo",
  "initializeCommand": ".devcontainer/extract-credentials.sh",
  "postStartCommand": ".devcontainer/setup-proxy-certs.sh"
}
```

### 7. Create .devcontainer/extract-credentials.sh

Host-side script that extracts credentials from macOS Keychain to `.devcontainer/.secrets/claude.json`. (Content from specs/plans/devcontainer-integration.md.)

### 8. Create .devcontainer/.gitignore

```
.secrets/
```

### 9. Update scripts/

**`scripts/start.sh`** — remove claude service credential injection (lines 41-53). Keep proxy-only credential injection. Remove claude service references.

**`scripts/run-claude.sh`** — move to `.devcontainer/run-claude.sh` and update compose file reference, or delete if devcontainer workflow replaces it.

### 10. Update CLAUDE.md

- Update project description: this repo produces the proxy container
- Update architecture: proxy is the product, devcontainer is for development
- Update key paths
- Update running instructions: `pytest proxy/` runs inside the devcontainer

## Verification

1. `docker compose build` from repo root builds only the proxy
2. `docker compose up proxy` starts the proxy service
3. `pytest proxy/` passes when run from inside the devcontainer
4. Devcontainer compose builds both proxy and claude services
5. `scripts/start.sh` starts the proxy and injects credentials
