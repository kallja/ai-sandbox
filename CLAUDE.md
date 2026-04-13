# ai-sandbox

Produces a proxy container (mitmproxy + Python addons) for intercepting and controlling Claude Code CLI traffic. Handles OAuth credential injection, auth header management, and default-deny traffic control.

## Architecture

- **proxy** (the product) — mitmproxy that intercepts all HTTPS traffic. Injects real auth credentials into API requests while only exposing fake tokens to the CLI. Enforces traffic control rules (default-deny for POST/PUT/DELETE).
- **devcontainer** (for development) — Claude Code CLI container in `.devcontainer/` that routes traffic through the proxy via `internal_only` network.
- Two networks: `internal_only` (no external access) and `public` (proxy web UI only).
- Credentials are extracted from macOS Keychain on the host and injected into the proxy container at runtime.

## Running

From the host (macOS):

```
.devcontainer/run-claude.sh         # Run Claude CLI in devcontainer (starts services if needed)
```

mitmweb UI is at http://localhost:8081 when running.

## Testing

Proxy addon tests (run inside the devcontainer):

```
pytest proxy/
```

## Key paths

- `proxy/claude_auth.py` — OAuth token swapping and auth header injection
- `proxy/traffic_control.py` — Request allow/deny rules
- `proxy/rule.py` — Rule matching DSL
- `proxy/Dockerfile` — Proxy container image (self-contained build context)
- `.devcontainer/Dockerfile` — Devcontainer image (Claude CLI + dev tools)
- `.devcontainer/config/` — Pre-baked Claude CLI settings (bypass permissions, skip onboarding)

## Worktrees

Use git worktrees for any code or infrastructure changes that risk breaking the container setup. If the container doesn't start, we can't develop. Always create worktrees at `.worktrees/<worktree_name>`.

## Conventions

- Proxy addons are Python, tests use pytest.
- Shell scripts use `set -euo pipefail`.
- Commit messages are single-line, prefixed with a Conventional Commits type: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`, `perf:`, `style:`, `build:`.
