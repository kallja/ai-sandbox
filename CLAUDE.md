# ai-sandbox

Docker-based sandbox for running Claude Code CLI with network isolation, traffic interception, and credential proxy injection.

## Architecture

- **proxy** — mitmproxy that intercepts all HTTPS traffic from the Claude container. Injects real auth credentials into API requests while only exposing fake tokens to the CLI. Enforces traffic control rules (default-deny for POST/PUT/DELETE).
- **claude** — Runs Claude Code CLI as non-root user. All network traffic routes through the proxy via `internal_only` network (no direct internet access).
- Two networks: `internal_only` (no external access) and `public` (proxy web UI only).
- Credentials are extracted from macOS Keychain on the host and injected into the proxy container at runtime.

## Running

From the host (macOS):

```
./scripts/start.sh          # Start everything, inject credentials, follow logs
./scripts/run-claude.sh     # Run Claude CLI in the container (starts services if needed)
```

mitmweb UI is at http://localhost:8081 when running.

## Testing

Proxy addon tests (run inside the claude container or any environment with pytest):

```
pytest proxy/
```

## Key paths

- `proxy/claude_auth.py` — OAuth token swapping and auth header injection
- `proxy/traffic_control.py` — Request allow/deny rules
- `proxy/rule.py` — Rule matching DSL
- `claude-code/Dockerfile` — Claude CLI container image
- `claude-code/config/` — Pre-baked Claude CLI settings (bypass permissions, skip onboarding)
- `scripts/start.sh` — Host-side startup with Keychain credential extraction

## Worktrees

Use git worktrees for any code or infrastructure changes that risk breaking the container setup. If the container doesn't start, we can't develop. Always create worktrees at `.worktrees/<worktree_name>`.

## Conventions

- Proxy addons are Python, tests use pytest.
- Shell scripts use `set -euo pipefail`.
- Commit messages are single-line, prefixed with a Conventional Commits type: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`, `perf:`, `style:`, `build:`.
