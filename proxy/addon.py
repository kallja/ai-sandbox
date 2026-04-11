import json
import os
import sys
from mitmproxy import http, ctx

BLOCKED_URLS = {
    "api.anthropic.com": (
        "/api/claude_code/metrics",
        "/api/claude_code/organization/metrics",
        "/api/claude_code/organizations/metrics_enabled",
        "/api/event_logging",
        "/api/oauth/profile",
        "/mcp-registry",
        "/v1/mcp_servers",
    ),
    "platform.claude.com": (
        "/v1/oauth/token",
    ),
}
ANTHROPIC_HOST = "api.anthropic.com"
ALLOWED_PATH_PREFIXES = (
    "/api/claude_cli/bootstrap",
    "/api/claude_code/policy_limits",
    "/api/claude_code/settings",
    "/api/claude_code_penguin_mode",
    "/v1/messages",
)
CREDENTIALS_PATH = os.path.expanduser("~/.config/proxy/secrets/claude.json")
DRY_RUN = False


def load_access_token() -> str | None:
    try:
        with open(CREDENTIALS_PATH) as f:
            creds = json.load(f)
        return creds["claudeAiOauth"]["accessToken"]
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        ctx.log.warn(f"Could not load access token: {e}")
        return None


class LogAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        msg = f">>> {flow.request.method} {flow.request.pretty_url}"
        ctx.log.info(msg)
        print(msg, flush=True, file=sys.stderr)

        blocked_prefixes = BLOCKED_URLS.get(flow.request.host, ())
        if blocked_prefixes and any(flow.request.path.startswith(p) for p in blocked_prefixes):
            msg = f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}"
            ctx.log.info(msg)
            print(msg, flush=True, file=sys.stderr)
            flow.response = http.Response.make(502)
            return

        if flow.request.host == ANTHROPIC_HOST and any(flow.request.path.startswith(p) for p in ALLOWED_PATH_PREFIXES):
            if DRY_RUN:
                msg = f"[DRY RUN] Would inject auth header into {flow.request.method} {flow.request.pretty_url}"
                ctx.log.info(msg)
                print(msg, flush=True, file=sys.stderr)
            else:
                token = load_access_token()
                if token:
                    flow.request.headers["Authorization"] = f"Bearer {token}"
                    msg = f"[INJECT] Auth header injected into {flow.request.method} {flow.request.pretty_url}"
                else:
                    msg = f"[ERROR] No access token available for {flow.request.pretty_url}"
                ctx.log.info(msg)
                print(msg, flush=True, file=sys.stderr)

    def response(self, flow: http.HTTPFlow) -> None:
        msg = f"<<< {flow.response.status_code} {flow.request.pretty_url}"
        ctx.log.info(msg)
        print(msg, flush=True, file=sys.stderr)


addons = [LogAddon()]
