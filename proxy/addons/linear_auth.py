import json
import logging
import sys
from mitmproxy import http
from rule import rule

logger = logging.getLogger(__name__)

CREDENTIALS_PATH = None  # Shared with claude_auth; set at import time below

LINEAR_MCP_HOST = "mcp.linear.app"
LINEAR_MCP_PATH = "/mcp"
CRED_PARENT = "mcpOAuth"
CRED_KEY = "linear-server|638130d5ab3558f4"

RULES = {
    LINEAR_MCP_HOST: [
        rule.method("post").path(LINEAR_MCP_PATH).then("allow"),
    ],
}


def _log(msg: str) -> None:
    logger.info(msg)
    print(msg, flush=True, file=sys.stderr)


def _warn(msg: str) -> None:
    logger.warning(msg)
    print(msg, flush=True, file=sys.stderr)


def _get_credentials_path() -> str:
    # Import lazily to avoid circular dependency; share the same creds file.
    import claude_auth
    return claude_auth.CREDENTIALS_PATH


def load_access_token() -> str | None:
    try:
        with open(_get_credentials_path()) as f:
            creds = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        _warn(f"[LINEAR] Could not load credentials: {e}")
        return None
    return creds.get(CRED_PARENT, {}).get(CRED_KEY, {}).get("accessToken")


class LinearAuthAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.host != LINEAR_MCP_HOST:
            return
        if flow.request.path != LINEAR_MCP_PATH:
            return

        token = load_access_token()
        if token:
            flow.request.headers["Authorization"] = f"Bearer {token}"
            _log(f"[LINEAR] Auth header injected into {flow.request.method} {flow.request.pretty_url}")
        else:
            _warn(f"[LINEAR] No access token available for {flow.request.pretty_url}")
