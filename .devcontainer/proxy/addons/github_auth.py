import logging
import os
import sys
from mitmproxy import http
from rule import rule

logger = logging.getLogger(__name__)

GITHUB_API_HOST = "api.github.com"
GITHUB_API_PATHS = [
    "/graphql",
]
TOKEN_PATH = os.path.expanduser("~/.config/proxy/secrets/github-token")

RULES = {
    GITHUB_API_HOST: [
        rule.path.starts_with.one_of(GITHUB_API_PATHS).then("allow"),
    ],
}


def _log(msg: str) -> None:
    logger.info(msg)
    print(msg, flush=True, file=sys.stderr)


def _warn(msg: str) -> None:
    logger.warning(msg)
    print(msg, flush=True, file=sys.stderr)


def load_access_token() -> str | None:
    try:
        with open(TOKEN_PATH) as f:
            token = f.read().strip()
            return token if token else None
    except FileNotFoundError:
        return None


class GitHubAuthAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.host != GITHUB_API_HOST:
            return
        if not any(flow.request.path.startswith(p) for p in GITHUB_API_PATHS):
            return

        token = load_access_token()
        if token:
            flow.request.headers["Authorization"] = f"token {token}"
            _log(f"[GITHUB] Auth header injected into {flow.request.method} {flow.request.pretty_url}")
        else:
            _warn(f"[GITHUB] No access token available for {flow.request.pretty_url}")
