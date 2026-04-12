import logging
import sys
from mitmproxy import http
from rule import rule

logger = logging.getLogger(__name__)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

BLOCKED_URLS = {
    "api.anthropic.com": (
        "/api/claude_code/metrics",
        "/api/claude_code/organization/metrics",
        "/api/claude_code/organizations/metrics_enabled",
        "/api/claude_code/settings",
        "/api/event_logging",
        "/mcp-registry",
        "/v1/mcp_servers",
    ),
}

RULES = {
    "*": [
        rule.method_one_of(["get", "head", "options"]).then("allow"),
        rule.then("deny"),
    ],
}


def _log(msg: str) -> None:
    logger.info(msg)
    print(msg, flush=True, file=sys.stderr)


class TrafficControlAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        _log(f">>> {flow.request.method} {flow.request.pretty_url}")

        if self._is_blocked(flow):
            _log(f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}")
            flow.response = http.Response.make(502)
            return

        if flow.request.method in SAFE_METHODS:
            return

        if flow.metadata.get("handled"):
            return

        # Default deny: unsafe method to unknown destination
        _log(f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}")
        flow.response = http.Response.make(502)

    def response(self, flow: http.HTTPFlow) -> None:
        _log(f"<<< {flow.response.status_code} {flow.request.pretty_url}")

    @staticmethod
    def _is_blocked(flow: http.HTTPFlow) -> bool:
        prefixes = BLOCKED_URLS.get(flow.request.host, ())
        return any(flow.request.path.startswith(p) for p in prefixes)
