import logging
import sys
from mitmproxy import http

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


class TrafficControlAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        msg = f">>> {flow.request.method} {flow.request.pretty_url}"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)

        # Explicit blocks always win, regardless of handled status
        blocked_prefixes = BLOCKED_URLS.get(flow.request.host, ())
        if blocked_prefixes and any(flow.request.path.startswith(p) for p in blocked_prefixes):
            msg = f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}"
            logger.info(msg)
            print(msg, flush=True, file=sys.stderr)
            flow.response = http.Response.make(502)
            return

        # Safe (read-only) methods are allowed to any destination
        if flow.request.method in SAFE_METHODS:
            return

        # Auth-handled flows (known API endpoints) are allowed for any method
        if flow.metadata.get("handled"):
            return

        # Default deny: unsafe method to unknown destination
        msg = f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)
        flow.response = http.Response.make(502)

    def response(self, flow: http.HTTPFlow) -> None:
        msg = f"<<< {flow.response.status_code} {flow.request.pretty_url}"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)
