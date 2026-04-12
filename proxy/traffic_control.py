import logging
import sys
from mitmproxy import http

logger = logging.getLogger(__name__)

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

        # Skip flows already handled by auth addons
        if flow.metadata.get("handled"):
            return

        blocked_prefixes = BLOCKED_URLS.get(flow.request.host, ())
        if blocked_prefixes and any(flow.request.path.startswith(p) for p in blocked_prefixes):
            msg = f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}"
            logger.info(msg)
            print(msg, flush=True, file=sys.stderr)
            flow.response = http.Response.make(502)
            return

    def response(self, flow: http.HTTPFlow) -> None:
        msg = f"<<< {flow.response.status_code} {flow.request.pretty_url}"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)
