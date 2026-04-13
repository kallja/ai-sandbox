import logging
import sys
from mitmproxy import http
from rule import rule

logger = logging.getLogger(__name__)

RULES = {
    "api.anthropic.com": [
        rule.path_starts_with(
            "/api/claude_code/metrics",
            "/api/claude_code/organization/metrics",
            "/api/claude_code/organizations/metrics_enabled",
            "/api/claude_code/settings",
            "/api/event_logging",
            "/mcp-registry",
            "/v1/mcp_servers",
        ).then("deny"),
    ],
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

        action = self._evaluate(flow)
        if action == "allow":
            return

        _log(f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}")
        flow.response = http.Response.make(502)

    def response(self, flow: http.HTTPFlow) -> None:
        _log(f"<<< {flow.response.status_code} {flow.request.pretty_url}")

    @staticmethod
    def _evaluate(flow: http.HTTPFlow) -> str | None:
        """Evaluate rules: host-specific first, then handled check, then wildcard."""
        host = flow.request.host
        for r in RULES.get(host, []):
            action = r.evaluate(flow)
            if action is not None:
                return action
        if flow.metadata.get("handled"):
            return "allow"
        for r in RULES.get("*", []):
            action = r.evaluate(flow)
            if action is not None:
                return action
        return None
