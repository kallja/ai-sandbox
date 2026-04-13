import logging
import sys
from mitmproxy import http
from rule import rule

logger = logging.getLogger(__name__)

RULES = {
    "api.anthropic.com": [
        rule.path_starts_with("/").then("deny"),
    ],
    "downloads.claude.ai": [
        rule.path_starts_with("/").then("deny"),
    ],
    "raw.githubusercontent.com": [
        rule.path_starts_with("/anthropics/").then("deny"),
    ],
    "github.com": [
        rule.path_starts_with("/anthropics/").then("deny"),
    ],
    "storage.googleapis.com": [
        rule.path_starts_with("/claude-code-").then("deny"),
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
        """Evaluate rules: handled check first, then host-specific, then wildcard."""
        if flow.metadata.get("handled"):
            return "allow"
        host = flow.request.host
        for r in RULES.get(host, []):
            action = r.evaluate(flow)
            if action is not None:
                return action
        for r in RULES.get("*", []):
            action = r.evaluate(flow)
            if action is not None:
                return action
        return None
