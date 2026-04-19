import logging
import sys
from mitmproxy import http
from rule import rule, FinalizedRule
from claude_auth import RULES as CLAUDE_AUTH_RULES
# from github_auth import RULES as GITHUB_AUTH_RULES
# from linear_auth import RULES as LINEAR_AUTH_RULES

logger = logging.getLogger(__name__)


LOCAL_RULES: dict[str, list[FinalizedRule]] = {
    "api.anthropic.com": [
        rule.path.starts_with("/api/hello").then("allow"),
        rule.path.starts_with("/").then("deny"),
    ],
    # "api.github.com": [
    #     rule.then("deny"),
    # ],
    # "mcp.linear.app": [
    #     rule.then("deny"),
    # ],
    "downloads.claude.ai": [
        rule.path.starts_with("/").then("deny"),
    ],
    "raw.githubusercontent.com": [
        rule.path.starts_with("/anthropics/").then("deny"),
    ],
    "github.com": [
        rule.path("/anthropics").then("deny"),
        rule.path.starts_with("/anthropics/").then("deny"),
    ],
    "storage.googleapis.com": [
        rule.path.starts_with("/claude-code-").then("deny"),
    ],
    "*": [
        rule.method.one_of(["get", "head", "options"]).then("allow"),
        rule.then("deny"),
    ],
}


def _merge_rules(
    *rule_dicts: dict[str, list[FinalizedRule]],
) -> dict[str, list[FinalizedRule]]:
    """Merge rule dicts. Earlier dicts take priority (their rules come first per host)."""
    merged: dict[str, list[FinalizedRule]] = {}
    for rd in rule_dicts:
        for host, rules in rd.items():
            merged.setdefault(host, []).extend(rules)
    return merged


RULES = _merge_rules(
    CLAUDE_AUTH_RULES,
    # GITHUB_AUTH_RULES,
    # LINEAR_AUTH_RULES,
    LOCAL_RULES,
)


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
        """Evaluate rules: host-specific first, then wildcard."""
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
