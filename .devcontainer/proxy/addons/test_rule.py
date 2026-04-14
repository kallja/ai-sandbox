import pytest
from mitmproxy import http
from mitmproxy.test import tflow

from rule import FinalizedRule, Rule, rule


def make_flow(method, url):
    flow = tflow.tflow()
    flow.request = http.Request.make(method, url)
    return flow


class TestRuleEvaluate:
    def test_unconditional_allow(self):
        r = rule("allow")
        assert r.evaluate(make_flow("GET", "https://example.com")) == "allow"

    def test_unconditional_deny(self):
        r = rule("deny")
        assert r.evaluate(make_flow("POST", "https://example.com")) == "deny"

    def test_then_syntax_same_as_call(self):
        r = rule.then("deny")
        assert r.evaluate(make_flow("GET", "https://example.com")) == "deny"

    def test_no_action_has_no_evaluate(self):
        r = rule.method.one_of(["get"])
        assert not hasattr(r, "evaluate")


class TestMethodOneOf:
    def test_matching_method(self):
        r = rule.method.one_of(["get", "head"]).then("allow")
        assert r.evaluate(make_flow("GET", "https://example.com")) == "allow"
        assert r.evaluate(make_flow("HEAD", "https://example.com")) == "allow"

    def test_non_matching_method(self):
        r = rule.method.one_of(["get", "head"]).then("allow")
        assert r.evaluate(make_flow("POST", "https://example.com")) is None

    def test_case_insensitive(self):
        r = rule.method.one_of(["GET", "Head"]).then("allow")
        assert r.evaluate(make_flow("GET", "https://example.com")) == "allow"
        assert r.evaluate(make_flow("HEAD", "https://example.com")) == "allow"


class TestPathStartsWith:
    def test_matching_prefix(self):
        r = rule.path.starts_with("/api/metrics").then("deny")
        assert r.evaluate(make_flow("GET", "https://example.com/api/metrics")) == "deny"
        assert r.evaluate(make_flow("GET", "https://example.com/api/metrics/foo")) == "deny"

    def test_non_matching_prefix(self):
        r = rule.path.starts_with("/api/metrics").then("deny")
        assert r.evaluate(make_flow("GET", "https://example.com/api/other")) is None

    def test_multiple_prefixes(self):
        r = rule.path.starts_with.one_of(["/foo", "/bar"]).then("deny")
        assert r.evaluate(make_flow("GET", "https://example.com/foo")) == "deny"
        assert r.evaluate(make_flow("GET", "https://example.com/bar")) == "deny"
        assert r.evaluate(make_flow("GET", "https://example.com/baz")) is None


class TestPathOneOf:
    def test_exact_match(self):
        r = rule.path.one_of(["/foo", "/bar"]).then("deny")
        assert r.evaluate(make_flow("GET", "https://example.com/foo")) == "deny"
        assert r.evaluate(make_flow("GET", "https://example.com/bar")) == "deny"
        assert r.evaluate(make_flow("GET", "https://example.com/foo/extra")) is None


class TestChaining:
    def test_method_and_path(self):
        r = rule.method.one_of(["post"]).path.starts_with("/api").then("deny")
        assert r.evaluate(make_flow("POST", "https://example.com/api/data")) == "deny"
        assert r.evaluate(make_flow("GET", "https://example.com/api/data")) is None
        assert r.evaluate(make_flow("POST", "https://example.com/other")) is None


class TestImmutability:
    def test_rule_singleton_not_mutated(self):
        rule.method.one_of(["get"]).then("allow")
        rule("deny")
        assert isinstance(rule, Rule)
        assert not isinstance(rule, FinalizedRule)

    def test_branching_from_same_base(self):
        base = rule.method.one_of(["get"])
        allow = base.then("allow")
        deny = base.then("deny")
        flow = make_flow("GET", "https://example.com")
        assert allow.evaluate(flow) == "allow"
        assert deny.evaluate(flow) == "deny"
