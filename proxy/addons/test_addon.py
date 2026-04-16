import json
import pytest
from mitmproxy import http
from mitmproxy.test import taddons, tflow

import claude_auth
import linear_auth
import traffic_control


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_CREDS = {
    "claudeAiOauth": {
        "accessToken": "real-access-token",
        "refreshToken": "real-refresh-token",
        "expiresAt": 1700000000000,
        "scopes": ["user:inference"],
        "subscriptionType": "pro",
        "rateLimitTier": "tier1",
    },
    "mcpOAuth.linear-server|638130d5ab3558f4": {
        "accessToken": "linear-access-token",
        "refreshToken": "linear-refresh-token",
    },
}

SAMPLE_TOKEN_RESPONSE = {
    "token_type": "Bearer",
    "access_token": "fresh-access-token",
    "expires_in": 28800,
    "refresh_token": "fresh-refresh-token",
    "scope": "user:inference",
    "organization": {"uuid": "org-uuid", "name": "Hoxhunt"},
    "account": {"uuid": "acc-uuid", "email_address": "test@hoxhunt.com"},
}


def write_creds(tmp_path, creds=SAMPLE_CREDS):
    creds_file = tmp_path / "claude.json"
    creds_file.write_text(json.dumps(creds))
    return str(creds_file)


def make_flow(method, url, content=b"", headers=None, response_code=None, response_body=None):
    """Build an HTTPFlow with the given request (and optional response)."""
    flow = tflow.tflow()
    flow.request = http.Request.make(method, url, content=content, headers=headers or {})
    if response_code is not None:
        body = response_body.encode() if isinstance(response_body, str) else (response_body or b"")
        flow.response = http.Response.make(response_code, body, {"content-type": "application/json"})
    return flow


def make_token_request_flow(grant_type="refresh_token", extra_fields=None):
    """Build a token request flow matching real Claude traffic."""
    body = {"grant_type": grant_type}
    if grant_type == "refresh_token":
        body["refresh_token"] = "proxy-injected"
        body["client_id"] = "test-client-id"
        body["scope"] = "user:inference"
    elif grant_type == "authorization_code":
        body["code"] = "auth-code-123"
        body["redirect_uri"] = "https://platform.claude.com/oauth/code/callback"
        body["client_id"] = "test-client-id"
        body["code_verifier"] = "verifier-123"
        body["state"] = "state-123"
    if extra_fields:
        body.update(extra_fields)
    return make_flow(
        "POST",
        "https://platform.claude.com/v1/oauth/token",
        content=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def creds_path(tmp_path, monkeypatch):
    """Point claude_auth.CREDENTIALS_PATH to a temp file and write sample creds."""
    path = write_creds(tmp_path)
    monkeypatch.setattr(claude_auth, "CREDENTIALS_PATH", path)
    return path


@pytest.fixture
def no_creds(tmp_path, monkeypatch):
    """Point claude_auth.CREDENTIALS_PATH to a non-existent file."""
    path = str(tmp_path / "nonexistent.json")
    monkeypatch.setattr(claude_auth, "CREDENTIALS_PATH", path)
    return path


@pytest.fixture
def auth_addon():
    inst = claude_auth.ClaudeAuthAddon()
    with taddons.context(inst):
        yield inst


@pytest.fixture
def linear_addon():
    inst = linear_auth.LinearAuthAddon()
    with taddons.context(inst):
        yield inst


@pytest.fixture
def tc_addon():
    inst = traffic_control.TrafficControlAddon()
    with taddons.context(inst):
        yield inst


# ---------------------------------------------------------------------------
# Tests: traffic control — blocked URLs
# ---------------------------------------------------------------------------

class TestBlockedUrls:
    def test_blocked_anthropic_metrics(self, tc_addon):
        flow = make_flow("GET", "https://api.anthropic.com/api/claude_code/metrics")
        tc_addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 502

    def test_blocked_anthropic_event_logging(self, tc_addon):
        flow = make_flow("POST", "https://api.anthropic.com/api/event_logging")
        tc_addon.request(flow)
        assert flow.response.status_code == 502

    def test_blocked_claude_code_settings(self, tc_addon):
        flow = make_flow("GET", "https://api.anthropic.com/api/claude_code/settings")
        tc_addon.request(flow)
        assert flow.response.status_code == 502

    def test_non_blocked_url_passes_through(self, tc_addon):
        flow = make_flow("GET", "https://example.com/something")
        tc_addon.request(flow)
        assert flow.response is None

    def test_claude_auth_rules_allow_api_paths(self, tc_addon):
        """Claude auth rules explicitly allow API paths that would otherwise be blocked."""
        flow = make_flow("POST", "https://api.anthropic.com/v1/messages")
        tc_addon.request(flow)
        assert flow.response is None

    def test_claude_auth_rules_allow_token_endpoint(self, tc_addon):
        """Claude auth rules explicitly allow the token endpoint."""
        flow = make_flow("POST", "https://platform.claude.com/v1/oauth/token")
        tc_addon.request(flow)
        assert flow.response is None

    def test_github_graphql_allowed(self, tc_addon):
        """GitHub GraphQL API is explicitly allowed."""
        flow = make_flow("POST", "https://api.github.com/graphql")
        tc_addon.request(flow)
        assert flow.response is None

    def test_linear_mcp_post_allowed(self, tc_addon):
        """POST to Linear MCP endpoint is explicitly allowed."""
        flow = make_flow("POST", "https://mcp.linear.app/mcp")
        tc_addon.request(flow)
        assert flow.response is None

    def test_linear_mcp_get_blocked(self, tc_addon):
        """GET to Linear MCP endpoint is blocked."""
        flow = make_flow("GET", "https://mcp.linear.app/mcp")
        tc_addon.request(flow)
        assert flow.response.status_code == 502


# ---------------------------------------------------------------------------
# Tests: traffic control — default deny for unsafe methods
# ---------------------------------------------------------------------------

class TestDefaultDeny:
    def test_post_to_unknown_host_blocked(self, tc_addon):
        flow = make_flow("POST", "https://example.com/api/data")
        tc_addon.request(flow)
        assert flow.response.status_code == 502

    def test_put_to_unknown_host_blocked(self, tc_addon):
        flow = make_flow("PUT", "https://example.com/api/data")
        tc_addon.request(flow)
        assert flow.response.status_code == 502

    def test_get_to_unknown_host_allowed(self, tc_addon):
        flow = make_flow("GET", "https://example.com/something")
        tc_addon.request(flow)
        assert flow.response is None

    def test_head_to_unknown_host_allowed(self, tc_addon):
        flow = make_flow("HEAD", "https://example.com/something")
        tc_addon.request(flow)
        assert flow.response is None

    def test_options_to_unknown_host_allowed(self, tc_addon):
        flow = make_flow("OPTIONS", "https://example.com/something")
        tc_addon.request(flow)
        assert flow.response is None

    def test_claude_auth_allows_unsafe_method_on_allowed_paths(self, tc_addon):
        """Claude auth rules allow POST to explicitly allowed API paths."""
        flow = make_flow("POST", "https://api.anthropic.com/v1/messages")
        tc_addon.request(flow)
        assert flow.response is None


# ---------------------------------------------------------------------------
# Tests: claude auth — header injection on API requests
# ---------------------------------------------------------------------------

class TestAuthInjection:
    def test_injects_auth_header_on_messages(self, auth_addon, creds_path):
        flow = make_flow("POST", "https://api.anthropic.com/v1/messages")
        auth_addon.request(flow)
        assert flow.request.headers.get("Authorization") == "Bearer real-access-token"

    def test_no_injection_on_bootstrap(self, auth_addon, creds_path):
        """Bootstrap path is not auth-handled; traffic control will block it."""
        flow = make_flow("GET", "https://api.anthropic.com/api/claude_cli/bootstrap")
        auth_addon.request(flow)
        assert "Authorization" not in flow.request.headers

    def test_no_injection_without_credentials(self, auth_addon, no_creds):
        flow = make_flow("POST", "https://api.anthropic.com/v1/messages")
        auth_addon.request(flow)
        assert "Authorization" not in flow.request.headers

    def test_no_injection_on_non_allowed_path(self, auth_addon, creds_path):
        flow = make_flow("GET", "https://api.anthropic.com/v1/something-else")
        auth_addon.request(flow)
        assert "Authorization" not in flow.request.headers

    def test_does_not_handle_unknown_hosts(self, auth_addon, creds_path):
        flow = make_flow("GET", "https://example.com/something")
        auth_addon.request(flow)
        assert "Authorization" not in flow.request.headers


# ---------------------------------------------------------------------------
# Tests: claude auth — token request (refresh_token grant)
# ---------------------------------------------------------------------------

class TestTokenRequestRefresh:
    def test_swaps_refresh_token_in_json_body(self, auth_addon, creds_path):
        flow = make_token_request_flow("refresh_token")
        auth_addon.request(flow)

        body = json.loads(flow.request.get_text())
        assert body["refresh_token"] == "real-refresh-token"
        assert body["grant_type"] == "refresh_token"
        assert flow.metadata.get("proxy_token_request") is True

    def test_swaps_refresh_token_in_form_body(self, auth_addon, creds_path):
        form_body = "grant_type=refresh_token&refresh_token=proxy-injected&client_id=test"
        flow = make_flow(
            "POST",
            "https://platform.claude.com/v1/oauth/token",
            content=form_body.encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        auth_addon.request(flow)

        from urllib.parse import parse_qs
        params = parse_qs(flow.request.get_text())
        assert params["refresh_token"] == ["real-refresh-token"]
        assert flow.metadata.get("proxy_token_request") is True

    def test_warns_when_no_creds_for_refresh(self, auth_addon, no_creds):
        """refresh_token grant without stored creds: still forwards, but warns."""
        flow = make_token_request_flow("refresh_token")
        auth_addon.request(flow)

        body = json.loads(flow.request.get_text())
        assert body["refresh_token"] == "proxy-injected"
        assert flow.response is None
        assert flow.metadata.get("proxy_token_request") is True

    def test_preserves_other_fields(self, auth_addon, creds_path):
        flow = make_token_request_flow("refresh_token", extra_fields={"custom": "value"})
        auth_addon.request(flow)

        body = json.loads(flow.request.get_text())
        assert body["custom"] == "value"
        assert body["client_id"] == "test-client-id"


# ---------------------------------------------------------------------------
# Tests: claude auth — token request (authorization_code grant)
# ---------------------------------------------------------------------------

class TestTokenRequestAuthCode:
    def test_auth_code_passes_through_unmodified(self, auth_addon, creds_path):
        flow = make_token_request_flow("authorization_code")
        auth_addon.request(flow)

        body = json.loads(flow.request.get_text())
        assert body["code"] == "auth-code-123"
        assert body["grant_type"] == "authorization_code"
        assert "refresh_token" not in body
        assert flow.metadata.get("proxy_token_request") is True

    def test_auth_code_works_without_stored_creds(self, auth_addon, no_creds):
        """Initial login: no stored creds, auth_code should still forward."""
        flow = make_token_request_flow("authorization_code")
        auth_addon.request(flow)

        assert flow.response is None
        assert flow.metadata.get("proxy_token_request") is True


# ---------------------------------------------------------------------------
# Tests: claude auth — token response interception
# ---------------------------------------------------------------------------

class TestTokenResponse:
    def test_saves_real_tokens_returns_fake(self, auth_addon, creds_path):
        flow = make_token_request_flow("refresh_token")
        auth_addon.request(flow)

        flow.response = http.Response.make(
            200,
            json.dumps(SAMPLE_TOKEN_RESPONSE).encode(),
            {"content-type": "application/json"},
        )
        auth_addon.response(flow)

        caller_response = json.loads(flow.response.get_text())
        assert caller_response["access_token"] == "proxy-injected"
        assert caller_response["refresh_token"] == "proxy-injected"
        assert caller_response["token_type"] == "Bearer"
        assert caller_response["organization"]["name"] == "Hoxhunt"
        assert caller_response["scope"] == "user:inference"

        saved = json.loads(open(creds_path).read())
        assert saved["claudeAiOauth"]["accessToken"] == "fresh-access-token"
        assert saved["claudeAiOauth"]["refreshToken"] == "fresh-refresh-token"
        assert saved["claudeAiOauth"]["expiresAt"] > 0

    def test_auth_code_response_saves_tokens(self, auth_addon, no_creds, tmp_path, monkeypatch):
        """First login via auth_code: creates credentials file from scratch."""
        creds_path = str(tmp_path / "new-creds.json")
        monkeypatch.setattr(claude_auth, "CREDENTIALS_PATH", creds_path)

        flow = make_token_request_flow("authorization_code")
        auth_addon.request(flow)

        flow.response = http.Response.make(
            200,
            json.dumps(SAMPLE_TOKEN_RESPONSE).encode(),
            {"content-type": "application/json"},
        )
        auth_addon.response(flow)

        caller_response = json.loads(flow.response.get_text())
        assert caller_response["access_token"] == "proxy-injected"
        assert caller_response["refresh_token"] == "proxy-injected"

        saved = json.loads(open(creds_path).read())
        assert saved["claudeAiOauth"]["accessToken"] == "fresh-access-token"
        assert saved["claudeAiOauth"]["refreshToken"] == "fresh-refresh-token"

    def test_non_200_response_passes_through(self, auth_addon, creds_path):
        flow = make_token_request_flow("refresh_token")
        auth_addon.request(flow)

        flow.response = http.Response.make(401, b'{"error": "invalid_grant"}')
        auth_addon.response(flow)

        resp = json.loads(flow.response.get_text())
        assert resp["error"] == "invalid_grant"

    def test_non_token_response_not_intercepted(self, auth_addon, creds_path):
        """Normal API responses should not be modified."""
        flow = make_flow(
            "POST", "https://api.anthropic.com/v1/messages",
            response_code=200,
            response_body='{"content": "hello"}',
        )
        auth_addon.request(flow)
        auth_addon.response(flow)

        resp = json.loads(flow.response.get_text())
        assert resp["content"] == "hello"

    def test_preserves_existing_cred_fields(self, auth_addon, creds_path):
        """Token refresh should preserve non-token fields in stored creds."""
        flow = make_token_request_flow("refresh_token")
        auth_addon.request(flow)

        flow.response = http.Response.make(
            200,
            json.dumps(SAMPLE_TOKEN_RESPONSE).encode(),
            {"content-type": "application/json"},
        )
        auth_addon.response(flow)

        saved = json.loads(open(creds_path).read())
        assert saved["claudeAiOauth"]["scopes"] == ["user:inference"]
        assert saved["claudeAiOauth"]["subscriptionType"] == "pro"


# ---------------------------------------------------------------------------
# Tests: claude auth — dry run mode
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_dry_run_does_not_inject_auth(self, auth_addon, creds_path, monkeypatch):
        monkeypatch.setattr(claude_auth, "DRY_RUN", True)
        flow = make_flow("POST", "https://api.anthropic.com/v1/messages")
        auth_addon.request(flow)
        assert "Authorization" not in flow.request.headers


# ---------------------------------------------------------------------------
# Tests: linear auth — header injection
# ---------------------------------------------------------------------------

class TestLinearAuthInjection:
    def test_injects_auth_header_on_mcp(self, linear_addon, creds_path):
        flow = make_flow("POST", "https://mcp.linear.app/mcp")
        linear_addon.request(flow)
        assert flow.request.headers.get("Authorization") == "Bearer linear-access-token"

    def test_no_injection_without_credentials(self, linear_addon, no_creds):
        flow = make_flow("POST", "https://mcp.linear.app/mcp")
        linear_addon.request(flow)
        assert "Authorization" not in flow.request.headers

    def test_no_injection_on_wrong_path(self, linear_addon, creds_path):
        flow = make_flow("POST", "https://mcp.linear.app/other")
        linear_addon.request(flow)
        assert "Authorization" not in flow.request.headers

    def test_no_injection_on_unknown_host(self, linear_addon, creds_path):
        flow = make_flow("POST", "https://example.com/mcp")
        linear_addon.request(flow)
        assert "Authorization" not in flow.request.headers


# ---------------------------------------------------------------------------
# Tests: addon pipeline (auth + traffic control together)
# ---------------------------------------------------------------------------

class TestAddonPipeline:
    def test_claude_api_not_blocked_by_traffic_control(self, auth_addon, tc_addon, creds_path):
        """Claude auth rules explicitly allow API paths, so traffic control passes them."""
        flow = make_flow("POST", "https://api.anthropic.com/v1/messages")
        auth_addon.request(flow)
        tc_addon.request(flow)
        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer real-access-token"

    def test_blocked_url_not_handled_by_auth(self, auth_addon, tc_addon):
        """Metrics endpoint is not handled by auth, so traffic control blocks it."""
        flow = make_flow("GET", "https://api.anthropic.com/api/claude_code/metrics")
        auth_addon.request(flow)
        tc_addon.request(flow)
        assert flow.response.status_code == 502

    def test_unknown_get_passes_through(self, auth_addon, tc_addon):
        """GET to unknown hosts passes through both addons."""
        flow = make_flow("GET", "https://example.com/something")
        auth_addon.request(flow)
        tc_addon.request(flow)
        assert flow.response is None

    def test_unknown_post_blocked(self, auth_addon, tc_addon):
        """POST to unknown hosts is blocked by traffic control."""
        flow = make_flow("POST", "https://example.com/api/data")
        auth_addon.request(flow)
        tc_addon.request(flow)
        assert flow.response.status_code == 502

    def test_linear_mcp_pipeline(self, linear_addon, tc_addon, creds_path):
        """Linear auth injects token, traffic control allows POST to /mcp."""
        flow = make_flow("POST", "https://mcp.linear.app/mcp")
        linear_addon.request(flow)
        tc_addon.request(flow)
        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer linear-access-token"
