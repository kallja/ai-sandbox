import json
import logging
import os
import sys
import time
from urllib.parse import urlencode, parse_qs
from mitmproxy import http

logger = logging.getLogger(__name__)

ANTHROPIC_API_HOST = "api.anthropic.com"
ANTHROPIC_API_PATHS = (
    "/api/claude_cli/bootstrap",
    "/api/claude_code/policy_limits",
    "/api/claude_code_penguin_mode",
    "/api/oauth/profile",
    "/v1/messages",
)
TOKEN_HOST = "platform.claude.com"
TOKEN_PATH = "/v1/oauth/token"
CREDENTIALS_PATH = os.path.expanduser("~/.config/proxy/secrets/claude.json")
DRY_RUN = False


def load_credentials() -> dict | None:
    try:
        with open(CREDENTIALS_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Could not load credentials: {e}")
        return None


def save_credentials(creds: dict) -> None:
    os.makedirs(os.path.dirname(CREDENTIALS_PATH), exist_ok=True)
    with open(CREDENTIALS_PATH, "w") as f:
        json.dump(creds, f, indent=2)


def load_access_token() -> str | None:
    creds = load_credentials()
    if creds:
        try:
            return creds["claudeAiOauth"]["accessToken"]
        except KeyError:
            return None
    return None


class ClaudeAuthAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        # Token endpoint: swap fake credentials for real ones before forwarding
        if flow.request.host == TOKEN_HOST and flow.request.path.startswith(TOKEN_PATH):
            self._handle_token_request(flow)
            flow.metadata["handled"] = True
            return

        # Anthropic API: inject real auth header
        if flow.request.host == ANTHROPIC_API_HOST and any(
            flow.request.path.startswith(p) for p in ANTHROPIC_API_PATHS
        ):
            if DRY_RUN:
                msg = f"[DRY RUN] Would inject auth header into {flow.request.method} {flow.request.pretty_url}"
                logger.info(msg)
                print(msg, flush=True, file=sys.stderr)
            else:
                token = load_access_token()
                if token:
                    flow.request.headers["Authorization"] = f"Bearer {token}"
                    msg = f"[INJECT] Auth header injected into {flow.request.method} {flow.request.pretty_url}"
                else:
                    msg = f"[ERROR] No access token available for {flow.request.pretty_url}"
                logger.info(msg)
                print(msg, flush=True, file=sys.stderr)
            flow.metadata["handled"] = True

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("proxy_token_request"):
            self._handle_token_response(flow)

    def _handle_token_request(self, flow: http.HTTPFlow) -> None:
        content_type = flow.request.headers.get("content-type", "")
        swapped = False

        if "application/x-www-form-urlencoded" in content_type:
            params = parse_qs(flow.request.get_text(), keep_blank_values=True)
            if "refresh_token" in params:
                swapped = self._swap_refresh_token_form(flow, params)
        elif "application/json" in content_type:
            try:
                body = json.loads(flow.request.get_text())
                if "refresh_token" in body:
                    swapped = self._swap_refresh_token_json(flow, body)
            except json.JSONDecodeError:
                pass

        grant_type = self._get_grant_type(flow, content_type)
        if not swapped and grant_type == "refresh_token":
            msg = "[TOKEN] refresh_token grant but could not swap token — request will likely fail"
            logger.warning(msg)
            print(msg, flush=True, file=sys.stderr)

        flow.metadata["proxy_token_request"] = True
        msg = f"[TOKEN] Forwarding {grant_type or 'unknown'} grant to {flow.request.pretty_url}"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)

    def _swap_refresh_token_form(self, flow: http.HTTPFlow, params: dict) -> bool:
        creds = load_credentials()
        if not creds:
            return False
        real_token = creds.get("claudeAiOauth", {}).get("refreshToken")
        if not real_token:
            return False
        params["refresh_token"] = [real_token]
        flow.request.set_text(urlencode(params, doseq=True))
        msg = "[TOKEN] Swapped fake refresh_token for real one in form body"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)
        return True

    def _swap_refresh_token_json(self, flow: http.HTTPFlow, body: dict) -> bool:
        creds = load_credentials()
        if not creds:
            return False
        real_token = creds.get("claudeAiOauth", {}).get("refreshToken")
        if not real_token:
            return False
        body["refresh_token"] = real_token
        flow.request.set_text(json.dumps(body))
        msg = "[TOKEN] Swapped fake refresh_token for real one in JSON body"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)
        return True

    @staticmethod
    def _get_grant_type(flow: http.HTTPFlow, content_type: str) -> str | None:
        try:
            if "application/json" in content_type:
                return json.loads(flow.request.get_text()).get("grant_type")
            elif "application/x-www-form-urlencoded" in content_type:
                params = parse_qs(flow.request.get_text())
                return params.get("grant_type", [None])[0]
        except (json.JSONDecodeError, IndexError):
            pass
        return None

    def _handle_token_response(self, flow: http.HTTPFlow) -> None:
        if flow.response.status_code != 200:
            msg = f"[TOKEN] Upstream returned {flow.response.status_code}, passing through"
            logger.warning(msg)
            print(msg, flush=True, file=sys.stderr)
            return

        try:
            real_response = json.loads(flow.response.get_text())
        except json.JSONDecodeError:
            msg = "[TOKEN] Could not parse upstream token response"
            logger.warning(msg)
            print(msg, flush=True, file=sys.stderr)
            return

        # Update stored credentials with fresh tokens from upstream
        creds = load_credentials() or {}
        oauth = creds.get("claudeAiOauth", {})
        if "access_token" in real_response:
            oauth["accessToken"] = real_response["access_token"]
        if "refresh_token" in real_response:
            oauth["refreshToken"] = real_response["refresh_token"]
        if "expires_in" in real_response:
            oauth["expiresAt"] = int(time.time() * 1000) + real_response["expires_in"] * 1000
        creds["claudeAiOauth"] = oauth
        save_credentials(creds)

        msg = "[TOKEN] Saved fresh tokens to credentials file"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)

        # Return fake tokens to caller
        fake_response = dict(real_response)
        fake_response["access_token"] = "proxy-injected"
        if "refresh_token" in fake_response:
            fake_response["refresh_token"] = "proxy-injected"

        flow.response.set_text(json.dumps(fake_response))
        msg = "[TOKEN] Returned fake tokens to caller"
        logger.info(msg)
        print(msg, flush=True, file=sys.stderr)
