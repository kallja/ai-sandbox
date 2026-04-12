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
    "/api/oauth/profile",
    "/v1/messages",
)
TOKEN_HOST = "platform.claude.com"
TOKEN_PATH = "/v1/oauth/token"
CREDENTIALS_PATH = os.path.expanduser("~/.config/proxy/secrets/claude.json")
DRY_RUN = False


def _log(msg: str) -> None:
    logger.info(msg)
    print(msg, flush=True, file=sys.stderr)


def _warn(msg: str) -> None:
    logger.warning(msg)
    print(msg, flush=True, file=sys.stderr)


def load_credentials() -> dict | None:
    try:
        with open(CREDENTIALS_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        _warn(f"Could not load credentials: {e}")
        return None


def save_credentials(creds: dict) -> None:
    os.makedirs(os.path.dirname(CREDENTIALS_PATH), exist_ok=True)
    with open(CREDENTIALS_PATH, "w") as f:
        json.dump(creds, f, indent=2)


def load_access_token() -> str | None:
    creds = load_credentials()
    if not creds:
        return None
    return creds.get("claudeAiOauth", {}).get("accessToken")


class ClaudeAuthAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        if self._is_token_request(flow):
            self._handle_token_request(flow)
            flow.metadata["handled"] = True
            return

        if self._is_anthropic_api(flow):
            self._inject_auth_header(flow)
            flow.metadata["handled"] = True

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("proxy_token_request"):
            self._handle_token_response(flow)

    # -- Matching --------------------------------------------------------------

    @staticmethod
    def _is_token_request(flow: http.HTTPFlow) -> bool:
        return flow.request.host == TOKEN_HOST and flow.request.path.startswith(
            TOKEN_PATH
        )

    @staticmethod
    def _is_anthropic_api(flow: http.HTTPFlow) -> bool:
        return flow.request.host == ANTHROPIC_API_HOST and any(
            flow.request.path.startswith(p) for p in ANTHROPIC_API_PATHS
        )

    # -- Auth header injection -------------------------------------------------

    @staticmethod
    def _inject_auth_header(flow: http.HTTPFlow) -> None:
        if DRY_RUN:
            _log(
                f"[DRY RUN] Would inject auth header into {flow.request.method} {flow.request.pretty_url}"
            )
            return

        token = load_access_token()
        if token:
            flow.request.headers["Authorization"] = f"Bearer {token}"
            _log(
                f"[INJECT] Auth header injected into {flow.request.method} {flow.request.pretty_url}"
            )
        else:
            _log(f"[ERROR] No access token available for {flow.request.pretty_url}")

    # -- Token request handling ------------------------------------------------

    def _handle_token_request(self, flow: http.HTTPFlow) -> None:
        content_type = flow.request.headers.get("content-type", "")
        creds = load_credentials()
        real_token = (
            creds.get("claudeAiOauth", {}).get("refreshToken") if creds else None
        )
        grant_type = None
        swapped = False

        if "application/json" in content_type:
            try:
                body = json.loads(flow.request.get_text())
                grant_type = body.get("grant_type")
                if "refresh_token" in body and real_token:
                    body["refresh_token"] = real_token
                    flow.request.set_text(json.dumps(body))
                    swapped = True
            except json.JSONDecodeError:
                pass

        elif "application/x-www-form-urlencoded" in content_type:
            params = parse_qs(flow.request.get_text(), keep_blank_values=True)
            grant_type = params.get("grant_type", [None])[0]
            if "refresh_token" in params and real_token:
                params["refresh_token"] = [real_token]
                flow.request.set_text(urlencode(params, doseq=True))
                swapped = True

        if swapped:
            _log("[TOKEN] Swapped proxy refresh_token for stored credential")
        elif grant_type == "refresh_token":
            _warn(
                "[TOKEN] refresh_token grant but could not swap — request will likely fail"
            )

        flow.metadata["proxy_token_request"] = True
        _log(
            f"[TOKEN] Forwarding {grant_type or 'unknown'} grant to {flow.request.pretty_url}"
        )

    # -- Token response handling -----------------------------------------------

    def _handle_token_response(self, flow: http.HTTPFlow) -> None:
        if flow.response.status_code != 200:
            _warn(
                f"[TOKEN] Upstream returned {flow.response.status_code}, passing through"
            )
            return

        try:
            real_response = json.loads(flow.response.get_text())
        except json.JSONDecodeError:
            _warn("[TOKEN] Could not parse upstream token response")
            return

        # Save real tokens to credential store
        creds = load_credentials() or {}
        oauth = creds.get("claudeAiOauth", {})
        if "access_token" in real_response:
            oauth["accessToken"] = real_response["access_token"]
        if "refresh_token" in real_response:
            oauth["refreshToken"] = real_response["refresh_token"]
        if "expires_in" in real_response:
            oauth["expiresAt"] = (
                int(time.time() * 1000) + real_response["expires_in"] * 1000
            )
        creds["claudeAiOauth"] = oauth
        save_credentials(creds)
        _log("[TOKEN] Saved fresh tokens to credentials file")

        # Return fake tokens to caller so it never sees the real ones
        fake_response = dict(real_response)
        fake_response["access_token"] = "proxy-injected"
        if "refresh_token" in fake_response:
            fake_response["refresh_token"] = "proxy-injected"
        flow.response.set_text(json.dumps(fake_response))
        _log("[TOKEN] Returned fake tokens to caller")
