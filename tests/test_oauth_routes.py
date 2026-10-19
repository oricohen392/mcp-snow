"""
Tests for modular OAuth routes, interactive consent screen, and self-service portal.
"""

import base64
import hashlib
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from servicenow_mcp.auth.portal import (
    render_consent_html,
    render_consent_response,
    render_portal_html,
    render_portal_response,
)
from servicenow_mcp.server_sse import create_servicenow_mcp, create_starlette_app


def _pkce_pair(verifier: str = "verifier-for-consent-testing-1234567890"):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


@pytest.fixture
def test_app(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-oauth-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-oauth-secret")
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "false")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    return server, app, TestClient(app)


def test_portal_html_and_response_headers():
    html_content = render_portal_html(
        base_url="https://mcp.example.com",
        mcp_token="mcp_test12345",
        expires_in=3600,
        user_hint="alice@example.com",
    )
    assert "https://mcp.example.com/mcp" in html_content
    assert "https://mcp.example.com/sse" in html_content
    assert "mcp_test12345" in html_content
    assert "alice@example.com" in html_content

    resp = render_portal_response(
        base_url="https://mcp.example.com",
        mcp_token="mcp_test12345",
        expires_in=3600,
        user_hint="alice@example.com",
    )
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["pragma"] == "no-cache"


def test_consent_html_and_response_headers():
    html_content = render_consent_html(
        client_name="Test MCP Client",
        client_id="client-456",
        redirect_uri="http://127.0.0.1:9999/callback",
        approve_url="/oauth/authorize?client_id=client-456&consent=approved",
        deny_url="http://127.0.0.1:9999/callback?error=access_denied&state=xyz",
    )
    assert "Authorize ServiceNow MCP Access" in html_content
    assert "Test MCP Client" in html_content
    assert "client-456" in html_content
    assert "http://127.0.0.1:9999/callback" in html_content
    assert 'href="/oauth/authorize?client_id=client-456&amp;consent=approved"' in html_content
    assert 'href="http://127.0.0.1:9999/callback?error=access_denied&amp;state=xyz"' in html_content
    assert "Approve" in html_content
    assert "Deny" in html_content

    resp = render_consent_response(
        client_name="Test MCP Client",
        client_id="client-456",
        redirect_uri="http://127.0.0.1:9999/callback",
        approve_url="/oauth/authorize?client_id=client-456&consent=approved",
        deny_url="http://127.0.0.1:9999/callback?error=access_denied&state=xyz",
    )
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["pragma"] == "no-cache"


def test_consent_screen_displays_when_require_oauth_consent_true(monkeypatch, test_app):
    server, app, client = test_app
    monkeypatch.setenv("REQUIRE_OAUTH_CONSENT", "true")

    # Register client
    reg = client.post(
        "/oauth/register",
        json={
            "client_name": "Cursor Editor",
            "redirect_uris": ["http://127.0.0.1:34567/callback"],
        },
    )
    assert reg.status_code == 201
    client_id = reg.json()["client_id"]

    verifier, challenge = _pkce_pair()
    auth_res = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:34567/callback",
            "state": "client-state-1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert auth_res.status_code == 200
    assert "Authorize ServiceNow MCP Access" in auth_res.text
    assert "Cursor Editor" in auth_res.text
    assert "client-state-1" in auth_res.text
    assert "consent_ticket=mcpt_" in auth_res.text
    assert "error=access_denied" in auth_res.text
    assert "no-store" in auth_res.headers.get("cache-control", "")


def test_consent_screen_displays_when_prompt_consent(monkeypatch, test_app):
    server, app, client = test_app
    monkeypatch.setenv("REQUIRE_OAUTH_CONSENT", "false")

    reg = client.post(
        "/oauth/register",
        json={
            "client_name": "Windsurf IDE",
            "redirect_uris": ["http://localhost:5000/callback"],
        },
    )
    assert reg.status_code == 201
    client_id = reg.json()["client_id"]

    verifier, challenge = _pkce_pair()
    auth_res = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://localhost:5000/callback",
            "state": "windsurf-state-101",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "consent",
        },
        follow_redirects=False,
    )
    assert auth_res.status_code == 200
    assert "Authorize ServiceNow MCP Access" in auth_res.text
    assert "Windsurf IDE" in auth_res.text
    assert "consent_ticket=mcpt_" in auth_res.text
    assert "error=access_denied" in auth_res.text


def test_approving_consent_redirects_to_upstream_idp(monkeypatch, test_app):
    server, app, client = test_app
    monkeypatch.setenv("REQUIRE_OAUTH_CONSENT", "true")

    reg = client.post(
        "/oauth/register",
        json={
            "client_name": "Claude Desktop",
            "redirect_uris": ["http://127.0.0.1:4000/callback"],
        },
    )
    client_id = reg.json()["client_id"]

    verifier, challenge = _pkce_pair()
    base_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "http://127.0.0.1:4000/callback",
        "state": "claude-state-42",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    # 1. Attempting to bypass consent via query param &consent=approved MUST FAIL
    bypass_attempt = client.get(
        "/oauth/authorize",
        params={**base_params, "consent": "approved"},
        follow_redirects=False,
    )
    assert bypass_attempt.status_code == 200
    assert "Authorize ServiceNow MCP Access" in bypass_attempt.text

    # Extract ticket from approve_url
    assert "consent_ticket=" in bypass_attempt.text
    raw_ticket = bypass_attempt.text.split("consent_ticket=")[1].split('"')[0].split("&")[0]

    # 2. Submitting with valid consent_ticket succeeds and redirects
    auth_res = client.get(
        "/oauth/authorize",
        params={**base_params, "consent_ticket": raw_ticket},
        follow_redirects=False,
    )
    assert auth_res.status_code == 302
    upstream_loc = auth_res.headers["location"]
    assert upstream_loc.startswith("https://acme.service-now.com/oauth_auth.do?")
    qs = parse_qs(urlsplit(upstream_loc).query)
    assert "state" in qs
    assert "code_challenge" in qs

    # 3. Single-use: reusing the same ticket is rejected and re-prompts for consent
    reuse_res = client.get(
        "/oauth/authorize",
        params={**base_params, "consent_ticket": raw_ticket},
        follow_redirects=False,
    )
    assert reuse_res.status_code == 200
    assert "Authorize ServiceNow MCP Access" in reuse_res.text


def test_denying_consent_redirect_format(monkeypatch, test_app):
    server, app, client = test_app
    monkeypatch.setenv("REQUIRE_OAUTH_CONSENT", "true")

    reg = client.post(
        "/oauth/register",
        json={
            "client_name": "Deny App",
            "redirect_uris": ["http://127.0.0.1:8000/auth/callback?env=dev"],
        },
    )
    client_id = reg.json()["client_id"]

    verifier, challenge = _pkce_pair()
    auth_res = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:8000/auth/callback?env=dev",
            "state": "my-client-state-99",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert auth_res.status_code == 200
    assert "http://127.0.0.1:8000/auth/callback?env=dev" in auth_res.text
    assert "error=access_denied" in auth_res.text
    assert "state=my-client-state-99" in auth_res.text



def test_portal_flow_response_and_ttl(monkeypatch, test_app):
    server, app, client = test_app

    # 1. Start portal flow
    login_res = client.get("/auth/login", follow_redirects=False)
    assert login_res.status_code == 302
    upstream_state = parse_qs(urlsplit(login_res.headers["location"]).query)["state"][0]

    # 2. Callback from IdP
    upstream_token_resp = MagicMock()
    upstream_token_resp.status_code = 200
    upstream_token_resp.json.return_value = {
        "access_token": "sn-portal-user-token",
        "refresh_token": "sn-portal-user-refresh",
        "token_type": "Bearer",
        "expires_in": 3600,
        "user_name": "developer1",
    }
    with patch("requests.post", return_value=upstream_token_resp):
        portal_cb = client.get(
            "/oauth/callback",
            params={"code": "auth-code-123", "state": upstream_state},
        )
    assert portal_cb.status_code == 200
    assert "no-store" in portal_cb.headers.get("cache-control", "")
    assert "pragma" in portal_cb.headers
    assert "developer1" in portal_cb.text
    assert "mcp_" in portal_cb.text


def test_async_refresh_token_and_direct_ttl_calculation(monkeypatch, test_app):
    server, app, client = test_app

    # Create a session directly in store
    session = server.session_store.create_session(
        access_token="initial-access-token",
        refresh_token="initial-refresh-token",
        token_type="Bearer",
        expires_in=1800,
        user_hint="user-test",
    )
    mcp_refresh = session.downstream_refresh_token

    # Mock the upstream refresh response
    refreshed_mock = MagicMock()
    refreshed_mock.status_code = 200
    refreshed_mock.json.return_value = {
        "access_token": "refreshed-upstream-access",
        "refresh_token": "refreshed-upstream-refresh",
        "token_type": "Bearer",
        "expires_in": 1800,
    }

    with patch("requests.post", return_value=refreshed_mock) as mock_post:
        tok_res = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": mcp_refresh,
            },
        )
    assert tok_res.status_code == 200
    mock_post.assert_called_once()
    body = tok_res.json()
    assert body["access_token"] == session.mcp_token
    assert body["refresh_token"] == session.downstream_refresh_token
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 60

    # Verify session tokens in store were updated
    updated_session = server.session_store.get_session(session.mcp_token)
    assert updated_session is not None
    assert updated_session.access_token == "refreshed-upstream-access"
    assert updated_session.refresh_token == "refreshed-upstream-refresh"


def test_logout_revokes_session(monkeypatch, test_app):
    server, app, client = test_app

    session = server.session_store.create_session(
        access_token="tok1",
        refresh_token="ref1",
        token_type="Bearer",
        expires_in=1800,
    )
    mcp_token = session.mcp_token
    assert server.session_store.get_session(mcp_token) is not None

    logout_res = client.post("/auth/logout", headers={"Authorization": f"Bearer {mcp_token}"})
    assert logout_res.status_code == 200
    assert logout_res.json() == {"status": "logged_out"}
    assert server.session_store.get_session(mcp_token) is None

    # Test browser HTML form submission logout
    session2 = server.session_store.create_session(
        access_token="tok2",
        refresh_token="ref2",
        expires_in=1800,
    )
    assert server.session_store.get_session(session2.mcp_token) is not None

    form_res = client.post(
        "/auth/logout",
        data={"token": session2.mcp_token},
        headers={"Accept": "text/html,application/xhtml+xml"},
    )
    assert form_res.status_code == 200
    assert "Logged Out" in form_res.text
    assert "no-store" in form_res.headers.get("cache-control", "")
    assert server.session_store.get_session(session2.mcp_token) is None


def test_authorize_validation_errors(monkeypatch, test_app):
    server, app, client = test_app

    # Unsupported response_type
    res_bad_rt = client.get("/oauth/authorize", params={"response_type": "token"})
    assert res_bad_rt.status_code == 400
    assert res_bad_rt.json()["error"] == "unsupported_response_type"

    # Missing redirect_uri and code_challenge
    res = client.get("/oauth/authorize", params={"response_type": "code"})
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_request"

    # Missing code_challenge
    res = client.get(
        "/oauth/authorize",
        params={"response_type": "code", "redirect_uri": "http://127.0.0.1:9000/callback"},
    )
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_request"

    # Unknown client_id
    res = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "nonexistent-client",
            "redirect_uri": "http://127.0.0.1:9000/callback",
            "code_challenge": "somechallenge",
        },
    )
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_client"
