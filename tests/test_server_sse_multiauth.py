"""Tests for centralized multi-user SSE authentication, OAuth 2.1 broker endpoints, and /auth/login."""

import base64
import hashlib
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from servicenow_mcp.server_sse import create_servicenow_mcp, create_starlette_app


def _pkce_pair(verifier: str = "verifier-for-mcp-ide-client-1234567890"):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def test_create_servicenow_mcp_without_service_account(monkeypatch):
    monkeypatch.delenv("SERVICENOW_USERNAME", raising=False)
    monkeypatch.delenv("SERVICENOW_PASSWORD", raising=False)
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "false")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    client = TestClient(
        create_starlette_app(
            server.mcp_server,
            auth_manager=server.auth_manager,
            session_store=server.session_store,
            oauth_broker=server.oauth_broker,
            require_auth=True,
        )
    )

    # Unauthenticated /sse is rejected with 401 + OAuth discovery metadata
    res = client.get("/sse")
    assert res.status_code == 401
    assert "Bearer" in res.headers["www-authenticate"]
    assert "/.well-known/oauth-protected-resource" in res.headers["www-authenticate"]

    # Discovery endpoints are open
    pr = client.get("/.well-known/oauth-protected-resource")
    assert pr.status_code == 200
    assert "authorization_servers" in pr.json()

    as_meta = client.get("/.well-known/oauth-authorization-server")
    assert as_meta.status_code == 200
    assert as_meta.json()["code_challenge_methods_supported"] == ["S256"]


def test_full_mcp_oauth21_dcr_pkce_and_refresh_flow(monkeypatch):
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
    client = TestClient(app)

    # 1. Dynamic Client Registration
    reg = client.post(
        "/oauth/register",
        json={
            "client_name": "Claude Code",
            "redirect_uris": ["http://127.0.0.1:45678/callback"],
        },
    )
    assert reg.status_code == 201
    client_id = reg.json()["client_id"]

    # Reject non-loopback open redirect in /oauth/register
    bad_reg = client.post(
        "/oauth/register",
        json={"client_name": "Evil", "redirect_uris": ["https://evil.example.com/cb"]},
    )
    assert bad_reg.status_code == 400

    # 2. Authorize redirect to ServiceNow
    verifier, challenge = _pkce_pair()
    auth_res = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:45678/callback",
            "state": "ide-state-999",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert auth_res.status_code == 302
    upstream_loc = auth_res.headers["location"]
    assert upstream_loc.startswith("https://acme.service-now.com/oauth_auth.do?")
    upstream_state = parse_qs(urlsplit(upstream_loc).query)["state"][0]

    # 3. Callback from ServiceNow exchanges upstream code and redirects back to IDE
    upstream_token_resp = MagicMock()
    upstream_token_resp.status_code = 200
    upstream_token_resp.json.return_value = {
        "access_token": "sn-user-access-token-1",
        "refresh_token": "sn-user-refresh-token-1",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    with patch("requests.post", return_value=upstream_token_resp):
        cb_res = client.get(
            "/oauth/callback",
            params={"code": "sn-upstream-code", "state": upstream_state},
            follow_redirects=False,
        )
    assert cb_res.status_code == 302
    ide_loc = cb_res.headers["location"]
    assert ide_loc.startswith("http://127.0.0.1:45678/callback?")
    ide_qs = parse_qs(urlsplit(ide_loc).query)
    assert ide_qs["state"] == ["ide-state-999"]
    downstream_code = ide_qs["code"][0]

    # 4. IDE exchanges downstream_code + PKCE verifier at POST /oauth/token
    tok_res = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": downstream_code,
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:45678/callback",
            "code_verifier": verifier,
        },
    )
    assert tok_res.status_code == 200
    tok_body = tok_res.json()
    mcp_token = tok_body["access_token"]
    mcp_refresh = tok_body["refresh_token"]
    assert mcp_token.startswith("mcp_")
    assert mcp_refresh.startswith("mcpr_")

    # 4b. Test refresh_token exchange at /oauth/token
    refresh_upstream_resp = MagicMock()
    refresh_upstream_resp.status_code = 200
    refresh_upstream_resp.json.return_value = {
        "access_token": "sn-user-refreshed-token",
        "refresh_token": "sn-user-refreshed-refresh",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    with patch("requests.post", return_value=refresh_upstream_resp):
        refresh_tok_res = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": mcp_refresh,
            },
        )
    assert refresh_tok_res.status_code == 200
    assert refresh_tok_res.json()["access_token"] == mcp_token

    # 5. Authenticated request with mcp_token passes middleware
    msg_res = client.post(
        "/messages/?session_id=" + "0" * 32,
        headers={"Authorization": f"Bearer {mcp_token}"},
        json={},
    )
    assert msg_res.status_code in (400, 404)

    # 6. Logout revokes the token
    logout_res = client.post("/auth/logout", headers={"Authorization": f"Bearer {mcp_token}"})
    assert logout_res.status_code == 200
    after_logout = client.post(
        "/messages/?session_id=" + "0" * 32,
        headers={"Authorization": f"Bearer {mcp_token}"},
        json={},
    )
    assert after_logout.status_code == 401


def test_self_service_portal_login_and_header_passthrough(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-oauth-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-oauth-secret")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    login_res = client.get("/auth/login", follow_redirects=False)
    assert login_res.status_code == 302
    state = parse_qs(urlsplit(login_res.headers["location"]).query)["state"][0]

    upstream_token_resp = MagicMock()
    upstream_token_resp.status_code = 200
    upstream_token_resp.json.return_value = {
        "access_token": "sn-portal-access",
        "refresh_token": "sn-portal-refresh",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    with patch("requests.post", return_value=upstream_token_resp):
        portal_cb = client.get("/oauth/callback", params={"code": "c1", "state": state})
    assert portal_cb.status_code == 200
    assert "mcp_" in portal_cb.text
    assert "/sse" in portal_cb.text

    # Direct X-ServiceNow-API-Key pass-through also works
    api_key_res = client.post(
        "/messages/?session_id=" + "0" * 32,
        headers={"X-ServiceNow-API-Key": "direct-sn-key"},
        json={},
    )
    assert api_key_res.status_code in (400, 404)
