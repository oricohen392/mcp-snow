"""
Tests for server_http.py:
- Bearer auth hardening (reject arbitrary junk bearer tokens unless ALLOW_BEARER_PASSTHROUGH=true)
- Valid JWT bearer pass-through
- Origin header validation (DNS rebinding / CSRF protection)
- Backward compatibility and module re-exports in server_sse.py
- MCP_PUBLIC_URL fallback warning
"""

import base64
import json
import logging
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

import servicenow_mcp.server_http as server_http
import servicenow_mcp.server_sse as server_sse
from servicenow_mcp.server_http import (
    ServiceNowHTTPMCP,
    ServiceNowSSEMCP,
    _external_base_url,
    create_servicenow_mcp,
    create_starlette_app,
)


def _make_dummy_jwt(sub: str = "user42", email: str = "user42@example.com") -> str:
    """Construct an unverified dummy JWT with standard claims for test assertions."""
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        .decode()
        .rstrip("=")
    )
    payload = (
        base64.urlsafe_b64encode(json.dumps({"sub": sub, "email": email}).encode())
        .decode()
        .rstrip("=")
    )
    sig = "dummy_signature"
    return f"{header}.{payload}.{sig}"


@pytest.fixture
def test_app(monkeypatch):
    monkeypatch.delenv("SERVICENOW_USERNAME", raising=False)
    monkeypatch.delenv("SERVICENOW_PASSWORD", raising=False)
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "false")
    monkeypatch.setenv("ALLOW_BEARER_PASSTHROUGH", "false")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    return create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )


def test_server_sse_backward_compatibility_reexports():
    """Verify server_sse.py cleanly re-exports server_http components."""
    assert server_sse.create_starlette_app is create_starlette_app
    assert server_sse.create_servicenow_mcp is create_servicenow_mcp
    assert server_sse.ServiceNowHTTPMCP is ServiceNowHTTPMCP
    assert server_sse.ServiceNowSSEMCP is ServiceNowSSEMCP
    assert server_sse.ServiceNowSSEMCP is ServiceNowHTTPMCP
    assert server_sse.main is server_http.main


def test_junk_bearer_token_rejected_when_passthrough_disabled(test_app, monkeypatch):
    """
    Arbitrary opaque bearer token without JWT claims is rejected with 401
    when ALLOW_BEARER_PASSTHROUGH=false.
    """
    monkeypatch.setenv("ALLOW_BEARER_PASSTHROUGH", "false")
    client = TestClient(test_app)

    # 1. Rejected on /mcp
    res_mcp = client.post(
        "/mcp",
        headers={"Authorization": "Bearer invalid-opaque-token"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res_mcp.status_code == 401
    assert "Bearer" in res_mcp.headers["www-authenticate"]

    # 2. Rejected on /sse
    res_sse = client.get(
        "/sse",
        headers={"Authorization": "Bearer invalid-opaque-token"},
    )
    assert res_sse.status_code == 401

    # 3. Rejected on /messages/
    res_msg = client.post(
        "/messages/?session_id=fake-session-id",
        headers={"Authorization": "Bearer invalid-opaque-token"},
        json={},
    )
    assert res_msg.status_code == 401


def test_valid_jwt_token_accepted_as_bearer_passthrough(test_app, monkeypatch):
    """
    Valid JWT token with claims is accepted as bearer passthrough
    even if ALLOW_BEARER_PASSTHROUGH=false.
    """
    monkeypatch.setenv("ALLOW_BEARER_PASSTHROUGH", "false")
    client = TestClient(test_app)
    jwt_token = _make_dummy_jwt(sub="user123", email="user123@acme.com")

    # On /mcp, ping should succeed (status 200)
    res_mcp = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {jwt_token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res_mcp.status_code == 200
    assert res_mcp.json() == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_opaque_bearer_token_accepted_when_passthrough_enabled(test_app, monkeypatch):
    """When ALLOW_BEARER_PASSTHROUGH=true, opaque non-JWT bearer tokens are accepted."""
    monkeypatch.setenv("ALLOW_BEARER_PASSTHROUGH", "true")
    client = TestClient(test_app)

    # On /mcp, ping should succeed (status 200)
    res_mcp = client.post(
        "/mcp",
        headers={"Authorization": "Bearer arbitrary-opaque-token"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res_mcp.status_code == 200
    assert res_mcp.json() == {"jsonrpc": "2.0", "id": 1, "result": {}}


@pytest.mark.parametrize(
    "path,method,extra_kw",
    [
        ("/sse", "GET", {}),
        ("/messages/?session_id=" + "0" * 32, "POST", {"json": {}}),
        ("/mcp", "POST", {"json": {"jsonrpc": "2.0", "id": 1, "method": "ping"}}),
    ],
)
def test_invalid_origin_header_rejected_with_403(test_app, path, method, extra_kw):
    """Invalid Origin header on /sse, /messages/, and /mcp is rejected with 403 Forbidden."""
    client = TestClient(test_app)
    headers = {"Origin": "https://evil.example.com"}

    if method == "GET":
        res = client.get(path, headers=headers, **extra_kw)
    else:
        res = client.post(path, headers=headers, **extra_kw)

    assert res.status_code == 403
    assert "Forbidden" in res.text


def test_allowed_origin_headers_accepted(test_app, monkeypatch):
    """Localhost and matching host Origin headers are allowed."""
    monkeypatch.setenv("ALLOW_BEARER_PASSTHROUGH", "true")
    client = TestClient(test_app)

    # testserver host matching default TestClient host
    res1 = client.post(
        "/mcp",
        headers={
            "Origin": "http://testserver",
            "Authorization": "Bearer arbitrary-token",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res1.status_code == 200

    # localhost is always allowed
    res2 = client.post(
        "/mcp",
        headers={
            "Origin": "http://localhost:3000",
            "Authorization": "Bearer arbitrary-token",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res2.status_code == 200

    # 127.0.0.1 is always allowed
    res3 = client.post(
        "/mcp",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Authorization": "Bearer arbitrary-token",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res3.status_code == 200


def test_mcp_public_url_warning_logged_once(caplog, monkeypatch):
    """Verify warning is logged exactly once when MCP_PUBLIC_URL is unset."""
    monkeypatch.delenv("MCP_PUBLIC_URL", raising=False)
    server_http._warned_mcp_public_url = False

    req = MagicMock()
    req.headers = {"host": "mcp.example.com"}
    req.url.scheme = "https"

    with caplog.at_level(logging.WARNING):
        url1 = _external_base_url(req)
        assert url1 == "https://mcp.example.com"
        assert len([r for r in caplog.records if "MCP_PUBLIC_URL is not set" in r.message]) == 1

        # Second call does not log warning again
        url2 = _external_base_url(req)
        assert url2 == "https://mcp.example.com"
        assert len([r for r in caplog.records if "MCP_PUBLIC_URL is not set" in r.message]) == 1


def test_mcp_public_url_strictly_enforces_configured_hostname(test_app, monkeypatch):
    """
    When MCP_PUBLIC_URL is set, attackers cannot bypass origin check with matching Host headers.
    """
    monkeypatch.setenv("MCP_PUBLIC_URL", "https://trusted-mcp.company.internal")
    monkeypatch.setenv("ALLOW_BEARER_PASSTHROUGH", "true")
    client = TestClient(test_app)

    # 1. Attacker sends matching Host & Origin for untrusted domain -> MUST BE REJECTED 403
    res_bypass = client.post(
        "/mcp",
        headers={
            "Host": "evil.attacker.com",
            "Origin": "https://evil.attacker.com",
            "Authorization": "Bearer test-tok",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res_bypass.status_code == 403
    assert "Forbidden: Invalid Origin" in res_bypass.text

    # 2. Legitimate request matching MCP_PUBLIC_URL -> MUST BE ALLOWED 200
    res_allowed = client.post(
        "/mcp",
        headers={
            "Host": "trusted-mcp.company.internal",
            "Origin": "https://trusted-mcp.company.internal",
            "Authorization": "Bearer test-tok",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert res_allowed.status_code == 200

