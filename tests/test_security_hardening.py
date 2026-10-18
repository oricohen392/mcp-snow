"""Tests for security hardening: headers, body limits, rate limits, and query sanitization."""

import json
import pytest
from starlette.testclient import TestClient
import mcp.types as types

from servicenow_mcp.server import _reject_query_separators
from servicenow_mcp.server_sse import create_servicenow_mcp, create_starlette_app


def test_security_headers_present_on_all_responses():
    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    # Healthz
    r_health = client.get("/healthz")
    assert r_health.status_code == 200
    assert r_health.headers.get("x-content-type-options") == "nosniff"
    assert r_health.headers.get("x-frame-options") == "DENY"
    assert r_health.headers.get("referrer-policy") == "no-referrer"
    assert "default-src 'self'" in r_health.headers.get("content-security-policy", "")

    # Sensitive endpoints must have Cache-Control: no-store
    session = server.session_store.create_session(access_token="tok", expires_in=3600)
    r_mcp = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {session.mcp_token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert r_mcp.status_code == 200
    cache_ctrl = r_mcp.headers.get("cache-control", "")
    assert "no-store" in cache_ctrl
    assert "no-cache" in cache_ctrl


def test_oversized_payload_rejected_with_413():
    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    session = server.session_store.create_session(access_token="tok", expires_in=3600)
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    # 5MB body exceeds 4MB limit
    huge_data = b"x" * (5 * 1024 * 1024)
    r = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {session.mcp_token}", "Content-Type": "application/json"},
        content=huge_data,
    )
    assert r.status_code == 413


def test_query_argument_sanitization_rejects_separators_and_control_chars():
    # Carat encoded-query separator
    with pytest.raises(ValueError, match="forbidden character"):
        _reject_query_separators("list_incidents", {"query": "active=true^NQpriority=1"})

    # Null byte
    with pytest.raises(ValueError, match="forbidden character"):
        _reject_query_separators("list_incidents", {"query": "active=true\x00malicious"})

    # Newline
    with pytest.raises(ValueError, match="forbidden character"):
        _reject_query_separators("list_incidents", {"query": "active=true\nORDERBYdesc"})

    # Safe arguments pass
    _reject_query_separators("list_incidents", {"query": "active=true", "number": "INC0010001"})


def test_client_registration_sanitizes_client_name():
    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    # Excessively long name with control characters
    bad_name = "Evil\x00Client\r\n" + "A" * 200
    reg = client.post(
        "/oauth/register",
        json={"client_name": bad_name, "redirect_uris": ["http://127.0.0.1:45678/cb"]},
    )
    assert reg.status_code == 201
    registered_name = reg.json()["client_name"]
    assert len(registered_name) <= 100
    assert "\x00" not in registered_name
    assert "\r" not in registered_name
    assert "\n" not in registered_name
