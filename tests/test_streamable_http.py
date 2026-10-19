"""Tests for the MCP Streamable HTTP transport (/mcp endpoint) with multi-user authentication."""

import json
from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient
import mcp.types as types

from servicenow_mcp.auth.session_context import CallerAuth, caller_auth_context
from servicenow_mcp.auth.session_store import OAuthSessionStore
from servicenow_mcp.server_sse import create_servicenow_mcp, create_starlette_app
from servicenow_mcp.utils.config import AuthConfig, AuthType, ServerConfig


def test_streamable_http_requires_auth_when_unauthenticated(monkeypatch):
    monkeypatch.delenv("SERVICENOW_USERNAME", raising=False)
    monkeypatch.delenv("SERVICENOW_PASSWORD", raising=False)
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

    # Unauthenticated POST /mcp is rejected with 401 and discovery metadata
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": types.LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        },
    )
    assert resp.status_code == 401
    assert "Bearer" in resp.headers["www-authenticate"]
    assert "/.well-known/oauth-protected-resource" in resp.headers["www-authenticate"]


def test_streamable_http_origin_validation(monkeypatch):
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

    session = server.session_store.create_session(access_token="sn-tok", expires_in=3600)
    # Disallowed external origin should be rejected with 403 Forbidden
    resp = client.post(
        "/mcp",
        headers={
            "Origin": "https://malicious-website.com",
            "Authorization": f"Bearer {session.mcp_token}",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    assert resp.status_code == 403


def test_streamable_http_full_session_lifecycle(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-oauth-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-oauth-secret")
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "false")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    store: OAuthSessionStore = server.session_store
    user_session = store.create_session(
        access_token="sn-access-tok-123",
        refresh_token="sn-refresh-tok-123",
        expires_in=3600,
        user_hint="stream_user",
    )
    auth_header = {"Authorization": f"Bearer {user_session.mcp_token}"}

    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    # 1. Initialize request
    init_res = client.post(
        "/mcp",
        headers=auth_header,
        json={
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "initialize",
            "params": {
                "protocolVersion": types.LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "cursor", "version": "0.45.0"},
            },
        },
    )
    assert init_res.status_code == 200
    init_body = init_res.json()
    assert init_body["id"] == "req-1"
    assert "result" in init_body
    assert init_body["result"]["protocolVersion"] == types.LATEST_PROTOCOL_VERSION
    assert init_body["result"]["serverInfo"]["name"] == "ServiceNow"
    session_id = init_res.headers.get("mcp-session-id")
    assert session_id is not None
    assert len(session_id) >= 16

    # 2. Initialized notification (id=None -> 202 Accepted)
    notif_headers = dict(auth_header)
    notif_headers["mcp-session-id"] = session_id
    notif_res = client.post(
        "/mcp",
        headers=notif_headers,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert notif_res.status_code == 202

    # 3. Ping request
    ping_res = client.post(
        "/mcp",
        headers=notif_headers,
        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    assert ping_res.status_code == 200
    assert ping_res.json() == {"jsonrpc": "2.0", "id": 2, "result": {}}

    # 4. List tools request
    list_res = client.post(
        "/mcp",
        headers=notif_headers,
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
    )
    assert list_res.status_code == 200
    list_body = list_res.json()
    assert list_body["id"] == 3
    tools = list_body["result"]["tools"]
    assert len(tools) > 0
    tool_names = [t["name"] for t in tools]
    assert "list_tool_packages" in tool_names

    # 5. Call tool request (list_tool_packages)
    call_res = client.post(
        "/mcp",
        headers=notif_headers,
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "list_tool_packages", "arguments": {}},
        },
    )
    assert call_res.status_code == 200
    call_body = call_res.json()
    assert call_body["id"] == 4
    content = call_body["result"]["content"]
    assert len(content) == 1
    assert content[0]["type"] == "text"
    parsed_pkg = json.loads(content[0]["text"])
    assert "current_package" in parsed_pkg

    # 6. Streamable response when Accept: text/event-stream
    stream_headers = dict(notif_headers)
    stream_headers["Accept"] = "text/event-stream"
    sse_res = client.post(
        "/mcp",
        headers=stream_headers,
        json={"jsonrpc": "2.0", "id": 5, "method": "ping"},
    )
    assert sse_res.status_code == 200
    assert "text/event-stream" in sse_res.headers["content-type"]
    assert "event: message\n" in sse_res.text
    assert '"id": 5' in sse_res.text

    # 7. GET /mcp with Accept: text/event-stream returns open stream
    get_res = client.get(
        "/mcp",
        headers=stream_headers,
    )
    assert get_res.status_code == 200
    assert "text/event-stream" in get_res.headers["content-type"]

    # GET /mcp without text/event-stream returns 405 Method Not Allowed
    get_bad = client.get("/mcp", headers=auth_header)
    assert get_bad.status_code == 405

    # 8. DELETE /mcp terminates session
    del_res = client.delete("/mcp", headers=notif_headers)
    assert del_res.status_code in (200, 204)


def test_streamable_http_stateless_and_direct_tool_call(monkeypatch):
    """Clients can make stateless tool calls without a preceding initialize handshake."""
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "false")
    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    store: OAuthSessionStore = server.session_store
    user_session = store.create_session(
        access_token="sn-tok",
        expires_in=3600,
        user_hint="stateless_user",
    )
    auth_header = {"Authorization": f"Bearer {user_session.mcp_token}"}

    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    # Directly list tools without initialize
    direct_res = client.post(
        "/mcp",
        headers=auth_header,
        json={"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}},
    )
    assert direct_res.status_code == 200
    assert direct_res.json()["id"] == 100
    assert "tools" in direct_res.json()["result"]


def test_streamable_http_batch_requests_and_error_handling(monkeypatch):
    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    session = server.session_store.create_session(access_token="tok", expires_in=3600)
    auth = {"Authorization": f"Bearer {session.mcp_token}"}
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    # 1. Batch requests
    batch_res = client.post(
        "/mcp",
        headers=auth,
        json=[
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "unknown/method"},
            {"jsonrpc": "2.0", "method": "notifications/ignored"},
        ],
    )
    assert batch_res.status_code == 200
    batch_data = batch_res.json()
    assert len(batch_data) == 2
    assert batch_data[0]["id"] == 1
    assert batch_data[0]["result"] == {}
    assert batch_data[1]["id"] == 2
    assert "error" in batch_data[1]
    assert batch_data[1]["error"]["code"] == -32601

    # 2. Malformed JSON body
    bad_res = client.post(
        "/mcp",
        headers=auth,
        content=b"not-json{{{",
    )
    assert bad_res.status_code == 400
    assert bad_res.json()["error"]["code"] == -32700


def test_streamable_http_api_key_auth_and_caller_identity(monkeypatch):
    """Test tool call execution over Streamable HTTP using X-ServiceNow-API-Key header."""
    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    api_key_headers = {"X-ServiceNow-API-Key": "user-custom-key-123"}

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": [
            {
                "sys_id": "u1234567890",
                "user_name": "apikey_stream_user",
                "name": "API Key User",
                "active": "true",
            }
        ]
    }
    mock_resp.headers = {"X-Total-Count": "1"}

    with patch("requests.get", return_value=mock_resp) as mock_get:
        res = client.post(
            "/mcp",
            headers=api_key_headers,
            json={
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "check_access", "arguments": {}},
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == 99
        text = data["result"]["content"][0]["text"]
        parsed = json.loads(text)
        assert parsed["success"] is True
        assert parsed["user"]["auth_type"] == "api_key"
        # Confirm that ServiceNow request was made with the caller's API key header
        assert mock_get.called
        headers_used = mock_get.call_args[1].get("headers", {})
        assert headers_used.get("x-sn-apikey") == "user-custom-key-123"

