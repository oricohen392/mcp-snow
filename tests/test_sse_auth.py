"""
Tests for the optional bearer-token protection of the SSE endpoints.
"""

import pytest
from starlette.testclient import TestClient

from servicenow_mcp.server import ServiceNowMCP
from servicenow_mcp.server_sse import create_starlette_app

CONFIG = {
    "instance_url": "https://example.service-now.com",
    "auth": {"type": "basic", "basic": {"username": "u", "password": "p"}},
}
TOKEN = "s3cret-token-value"


@pytest.fixture
def mcp_server():
    return ServiceNowMCP(CONFIG).mcp_server


def test_healthz_is_open(mcp_server):
    client = TestClient(create_starlette_app(mcp_server, auth_token=TOKEN))
    response = client.get("/healthz")
    assert response.status_code == 200 and response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}, {"Authorization": "Bearer"}],
)
def test_token_required_on_sse_and_messages(mcp_server, headers):
    client = TestClient(create_starlette_app(mcp_server, auth_token=TOKEN))
    sse = client.get("/sse", headers=headers)
    assert sse.status_code == 401
    assert sse.headers["www-authenticate"] == "Bearer"
    messages = client.post("/messages/?session_id=abc", headers=headers, json={})
    assert messages.status_code == 401


def test_valid_token_reaches_transport(mcp_server):
    client = TestClient(create_starlette_app(mcp_server, auth_token=TOKEN))
    response = client.post(
        "/messages/?session_id=" + "0" * 32,
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={},
    )
    # Past the auth layer: the MCP transport rejects the unknown session itself.
    assert response.status_code in (400, 404)


def test_no_token_means_no_auth(mcp_server):
    client = TestClient(create_starlette_app(mcp_server))
    response = client.post("/messages/?session_id=" + "0" * 32, json={})
    assert response.status_code in (400, 404)


def test_debug_disabled_by_default(mcp_server):
    assert create_starlette_app(mcp_server).debug is False
