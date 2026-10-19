"""Tests for request-scoped CallerAuth contextvar, JWT hint extraction, and SSE session binding."""

import asyncio
import base64
import json

from servicenow_mcp.auth.session_context import (
    CallerAuth,
    SseSessionAuthRegistry,
    caller_auth_context,
    extract_jwt_user_hint,
    get_current_caller_auth,
    parse_basic_auth_username,
)


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.signature"


def test_contextvar_isolation_across_async_tasks():
    assert get_current_caller_auth() is None

    async def worker(name: str) -> str:
        auth = CallerAuth(
            headers={"Authorization": f"Bearer token-{name}"},
            auth_source="bearer_passthrough",
            user_hint=name,
        )
        with caller_auth_context(auth):
            await asyncio.sleep(0.01)
            current = get_current_caller_auth()
            assert current is not None
            assert current.user_hint == name
            return current.headers["Authorization"]

    async def run_both():
        return await asyncio.gather(worker("alice"), worker("bob"))

    res_a, res_b = asyncio.run(run_both())
    assert res_a == "Bearer token-alice"
    assert res_b == "Bearer token-bob"
    assert get_current_caller_auth() is None


def test_extract_jwt_user_hint():
    jwt_token = _make_jwt({"preferred_username": "alice.smith", "sub": "12345"})
    assert extract_jwt_user_hint(jwt_token) == "alice.smith"

    jwt_email = _make_jwt({"email": "bob@example.com", "sub": "67890"})
    assert extract_jwt_user_hint(jwt_email) == "bob@example.com"

    assert extract_jwt_user_hint("opaque-servicenow-token") is None


def test_parse_basic_auth_username():
    encoded = base64.b64encode(b"itil_user:secret123").decode()
    assert parse_basic_auth_username(encoded) == "itil_user"
    assert parse_basic_auth_username("!!!not-base64!!!") is None


def test_sse_session_auth_registry_bind_get_and_remove():
    registry = SseSessionAuthRegistry(ttl_seconds=60)
    auth = CallerAuth(headers={"x-sn-apikey": "k1"}, auth_source="api_key")
    registry.bind("abc-123-session", auth)

    assert registry.get("abc-123-session") == auth
    assert registry.get("abc123session") == auth  # normalized UUID hex match
    registry.remove("abc-123-session")
    assert registry.get("abc-123-session") is None
