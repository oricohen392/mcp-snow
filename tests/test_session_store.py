"""Tests for OAuthSessionStore: sessions, PKCE verification, auth codes, and dynamic clients."""

import base64
import hashlib
import pytest

from servicenow_mcp.auth.session_store import (
    OAuthSessionStore,
    validate_client_redirect_uri,
    verify_pkce_challenge,
)


def _pkce_pair(verifier: str = "my-test-code-verifier-string-1234567890"):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def test_session_lifecycle_and_refresh():
    store = OAuthSessionStore(session_ttl_seconds=3600)
    session = store.create_session(
        access_token="sn-access-1",
        refresh_token="sn-refresh-1",
        expires_in=1800,
        user_hint="alice",
    )
    assert session.mcp_token.startswith("mcp_")
    fetched = store.get_session(session.mcp_token)
    assert fetched is not None
    assert fetched.access_token == "sn-access-1"
    assert fetched.user_hint == "alice"

    updated = store.update_session_tokens(
        session.mcp_token,
        access_token="sn-access-2",
        refresh_token="sn-refresh-2",
        expires_in=1800,
    )
    assert updated is not None
    assert updated.access_token == "sn-access-2"
    assert updated.refresh_token == "sn-refresh-2"

    assert store.revoke_session(session.mcp_token) is True
    assert store.get_session(session.mcp_token) is None


def test_refresh_token_lookup():
    store = OAuthSessionStore(session_ttl_seconds=3600)
    session = store.create_session(
        access_token="sn-access-1",
        refresh_token="sn-refresh-1",
        expires_in=1800,
    )
    assert session.downstream_refresh_token.startswith("mcpr_")
    found = store.get_session_by_downstream_refresh_token(session.downstream_refresh_token)
    assert found is not None
    assert found.mcp_token == session.mcp_token


def test_pending_auth_and_single_use_auth_code_with_pkce():
    store = OAuthSessionStore()
    verifier, challenge = _pkce_pair()

    pending = store.create_pending_auth(
        flow_type="mcp_oauth",
        client_id="client-1",
        redirect_uri="http://127.0.0.1:54321/callback",
        downstream_state="ide-state-xyz",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    assert pending.upstream_state
    assert pending.upstream_code_verifier
    assert pending.upstream_code_challenge

    # Consume pending auth state once
    popped = store.pop_pending_auth(pending.upstream_state)
    assert popped is not None
    assert popped.downstream_state == "ide-state-xyz"
    assert store.pop_pending_auth(pending.upstream_state) is None

    # Create session and issue downstream auth code
    session = store.create_session(access_token="sn-tok", refresh_token="sn-ref", expires_in=900)
    code_obj = store.issue_auth_code(
        mcp_token=session.mcp_token,
        client_id="client-1",
        redirect_uri="http://127.0.0.1:54321/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    # Single-use consumption
    consumed = store.consume_auth_code(code_obj.code)
    assert consumed is not None
    assert verify_pkce_challenge(verifier, consumed.code_challenge, consumed.code_challenge_method)
    assert not verify_pkce_challenge("wrong-verifier", consumed.code_challenge, "S256")
    assert store.consume_auth_code(code_obj.code) is None


def test_dynamic_client_registration_and_redirect_uri_validation():
    store = OAuthSessionStore()
    client = store.register_client(
        client_name="Cursor MCP",
        redirect_uris=["http://127.0.0.1:33445/callback", "cursor://anysphere.cursor-mcp/oauth"],
    )
    assert client.client_id.startswith("mcp_client_")
    assert store.get_client(client.client_id) is not None

    with pytest.raises(ValueError, match="Invalid redirect_uri"):
        validate_client_redirect_uri("https://evil.example.com/callback")
