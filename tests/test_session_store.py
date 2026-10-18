"""Tests for OAuthSessionStore: sessions, PKCE verification, auth codes, and dynamic clients."""

import base64
import hashlib
import time
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


def test_pkce_rejects_plain():
    verifier = "my-verifier-12345678901234567890"
    assert not verify_pkce_challenge(verifier, verifier, method="plain")
    assert not verify_pkce_challenge(verifier, verifier, method="PLAIN")


def test_session_rotation_and_absolute_expiry():
    store = OAuthSessionStore(session_ttl_seconds=3600, absolute_lifetime_seconds=7200)
    session = store.create_session(
        access_token="sn-acc-1",
        refresh_token="sn-ref-1",
        expires_in=1800,
        client_id="client-test",
    )
    first_downstream_refresh = session.downstream_refresh_token
    assert first_downstream_refresh.startswith("mcpr_")
    assert session.client_id == "client-test"

    # Refresh rotates the downstream refresh token
    updated = store.update_session_tokens(
        session.mcp_token,
        access_token="sn-acc-2",
        refresh_token="sn-ref-2",
        expires_in=1800,
    )
    assert updated is not None
    assert updated.downstream_refresh_token != first_downstream_refresh
    assert updated.downstream_refresh_token.startswith("mcpr_")

    # Old downstream refresh token no longer works
    assert store.get_session_by_downstream_refresh_token(first_downstream_refresh) is None
    # New downstream refresh token works
    assert store.get_session_by_downstream_refresh_token(updated.downstream_refresh_token) is not None

    # Force absolute expiration
    store._sessions[session.mcp_token].absolute_expires_at = time.time() - 1
    expired = store.update_session_tokens(
        session.mcp_token,
        access_token="sn-acc-3",
        refresh_token="sn-ref-3",
    )
    assert expired is None
    assert store.get_session(session.mcp_token) is None


def test_cleanup_does_not_evict_unexpired_pending_or_clients():
    store = OAuthSessionStore(max_pending=2, max_clients=2)
    # Register 2 clients
    c1 = store.register_client(client_name="C1", redirect_uris=["http://127.0.0.1:1000/cb"])
    c2 = store.register_client(client_name="C2", redirect_uris=["http://127.0.0.1:2000/cb"])
    # 3rd client registration must be rejected with capacity error rather than evicting c1
    with pytest.raises(ValueError, match="Client registration limit reached"):
        store.register_client(client_name="C3", redirect_uris=["http://127.0.0.1:3000/cb"])
    assert store.get_client(c1.client_id) is not None
    assert store.get_client(c2.client_id) is not None

    p1 = store.create_pending_auth(flow_type="mcp_oauth")
    p2 = store.create_pending_auth(flow_type="mcp_oauth")
    with pytest.raises(RuntimeError, match="Pending login capacity reached"):
        store.create_pending_auth(flow_type="mcp_oauth")
    assert store.pop_pending_auth(p1.upstream_state) is not None
    assert store.pop_pending_auth(p2.upstream_state) is not None


def test_max_sessions_eviction_purges_refresh_index():
    store = OAuthSessionStore(max_sessions=2)
    s1 = store.create_session(access_token="acc-1", refresh_token="ref-1")
    s2 = store.create_session(access_token="acc-2", refresh_token="ref-2")

    ref1 = s1.downstream_refresh_token
    ref2 = s2.downstream_refresh_token
    assert store.get_session_by_downstream_refresh_token(ref1) is not None

    # Creating 3rd session should evict s1 (oldest) and its refresh token
    s3 = store.create_session(access_token="acc-3", refresh_token="ref-3")
    assert store.get_session(s1.mcp_token) is None
    assert store.get_session_by_downstream_refresh_token(ref1) is None
    assert store.get_session(s2.mcp_token) is not None
    assert store.get_session(s3.mcp_token) is not None


def test_pkce_padded_and_non_string():
    verifier, challenge = _pkce_pair()
    # Padded challenge should be accepted
    assert verify_pkce_challenge(verifier, challenge + "=")
    assert verify_pkce_challenge(verifier, challenge + "==")
    # Non-string verifier/challenge fail closed
    assert not verify_pkce_challenge(12345, challenge)  # type: ignore
    assert not verify_pkce_challenge(verifier, None)


def test_register_client_limits():
    store = OAuthSessionStore()
    # More than 20 URIs
    too_many_uris = [f"http://127.0.0.1:{8000 + i}/callback" for i in range(21)]
    with pytest.raises(ValueError, match="Too many redirect_uris"):
        store.register_client(client_name="Test", redirect_uris=too_many_uris)

    # URI exceeding 1024 chars
    long_uri = "http://127.0.0.1:8000/callback?" + "a" * 1050
    with pytest.raises(ValueError, match="exceeds maximum length"):
        store.register_client(client_name="Test", redirect_uris=[long_uri])



