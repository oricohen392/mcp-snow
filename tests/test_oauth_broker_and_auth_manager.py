"""
Tests for OAuthBroker (OIDC discovery & ServiceNow OAuth) and AuthManager ContextVar resolution.
"""

import base64
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.auth.oauth_broker import OAuthBroker
from servicenow_mcp.auth.session_context import CallerAuth, caller_auth_context
from servicenow_mcp.auth.session_store import OAuthSessionStore
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, OAuthConfig


def _jwt(claims: dict) -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{h}.{p}.sig"


def test_broker_servicenow_native_endpoints(monkeypatch):
    monkeypatch.delenv("OIDC_ISSUER_URL", raising=False)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-client-id")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-client-secret")

    broker = OAuthBroker(instance_url="https://acme.service-now.com")
    assert broker.is_configured() is True
    endpoints = broker.get_endpoints()
    assert endpoints.authorization_endpoint == "https://acme.service-now.com/oauth_auth.do"
    assert endpoints.token_endpoint == "https://acme.service-now.com/oauth_token.do"

    auth_url = broker.build_authorize_url(
        redirect_uri="https://mcp.example.com/oauth/callback",
        state="state-1",
        code_challenge="challenge-1",
    )
    assert "https://acme.service-now.com/oauth_auth.do?" in auth_url
    assert "client_id=sn-client-id" in auth_url
    assert "state=state-1" in auth_url


def test_broker_oidc_discovery_and_code_exchange(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://idp.example.com/oauth2/default")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "oidc-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "oidc-secret")

    broker = OAuthBroker(instance_url="https://acme.service-now.com")

    discovery_resp = MagicMock()
    discovery_resp.status_code = 200
    discovery_resp.json.return_value = {
        "authorization_endpoint": "https://idp.example.com/oauth2/default/v1/authorize",
        "token_endpoint": "https://idp.example.com/oauth2/default/v1/token",
    }

    id_token = _jwt({"preferred_username": "carol@example.com"})
    token_resp = MagicMock()
    token_resp.status_code = 200
    token_resp.json.return_value = {
        "access_token": "oidc-access-xyz",
        "refresh_token": "oidc-refresh-xyz",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    with patch("requests.get", return_value=discovery_resp) as mock_get, patch(
        "requests.post", return_value=token_resp
    ) as mock_post:
        token_result = broker.exchange_code_for_tokens(
            code="auth-code-123",
            redirect_uri="https://mcp.example.com/oauth/callback",
            code_verifier="verifier-123",
        )
        assert mock_get.call_count == 1
        assert mock_post.call_count == 1
        assert token_result.access_token == "oidc-access-xyz"
        assert token_result.refresh_token == "oidc-refresh-xyz"
        assert token_result.user_hint == "carol@example.com"


def test_auth_manager_prefers_caller_auth_and_auto_refreshes(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-secret")

    store = OAuthSessionStore()
    broker = OAuthBroker(instance_url="https://acme.service-now.com")
    # Service account configured as Basic, but CallerAuth should override it
    svc_auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="svc", password="p"))
    manager = AuthManager(
        svc_auth,
        "https://acme.service-now.com",
        session_store=store,
        oauth_broker=broker,
    )

    # 1. API Key in CallerAuth overrides service account
    with caller_auth_context(
        CallerAuth(headers={"x-sn-apikey": "user-key-99"}, auth_source="api_key")
    ):
        headers = manager.get_headers()
        assert headers["x-sn-apikey"] == "user-key-99"
        assert "Authorization" not in headers

    # 2. Expiring OAuthSession triggers transparent refresh
    session = store.create_session(
        access_token="expired-access",
        refresh_token="valid-refresh",
        expires_in=30,  # within 60s buffer -> triggers refresh
        user_hint="dave",
    )
    refresh_resp = MagicMock()
    refresh_resp.status_code = 200
    refresh_resp.json.return_value = {
        "access_token": "fresh-access-token",
        "refresh_token": "fresh-refresh-token",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    with patch("requests.post", return_value=refresh_resp) as mock_post:
        with caller_auth_context(
            CallerAuth(
                headers={"Authorization": "Bearer expired-access"},
                auth_source="oauth_session",
                session_id=session.mcp_token,
                user_hint="dave",
            )
        ):
            headers = manager.get_headers()
            assert mock_post.call_count == 1
            assert headers["Authorization"] == "Bearer fresh-access-token"
            assert store.get_session(session.mcp_token).access_token == "fresh-access-token"


def test_auth_manager_raises_when_no_caller_and_no_service_account():
    manager = AuthManager(AuthConfig(type=AuthType.NONE), "https://acme.service-now.com")
    with pytest.raises(ValueError, match="Per-user authentication is required"):
        manager.get_headers()


def test_auth_manager_oauth_service_account_custom_domain():
    oauth_config = OAuthConfig(client_id="cid", client_secret="csecret")
    manager = AuthManager(
        AuthConfig(type=AuthType.OAUTH, oauth=oauth_config),
        "https://custom-domain.corp.internal/",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "access_token": "custom-token-xyz",
        "token_type": "Bearer",
    }
    with patch("requests.post", return_value=mock_resp) as mock_post:
        headers = manager.get_headers()
        assert mock_post.call_count == 1
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://custom-domain.corp.internal/oauth_token.do"
        assert headers["Authorization"] == "Bearer custom-token-xyz"


def test_auth_manager_oauth_service_account_missing_instance_url():
    oauth_config = OAuthConfig(client_id="cid", client_secret="csecret")
    manager = AuthManager(AuthConfig(type=AuthType.OAUTH, oauth=oauth_config))
    with pytest.raises(ValueError, match="Instance URL is required for OAuth authentication"):
        manager.get_headers()


def test_post_token_request_avoids_duplicate_client_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OAUTH_CLIENT_ID", "my-client-id")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "my-client-secret")
    broker = OAuthBroker(instance_url="https://acme.service-now.com")

    captured_kwargs: dict = {}

    def fake_post(url: str, **kwargs: Any) -> MagicMock:
        captured_kwargs.update(kwargs)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "access_token": "tok-1",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        return resp

    with patch("requests.post", side_effect=fake_post):
        broker.exchange_code_for_tokens(
            code="code-123",
            redirect_uri="http://127.0.0.1:8000/callback",
        )

    # Basic auth header MUST be present
    assert "Authorization" in captured_kwargs["headers"]
    assert captured_kwargs["headers"]["Authorization"].startswith("Basic ")
    # client_secret MUST NOT be in the form body (RFC 6749 §2.3: do not use multiple auth methods)
    assert "client_secret" not in captured_kwargs["data"]
    assert captured_kwargs["data"]["client_id"] == "my-client-id"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_oauth_broker_async_wrappers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OAUTH_CLIENT_ID", "async-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "async-secret")
    broker = OAuthBroker(instance_url="https://acme.service-now.com")

    token_resp = MagicMock()
    token_resp.status_code = 200
    token_resp.json.return_value = {
        "access_token": "async-acc",
        "refresh_token": "async-ref",
        "token_type": "Bearer",
        "expires_in": 1800,
    }

    with patch("requests.post", return_value=token_resp):
        res = await broker.async_exchange_code_for_tokens(
            code="code-abc",
            redirect_uri="http://127.0.0.1:8000/callback",
        )
        assert res.access_token == "async-acc"

        ref = await broker.async_refresh_access_token("async-ref")
        assert ref.access_token == "async-acc"

    auth_url = await broker.async_build_authorize_url(
        redirect_uri="http://127.0.0.1:8000/callback",
        state="s1",
    )
    assert "oauth_auth.do" in auth_url

    endpoints = await broker.async_get_endpoints()
    assert endpoints.authorization_endpoint == "https://acme.service-now.com/oauth_auth.do"


def test_post_token_request_public_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OAUTH_CLIENT_ID", "public-client-id")
    monkeypatch.delenv("OAUTH_CLIENT_SECRET", raising=False)
    broker = OAuthBroker(instance_url="https://acme.service-now.com")

    captured_kwargs = {}

    def fake_post(url, **kwargs):
        captured_kwargs.update(kwargs)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "access_token": "tok-pub",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        return resp

    with patch("requests.post", side_effect=fake_post):
        broker.exchange_code_for_tokens(
            code="code-pub",
            redirect_uri="http://127.0.0.1:8000/callback",
        )

    # For public clients, no Authorization header is attached
    assert "Authorization" not in captured_kwargs["headers"]
    assert captured_kwargs["data"]["client_id"] == "public-client-id"
    assert "client_secret" not in captured_kwargs["data"]



