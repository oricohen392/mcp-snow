"""Tests for centralized multi-user authentication settings and optional AuthConfig."""

import pytest

from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import AuthConfig, AuthType, ServerConfig


def test_default_multi_user_settings(monkeypatch):
    for key in (
        "MCP_PUBLIC_URL",
        "OIDC_ISSUER_URL",
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET",
        "OAUTH_AUTHORIZE_URL",
        "OAUTH_TOKEN_URL",
        "OAUTH_SCOPES",
        "SERVICENOW_API_KEY_HEADER",
        "ALLOW_SERVICE_ACCOUNT_FALLBACK",
        "SESSION_TTL_SECONDS",
    ):
        monkeypatch.delenv(key, raising=False)

    assert settings.mcp_public_url() is None
    assert settings.oidc_issuer_url() is None
    assert settings.oauth_client_id() is None
    assert settings.oauth_client_secret() is None
    assert settings.oauth_authorize_url() is None
    assert settings.oauth_token_url() is None
    assert settings.oauth_scopes() is None
    assert settings.servicenow_api_key_header() == "x-sn-apikey"
    assert settings.allow_service_account_fallback() is False
    assert settings.session_ttl_seconds() == 86400


def test_configured_multi_user_settings(monkeypatch):
    monkeypatch.setenv("MCP_PUBLIC_URL", "https://mcp.example.com/")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://idp.example.com/realms/corp/")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "client-123")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "secret-456")
    monkeypatch.setenv("OAUTH_AUTHORIZE_URL", "https://acme.service-now.com/oauth_auth.do")
    monkeypatch.setenv("OAUTH_TOKEN_URL", "https://acme.service-now.com/oauth_token.do")
    monkeypatch.setenv("OAUTH_SCOPES", "openid profile email")
    monkeypatch.setenv("SERVICENOW_API_KEY_HEADER", "X-Custom-SN-Key")
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "true")
    monkeypatch.setenv("SESSION_TTL_SECONDS", "3600")

    assert settings.mcp_public_url() == "https://mcp.example.com"
    assert settings.oidc_issuer_url() == "https://idp.example.com/realms/corp"
    assert settings.oauth_client_id() == "client-123"
    assert settings.oauth_client_secret() == "secret-456"
    assert settings.oauth_authorize_url() == "https://acme.service-now.com/oauth_auth.do"
    assert settings.oauth_token_url() == "https://acme.service-now.com/oauth_token.do"
    assert settings.oauth_scopes() == "openid profile email"
    assert settings.servicenow_api_key_header() == "X-Custom-SN-Key"
    assert settings.allow_service_account_fallback() is True
    assert settings.session_ttl_seconds() == 3600


def test_server_config_allows_none_auth_for_per_user_mode():
    cfg = ServerConfig(
        instance_url="https://acme.service-now.com",
        auth=AuthConfig(type=AuthType.NONE),
    )
    assert cfg.auth.type == AuthType.NONE
    assert cfg.api_url == "https://acme.service-now.com/api/now"
