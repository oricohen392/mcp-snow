"""
Tests for LOG_LEVEL handling and for keeping credentials out of logs.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig
from servicenow_mcp.utils.http import sn_get
from servicenow_mcp.utils.logging_setup import configure_logging

PASSWORD = "S3cr3t-Passw0rd!"


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="svc", password=PASSWORD))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


def _ok_response(records=None, total="0"):
    response = MagicMock()
    response.status_code = 200
    response.headers = {"X-Total-Count": total}
    response.json.return_value = {"result": records or []}
    response.raise_for_status = MagicMock()
    return response


@pytest.mark.parametrize(
    "env,expected",
    [
        ({}, logging.INFO),
        ({"LOG_LEVEL": "debug"}, logging.DEBUG),
        ({"LOG_LEVEL": "WARNING"}, logging.WARNING),
        ({"SERVICENOW_DEBUG": "true"}, logging.DEBUG),
    ],
)
def test_log_level_env_is_honored(monkeypatch, env, expected):
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.delenv("SERVICENOW_DEBUG", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert configure_logging() == expected
    assert logging.getLogger().level == expected


def test_invalid_log_level_fails_loudly(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "LOUD")
    with pytest.raises(ValueError):
        configure_logging()


def test_debug_logs_request_but_never_credentials(config, caplog):
    auth_manager = AuthManager(config.auth, config.instance_url)
    caplog.set_level(logging.DEBUG)
    with patch("requests.get", return_value=_ok_response(total="3")) as mock_get:
        result = sn_get(
            config, auth_manager, "table/incident", {"sysparm_query": "active=true", "sysparm_limit": 5}
        )

    assert result.ok and result.total_count == 3
    # The real Authorization header was sent ...
    sent_headers = mock_get.call_args.kwargs["headers"]
    assert sent_headers["Authorization"].startswith("Basic ")
    # ... but never logged.
    text = caplog.text
    assert "/api/now/table/incident" in text
    assert "active=true" in text
    assert "HTTP 200" in text
    assert " ms" in text
    assert PASSWORD not in text
    assert "Authorization" not in text
    assert sent_headers["Authorization"].split(" ", 1)[1] not in text


def test_error_logs_never_contain_credentials(config, caplog):
    auth_manager = AuthManager(config.auth, config.instance_url)
    caplog.set_level(logging.DEBUG)
    response = _ok_response()
    response.status_code = 401
    with patch("requests.get", return_value=response):
        result = sn_get(config, auth_manager, "table/incident", {})
    assert not result.ok and result.error_type == "unauthorized"
    assert PASSWORD not in caplog.text
    assert "Authorization" not in caplog.text


def test_oauth_token_body_not_logged(caplog):
    from servicenow_mcp.utils.config import OAuthConfig

    auth = AuthConfig(
        type=AuthType.OAUTH,
        oauth=OAuthConfig(
            client_id="cid", client_secret="csecret", username="u", password=PASSWORD,
            token_url="https://example.service-now.com/oauth_token.do",
        ),
    )
    token_response = MagicMock()
    token_response.status_code = 200
    token_response.text = '{"access_token": "TOKEN-VALUE-123"}'
    token_response.json.return_value = {"access_token": "TOKEN-VALUE-123", "token_type": "Bearer"}
    caplog.set_level(logging.DEBUG)
    with patch("requests.post", return_value=token_response):
        headers = AuthManager(auth, "https://example.service-now.com").get_headers()
    assert headers["Authorization"] == "Bearer TOKEN-VALUE-123"
    assert "TOKEN-VALUE-123" not in caplog.text
    assert "csecret" not in caplog.text
