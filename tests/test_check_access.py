"""
Mocked-HTTP tests for check_access.
"""

from unittest.mock import patch

import pytest
import requests
from fake_servicenow import make_response

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.auth.session_context import CallerAuth, caller_auth_context
from servicenow_mcp.tools.access_tools import ACCESS_CHECK_TABLES, CheckAccessParams, check_access
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="svc_mcp", password="p"))
    return ServerConfig(instance_url="https://acme.service-now.com", auth=auth)


@pytest.fixture
def auth(config):
    return AuthManager(config.auth, config.instance_url)


def _run(config, auth, fake_get):
    with patch("requests.get", side_effect=fake_get):
        return check_access(config, auth, CheckAccessParams())


def test_reports_user_host_and_counts(config, auth):
    counts = {"incident": 1200, "change_request": 0, "sc_request": 30, "sc_req_item": 45,
              "sys_user_group": 80, "sys_choice": 5000}

    def fake_get(url, params=None, **kwargs):
        table = url.rsplit("/", 1)[1]
        if table == "sys_user":
            assert params["sysparm_query"] == "user_name=svc_mcp"
            return make_response(200, {"result": [{"sys_id": "u" * 32, "user_name": "svc_mcp",
                                                   "name": "MCP Service", "active": "true"}]})
        if table == "sys_user_has_role":
            return make_response(200, {"result": [{"role": "itil"}, {"role": "snc_read_only"}]})
        if table == "sc_request":
            return make_response(403, {"error": {"message": "User Not Authorized"}})
        return make_response(200, {"result": [{"sys_id": "x"}] if counts[table] else []},
                             total=counts[table])

    result = _run(config, auth, fake_get)
    assert result["success"] is True
    assert result["authenticated"] is True
    assert result["instance_host"] == "acme.service-now.com"
    assert result["user"]["verified"] is True
    assert result["user"]["user_name"] == "svc_mcp"
    assert result["user"]["roles"] == ["itil", "snc_read_only"]
    assert set(result["tables"]) == set(ACCESS_CHECK_TABLES)
    assert result["tables"]["incident"] == {"status_code": 200, "readable": True, "visible_count": 1200}
    assert result["tables"]["change_request"]["visible_count"] == 0
    assert "row-level ACLs" in result["tables"]["change_request"]["note"]
    assert result["tables"]["sc_request"]["readable"] is False
    assert result["tables"]["sc_request"]["status_code"] == 403
    assert "User Not Authorized" in result["tables"]["sc_request"]["note"]


def test_200_empty_everywhere(config, auth):
    result = _run(config, auth, lambda url, params=None, **kw: make_response(200, {"result": []}, total=0))
    assert result["success"] is True
    assert all(t["visible_count"] == 0 for t in result["tables"].values())
    assert result["user"]["verified"] is False
    assert "cannot read its own sys_user" in result["user"]["note"]


@pytest.mark.parametrize("status,error_type", [(401, "unauthorized"), (403, "forbidden"), (500, "server_error")])
def test_http_error_everywhere_is_failure(config, auth, status, error_type):
    result = _run(config, auth, lambda url, params=None, **kw: make_response(status, {"error": {"message": "x"}}))
    assert result["success"] is False
    assert result["status_code"] == status
    assert result["error_type"] == error_type
    assert result["authenticated"] is False
    assert "user" not in result


def test_timeout_is_failure(config, auth):
    def fake_get(url, params=None, **kwargs):
        raise requests.exceptions.ReadTimeout("slow")

    result = _run(config, auth, fake_get)
    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["status_code"] is None


def test_check_access_uses_caller_auth_user_hint():
    cfg = ServerConfig(
        instance_url="https://acme.service-now.com",
        auth=AuthConfig(type=AuthType.NONE),
    )
    mgr = AuthManager(cfg.auth, cfg.instance_url)

    def fake_get(url, params=None, **kwargs):
        table = url.rsplit("/", 1)[1]
        if table == "sys_user":
            assert params["sysparm_query"] == "user_name=alice.oidc"
            return make_response(
                200,
                {
                    "result": [
                        {
                            "sys_id": "a" * 32,
                            "user_name": "alice.oidc",
                            "name": "Alice OIDC",
                            "active": "true",
                        }
                    ]
                },
            )
        if table == "sys_user_has_role":
            return make_response(200, {"result": [{"role": "itil"}]})
        return make_response(200, {"result": [{"sys_id": "x"}]}, total=10)

    with caller_auth_context(
        CallerAuth(
            headers={"Authorization": "Bearer user-jwt"},
            auth_source="oauth_session",
            user_hint="alice.oidc",
        )
    ):
        result = _run(cfg, mgr, fake_get)

    assert result["success"] is True
    assert result["user"]["verified"] is True
    assert result["user"]["user_name"] == "alice.oidc"
    assert result["user"]["auth_type"] == "oauth_session"


def test_check_access_falls_back_to_gs_get_user_id_when_no_username():
    cfg = ServerConfig(
        instance_url="https://acme.service-now.com",
        auth=AuthConfig(type=AuthType.NONE),
    )
    mgr = AuthManager(cfg.auth, cfg.instance_url)

    def fake_get(url, params=None, **kwargs):
        table = url.rsplit("/", 1)[1]
        if table == "sys_user":
            assert params["sysparm_query"] == "sys_id=javascript:gs.getUserID()"
            return make_response(
                200,
                {
                    "result": [
                        {
                            "sys_id": "b" * 32,
                            "user_name": "apikey.user",
                            "name": "API Key User",
                            "active": "true",
                        }
                    ]
                },
            )
        if table == "sys_user_has_role":
            return make_response(200, {"result": [{"role": "itil"}]})
        return make_response(200, {"result": [{"sys_id": "x"}]}, total=5)

    with caller_auth_context(
        CallerAuth(headers={"x-sn-apikey": "key-1"}, auth_source="api_key")
    ):
        result = _run(cfg, mgr, fake_get)

    assert result["success"] is True
    assert result["user"]["verified"] is True
    assert result["user"]["user_name"] == "apikey.user"
    assert result["user"]["auth_type"] == "api_key"


def test_check_access_uses_email_query_when_user_hint_has_at():
    cfg = ServerConfig(
        instance_url="https://acme.service-now.com",
        auth=AuthConfig(type=AuthType.NONE),
    )
    mgr = AuthManager(cfg.auth, cfg.instance_url)

    def fake_get(url, params=None, **kwargs):
        table = url.rsplit("/", 1)[1]
        if table == "sys_user":
            assert params["sysparm_query"] == "email=alice@example.com"
            return make_response(
                200,
                {
                    "result": [
                        {
                            "sys_id": "a" * 32,
                            "user_name": "alice",
                            "name": "Alice Example",
                            "active": "true",
                        }
                    ]
                },
            )
        if table == "sys_user_has_role":
            return make_response(200, {"result": [{"role": "itil"}]})
        return make_response(200, {"result": [{"sys_id": "x"}]}, total=10)

    with caller_auth_context(
        CallerAuth(
            headers={"Authorization": "Bearer user-jwt"},
            auth_source="oauth_session",
            user_hint="alice@example.com",
        )
    ):
        result = _run(cfg, mgr, fake_get)

    assert result["success"] is True
    assert result["user"]["verified"] is True
    assert result["user"]["user_name"] == "alice"


