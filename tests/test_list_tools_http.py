"""
Mocked-HTTP behaviour of every read tool: 200-empty, 401, 403, 5xx, timeout,
connection error and non-JSON responses. Errors must be success=false with a
status code; they must never be reported as "0 results".
"""

from unittest.mock import patch

import pytest
import requests
from fake_servicenow import FakeServiceNow, make_response

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.access_tools import SearchGroupsParams, search_groups
from servicenow_mcp.tools.change_tools import get_change_request_details, list_change_requests
from servicenow_mcp.tools.incident_tools import (
    GetIncidentByNumberParams,
    ListIncidentsParams,
    get_incident_by_number,
    list_incidents,
)
from servicenow_mcp.tools.request_tools import (
    GetRequestByNumberParams,
    GetRequestItemByNumberParams,
    ListRequestItemsParams,
    ListRequestsParams,
    get_request_by_number,
    get_request_item_by_number,
    list_request_items,
    list_requests,
)
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="u", password="p"))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


@pytest.fixture
def auth(config):
    return AuthManager(config.auth, config.instance_url)


# (name, callable(config, auth), records key)
LIST_TOOLS = [
    ("list_incidents", lambda c, a: list_incidents(c, a, ListIncidentsParams(state="1")), "incidents"),
    ("list_change_requests", lambda c, a: list_change_requests(a, c, {"type": "normal"}), "change_requests"),
    ("list_requests", lambda c, a: list_requests(c, a, ListRequestsParams(active=True)), "requests"),
    (
        "list_request_items",
        lambda c, a: list_request_items(c, a, ListRequestItemsParams(assignment_group="NOC")),
        "request_items",
    ),
    ("search_groups", lambda c, a: search_groups(c, a, SearchGroupsParams(name_part="NOC")), "groups"),
]

GET_TOOLS = [
    ("get_incident_by_number", lambda c, a: get_incident_by_number(c, a, GetIncidentByNumberParams(incident_number="INC0010001"))),
    ("get_request_by_number", lambda c, a: get_request_by_number(c, a, GetRequestByNumberParams(request_number="REQ0010001"))),
    ("get_request_item_by_number", lambda c, a: get_request_item_by_number(c, a, GetRequestItemByNumberParams(request_item_number="RITM0010001"))),
    ("get_change_request_details", lambda c, a: get_change_request_details(a, c, {"change_id": "CHG0030001"})),
]

ALL_TOOLS = [(name, fn) for name, fn, _ in LIST_TOOLS] + GET_TOOLS


@pytest.mark.parametrize("name,tool,key", LIST_TOOLS, ids=[t[0] for t in LIST_TOOLS])
def test_200_empty_is_success_with_hint(config, auth, name, tool, key):
    fake = FakeServiceNow(records=[], total=0)
    with patch("requests.get", side_effect=fake):
        result = tool(config, auth)
    assert result["success"] is True
    assert result[key] == []
    assert result["returned"] == 0
    assert result["total_count"] == 0
    assert result["query_used"]
    assert "check_access" in result["hint"]
    assert "ACL" in result["hint"]


@pytest.mark.parametrize("name,tool,key", LIST_TOOLS, ids=[t[0] for t in LIST_TOOLS])
def test_200_with_rows_reports_counts(config, auth, name, tool, key):
    rows = [{"sys_id": "a" * 32, "number": "X1", "name": "INOC_1"}]
    fake = FakeServiceNow(records=rows, total=57)
    with patch("requests.get", side_effect=fake):
        result = tool(config, auth)
    assert result["success"] is True
    assert result["returned"] == 1
    assert result["total_count"] == 57
    assert "hint" not in result or "row-level" in result["hint"]


@pytest.mark.parametrize(
    "status,error_type", [(401, "unauthorized"), (403, "forbidden"), (500, "server_error")]
)
@pytest.mark.parametrize("name,tool", ALL_TOOLS, ids=[t[0] for t in ALL_TOOLS])
def test_http_errors_are_failures_with_status(config, auth, name, tool, status, error_type):
    fake = FakeServiceNow(status=status)
    with patch("requests.get", side_effect=fake):
        result = tool(config, auth)
    assert result["success"] is False
    assert result["status_code"] == status
    assert result["error_type"] == error_type
    assert "Found 0" not in result["message"]
    if status in (401, 403):
        assert "fake detail" in result["message"]  # ServiceNow's error body is surfaced


@pytest.mark.parametrize(
    "exc,error_type",
    [
        (requests.exceptions.ReadTimeout("read timed out"), "timeout"),
        (requests.exceptions.ConnectTimeout("connect timed out"), "timeout"),
        (requests.exceptions.ConnectionError("no route to host"), "connection"),
    ],
)
@pytest.mark.parametrize("name,tool", ALL_TOOLS, ids=[t[0] for t in ALL_TOOLS])
def test_transport_errors_are_failures(config, auth, name, tool, exc, error_type):
    def fake_get(url, params=None, **kwargs):
        if url.endswith("/table/sys_choice"):
            return make_response(200, {"result": [{"value": "1", "label": "One"}, {"value": "normal", "label": "Normal"}]})
        raise exc

    with patch("requests.get", side_effect=fake_get):
        result = tool(config, auth)
    assert result["success"] is False
    assert result["error_type"] == error_type
    assert result["status_code"] is None


@pytest.mark.parametrize("name,tool", ALL_TOOLS, ids=[t[0] for t in ALL_TOOLS])
def test_non_json_response_is_failure(config, auth, name, tool):
    def fake_get(url, params=None, **kwargs):
        if url.endswith("/table/sys_choice"):
            return make_response(200, {"result": [{"value": "1", "label": "One"}, {"value": "normal", "label": "Normal"}]})
        return make_response(200, b"<html>Login</html>")

    with patch("requests.get", side_effect=fake_get):
        result = tool(config, auth)
    assert result["success"] is False
    assert result["error_type"] == "invalid_response"


@pytest.mark.parametrize("name,tool", GET_TOOLS, ids=[t[0] for t in GET_TOOLS])
def test_get_not_found_has_hint(config, auth, name, tool):
    fake = FakeServiceNow(records=[], total=0)
    with patch("requests.get", side_effect=fake):
        result = tool(config, auth)
    assert result["success"] is False
    assert "not found" in result["message"]
    assert "check_access" in result["hint"]
    assert result["query_used"]


def test_sys_choice_forbidden_numeric_label_is_clear_error(config, auth):
    def fake_get(url, params=None, **kwargs):
        if url.endswith("/table/sys_choice"):
            return make_response(403, {"error": {"message": "no"}})
        return make_response(200, {"result": []}, total=0)

    with patch("requests.get", side_effect=fake_get):
        result = list_incidents(config, auth, ListIncidentsParams(state="New"))
        by_value = list_incidents(config, auth, ListIncidentsParams(state="2"))
    assert result["success"] is False and "403" in result["message"]
    assert by_value["success"] is True
    assert by_value["query_used"].startswith("state=2")
    assert by_value["warnings"]


def test_change_details_by_number_then_tasks(config, auth):
    change = {"sys_id": "c" * 32, "number": "CHG0030001"}
    calls = []

    def fake_get(url, params=None, **kwargs):
        calls.append((url, params))
        if url.endswith("/table/change_request"):
            return make_response(200, {"result": [change]}, total=1)
        return make_response(200, {"result": [{"number": "CTASK0010001"}]}, total=1)

    with patch("requests.get", side_effect=fake_get):
        result = get_change_request_details(auth, config, {"change_id": "chg0030001"})
    assert result["success"] and result["tasks"][0]["number"] == "CTASK0010001"
    assert calls[0][1]["sysparm_query"] == "number=CHG0030001"
    assert calls[1][1]["sysparm_query"] == f"change_request={'c' * 32}"
