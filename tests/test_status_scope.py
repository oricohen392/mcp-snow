"""
status_scope (open / closed / all), the change-request default of 'open', and
count_ignoring_status: a status filter must never hide records silently.
"""

from unittest.mock import patch

import pytest
import requests
from fake_servicenow import DEFAULT_GROUPS, FakeServiceNow, make_response

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.change_tools import list_change_requests
from servicenow_mcp.tools.incident_tools import ListIncidentsParams, list_incidents
from servicenow_mcp.tools.request_tools import ListRequestsParams, list_requests
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig

ORDER = "^ORDERBYDESCsys_created_on"
ROWS = [{"sys_id": "a" * 32, "number": "INC0010001"}] * 6


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="u", password="p"))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


@pytest.fixture
def auth(config):
    return AuthManager(config.auth, config.instance_url)


def incidents(config, auth, fake=None, **kwargs):
    fake = fake or FakeServiceNow(records=ROWS, total=6, stats_count=9, groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        return list_incidents(config, auth, ListIncidentsParams(**kwargs)), fake


def changes(config, auth, params):
    fake = FakeServiceNow(records=[], total=0, stats_count=0, groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        return list_change_requests(auth, config, params), fake


def test_incident_default_is_all_and_costs_no_extra_call(config, auth):
    result, fake = incidents(config, auth)
    assert result["query_used"] == ORDER.lstrip("^")
    assert result["status_scope"] == "all"
    assert "count_ignoring_status" not in result
    assert not fake.stats_calls("incident")


def test_open_scope_reports_records_in_other_statuses(config, auth):
    result, fake = incidents(config, auth, status_scope="open", assignment_group="תשתיות ענן")
    assert result["query_used"].startswith("active=true^assignment_groupIN")
    assert result["total_count"] == 6
    assert result["count_ignoring_status"] == 9
    assert "3 more incidents" in result["status_note"]
    assert "status_scope='all'" in result["status_note"]
    counted = fake.stats_calls("incident")[0]["params"]
    assert counted["sysparm_count"] == "true"
    assert "active=" not in counted["sysparm_query"]
    assert counted["sysparm_query"].startswith("assignment_groupIN")
    assert "ORDERBY" not in counted["sysparm_query"]


def test_closed_scope_and_active_alias(config, auth):
    result, _ = incidents(config, auth, status_scope="CLOSED")
    assert result["query_used"] == "active=false" + ORDER
    result, _ = incidents(config, auth, active=True)
    assert result["query_used"] == "active=true" + ORDER
    assert result["status_scope"] == "open"


@pytest.mark.parametrize(
    "kwargs",
    [{"status_scope": "pending"}, {"status_scope": "closed", "active": True}],
)
def test_invalid_or_contradicting_scope_is_an_error(config, auth, kwargs):
    result, fake = incidents(config, auth, **kwargs)
    assert result["success"] is False
    assert result["error_type"] == "invalid_input"
    assert not fake.table_calls("incident")


def test_state_filter_counts_other_states_without_state(config, auth):
    result, fake = incidents(config, auth, state="New", priority="1")
    assert result["query_used"] == "state=1^priority=1" + ORDER
    counted = fake.stats_calls("incident")[0]["params"]["sysparm_query"]
    assert counted == "priority=1"
    assert result["count_ignoring_status"] == 9


def test_change_requests_default_to_every_active_state(config, auth):
    result, _ = changes(config, auth, {})
    assert result["query_used"] == "active=true" + ORDER
    assert result["status_scope"] == "open"
    assert "default for change requests" in result["filters_description"]


@pytest.mark.parametrize(
    "params,expected",
    [
        ({"status_scope": "all"}, ORDER.lstrip("^")),
        ({"number": "CHG0030001"}, "number=CHG0030001" + ORDER),
        ({"state": "Closed"}, "state=3" + ORDER),
        ({"status_scope": "closed"}, "active=false" + ORDER),
    ],
)
def test_change_default_is_not_applied_to_explicit_requests(config, auth, params, expected):
    result, _ = changes(config, auth, params)
    assert result["query_used"] == expected


def test_aggregate_api_forbidden_falls_back_to_x_total_count(config, auth):
    fake = FakeServiceNow(records=ROWS, total=6, stats_status=403)
    result, fake = incidents(config, auth, fake=fake, status_scope="open")
    assert result["success"] is True
    assert result["count_ignoring_status"] == 6
    fallback = fake.table_calls("incident")[0]["params"]
    assert fallback["sysparm_limit"] == 1 and fallback["sysparm_query"] == ""


def test_count_failure_does_not_break_the_list(config, auth):
    def fake_get(url, params=None, **kwargs):
        if "/stats/" in url:
            raise requests.exceptions.ReadTimeout("slow")
        return make_response(200, {"result": ROWS}, total=6)

    with patch("requests.get", side_effect=fake_get):
        result = list_requests(config, auth, ListRequestsParams(status_scope="open"))
    assert result["success"] is True
    assert result["returned"] == 6
    assert "count_ignoring_status" not in result


def test_filters_description_is_human_readable(config, auth):
    result, _ = incidents(
        config, auth, status_scope="open", assignment_group="NOC", query="vpn", priority="1"
    )
    text = result["filters_description"]
    assert text.startswith("incident: ")
    assert "any active state" in text
    assert "assignment group in [NOC, INOC_1]" in text
    assert "text 'vpn'" in text
    assert "priority in [1]" in text
