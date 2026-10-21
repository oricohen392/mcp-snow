"""
count_records: Aggregate API counts, group_by, the 'all' default, the
X-Total-Count fallback and error reporting.
"""

from unittest.mock import patch

import pytest
import requests
from fake_servicenow import DEFAULT_GROUPS, FakeServiceNow, gid, make_response

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.count_tools import CountRecordsParams, count_records
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="svc_mcp", password="p"))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


@pytest.fixture
def auth(config):
    return AuthManager(config.auth, config.instance_url)


def count(config, auth, fake=None, **kwargs):
    fake = fake or FakeServiceNow(stats_count=48213, groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        return count_records(config, auth, CountRecordsParams(**kwargs)), fake


def test_counts_every_incident_ever_by_default(config, auth):
    result, fake = count(config, auth)
    assert result["success"] is True
    assert result["count"] == 48213
    assert result["status_scope"] == "all"
    assert result["query_used"] == ""
    assert result["source"] == "aggregate_api"
    assert "48213 incidents visible to ServiceNow user 'svc_mcp'" in result["scope_description"]
    assert "status: any (open and closed)" in result["scope_description"]
    assert "itil" in result["note"]
    sent = fake.stats_calls("incident")[0]["params"]
    assert sent == {"sysparm_count": "true", "sysparm_query": ""}
    assert not fake.table_calls("incident")  # no records are fetched


def test_change_counts_also_default_to_all(config, auth):
    result, fake = count(config, auth, table="change_request")
    assert result["query_used"] == ""
    assert result["status_scope"] == "all"


def test_open_scope_and_group_filter(config, auth):
    result, fake = count(config, auth, status_scope="open", assignment_group="תשתיות ענן")
    assert result["query_used"] == f"active=true^assignment_groupIN{gid(6)},{gid(7)}"
    assert [g["name"] for g in result["matched_groups"]] == ["תשתיות ענן", "ענן - תשתיות Tier2"]
    assert "any active state" in result["scope_description"]


def test_group_by_state_returns_sorted_breakdown(config, auth):
    fake = FakeServiceNow(
        stats_groups=[("1", "New", 10), ("2", "In Progress", 30), ("7", "Closed", 900)]
    )
    result, fake = count(config, auth, fake=fake, group_by="state")
    assert result["count"] == 940
    assert result["groups"][0] == {"value": "7", "display": "Closed", "count": 900}
    sent = fake.stats_calls("incident")[0]["params"]
    assert sent["sysparm_group_by"] == "state"
    assert sent["sysparm_display_value"] == "all"


@pytest.mark.parametrize(
    "kwargs,fragment",
    [
        ({"table": "problem"}, "not supported"),
        ({"group_by": "caller_id.password"}, "not allowed"),
        ({"table": "incident", "risk": "High"}, "risk cannot be used"),
        ({"status_scope": "maybe"}, "status_scope"),
        ({"query": "x^NQactive=true"}, "not allowed"),
    ],
)
def test_invalid_input_is_rejected_before_any_request(config, auth, kwargs, fragment):
    result, fake = count(config, auth, **kwargs)
    assert result["success"] is False
    assert result["error_type"] == "invalid_input"
    assert fragment in result["message"]
    assert not fake.calls


def test_unknown_group_is_reported(config, auth):
    result, _ = count(config, auth, assignment_group="cloud infrastructure")
    assert result["success"] is False
    assert result["error_type"] == "no_matching_group"


def test_aggregate_api_forbidden_falls_back_to_x_total_count(config, auth):
    fake = FakeServiceNow(records=[{"sys_id": "x"}], total=1598, stats_status=403)
    result, fake = count(config, auth, fake=fake, status_scope="open")
    assert result["success"] is True
    assert result["count"] == 1598
    assert result["source"] == "x_total_count"
    assert any("Aggregate API not available" in w for w in result["warnings"])
    sent = fake.table_calls("incident")[0]["params"]
    assert sent["sysparm_query"] == "active=true" and sent["sysparm_limit"] == 1


def test_group_by_without_aggregate_api_is_an_error(config, auth):
    fake = FakeServiceNow(stats_status=403)
    result, _ = count(config, auth, fake=fake, group_by="priority")
    assert result["success"] is False
    assert result["status_code"] == 403


@pytest.mark.parametrize("status,error_type", [(401, "unauthorized"), (500, "server_error")])
def test_http_errors(config, auth, status, error_type):
    result, _ = count(config, auth, fake=FakeServiceNow(status=status))
    assert result["success"] is False
    assert result["status_code"] == status
    assert result["error_type"] == error_type


def test_timeout(config, auth):
    def fake_get(url, params=None, **kwargs):
        raise requests.exceptions.ReadTimeout("slow")

    with patch("requests.get", side_effect=fake_get):
        result = count_records(config, auth, CountRecordsParams())
    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert result["status_code"] is None


def test_malformed_stats_body_is_not_a_zero(config, auth):
    def fake_get(url, params=None, **kwargs):
        return make_response(200, {"result": {"unexpected": True}})

    with patch("requests.get", side_effect=fake_get):
        result = count_records(config, auth, CountRecordsParams())
    assert result["success"] is False
    assert result["error_type"] == "invalid_response"
