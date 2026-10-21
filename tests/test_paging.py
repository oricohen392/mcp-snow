"""
Paging and payload size: has_more / next_offset, the explicit "call again"
message, MAX_LIMIT 500, sysparm_fields, compact change records and truncated
descriptions in lists.
"""

from unittest.mock import patch

import pytest
from fake_servicenow import FakeServiceNow

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.change_tools import list_change_requests
from servicenow_mcp.tools.incident_tools import (
    GetIncidentByNumberParams,
    ListIncidentsParams,
    get_incident_by_number,
    list_incidents,
)
from servicenow_mcp.tools.request_tools import ListRequestsParams, list_requests
from servicenow_mcp.tools.ticket_query import CHANGE_FIELDS, LIST_DESCRIPTION_CHARS
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="u", password="p"))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


@pytest.fixture
def auth(config):
    return AuthManager(config.auth, config.instance_url)


def rows(n):
    return [{"sys_id": f"{i:032x}", "number": f"REQ{i:07d}"} for i in range(n)]


def requests_page(config, auth, records, total, **kwargs):
    fake = FakeServiceNow(records=records, total=total)
    with patch("requests.get", side_effect=fake):
        return list_requests(config, auth, ListRequestsParams(**kwargs)), fake


def test_first_page_says_how_to_get_the_rest(config, auth):
    result, _ = requests_page(config, auth, rows(100), 2345, limit=100)
    assert result["has_more"] is True
    assert result["next_offset"] == 100
    assert "records 1-100 of 2345" in result["message"]
    assert "2245 more" in result["message"] and "offset=100" in result["message"]


def test_last_page_has_no_next_offset(config, auth):
    result, _ = requests_page(config, auth, rows(20), 120, limit=100, offset=100)
    assert result["has_more"] is False
    assert "next_offset" not in result
    assert "records 101-120 of 120" in result["message"]


def test_without_total_a_full_page_means_maybe_more(config, auth):
    fake = FakeServiceNow(records=rows(10))
    fake.total = None

    def no_header(url, params=None, **kwargs):
        response = fake(url, params=params, **kwargs)
        response.headers.pop("X-Total-Count", None)
        return response

    with patch("requests.get", side_effect=no_header):
        result = list_requests(config, auth, ListRequestsParams(limit=10))
    assert result["total_count"] is None
    assert result["has_more"] is True and result["next_offset"] == 10


def test_max_limit_default_is_500_and_message_says_capped(config, auth):
    result, fake = requests_page(config, auth, rows(3), 3, limit=1000)
    assert fake.table_calls("sc_request")[-1]["params"]["sysparm_limit"] == 500
    assert result["limit_capped"] is True
    assert "capped at MAX_LIMIT=500" in result["message"]


def test_sysparm_fields_limits_the_payload(config, auth):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        list_incidents(config, auth, ListIncidentsParams())
        list_change_requests(auth, config, {})
    incident_fields = fake.table_calls("incident")[-1]["params"]["sysparm_fields"].split(",")
    assert "sys_created_on" in incident_fields and "number" in incident_fields
    assert len(incident_fields) == len(set(incident_fields))
    change_fields = fake.table_calls("change_request")[-1]["params"]["sysparm_fields"]
    assert "start_date" in change_fields and "end_date" in change_fields


def test_change_list_records_are_compact(config, auth):
    raw = {f"u_custom_{i}": "x" for i in range(150)}
    raw.update({"sys_id": "c" * 32, "number": "CHG0030001", "state": "Implement"})
    fake = FakeServiceNow(records=[raw], stats_count=1)
    with patch("requests.get", side_effect=fake):
        result = list_change_requests(auth, config, {})
    record = result["change_requests"][0]
    assert set(record) == set(CHANGE_FIELDS)
    assert record["number"] == "CHG0030001" and record["state"] == "Implement"


def test_list_truncates_descriptions_but_get_does_not(config, auth):
    long_text = "word " * 200
    record = {"sys_id": "a" * 32, "number": "INC0010001", "description": long_text}
    fake = FakeServiceNow(records=[record])
    with patch("requests.get", side_effect=fake):
        listed = list_incidents(config, auth, ListIncidentsParams())
        single = get_incident_by_number(
            config, auth, GetIncidentByNumberParams(incident_number="INC0010001")
        )
    description = listed["incidents"][0]["description"]
    assert description.startswith(long_text[:LIST_DESCRIPTION_CHARS])
    assert "truncated" in description
    assert single["incident"]["description"] == long_text
