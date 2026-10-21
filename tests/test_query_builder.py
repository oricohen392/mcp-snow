"""
Query-building tests for the task list tools (incident, change_request,
sc_request, sc_req_item): group filters, OR lists, numbers, dates with
timezones, label resolution, injection, precedence, ordering and limit cap.
"""

from unittest.mock import patch

import pytest
from fake_servicenow import DEFAULT_GROUPS, FakeServiceNow, gid

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.access_tools import SearchGroupsParams, search_groups
from servicenow_mcp.tools.change_tools import list_change_requests
from servicenow_mcp.tools.incident_tools import ListIncidentsParams, list_incidents
from servicenow_mcp.tools.request_tools import (
    ListRequestItemsParams,
    ListRequestsParams,
    list_request_items,
    list_requests,
)
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig

ORDER = "^ORDERBYDESCsys_created_on"
SYS_ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="u", password="p"))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


@pytest.fixture
def auth(config):
    return AuthManager(config.auth, config.instance_url)


NOC_IDS = f"assignment_groupIN{gid(1)},{gid(2)}"  # 'NOC' matches NOC and INOC_1


def run_incidents(config, auth, **kwargs):
    fake = FakeServiceNow(groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        result = list_incidents(config, auth, ListIncidentsParams(**kwargs))
    return result, fake


# --- A: group filters -------------------------------------------------------


def test_group_partial_match(config, auth):
    result, fake = run_incidents(config, auth, assignment_group="NOC")
    assert result["query_used"] == NOC_IDS + ORDER
    assert fake.last_query("incident") == result["query_used"]
    assert [g["name"] for g in result["matched_groups"]] == ["NOC", "INOC_1"]


def test_group_or_list_from_csv_json_and_list(config, auth):
    expected = f"assignment_groupIN{gid(1)},{gid(2)},{gid(3)}" + ORDER
    for value in ("NOC, Service Desk", '["NOC", "Service Desk"]', ["NOC", "Service Desk"]):
        result, _ = run_incidents(config, auth, assignment_group=value)
        assert result["query_used"] == expected


def test_group_exact_and_sys_id(config, auth):
    result, _ = run_incidents(config, auth, assignment_group_exact="Network Ops, DBA")
    assert result["query_used"] == (
        "assignment_group.name=Network Ops^ORassignment_group.name=DBA" + ORDER
    )
    result, _ = run_incidents(config, auth, assignment_group=SYS_ID.upper())
    assert result["query_used"] == f"assignment_group={SYS_ID}" + ORDER


def test_assigned_to_dot_walks(config, auth):
    result, _ = run_incidents(config, auth, assigned_to="cohen")
    assert result["query_used"] == (
        "assigned_to.nameLIKEcohen^ORassigned_to.user_name=cohen" + ORDER
    )


@pytest.mark.parametrize(
    "tool,params_cls,table",
    [
        (list_requests, ListRequestsParams, "sc_request"),
        (list_request_items, ListRequestItemsParams, "sc_req_item"),
    ],
)
def test_group_filter_on_request_tables(config, auth, tool, params_cls, table):
    fake = FakeServiceNow(groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        result = tool(config, auth, params_cls(assignment_group="NOC"))
    assert result["success"]
    assert fake.last_query(table) == NOC_IDS + ORDER


def test_group_filter_on_change(config, auth):
    fake = FakeServiceNow(groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        result = list_change_requests(auth, config, {"assignment_group": "NOC"})
    assert fake.last_query("change_request") == NOC_IDS + ORDER
    assert result["query_used"] == fake.last_query("change_request")


def test_search_groups_query(config, auth):
    fake = FakeServiceNow(records=[{"sys_id": SYS_ID, "name": "INOC_1", "active": "true"}])
    with patch("requests.get", side_effect=fake):
        result = search_groups(config, auth, SearchGroupsParams(name_part="NOC"))
    assert result["success"] and result["groups"][0]["name"] == "INOC_1"
    assert result["query_used"] == "nameLIKENOC^active=true^ORDERBYname"


# --- B: label resolution ------------------------------------------------------


def test_state_priority_category_labels(config, auth):
    result, _ = run_incidents(
        config, auth, state="New, in progress", priority="Critical", category="Network"
    )
    assert result["query_used"] == "stateIN1,2^priority=1^category=network" + ORDER


def test_state_values_pass(config, auth):
    result, _ = run_incidents(config, auth, state="6")
    assert result["query_used"] == "state=6" + ORDER


def test_unknown_label_is_an_error_with_valid_labels(config, auth):
    result, fake = run_incidents(config, auth, state="open")
    assert result["success"] is False
    assert result["error_type"] == "invalid_input"
    assert "New (1)" in result["message"] and "Resolved (6)" in result["message"]
    assert not fake.table_calls("incident"), "no incident query may be sent"


def test_change_type_and_risk_labels(config, auth):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        result = list_change_requests(
            auth, config, {"type": "Emergency", "risk": "high", "state": "Implement"}
        )
    assert result["query_used"] == "state=-1^type=emergency^risk=2" + ORDER


def test_request_specific_choices(config, auth):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        list_requests(config, auth, ListRequestsParams(request_state="Approved", state="Open"))
        list_request_items(config, auth, ListRequestItemsParams(stage="fulfillment"))
    assert fake.last_query("sc_request") == "state=1^request_state=in_process" + ORDER
    assert fake.last_query("sc_req_item") == "stage=fulfillment" + ORDER


# --- C: dates -----------------------------------------------------------------


def test_dates_with_timezone(config, auth):
    result, _ = run_incidents(
        config,
        auth,
        created_after="2024-05-01",
        created_before="2024-05-02T00:00:00+03:00",
        updated_after="2024-05-01T10:00:00Z",
        timezone="Asia/Jerusalem",
    )
    assert result["query_used"] == (
        "sys_created_on>=2024-04-30 21:00:00^sys_created_on<2024-05-01 21:00:00"
        "^sys_updated_on>=2024-05-01 10:00:00" + ORDER
    )


def test_dates_default_timezone_env(config, auth, monkeypatch):
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Asia/Jerusalem")
    result, _ = run_incidents(config, auth, updated_before="2024-01-15T10:00:00")
    assert result["query_used"] == "sys_updated_on<2024-01-15 08:00:00" + ORDER


def test_change_planned_dates_and_timeframe(config, auth):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        result = list_change_requests(
            auth, config, {"start_after": "2024-06-01T00:00:00Z", "end_before": "2024-06-30"}
        )
        bad = list_change_requests(auth, config, {"timeframe": "next-week"})
    assert result["query_used"] == (
        "start_date>=2024-06-01 00:00:00^end_date<2024-06-30 00:00:00" + ORDER
    )
    assert bad["success"] is False and "upcoming" in bad["message"]


def test_bad_date_is_an_error(config, auth):
    result, fake = run_incidents(config, auth, created_after="last tuesday")
    assert result["success"] is False and result["error_type"] == "invalid_input"
    assert not fake.calls


# --- D: numbers -------------------------------------------------------------------


def test_number_lists_and_prefix_validation(config, auth):
    result, _ = run_incidents(config, auth, number="inc0010001, INC0010002")
    assert result["query_used"] == "numberININC0010001,INC0010002" + ORDER
    result, fake = run_incidents(config, auth, number="CHG0030001")
    assert result["success"] is False and "INC" in result["message"]
    assert not fake.calls


@pytest.mark.parametrize(
    "tool,params,table,good,bad",
    [
        (list_requests, ListRequestsParams, "sc_request", "REQ0010001", "RITM0010001"),
        (list_request_items, ListRequestItemsParams, "sc_req_item", "RITM0010001", "REQ0010001"),
    ],
)
def test_number_prefix_requests(config, auth, tool, params, table, good, bad):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        ok = tool(config, auth, params(number=good))
        ko = tool(config, auth, params(number=bad))
    assert ok["query_used"] == f"number={good}" + ORDER
    assert ko["success"] is False


def test_change_number(config, auth):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        result = list_change_requests(auth, config, {"number": "CHG0030001,CHG0030002"})
    assert result["query_used"] == "numberINCHG0030001,CHG0030002" + ORDER


# --- E/F: injection and precedence -----------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("query", "foo^ORnumberISNOTEMPTY"),
        ("query", "x^NQactive=true"),
        ("assignment_group", "NOC^NQactive=true"),
        ("assigned_to", "a\nb"),
        ("state", "1^ORstate=2"),
        ("number", "INC0010001^NQ"),
        ("created_after", "2024-01-01^NQ"),
    ],
)
def test_injection_rejected_before_any_request(config, auth, field, value):
    result, fake = run_incidents(config, auth, **{field: value})
    assert result["success"] is False
    assert result["error_type"] == "invalid_input"
    assert not fake.table_calls("incident")


def test_change_query_is_no_longer_raw_passthrough(config, auth):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        result = list_change_requests(auth, config, {"query": "short_description=Test^NQactive=true"})
    assert result["success"] is False
    assert not fake.table_calls("change_request")


def test_free_text_or_group_does_not_leak(config, auth):
    result, _ = run_incidents(
        config, auth, query="vpn", state="New", assignment_group="NOC, DBA", active=True
    )
    q = result["query_used"]
    assert q == (
        "state=1^active=true"
        f"^assignment_groupIN{gid(1)},{gid(2)},{gid(4)}"
        "^short_descriptionLIKEvpn^ORdescriptionLIKEvpn" + ORDER
    )
    # Every ^OR is followed by a condition on the same kind of field as its group
    for part in q[: -len(ORDER)].split("^OR")[1:]:
        assert part.startswith("description")


# --- I: limit, ordering --------------------------------------------------------------


def test_limit_cap_and_offset(config, auth, monkeypatch):
    result, fake = run_incidents(config, auth, limit=500, offset=40)
    sent = fake.table_calls("incident")[-1]["params"]
    assert sent["sysparm_limit"] == 100 and sent["sysparm_offset"] == 40
    assert result["limit"] == 100 and result["limit_capped"] is True
    monkeypatch.setenv("MAX_LIMIT", "20")
    result, fake = run_incidents(config, auth, limit=50)
    assert fake.table_calls("incident")[-1]["params"]["sysparm_limit"] == 20
    result, _ = run_incidents(config, auth, limit=5)
    assert "limit_capped" not in result


def test_order_by_whitelist(config, auth):
    result, _ = run_incidents(config, auth, order_by="priority", descending=False)
    assert result["query_used"] == "ORDERBYpriority"
    result, fake = run_incidents(config, auth, order_by="caller_id.password")
    assert result["success"] is False and "Allowed" in result["message"]
    assert not fake.calls


def test_change_order_by_start_date(config, auth):
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake):
        result = list_change_requests(auth, config, {"order_by": "start_date"})
    assert result["query_used"] == "ORDERBYDESCstart_date"


def test_timeout_and_tls_settings_used(config, auth, monkeypatch):
    monkeypatch.setenv("CA_BUNDLE", "/etc/pki/ca.pem")
    fake = FakeServiceNow()
    with patch("requests.get", side_effect=fake) as mock_get:
        list_incidents(config, auth, ListIncidentsParams())
    kwargs = mock_get.call_args.kwargs
    assert kwargs["timeout"] == config.timeout
    assert kwargs["verify"] == "/etc/pki/ca.pem"
