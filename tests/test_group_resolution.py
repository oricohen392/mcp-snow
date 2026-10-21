"""
Assignment group resolution: every word of the requested name must appear in
the group name (any order), all matching groups are included and reported in
matched_groups, and a name that matches nothing is an error, not "0 results".
"""

from unittest.mock import patch

import pytest
from fake_servicenow import DEFAULT_GROUPS, FakeServiceNow, gid, make_response

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.access_tools import SearchGroupsParams, search_groups
from servicenow_mcp.tools.incident_tools import ListIncidentsParams, list_incidents
from servicenow_mcp.tools.ticket_query import GROUP_MATCH_LIMIT, group_name_tokens
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig

ORDER = "^ORDERBYDESCsys_created_on"


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="u", password="p"))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


@pytest.fixture
def auth(config):
    return AuthManager(config.auth, config.instance_url)


def run(config, auth, fake=None, **kwargs):
    fake = fake or FakeServiceNow(groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        result = list_incidents(config, auth, ListIncidentsParams(**kwargs))
    return result, fake


def test_tokens_split_on_spaces_and_separators():
    assert group_name_tokens("תשתיות ענן") == ["תשתיות", "ענן"]
    assert group_name_tokens(" Cloud-Infra / Tier2 ") == ["Cloud", "Infra", "Tier2"]
    assert group_name_tokens("NOC") == ["NOC"]


def test_hebrew_words_match_in_any_order(config, auth):
    result, fake = run(config, auth, assignment_group="תשתיות ענן")
    assert result["success"] is True
    names = [g["name"] for g in result["matched_groups"]]
    assert names == ["תשתיות ענן", "ענן - תשתיות Tier2"]
    assert result["query_used"] == f"assignment_groupIN{gid(6)},{gid(7)}" + ORDER
    lookup = fake.table_calls("sys_user_group")[0]["params"]["sysparm_query"]
    assert lookup == "nameLIKEתשתיות^nameLIKEענן^active=true^ORDERBYname"


def test_child_groups_are_opt_in(config, auth):
    result, _ = run(config, auth, assignment_group="תשתיות ענן", include_child_groups=True)
    names = [g["name"] for g in result["matched_groups"]]
    assert names == ["תשתיות ענן", "ענן - תשתיות Tier2", "Linux Team", "Linux Night Shift"]
    assert result["matched_groups"][2]["child_of_match"] is True
    assert result["query_used"] == (
        f"assignment_groupIN{gid(6)},{gid(7)},{gid(8)},{gid(10)}" + ORDER
    )


def test_inactive_groups_only_when_no_active_match(config, auth):
    result, _ = run(config, auth, assignment_group="mainframe")
    assert result["matched_groups"] == [
        {"name": "Legacy Mainframe", "sys_id": gid(11), "active": False}
    ]
    # 'NOC' has active matches, so the inactive 'Old NOC' is not added
    result, _ = run(config, auth, assignment_group="NOC")
    assert "Old NOC" not in [g["name"] for g in result["matched_groups"]]


def test_unknown_group_is_an_error_not_zero_results(config, auth):
    result, fake = run(config, auth, assignment_group="cloud infrastructure")
    assert result["success"] is False
    assert result["error_type"] == "no_matching_group"
    assert "search_groups" in result["message"]
    assert result["incidents"] == []
    assert not fake.table_calls("incident")


def test_sys_id_skips_lookup(config, auth):
    result, fake = run(config, auth, assignment_group=gid(3))
    assert result["query_used"] == f"assignment_group={gid(3)}" + ORDER
    assert not fake.table_calls("sys_user_group")


def test_group_table_forbidden_falls_back_to_like_with_warning(config, auth):
    def fake_get(url, params=None, **kwargs):
        if url.endswith("/table/sys_user_group"):
            return make_response(403, {"error": {"message": "no"}})
        return make_response(200, {"result": []}, total=0)

    with patch("requests.get", side_effect=fake_get):
        result = list_incidents(config, auth, ListIncidentsParams(assignment_group="NOC"))
    assert result["success"] is True
    assert result["query_used"] == "assignment_group.nameLIKENOC" + ORDER
    assert any("403" in w for w in result["warnings"])


def test_group_lookup_auth_failure_is_reported(config, auth):
    def fake_get(url, params=None, **kwargs):
        if url.endswith("/table/sys_user_group"):
            return make_response(401, {"error": {"message": "bad creds"}})
        raise AssertionError("must not query incident after a failed lookup")

    with patch("requests.get", side_effect=fake_get):
        result = list_incidents(config, auth, ListIncidentsParams(assignment_group="NOC"))
    assert result["success"] is False
    assert result["status_code"] == 401
    assert "assignment group lookup" in result["message"]


def test_too_many_groups_falls_back_to_like(config, auth):
    many = [
        {"sys_id": gid(1000 + i), "name": f"Team {i}", "active": "true", "parent": ""}
        for i in range(GROUP_MATCH_LIMIT + 5)
    ]
    result, _ = run(config, auth, fake=FakeServiceNow(groups=many), assignment_group="Team")
    assert result["query_used"] == "assignment_group.nameLIKETeam" + ORDER
    assert any("more than" in w for w in result["warnings"])


def test_search_groups_uses_word_matching(config, auth):
    fake = FakeServiceNow(groups=DEFAULT_GROUPS)
    with patch("requests.get", side_effect=fake):
        result = search_groups(config, auth, SearchGroupsParams(name_part="ענן תשתיות"))
    assert [g["name"] for g in result["groups"]] == ["תשתיות ענן", "ענן - תשתיות Tier2"]
    assert result["query_used"] == "nameLIKEענן^nameLIKEתשתיות^active=true^ORDERBYname"
