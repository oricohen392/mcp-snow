"""
Tests for sys_choice label -> value resolution.
"""

from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

import pytest

from servicenow_mcp.utils.choices import ChoiceResolutionError, ChoiceResolver
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig

INCIDENT_STATE = [
    {"value": "1", "label": "New"},
    {"value": "2", "label": "In Progress"},
    {"value": "3", "label": "On Hold"},
    {"value": "6", "label": "Resolved"},
    {"value": "7", "label": "Closed"},
    {"value": "8", "label": "Canceled"},
    {"value": "1", "label": "חדש"},  # second language row for the same value
]
TASK_PRIORITY = [
    {"value": "1", "label": "1 - Critical"},
    {"value": "2", "label": "2 - High"},
    {"value": "3", "label": "3 - Moderate"},
    {"value": "4", "label": "4 - Low"},
    {"value": "5", "label": "5 - Planning"},
]


@pytest.fixture
def config():
    auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="u", password="p"))
    return ServerConfig(instance_url="https://example.service-now.com", auth=auth)


@pytest.fixture
def auth():
    m = MagicMock()
    m.get_headers.return_value = {"Authorization": "Basic x"}
    return m


def _response(records, status=200):
    r = MagicMock()
    r.status_code = status
    r.headers = {"X-Total-Count": str(len(records))}
    r.json.return_value = {"result": records}
    r.raise_for_status = MagicMock()
    return r


def _sys_choice_backend(tables):
    """Fake requests.get serving sys_choice rows per name=<table>^element=<field>."""
    calls = []

    def fake_get(url, params=None, **kwargs):
        calls.append(params["sysparm_query"])
        assert url.endswith("/api/now/table/sys_choice")
        query = params["sysparm_query"]
        name = query.split("name=")[1].split("^")[0]
        element = query.split("element=")[1].split("^")[0]
        return _response(tables.get((name, element), []))

    return fake_get, calls


def test_label_and_value_resolution(config, auth):
    fake, calls = _sys_choice_backend({("incident", "state"): INCIDENT_STATE})
    resolver = ChoiceResolver()
    with patch("requests.get", side_effect=fake):
        assert resolver.resolve(config, auth, "incident", "state", ["New"]).values == ["1"]
        assert resolver.resolve(config, auth, "incident", "state", ["in progress"]).values == ["2"]
        assert resolver.resolve(config, auth, "incident", "state", ["6"]).values == ["6"]
        assert resolver.resolve(config, auth, "incident", "state", ["חדש", "New", "On Hold"]).values == [
            "1",
            "3",
        ]
    assert calls[0] == "name=incident^element=state^inactive=false^ORDERBYsequence"
    assert len(calls) == 1, "choices must be cached"


def test_priority_falls_back_to_task_and_strips_number_prefix(config, auth):
    fake, calls = _sys_choice_backend({("task", "priority"): TASK_PRIORITY})
    resolver = ChoiceResolver()
    with patch("requests.get", side_effect=fake):
        for raw in ("1 - Critical", "critical", "Critical", "1"):
            assert resolver.resolve(config, auth, "incident", "priority", [raw]).values == ["1"]
        assert resolver.resolve(config, auth, "incident", "priority", ["High", "Low"]).values == [
            "2",
            "4",
        ]
    assert [c.split("^")[0] for c in calls] == ["name=incident", "name=task"]


def test_unknown_label_lists_valid_labels(config, auth):
    fake, _ = _sys_choice_backend({("incident", "state"): INCIDENT_STATE})
    with patch("requests.get", side_effect=fake):
        with pytest.raises(ChoiceResolutionError) as exc:
            ChoiceResolver().resolve(config, auth, "incident", "state", ["open"])
    message = str(exc.value)
    assert "Unknown state 'open'" in message
    for expected in ("New (1)", "In Progress (2)", "Resolved (6)", "Canceled (8)"):
        assert expected in message


def test_cache_ttl_expiry(config, auth):
    fake, calls = _sys_choice_backend({("incident", "state"): INCIDENT_STATE})
    now = [1000.0]
    resolver = ChoiceResolver(ttl_seconds=lambda: 60, clock=lambda: now[0])
    with patch("requests.get", side_effect=fake):
        resolver.resolve(config, auth, "incident", "state", ["New"])
        now[0] += 59
        resolver.resolve(config, auth, "incident", "state", ["New"])
        assert len(calls) == 1
        now[0] += 2
        resolver.resolve(config, auth, "incident", "state", ["New"])
        assert len(calls) == 2


def test_sys_choice_forbidden_numeric_field(config, auth):
    resolver = ChoiceResolver()
    with patch("requests.get", return_value=_response([], status=403)):
        resolution = resolver.resolve(config, auth, "incident", "state", ["2"], numeric=True)
        assert resolution.values == ["2"]
        assert "not validated" in resolution.warnings[0]
        assert "403" in resolution.warnings[0]
        with pytest.raises(ChoiceResolutionError) as exc:
            resolver.resolve(config, auth, "incident", "state", ["New"], numeric=True)
        assert "numeric value" in str(exc.value)


def test_sys_choice_forbidden_string_field_passes_through(config, auth):
    with patch("requests.get", return_value=_response([], status=403)):
        resolution = ChoiceResolver().resolve(config, auth, "incident", "category", ["network"])
    assert resolution.values == ["network"]
    assert resolution.warnings


def test_errors_are_not_cached(config, auth):
    resolver = ChoiceResolver()
    with patch("requests.get", return_value=_response([], status=403)):
        resolver.resolve(config, auth, "incident", "category", ["network"])
    fake, calls = _sys_choice_backend({("incident", "category"): [{"value": "network", "label": "Network"}]})
    with patch("requests.get", side_effect=fake):
        assert resolver.resolve(config, auth, "incident", "category", ["Network"]).values == ["network"]
    assert calls


def test_injection_in_label_rejected(config, auth):
    with pytest.raises(Exception):
        ChoiceResolver().resolve(config, auth, "incident", "state", ["New^NQactive=true"])
