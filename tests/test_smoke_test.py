"""
The in-pod smoke test runs end to end against the fake Table API.
"""

from unittest.mock import patch

from fake_servicenow import FakeServiceNow

from servicenow_mcp.smoke_test import main


def _env(monkeypatch):
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://acme.service-now.com")
    monkeypatch.setenv("SERVICENOW_USERNAME", "svc")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "never-printed")


def test_smoke_pass(monkeypatch, capsys):
    _env(monkeypatch)
    fake = FakeServiceNow(records=[{"sys_id": "a" * 32, "number": "INC0010001", "name": "INOC_1"}], total=1)
    with patch("requests.get", side_effect=fake):
        assert main(["--group", "NOC", "--limit", "2"]) == 0
    out = capsys.readouterr().out
    assert "query_used : assignment_group.nameLIKENOC^ORDERBYDESCsys_created_on" in out
    assert "search_groups('NOC'): OK" in out
    assert "never-printed" not in out
    assert "RESULT: PASS" in out


def test_smoke_fail_on_401(monkeypatch, capsys):
    _env(monkeypatch)
    with patch("requests.get", side_effect=FakeServiceNow(status=401)):
        assert main([]) == 1
    out = capsys.readouterr().out
    assert "HTTP 401" in out and "RESULT: FAIL" in out
    assert "never-printed" not in out
