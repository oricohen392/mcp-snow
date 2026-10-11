"""
Tests for ISO date parsing and UTC conversion.
"""

import pytest

from servicenow_mcp.utils.dates import DateInputError, to_servicenow_utc


@pytest.mark.parametrize(
    "value,tz,expected",
    [
        ("2024-05-01", None, "2024-05-01 00:00:00"),
        ("2024-05-01T08:30:00", None, "2024-05-01 08:30:00"),
        ("2024-05-01T08:30:00Z", None, "2024-05-01 08:30:00"),
        ("2024-05-01T08:30:00+03:00", None, "2024-05-01 05:30:00"),
        ("2024-05-01 08:30", None, "2024-05-01 08:30:00"),
        # Naive input interpreted in the given zone (Israel is UTC+3 in May: IDT)
        ("2024-05-01T08:30:00", "Asia/Jerusalem", "2024-05-01 05:30:00"),
        ("2024-05-01", "Asia/Jerusalem", "2024-04-30 21:00:00"),
        # ... and UTC+2 in January (IST)
        ("2024-01-15T10:00:00", "Asia/Jerusalem", "2024-01-15 08:00:00"),
        # An explicit offset wins over the timezone argument
        ("2024-05-01T08:30:00Z", "Asia/Jerusalem", "2024-05-01 08:30:00"),
        ("2024-03-10T12:00:00", "America/New_York", "2024-03-10 16:00:00"),
    ],
)
def test_to_servicenow_utc(value, tz, expected, monkeypatch):
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    assert to_servicenow_utc(value, tz) == expected


def test_default_timezone_env(monkeypatch):
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Europe/Berlin")
    assert to_servicenow_utc("2024-07-01T12:00:00") == "2024-07-01 10:00:00"
    assert to_servicenow_utc("2024-07-01T12:00:00", "UTC") == "2024-07-01 12:00:00"


@pytest.mark.parametrize("value", ["yesterday", "2024-13-01", "01/05/2024", "2024-05-01^NQactive=true"])
def test_invalid_dates_rejected(value):
    with pytest.raises(DateInputError if "^" not in value else Exception):
        to_servicenow_utc(value)


def test_invalid_timezone_rejected():
    with pytest.raises(DateInputError) as exc:
        to_servicenow_utc("2024-05-01", "Mars/Olympus")
    assert "IANA" in str(exc.value)
