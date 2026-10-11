"""
Date filter parsing: ISO-8601 input -> UTC 'YYYY-MM-DD HH:MM:SS' for encoded queries.

- Input with an explicit offset ('Z', '+03:00') is converted to UTC directly.
- Input without an offset (including date-only '2024-05-01') is interpreted in
  the given ``timezone`` argument, else DEFAULT_TIMEZONE (default UTC).
- Date-only input means midnight at the start of that day in that zone.
"""

from datetime import date, datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from servicenow_mcp.utils import settings
from servicenow_mcp.utils.query import QueryInputError, sanitize_value

SERVICENOW_FORMAT = "%Y-%m-%d %H:%M:%S"


class DateInputError(QueryInputError):
    """A date or timezone argument could not be parsed."""


def resolve_timezone(name: Optional[str] = None):
    """Return a tzinfo for ``name`` or DEFAULT_TIMEZONE."""
    zone = (name or "").strip() or settings.default_timezone()
    if zone.upper() in ("UTC", "Z"):
        return timezone.utc
    try:
        return ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise DateInputError(
            f"Unknown timezone {zone!r}. Use an IANA name such as 'UTC', 'Asia/Jerusalem', "
            "'Europe/Berlin'."
        ) from e


def parse_datetime(value: str, tz_name: Optional[str] = None, field: str = "date") -> datetime:
    """Parse ISO date/datetime and return an aware UTC datetime."""
    text = sanitize_value(value, field, max_length=40)
    parsed: datetime
    try:
        if len(text) == 10:
            d = date.fromisoformat(text)
            parsed = datetime(d.year, d.month, d.day)
        else:
            parsed = datetime.fromisoformat(text.replace("z", "Z"))
    except ValueError as e:
        raise DateInputError(
            f"{field}: {value!r} is not an ISO date. Examples: '2024-05-01', "
            "'2024-05-01T08:30:00', '2024-05-01T08:30:00Z', '2024-05-01T08:30:00+03:00'."
        ) from e
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=resolve_timezone(tz_name))
    return parsed.astimezone(timezone.utc)


def to_servicenow_utc(value: str, tz_name: Optional[str] = None, field: str = "date") -> str:
    """Parse ISO input and format it as UTC 'YYYY-MM-DD HH:MM:SS'."""
    return parse_datetime(value, tz_name, field).strftime(SERVICENOW_FORMAT)


def utc_now_string() -> str:
    return datetime.now(timezone.utc).strftime(SERVICENOW_FORMAT)
