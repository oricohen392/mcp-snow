import re
import urllib.parse
from typing import Optional

_TABLE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_]+$")
_RECORD_ID_REGEX = re.compile(r"^[0-9a-zA-Z_.\-]+$")
_FORBIDDEN_RECORD_ID_CHARS = {"\x00", "\r", "\n", "\t", "?", "#"}


class SafeUrlError(ValueError):
    """Raised when an invalid table name or record ID is supplied."""


def safe_table_url(instance_url_or_base: str, table: str, record_id: Optional[str] = None) -> str:
    """
    Safely construct a ServiceNow Table API endpoint URL.

    Args:
        instance_url_or_base: ServiceNow instance or API base URL (e.g. 'https://dev.service-now.com' or 'https://dev.service-now.com/api/now')
        table: ServiceNow table name (must match ^[a-zA-Z0-9_]+$)
        record_id: Optional record ID or sys_id. If provided, verified against path traversal
                   and control characters, and safely quoted.

    Returns:
        The full Table API endpoint URL.
    """
    if not table or not _TABLE_NAME_REGEX.match(table):
        raise SafeUrlError(f"Invalid table name {table!r}: must contain only alphanumeric characters and underscores")

    base = instance_url_or_base.rstrip("/")
    if not base.endswith("/api/now"):
        base = f"{base}/api/now"

    if record_id is None:
        return f"{base}/table/{table}"

    raw_rid = str(record_id)
    for ch in _FORBIDDEN_RECORD_ID_CHARS:
        if ch in raw_rid:
            raise SafeUrlError(f"Forbidden character {ch!r} in record_id: {record_id!r}")

    rid = raw_rid.strip()
    if not rid:
        raise SafeUrlError("record_id cannot be empty")

    if ".." in rid or "/" in rid or "\\" in rid:
        raise SafeUrlError(f"Path traversal detected in record_id: {record_id!r}")

    if not _RECORD_ID_REGEX.match(rid):
        raise SafeUrlError(f"Invalid record_id {record_id!r}: must contain only alphanumeric characters, underscores, hyphens, and dots")

    safe_rid = urllib.parse.quote(rid, safe="")
    return f"{base}/table/{table}/{safe_rid}"
