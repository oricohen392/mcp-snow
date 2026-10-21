"""
Runtime settings read from environment variables.

Values are read at call time (not import time) so tests and operators can
change them without reloading modules.
"""

import os
from typing import Optional

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    raise ValueError(f"{name} must be true/false, got {raw!r}")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as e:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from e
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def log_level() -> str:
    """LOG_LEVEL (default INFO). SERVICENOW_DEBUG=true is kept as an alias for DEBUG."""
    level = os.getenv("LOG_LEVEL", "").strip().upper()
    if level:
        return level
    if os.getenv("SERVICENOW_DEBUG", "false").strip().lower() in _TRUTHY:
        return "DEBUG"
    return "INFO"


def read_only() -> bool:
    """READ_ONLY (default true). Write tools are only registered when explicitly false."""
    return _env_bool("READ_ONLY", True)


def max_limit() -> int:
    """MAX_LIMIT (default 500): upper bound for any list tool's limit."""
    return _env_int("MAX_LIMIT", 500)


def choice_cache_ttl_seconds() -> int:
    """CHOICE_CACHE_TTL_SECONDS (default 3600): TTL of the sys_choice label cache."""
    return _env_int("CHOICE_CACHE_TTL_SECONDS", 3600)


def default_timezone() -> str:
    """DEFAULT_TIMEZONE (default UTC): IANA zone used for dates given without an offset."""
    return os.getenv("DEFAULT_TIMEZONE", "").strip() or "UTC"


def mcp_auth_token() -> Optional[str]:
    """MCP_AUTH_TOKEN: when set, the SSE endpoints require 'Authorization: Bearer <token>'."""
    token = os.getenv("MCP_AUTH_TOKEN", "").strip()
    return token or None


def ca_bundle() -> Optional[str]:
    """CA_BUNDLE: optional path to a PEM bundle used to verify the ServiceNow TLS certificate."""
    path = os.getenv("CA_BUNDLE", "").strip()
    return path or None


def tls_verify():
    """Value for requests' ``verify=`` argument."""
    return ca_bundle() or True


def servicenow_timeout() -> int:
    """SERVICENOW_TIMEOUT (default 30): HTTP timeout in seconds for ServiceNow calls."""
    return _env_int("SERVICENOW_TIMEOUT", 30)
