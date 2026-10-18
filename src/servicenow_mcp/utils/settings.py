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
    """MAX_LIMIT (default 100): upper bound for any list tool's limit."""
    return _env_int("MAX_LIMIT", 100)


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


def mcp_public_url() -> Optional[str]:
    """MCP_PUBLIC_URL: public base URL of this MCP server (trailing slash stripped)."""
    value = os.getenv("MCP_PUBLIC_URL", "").strip().rstrip("/")
    return value or None


def oidc_issuer_url() -> Optional[str]:
    """
    OIDC_ISSUER_URL: OIDC issuer URL for token validation / discovery
    (trailing slash stripped).
    """
    value = os.getenv("OIDC_ISSUER_URL", "").strip().rstrip("/")
    return value or None


def oauth_client_id() -> Optional[str]:
    """OAUTH_CLIENT_ID: OAuth client ID for per-user OAuth / OIDC flows."""
    value = os.getenv("OAUTH_CLIENT_ID", "").strip()
    return value or None


def oauth_client_secret() -> Optional[str]:
    """OAUTH_CLIENT_SECRET: OAuth client secret for per-user OAuth / OIDC flows."""
    value = os.getenv("OAUTH_CLIENT_SECRET", "").strip()
    return value or None


def oauth_authorize_url() -> Optional[str]:
    """OAUTH_AUTHORIZE_URL: explicit OAuth authorization endpoint URL."""
    value = os.getenv("OAUTH_AUTHORIZE_URL", "").strip()
    return value or None


def oauth_token_url() -> Optional[str]:
    """OAUTH_TOKEN_URL: explicit OAuth token endpoint URL."""
    value = os.getenv("OAUTH_TOKEN_URL", "").strip()
    return value or None


def oauth_scopes() -> Optional[str]:
    """OAUTH_SCOPES: space-delimited OAuth scopes requested during authorization."""
    value = os.getenv("OAUTH_SCOPES", "").strip()
    return value or None


def servicenow_api_key_header() -> str:
    """SERVICENOW_API_KEY_HEADER (default 'x-sn-apikey'): header for API key auth."""
    return os.getenv("SERVICENOW_API_KEY_HEADER", "").strip() or "x-sn-apikey"


def allow_service_account_fallback() -> bool:
    """ALLOW_SERVICE_ACCOUNT_FALLBACK (default false): allow falling back to service account."""
    return _env_bool("ALLOW_SERVICE_ACCOUNT_FALLBACK", False)


def session_ttl_seconds() -> int:
    """SESSION_TTL_SECONDS (default 86400, minimum 60): TTL for cached user sessions."""
    return _env_int("SESSION_TTL_SECONDS", 86400, minimum=60)


def session_absolute_lifetime_seconds() -> int:
    """
    SESSION_ABSOLUTE_LIFETIME_SECONDS (default 604800, minimum 60):
    Absolute lifetime ceiling for a session.
    """
    return _env_int("SESSION_ABSOLUTE_LIFETIME_SECONDS", 7 * 86400, minimum=60)


def require_oauth_consent() -> bool:
    """
    REQUIRE_OAUTH_CONSENT (default false): require interactive user consent
    before redirecting to upstream IdP.
    """
    return _env_bool("REQUIRE_OAUTH_CONSENT", False)


def allow_bearer_passthrough() -> bool:
    """
    ALLOW_BEARER_PASSTHROUGH (default false): allow unverified arbitrary Bearer tokens
    to pass through.
    """
    return _env_bool("ALLOW_BEARER_PASSTHROUGH", False)
