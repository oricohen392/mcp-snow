"""
Shared HTTP helper for ServiceNow Table API reads.

Every read goes through ``sn_get`` so that requests get a timeout, the
optional CA bundle, DEBUG logging of what was sent (never headers or
credentials), ``X-Total-Count`` parsing and a uniform error classification
that callers can surface as ``success=false`` instead of "0 results".
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import requests

from servicenow_mcp.utils import settings

logger = logging.getLogger(__name__)

_ERROR_HINTS = {
    "unauthorized": "ServiceNow rejected the credentials (HTTP 401). "
    "Verify your OAuth/OIDC token, API key, or service account credentials, or re-authenticate via /auth/login.",
    "forbidden": "ServiceNow denied access (HTTP 403). The integration user lacks a role or "
    "table-level ACL for this table. Run check_access to see which tables are readable.",
    "not_found": "ServiceNow returned HTTP 404 (unknown table, record or API path).",
    "rate_limited": "ServiceNow rate limit hit (HTTP 429). Retry later.",
    "server_error": "ServiceNow returned a server error (HTTP 5xx).",
    "http_error": "ServiceNow returned an HTTP error.",
    "timeout": "The request to ServiceNow timed out (SERVICENOW_TIMEOUT).",
    "connection": "Could not connect to ServiceNow (DNS, network policy, proxy or TLS problem).",
    "invalid_response": "ServiceNow returned a non-JSON response (often an SSO/login page or proxy error).",
    "auth_config": "Could not build authentication headers.",
    "request_error": "The request to ServiceNow failed.",
}


@dataclass
class SnResult:
    """Outcome of a ServiceNow GET."""

    ok: bool
    status_code: Optional[int]
    records: List[Dict[str, Any]] = field(default_factory=list)
    total_count: Optional[int] = None
    elapsed_ms: int = 0
    error_type: Optional[str] = None
    message: str = ""

    def error_dict(self, prefix: str = "") -> Dict[str, Any]:
        """Uniform failure payload for tool responses."""
        message = f"{prefix}: {self.message}" if prefix else self.message
        return {
            "success": False,
            "status_code": self.status_code,
            "error_type": self.error_type,
            "message": message,
        }


def _classify_status(status: int) -> str:
    if status == 401:
        return "unauthorized"
    if status == 403:
        return "forbidden"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "server_error"
    return "http_error"


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _service_now_error_detail(response: Any) -> str:
    """Extract ServiceNow's {"error": {"message", "detail"}} body if present."""
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 - body is optional diagnostic data
        return ""
    if not isinstance(body, dict):
        return ""
    error = body.get("error")
    if not isinstance(error, dict):
        return ""
    parts = [str(error.get(k)) for k in ("message", "detail") if error.get(k)]
    return " - ".join(parts)


def build_url(config: Any, path: str) -> str:
    """Resolve 'table/incident' (relative to /api/now) or an absolute URL."""
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{config.api_url}/{path.lstrip('/')}"


def sn_get(config: Any, auth_manager: Any, path: str, params: Dict[str, Any]) -> SnResult:
    """
    GET a ServiceNow API path and normalise the outcome.

    Args:
        config: ServerConfig (instance_url, timeout).
        auth_manager: object exposing get_headers().
        path: 'table/<name>' (relative to /api/now) or an absolute URL.
        params: query parameters (sysparm_*).
    """
    url = build_url(config, path)
    log_path = urlsplit(url).path
    timeout = getattr(config, "timeout", None) or settings.servicenow_timeout()

    try:
        headers = auth_manager.get_headers()
    except Exception as e:  # noqa: BLE001 - surfaced to the caller as a typed error
        return SnResult(
            ok=False,
            status_code=None,
            error_type="auth_config",
            message=f"{_ERROR_HINTS['auth_config']} {e}",
        )

    started = time.monotonic()
    try:
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=timeout,
            verify=settings.tls_verify(),
        )
    except requests.exceptions.Timeout as e:
        return _transport_failure("timeout", log_path, params, started, e)
    except requests.exceptions.ConnectionError as e:
        return _transport_failure("connection", log_path, params, started, e)
    except requests.exceptions.RequestException as e:
        return _transport_failure("request_error", log_path, params, started, e)

    elapsed_ms = int((time.monotonic() - started) * 1000)
    status = _int_or_none(getattr(response, "status_code", None))

    error_type = None
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        err_response = getattr(e, "response", None)
        status = _int_or_none(getattr(err_response, "status_code", None)) or status
        error_type = _classify_status(status) if status else "http_error"
    if error_type is None and status is not None and status >= 400:
        error_type = _classify_status(status)

    if error_type is not None:
        detail = _service_now_error_detail(response)
        message = _ERROR_HINTS[error_type]
        if detail:
            message = f"{message} ServiceNow said: {detail}"
        logger.warning("GET %s -> HTTP %s (%s) in %d ms", log_path, status, error_type, elapsed_ms)
        logger.debug("GET %s params=%s", log_path, params)
        return SnResult(
            ok=False,
            status_code=status,
            elapsed_ms=elapsed_ms,
            error_type=error_type,
            message=message,
        )

    try:
        body = response.json()
    except ValueError:
        logger.warning("GET %s -> HTTP %s with non-JSON body in %d ms", log_path, status, elapsed_ms)
        return SnResult(
            ok=False,
            status_code=status,
            elapsed_ms=elapsed_ms,
            error_type="invalid_response",
            message=_ERROR_HINTS["invalid_response"],
        )

    result = body.get("result", []) if isinstance(body, dict) else []
    if isinstance(result, dict):
        records = [result]
    elif isinstance(result, list):
        records = result
    else:
        records = []

    total_count = None
    response_headers = getattr(response, "headers", None)
    if response_headers is not None:
        try:
            total_count = _int_or_none(response_headers.get("X-Total-Count"))
        except Exception:  # noqa: BLE001 - header is optional
            total_count = None

    logger.debug(
        "GET %s params=%s -> HTTP %s in %d ms (returned=%d, X-Total-Count=%s)",
        log_path,
        params,
        status,
        elapsed_ms,
        len(records),
        total_count,
    )
    return SnResult(
        ok=True,
        status_code=status,
        records=records,
        total_count=total_count,
        elapsed_ms=elapsed_ms,
    )


def _transport_failure(
    error_type: str, log_path: str, params: Dict[str, Any], started: float, exc: Exception
) -> SnResult:
    elapsed_ms = int((time.monotonic() - started) * 1000)
    logger.warning("GET %s failed (%s) after %d ms: %s", log_path, error_type, elapsed_ms, exc)
    logger.debug("GET %s params=%s", log_path, params)
    return SnResult(
        ok=False,
        status_code=None,
        elapsed_ms=elapsed_ms,
        error_type=error_type,
        message=f"{_ERROR_HINTS[error_type]} ({type(exc).__name__}: {exc})",
    )
