"""
Per-request and per-SSE-session authentication context.

Uses a ContextVar so concurrent SSE sessions and tool invocations remain isolated
while allowing existing synchronous tool functions to read the caller's credentials
through AuthManager.get_headers().
"""

import base64
import json
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional


@dataclass(frozen=True)
class CallerAuth:
    """Resolved authentication context for the current MCP caller."""

    headers: Dict[str, str] = field(default_factory=dict, repr=False)
    auth_source: str = "unknown"
    session_id: Optional[str] = None
    user_hint: Optional[str] = None


_current_caller_auth: ContextVar[Optional[CallerAuth]] = ContextVar(
    "servicenow_mcp_caller_auth", default=None
)


def get_current_caller_auth() -> Optional[CallerAuth]:
    """Return the CallerAuth bound to the current execution context, if any."""
    return _current_caller_auth.get()


@contextmanager
def caller_auth_context(auth: Optional[CallerAuth]) -> Iterator[Optional[CallerAuth]]:
    """Bind CallerAuth for the duration of a synchronous or asynchronous block."""
    token = _current_caller_auth.set(auth)
    try:
        yield auth
    finally:
        _current_caller_auth.reset(token)


def extract_jwt_user_hint(token: str) -> Optional[str]:
    """
    Extract a human-readable user identifier from an unverified JWT payload if present.

    Used only as a lookup hint for check_access; ServiceNow itself validates the token.
    Never logs the token or payload.
    """
    if not token or token.count(".") != 2:
        return None
    parts = token.split(".")
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode((payload_b64 + padding).encode("ascii"))
        claims = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(claims, dict):
        return None
    for claim in ("preferred_username", "upn", "user_name", "username", "email", "sub"):
        val = claims.get(claim)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def parse_basic_auth_username(encoded_credentials: str) -> Optional[str]:
    """Decode base64 Basic credentials ('username:password') and return the username."""
    try:
        raw = base64.b64decode(encoded_credentials.strip().encode("ascii"), validate=True).decode(
            "utf-8"
        )
    except Exception:  # noqa: BLE001
        return None
    if ":" not in raw:
        return None
    username, _, _ = raw.partition(":")
    return username.strip() or None


def _normalize_session_key(session_id: str) -> str:
    """Normalize UUID / hex session IDs by stripping hyphens and lowercasing."""
    return session_id.strip().replace("-", "").lower()


class SseSessionAuthRegistry:
    """
    Maps active MCP SSE transport session_ids to the CallerAuth established on GET /sse.

    Some MCP clients send custom headers (such as X-ServiceNow-API-Key or Authorization)
    when opening GET /sse, or we bind the last-established SSE stream when only one client
    is connecting. Entries expire automatically after ttl_seconds or when the SSE stream closes.
    """

    def __init__(self, ttl_seconds: int = 86400, max_entries: int = 2048):
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: Dict[str, tuple[CallerAuth, float]] = {}

    def _evict_expired_locked(self, now: float) -> None:
        expired = [k for k, (_, exp) in self._entries.items() if exp <= now]
        for k in expired:
            self._entries.pop(k, None)
        while len(self._entries) >= self._max_entries:
            oldest_key = next(iter(self._entries))
            self._entries.pop(oldest_key, None)

    def bind(self, session_id: str, auth: CallerAuth) -> None:
        if not session_id:
            return
        key = _normalize_session_key(session_id)
        now = time.monotonic()
        with self._lock:
            self._evict_expired_locked(now)
            self._entries[key] = (auth, now + self._ttl_seconds)

    def get(self, session_id: str) -> Optional[CallerAuth]:
        if not session_id:
            return None
        key = _normalize_session_key(session_id)
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if not entry:
                return None
            auth, expires_at = entry
            if expires_at <= now:
                self._entries.pop(key, None)
                return None
            return auth

    def remove(self, session_id: str) -> None:
        if not session_id:
            return
        key = _normalize_session_key(session_id)
        with self._lock:
            self._entries.pop(key, None)
