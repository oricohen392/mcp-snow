# Centralized Multi-User ServiceNow MCP Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `servicenow-mcp` SSE mode into a centralized, multi-user HTTP/SSE MCP server supporting OIDC / ServiceNow OAuth 2.1 browser login (with Dynamic Client Registration, PKCE, and automatic token refresh), a self-service `/auth/login` token portal, per-user HTTP header pass-through (`Authorization: Bearer`, `X-ServiceNow-API-Key`, `X-ServiceNow-Basic`), and opt-in service-account fallback.

**Architecture:** Request-scoped authentication (`CallerAuth` stored in a `ContextVar` and bound to SSE `session_id`s) is resolved by `MultiAuthMiddleware` in `server_sse.py` and consumed by `AuthManager.get_headers()`, making all 80+ existing ServiceNow tools multi-user aware without changing tool signatures. An in-process `OAuthBroker` and `OAuthSessionStore` handle upstream OIDC / ServiceNow `/oauth_auth.do` code exchange, automatic token refresh, MCP OAuth 2.1 endpoints (`/.well-known/*`, `/oauth/register`, `/oauth/authorize`, `/oauth/token`), and the `/auth/login` portal using only the Python standard library, `requests`, and `starlette`.

**Tech Stack:** Python 3.11+, Starlette, Uvicorn, MCP SDK (`mcp==1.3.0`), Pydantic v2, Requests, Pytest.

---

## File Structure

- **Modify:** `src/servicenow_mcp/utils/settings.py` — Add runtime env helpers for OIDC/OAuth, API key header name, public URL, session TTL, and `ALLOW_SERVICE_ACCOUNT_FALLBACK`.
- **Modify:** `src/servicenow_mcp/utils/config.py` — Allow `ServerConfig.auth` and `AuthConfig.type` to be optional when running in centralized per-user-only mode.
- **Create:** `src/servicenow_mcp/auth/session_context.py` — `CallerAuth` dataclass, `ContextVar` helpers, JWT claim hint parser, and `SseSessionAuthRegistry` for `/sse` -> `/messages/?session_id=...` binding.
- **Create:** `src/servicenow_mcp/auth/session_store.py` — Thread-safe `OAuthSessionStore` for `mcp_<token>` sessions, pending OAuth states, short-lived downstream authorization codes, and dynamically registered MCP clients.
- **Create:** `src/servicenow_mcp/auth/oauth_broker.py` — Upstream OIDC discovery (`.well-known/openid-configuration`) and ServiceNow OAuth (`/oauth_auth.do` & `/oauth_token.do`) URL builder, authorization code exchange, and refresh-token grant client.
- **Modify:** `src/servicenow_mcp/auth/auth_manager.py` — Read `CallerAuth` from `session_context`, transparently refresh expiring `mcp_<token>` sessions via `OAuthBroker`, and fall back to service-account credentials only when configured/allowed.
- **Modify:** `src/servicenow_mcp/auth/__init__.py` — Export new auth classes and helpers.
- **Modify:** `src/servicenow_mcp/utils/http.py` — Update `_ERROR_HINTS["unauthorized"]` for multi-user token/API key guidance.
- **Modify:** `src/servicenow_mcp/server_sse.py` — Replace static single-account startup with `MultiAuthMiddleware`, MCP OAuth 2.1 routes (`/.well-known/*`, `/oauth/*`), and self-service `/auth/login` + `/auth/logout` routes while preserving backward compatibility when `auth_token` is passed directly in tests.
- **Modify:** `src/servicenow_mcp/tools/access_tools.py` — Enhance `_user_identity` to resolve the authenticated caller via `CallerAuth.user_hint` or `sys_id=javascript:gs.getUserID()` when no static username is configured.
- **Modify:** `k8s/configmap.yaml`, `k8s/secret.example.yaml`, `.env.example`, `README.md` — Document centralized multi-user OIDC/OAuth, API key, and client configuration.
- **Create/Modify Tests:**
  - `tests/test_multi_user_settings.py`
  - `tests/test_session_context.py`
  - `tests/test_session_store.py`
  - `tests/test_oauth_broker_and_auth_manager.py`
  - `tests/test_server_sse_multiauth.py`
  - `tests/test_check_access.py`

---

### Task 1: Runtime Settings & Config Model Updates

**Files:**
- Modify: `src/servicenow_mcp/utils/settings.py`
- Modify: `src/servicenow_mcp/utils/config.py`
- Test: `tests/test_multi_user_settings.py`

- [ ] **Step 1: Write the failing test in `tests/test_multi_user_settings.py`**

```python
"""Tests for centralized multi-user authentication settings and optional AuthConfig."""

import pytest

from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import AuthConfig, AuthType, ServerConfig


def test_default_multi_user_settings(monkeypatch):
    for key in (
        "MCP_PUBLIC_URL",
        "OIDC_ISSUER_URL",
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET",
        "OAUTH_AUTHORIZE_URL",
        "OAUTH_TOKEN_URL",
        "OAUTH_SCOPES",
        "SERVICENOW_API_KEY_HEADER",
        "ALLOW_SERVICE_ACCOUNT_FALLBACK",
        "SESSION_TTL_SECONDS",
    ):
        monkeypatch.delenv(key, raising=False)

    assert settings.mcp_public_url() is None
    assert settings.oidc_issuer_url() is None
    assert settings.oauth_client_id() is None
    assert settings.oauth_client_secret() is None
    assert settings.oauth_authorize_url() is None
    assert settings.oauth_token_url() is None
    assert settings.oauth_scopes() is None
    assert settings.servicenow_api_key_header() == "x-sn-apikey"
    assert settings.allow_service_account_fallback() is False
    assert settings.session_ttl_seconds() == 86400


def test_configured_multi_user_settings(monkeypatch):
    monkeypatch.setenv("MCP_PUBLIC_URL", "https://mcp.example.com/")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://idp.example.com/realms/corp/")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "client-123")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "secret-456")
    monkeypatch.setenv("OAUTH_AUTHORIZE_URL", "https://acme.service-now.com/oauth_auth.do")
    monkeypatch.setenv("OAUTH_TOKEN_URL", "https://acme.service-now.com/oauth_token.do")
    monkeypatch.setenv("OAUTH_SCOPES", "openid profile email")
    monkeypatch.setenv("SERVICENOW_API_KEY_HEADER", "X-Custom-SN-Key")
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "true")
    monkeypatch.setenv("SESSION_TTL_SECONDS", "3600")

    assert settings.mcp_public_url() == "https://mcp.example.com"
    assert settings.oidc_issuer_url() == "https://idp.example.com/realms/corp"
    assert settings.oauth_client_id() == "client-123"
    assert settings.oauth_client_secret() == "secret-456"
    assert settings.oauth_authorize_url() == "https://acme.service-now.com/oauth_auth.do"
    assert settings.oauth_token_url() == "https://acme.service-now.com/oauth_token.do"
    assert settings.oauth_scopes() == "openid profile email"
    assert settings.servicenow_api_key_header() == "X-Custom-SN-Key"
    assert settings.allow_service_account_fallback() is True
    assert settings.session_ttl_seconds() == 3600


def test_server_config_allows_none_auth_for_per_user_mode():
    cfg = ServerConfig(
        instance_url="https://acme.service-now.com",
        auth=AuthConfig(type=AuthType.NONE),
    )
    assert cfg.auth.type == AuthType.NONE
    assert cfg.api_url == "https://acme.service-now.com/api/now"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_multi_user_settings.py -v`
Expected: FAIL with `AttributeError: module 'servicenow_mcp.utils.settings' has no attribute 'mcp_public_url'`

- [ ] **Step 3: Implement settings and config updates in `src/servicenow_mcp/utils/settings.py` and `src/servicenow_mcp/utils/config.py`**

Update `src/servicenow_mcp/utils/settings.py` by adding the new settings functions at the bottom of the file:

```python
def mcp_public_url() -> Optional[str]:
    """MCP_PUBLIC_URL: external base URL of the centralized MCP server (without trailing slash)."""
    url = os.getenv("MCP_PUBLIC_URL", "").strip().rstrip("/")
    return url or None


def oidc_issuer_url() -> Optional[str]:
    """OIDC_ISSUER_URL: OIDC issuer base URL for .well-known/openid-configuration discovery."""
    url = os.getenv("OIDC_ISSUER_URL", "").strip().rstrip("/")
    return url or None


def oauth_client_id() -> Optional[str]:
    """OAUTH_CLIENT_ID: OAuth 2.0 / OIDC client ID."""
    val = os.getenv("OAUTH_CLIENT_ID", "").strip()
    return val or None


def oauth_client_secret() -> Optional[str]:
    """OAUTH_CLIENT_SECRET: OAuth 2.0 / OIDC client secret."""
    val = os.getenv("OAUTH_CLIENT_SECRET", "").strip()
    return val or None


def oauth_authorize_url() -> Optional[str]:
    """OAUTH_AUTHORIZE_URL: explicit override for upstream OAuth authorization URL."""
    val = os.getenv("OAUTH_AUTHORIZE_URL", "").strip()
    return val or None


def oauth_token_url() -> Optional[str]:
    """OAUTH_TOKEN_URL: explicit override for upstream OAuth token URL."""
    val = os.getenv("OAUTH_TOKEN_URL", "").strip()
    return val or None


def oauth_scopes() -> Optional[str]:
    """OAUTH_SCOPES: optional space-separated OAuth scopes."""
    val = os.getenv("OAUTH_SCOPES", "").strip()
    return val or None


def servicenow_api_key_header() -> str:
    """SERVICENOW_API_KEY_HEADER (default x-sn-apikey): outbound header sent to ServiceNow."""
    val = os.getenv("SERVICENOW_API_KEY_HEADER", "").strip()
    return val or "x-sn-apikey"


def allow_service_account_fallback() -> bool:
    """ALLOW_SERVICE_ACCOUNT_FALLBACK (default false): allow service account fallback."""
    return _env_bool("ALLOW_SERVICE_ACCOUNT_FALLBACK", False)


def session_ttl_seconds() -> int:
    """SESSION_TTL_SECONDS (default 86400): lifetime of issued mcp_ session tokens."""
    return _env_int("SESSION_TTL_SECONDS", 86400, minimum=60)
```

Update `src/servicenow_mcp/utils/config.py` to add `NONE = "none"` to `AuthType` and allow `OAuthConfig.username` / `OAuthConfig.password` to be optional:

```python
"""
Configuration module for the ServiceNow MCP server.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class AuthType(str, Enum):
    """Authentication types supported by the ServiceNow MCP server."""

    BASIC = "basic"
    OAUTH = "oauth"
    API_KEY = "api_key"
    NONE = "none"


class BasicAuthConfig(BaseModel):
    """Configuration for basic authentication."""

    username: str
    password: str


class OAuthConfig(BaseModel):
    """Configuration for OAuth authentication."""

    client_id: str
    client_secret: str
    username: Optional[str] = None
    password: Optional[str] = None
    token_url: Optional[str] = None


class ApiKeyConfig(BaseModel):
    """Configuration for API key authentication."""

    api_key: str
    header_name: str = "X-ServiceNow-API-Key"


class AuthConfig(BaseModel):
    """Authentication configuration."""

    type: AuthType = AuthType.NONE
    basic: Optional[BasicAuthConfig] = None
    oauth: Optional[OAuthConfig] = None
    api_key: Optional[ApiKeyConfig] = None


class ServerConfig(BaseModel):
    """Server configuration."""

    instance_url: str
    auth: AuthConfig = AuthConfig()
    debug: bool = False
    timeout: int = 30

    @property
    def api_url(self) -> str:
        """Get the API URL for the ServiceNow instance."""
        return f"{self.instance_url}/api/now"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_multi_user_settings.py -v`
Expected: PASS

---

### Task 2: Request-Scoped Session Context & SSE Session Auth Registry

**Files:**
- Create: `src/servicenow_mcp/auth/session_context.py`
- Test: `tests/test_session_context.py`

- [ ] **Step 1: Write the failing test in `tests/test_session_context.py`**

```python
"""Tests for request-scoped CallerAuth contextvar, JWT hint extraction, and SSE session binding."""

import asyncio
import base64
import json

from servicenow_mcp.auth.session_context import (
    CallerAuth,
    SseSessionAuthRegistry,
    caller_auth_context,
    extract_jwt_user_hint,
    get_current_caller_auth,
    parse_basic_auth_username,
)


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.signature"


def test_contextvar_isolation_across_async_tasks():
    assert get_current_caller_auth() is None

    async def worker(name: str) -> str:
        auth = CallerAuth(
            headers={"Authorization": f"Bearer token-{name}"},
            auth_source="bearer_passthrough",
            user_hint=name,
        )
        with caller_auth_context(auth):
            await asyncio.sleep(0.01)
            current = get_current_caller_auth()
            assert current is not None
            assert current.user_hint == name
            return current.headers["Authorization"]

    async def run_both():
        return await asyncio.gather(worker("alice"), worker("bob"))

    res_a, res_b = asyncio.run(run_both())
    assert res_a == "Bearer token-alice"
    assert res_b == "Bearer token-bob"
    assert get_current_caller_auth() is None


def test_extract_jwt_user_hint():
    jwt_token = _make_jwt({"preferred_username": "alice.smith", "sub": "12345"})
    assert extract_jwt_user_hint(jwt_token) == "alice.smith"

    jwt_email = _make_jwt({"email": "bob@example.com", "sub": "67890"})
    assert extract_jwt_user_hint(jwt_email) == "bob@example.com"

    assert extract_jwt_user_hint("opaque-servicenow-token") is None


def test_parse_basic_auth_username():
    encoded = base64.b64encode(b"itil_user:secret123").decode()
    assert parse_basic_auth_username(encoded) == "itil_user"
    assert parse_basic_auth_username("!!!not-base64!!!") is None


def test_sse_session_auth_registry_bind_get_and_remove():
    registry = SseSessionAuthRegistry(ttl_seconds=60)
    auth = CallerAuth(headers={"x-sn-apikey": "k1"}, auth_source="api_key")
    registry.bind("abc-123-session", auth)

    assert registry.get("abc-123-session") == auth
    assert registry.get("abc123session") == auth  # normalized UUID hex match
    registry.remove("abc-123-session")
    assert registry.get("abc-123-session") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_session_context.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'servicenow_mcp.auth.session_context'`

- [ ] **Step 3: Create `src/servicenow_mcp/auth/session_context.py`**

```python
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

    headers: Dict[str, str] = field(default_factory=dict)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_session_context.py -v`
Expected: PASS

---

### Task 3: OAuth Session Store (Sessions, Pending Logins, Auth Codes, Dynamic Clients)

**Files:**
- Create: `src/servicenow_mcp/auth/session_store.py`
- Test: `tests/test_session_store.py`

- [ ] **Step 1: Write the failing test in `tests/test_session_store.py`**

```python
"""Tests for OAuthSessionStore: sessions, PKCE verification, auth codes, and dynamic clients."""

import base64
import hashlib
import pytest

from servicenow_mcp.auth.session_store import (
    OAuthSessionStore,
    validate_client_redirect_uri,
    verify_pkce_challenge,
)


def _pkce_pair(verifier: str = "my-test-code-verifier-string-1234567890"):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def test_session_lifecycle_and_refresh():
    store = OAuthSessionStore(session_ttl_seconds=3600)
    session = store.create_session(
        access_token="sn-access-1",
        refresh_token="sn-refresh-1",
        expires_in=1800,
        user_hint="alice",
    )
    assert session.mcp_token.startswith("mcp_")
    fetched = store.get_session(session.mcp_token)
    assert fetched is not None
    assert fetched.access_token == "sn-access-1"
    assert fetched.user_hint == "alice"

    updated = store.update_session_tokens(
        session.mcp_token,
        access_token="sn-access-2",
        refresh_token="sn-refresh-2",
        expires_in=1800,
    )
    assert updated is not None
    assert updated.access_token == "sn-access-2"
    assert updated.refresh_token == "sn-refresh-2"

    assert store.revoke_session(session.mcp_token) is True
    assert store.get_session(session.mcp_token) is None


def test_refresh_token_lookup():
    store = OAuthSessionStore(session_ttl_seconds=3600)
    session = store.create_session(
        access_token="sn-access-1",
        refresh_token="sn-refresh-1",
        expires_in=1800,
    )
    assert session.downstream_refresh_token.startswith("mcpr_")
    found = store.get_session_by_downstream_refresh_token(session.downstream_refresh_token)
    assert found is not None
    assert found.mcp_token == session.mcp_token


def test_pending_auth_and_single_use_auth_code_with_pkce():
    store = OAuthSessionStore()
    verifier, challenge = _pkce_pair()

    pending = store.create_pending_auth(
        flow_type="mcp_oauth",
        client_id="client-1",
        redirect_uri="http://127.0.0.1:54321/callback",
        downstream_state="ide-state-xyz",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    assert pending.upstream_state
    assert pending.upstream_code_verifier
    assert pending.upstream_code_challenge

    # Consume pending auth state once
    popped = store.pop_pending_auth(pending.upstream_state)
    assert popped is not None
    assert popped.downstream_state == "ide-state-xyz"
    assert store.pop_pending_auth(pending.upstream_state) is None

    # Create session and issue downstream auth code
    session = store.create_session(access_token="sn-tok", refresh_token="sn-ref", expires_in=900)
    code_obj = store.issue_auth_code(
        mcp_token=session.mcp_token,
        client_id="client-1",
        redirect_uri="http://127.0.0.1:54321/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    # Single-use consumption
    consumed = store.consume_auth_code(code_obj.code)
    assert consumed is not None
    assert verify_pkce_challenge(verifier, consumed.code_challenge, consumed.code_challenge_method)
    assert not verify_pkce_challenge("wrong-verifier", consumed.code_challenge, "S256")
    assert store.consume_auth_code(code_obj.code) is None


def test_dynamic_client_registration_and_redirect_uri_validation():
    store = OAuthSessionStore()
    client = store.register_client(
        client_name="Cursor MCP",
        redirect_uris=["http://127.0.0.1:33445/callback", "cursor://anysphere.cursor-mcp/oauth"],
    )
    assert client.client_id.startswith("mcp_client_")
    assert store.get_client(client.client_id) is not None

    with pytest.raises(ValueError, match="Invalid redirect_uri"):
        validate_client_redirect_uri("https://evil.example.com/callback")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_session_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'servicenow_mcp.auth.session_store'`

- [ ] **Step 3: Create `src/servicenow_mcp/auth/session_store.py`**

```python
"""
In-memory store for centralized OAuth/OIDC sessions, pending browser logins,
single-use authorization codes, and dynamically registered MCP OAuth 2.1 clients.
"""

import base64
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

ALLOWED_CUSTOM_SCHEMES = {"cursor", "vscode", "vscode-insiders", "claude", "windsurf"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a (code_verifier, code_challenge_S256) pair."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def verify_pkce_challenge(
    code_verifier: str, code_challenge: Optional[str], method: str = "S256"
) -> bool:
    """Verify RFC 7636 PKCE code_verifier against code_challenge."""
    if not code_challenge or not code_verifier:
        return False
    normalized_method = (method or "S256").upper()
    if normalized_method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return hmac.compare_digest(computed, code_challenge)
    if normalized_method == "PLAIN":
        return hmac.compare_digest(code_verifier, code_challenge)
    return False


def validate_client_redirect_uri(uri: str) -> str:
    """
    Validate a redirect URI for Dynamic Client Registration (RFC 7591) and /oauth/authorize.

    Allows loopback HTTP/HTTPS URIs (127.0.0.1, localhost, ::1) and approved IDE custom schemes.
    Raises ValueError on untrusted external redirect URIs to prevent open-redirect attacks.
    """
    if not uri or not isinstance(uri, str):
        raise ValueError("Invalid redirect_uri: must be a non-empty string")
    parsed = urlsplit(uri.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme in ALLOWED_CUSTOM_SCHEMES:
        return uri.strip()
    if scheme in ("http", "https") and (parsed.hostname or "").lower() in LOOPBACK_HOSTS:
        return uri.strip()
    raise ValueError(
        f"Invalid redirect_uri '{uri}': only loopback addresses (127.0.0.1, localhost, ::1) "
        f"or IDE schemes ({sorted(ALLOWED_CUSTOM_SCHEMES)}) are permitted."
    )


@dataclass
class OAuthSession:
    """Represents an authenticated user's session mapped to an mcp_ bearer token."""

    mcp_token: str
    downstream_refresh_token: str
    access_token: str
    refresh_token: Optional[str]
    token_type: str
    expires_at: float
    session_expires_at: float
    user_hint: Optional[str] = None
    refresh_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def is_access_token_expiring(self, buffer_seconds: int = 60) -> bool:
        return time.time() + buffer_seconds >= self.expires_at


@dataclass
class PendingAuthRequest:
    """State for an in-flight browser login started via /oauth/authorize or /auth/login."""

    upstream_state: str
    upstream_code_verifier: str
    upstream_code_challenge: str
    flow_type: str  # "mcp_oauth" or "portal"
    created_at: float
    expires_at: float
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    downstream_state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: str = "S256"


@dataclass
class IssuedAuthCode:
    """Short-lived single-use authorization code issued to an MCP OAuth client."""

    code: str
    mcp_token: str
    client_id: Optional[str]
    redirect_uri: Optional[str]
    code_challenge: Optional[str]
    code_challenge_method: str
    expires_at: float


@dataclass
class RegisteredClient:
    """Dynamically registered MCP OAuth 2.1 client."""

    client_id: str
    client_name: str
    redirect_uris: List[str]
    created_at: float


class OAuthSessionStore:
    """Thread-safe in-memory storage for OAuth sessions, pending states, codes, and clients."""

    def __init__(
        self,
        session_ttl_seconds: int = 86400,
        pending_ttl_seconds: int = 600,
        auth_code_ttl_seconds: int = 60,
        max_sessions: int = 2048,
        max_pending: int = 1000,
    ):
        self._session_ttl = session_ttl_seconds
        self._pending_ttl = pending_ttl_seconds
        self._code_ttl = auth_code_ttl_seconds
        self._max_sessions = max_sessions
        self._max_pending = max_pending
        self._lock = threading.Lock()
        self._sessions: Dict[str, OAuthSession] = {}
        self._refresh_index: Dict[str, str] = {}
        self._pending: Dict[str, PendingAuthRequest] = {}
        self._codes: Dict[str, IssuedAuthCode] = {}
        self._clients: Dict[str, RegisteredClient] = {}

    def _cleanup_locked(self, now: float) -> None:
        expired_sessions = [
            tok for tok, sess in self._sessions.items() if sess.session_expires_at <= now
        ]
        for tok in expired_sessions:
            sess = self._sessions.pop(tok, None)
            if sess:
                self._refresh_index.pop(sess.downstream_refresh_token, None)
        while len(self._sessions) >= self._max_sessions:
            oldest_tok = next(iter(self._sessions))
            sess = self._sessions.pop(oldest_tok, None)
            if sess:
                self._refresh_index.pop(sess.downstream_refresh_token, None)

        expired_pending = [st for st, p in self._pending.items() if p.expires_at <= now]
        for st in expired_pending:
            self._pending.pop(st, None)
        while len(self._pending) >= self._max_pending:
            oldest_st = next(iter(self._pending))
            self._pending.pop(oldest_st, None)

        expired_codes = [c for c, obj in self._codes.items() if obj.expires_at <= now]
        for c in expired_codes:
            self._codes.pop(c, None)

    def create_session(
        self,
        *,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_type: str = "Bearer",
        expires_in: int = 1800,
        user_hint: Optional[str] = None,
        session_ttl_seconds: Optional[int] = None,
    ) -> OAuthSession:
        now = time.time()
        ttl = session_ttl_seconds or self._session_ttl
        mcp_token = f"mcp_{secrets.token_urlsafe(32)}"
        downstream_refresh = f"mcpr_{secrets.token_urlsafe(32)}"
        session = OAuthSession(
            mcp_token=mcp_token,
            downstream_refresh_token=downstream_refresh,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type or "Bearer",
            expires_at=now + max(int(expires_in or 1800), 30),
            session_expires_at=now + ttl,
            user_hint=user_hint,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._sessions[mcp_token] = session
            self._refresh_index[downstream_refresh] = mcp_token
        return session

    def get_session(self, mcp_token: str) -> Optional[OAuthSession]:
        if not mcp_token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(mcp_token)
            if not session:
                return None
            if session.session_expires_at <= now:
                self._sessions.pop(mcp_token, None)
                self._refresh_index.pop(session.downstream_refresh_token, None)
                return None
            return session

    def get_session_by_downstream_refresh_token(
        self, downstream_refresh_token: str
    ) -> Optional[OAuthSession]:
        if not downstream_refresh_token:
            return None
        with self._lock:
            mcp_token = self._refresh_index.get(downstream_refresh_token)
        if not mcp_token:
            return None
        return self.get_session(mcp_token)

    def update_session_tokens(
        self,
        mcp_token: str,
        *,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_type: Optional[str] = None,
        expires_in: int = 1800,
        user_hint: Optional[str] = None,
    ) -> Optional[OAuthSession]:
        now = time.time()
        with self._lock:
            session = self._sessions.get(mcp_token)
            if not session or session.session_expires_at <= now:
                return None
            session.access_token = access_token
            if refresh_token:
                session.refresh_token = refresh_token
            if token_type:
                session.token_type = token_type
            session.expires_at = now + max(int(expires_in or 1800), 30)
            session.session_expires_at = max(session.session_expires_at, now + self._session_ttl)
            if user_hint:
                session.user_hint = user_hint
            return session

    def revoke_session(self, mcp_token: str) -> bool:
        if not mcp_token:
            return False
        with self._lock:
            session = self._sessions.pop(mcp_token, None)
            if session:
                self._refresh_index.pop(session.downstream_refresh_token, None)
                return True
            return False

    def create_pending_auth(
        self,
        *,
        flow_type: str,
        client_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        downstream_state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
    ) -> PendingAuthRequest:
        now = time.time()
        upstream_state = secrets.token_urlsafe(24)
        verifier, challenge = generate_pkce_pair()
        pending = PendingAuthRequest(
            upstream_state=upstream_state,
            upstream_code_verifier=verifier,
            upstream_code_challenge=challenge,
            flow_type=flow_type,
            created_at=now,
            expires_at=now + self._pending_ttl,
            client_id=client_id,
            redirect_uri=redirect_uri,
            downstream_state=downstream_state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or "S256",
        )
        with self._lock:
            self._cleanup_locked(now)
            self._pending[upstream_state] = pending
        return pending

    def pop_pending_auth(self, upstream_state: str) -> Optional[PendingAuthRequest]:
        if not upstream_state:
            return None
        now = time.time()
        with self._lock:
            pending = self._pending.pop(upstream_state, None)
            if not pending or pending.expires_at <= now:
                return None
            return pending

    def issue_auth_code(
        self,
        *,
        mcp_token: str,
        client_id: Optional[str],
        redirect_uri: Optional[str],
        code_challenge: Optional[str],
        code_challenge_method: str = "S256",
    ) -> IssuedAuthCode:
        now = time.time()
        code = f"mcpc_{secrets.token_urlsafe(24)}"
        issued = IssuedAuthCode(
            code=code,
            mcp_token=mcp_token,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or "S256",
            expires_at=now + self._code_ttl,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._codes[code] = issued
        return issued

    def consume_auth_code(self, code: str) -> Optional[IssuedAuthCode]:
        if not code:
            return None
        now = time.time()
        with self._lock:
            issued = self._codes.pop(code, None)
            if not issued or issued.expires_at <= now:
                return None
            return issued

    def register_client(self, *, client_name: str, redirect_uris: List[str]) -> RegisteredClient:
        if not redirect_uris or not isinstance(redirect_uris, list):
            raise ValueError("redirect_uris must be a non-empty list")
        validated_uris = [validate_client_redirect_uri(u) for u in redirect_uris]
        client_id = f"mcp_client_{secrets.token_urlsafe(16)}"
        client = RegisteredClient(
            client_id=client_id,
            client_name=(client_name or "MCP Client").strip(),
            redirect_uris=validated_uris,
            created_at=time.time(),
        )
        with self._lock:
            self._clients[client_id] = client
        return client

    def get_client(self, client_id: str) -> Optional[RegisteredClient]:
        if not client_id:
            return None
        with self._lock:
            return self._clients.get(client_id)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_session_store.py -v`
Expected: PASS

---

### Task 4: OAuth 2.0 / OIDC Upstream Broker & `AuthManager` Context Integration

**Files:**
- Create: `src/servicenow_mcp/auth/oauth_broker.py`
- Modify: `src/servicenow_mcp/auth/auth_manager.py`
- Modify: `src/servicenow_mcp/utils/http.py`
- Test: `tests/test_oauth_broker_and_auth_manager.py`

- [ ] **Step 1: Write the failing test in `tests/test_oauth_broker_and_auth_manager.py`**

```python
"""Tests for OAuthBroker (OIDC discovery & ServiceNow OAuth) and AuthManager ContextVar resolution."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.auth.oauth_broker import OAuthBroker
from servicenow_mcp.auth.session_context import CallerAuth, caller_auth_context
from servicenow_mcp.auth.session_store import OAuthSessionStore
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig


def _jwt(claims: dict) -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{h}.{p}.sig"


def test_broker_servicenow_native_endpoints(monkeypatch):
    monkeypatch.delenv("OIDC_ISSUER_URL", raising=False)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-client-id")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-client-secret")

    broker = OAuthBroker(instance_url="https://acme.service-now.com")
    assert broker.is_configured() is True
    endpoints = broker.get_endpoints()
    assert endpoints.authorization_endpoint == "https://acme.service-now.com/oauth_auth.do"
    assert endpoints.token_endpoint == "https://acme.service-now.com/oauth_token.do"

    auth_url = broker.build_authorize_url(
        redirect_uri="https://mcp.example.com/oauth/callback",
        state="state-1",
        code_challenge="challenge-1",
    )
    assert "https://acme.service-now.com/oauth_auth.do?" in auth_url
    assert "client_id=sn-client-id" in auth_url
    assert "state=state-1" in auth_url


def test_broker_oidc_discovery_and_code_exchange(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://idp.example.com/oauth2/default")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "oidc-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "oidc-secret")

    broker = OAuthBroker(instance_url="https://acme.service-now.com")

    discovery_resp = MagicMock()
    discovery_resp.status_code = 200
    discovery_resp.json.return_value = {
        "authorization_endpoint": "https://idp.example.com/oauth2/default/v1/authorize",
        "token_endpoint": "https://idp.example.com/oauth2/default/v1/token",
    }

    id_token = _jwt({"preferred_username": "carol@example.com"})
    token_resp = MagicMock()
    token_resp.status_code = 200
    token_resp.json.return_value = {
        "access_token": "oidc-access-xyz",
        "refresh_token": "oidc-refresh-xyz",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    with patch("requests.get", return_value=discovery_resp) as mock_get, patch(
        "requests.post", return_value=token_resp
    ) as mock_post:
        token_result = broker.exchange_code_for_tokens(
            code="auth-code-123",
            redirect_uri="https://mcp.example.com/oauth/callback",
            code_verifier="verifier-123",
        )
        assert mock_get.call_count == 1
        assert mock_post.call_count == 1
        assert token_result.access_token == "oidc-access-xyz"
        assert token_result.refresh_token == "oidc-refresh-xyz"
        assert token_result.user_hint == "carol@example.com"


def test_auth_manager_prefers_caller_auth_and_auto_refreshes(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-secret")

    store = OAuthSessionStore()
    broker = OAuthBroker(instance_url="https://acme.service-now.com")
    # Service account configured as Basic, but CallerAuth should override it
    svc_auth = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(username="svc", password="p"))
    manager = AuthManager(
        svc_auth,
        "https://acme.service-now.com",
        session_store=store,
        oauth_broker=broker,
    )

    # 1. API Key in CallerAuth overrides service account
    with caller_auth_context(
        CallerAuth(headers={"x-sn-apikey": "user-key-99"}, auth_source="api_key")
    ):
        headers = manager.get_headers()
        assert headers["x-sn-apikey"] == "user-key-99"
        assert "Authorization" not in headers

    # 2. Expiring OAuthSession triggers transparent refresh
    session = store.create_session(
        access_token="expired-access",
        refresh_token="valid-refresh",
        expires_in=30,  # within 60s buffer -> triggers refresh
        user_hint="dave",
    )
    refresh_resp = MagicMock()
    refresh_resp.status_code = 200
    refresh_resp.json.return_value = {
        "access_token": "fresh-access-token",
        "refresh_token": "fresh-refresh-token",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    with patch("requests.post", return_value=refresh_resp) as mock_post:
        with caller_auth_context(
            CallerAuth(
                headers={"Authorization": "Bearer expired-access"},
                auth_source="oauth_session",
                session_id=session.mcp_token,
                user_hint="dave",
            )
        ):
            headers = manager.get_headers()
            assert mock_post.call_count == 1
            assert headers["Authorization"] == "Bearer fresh-access-token"
            assert store.get_session(session.mcp_token).access_token == "fresh-access-token"


def test_auth_manager_raises_when_no_caller_and_no_service_account():
    manager = AuthManager(AuthConfig(type=AuthType.NONE), "https://acme.service-now.com")
    with pytest.raises(ValueError, match="Per-user authentication is required"):
        manager.get_headers()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_oauth_broker_and_auth_manager.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'servicenow_mcp.auth.oauth_broker'`

- [ ] **Step 3: Create `src/servicenow_mcp/auth/oauth_broker.py` and update `src/servicenow_mcp/auth/auth_manager.py` & `src/servicenow_mcp/utils/http.py`**

Create `src/servicenow_mcp/auth/oauth_broker.py`:

```python
"""
Upstream OAuth 2.0 / OIDC broker for ServiceNow and corporate Identity Providers.

Supports two upstream modes:
1. OIDC Discovery (OIDC_ISSUER_URL): fetches .well-known/openid-configuration.
2. ServiceNow OAuth Registry (OAUTH_CLIENT_ID + OAUTH_CLIENT_SECRET): uses
   <instance_url>/oauth_auth.do and <instance_url>/oauth_token.do (or explicit overrides).
"""

import base64
import logging
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import requests

from servicenow_mcp.auth.session_context import extract_jwt_user_hint
from servicenow_mcp.utils import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OAuthEndpoints:
    """Resolved upstream OAuth 2.0 / OIDC endpoints."""

    authorization_endpoint: str
    token_endpoint: str
    issuer: Optional[str] = None


@dataclass(frozen=True)
class UpstreamTokenResponse:
    """Normalized token response from upstream OIDC IdP or ServiceNow."""

    access_token: str
    refresh_token: Optional[str]
    token_type: str
    expires_in: int
    user_hint: Optional[str] = None


class OAuthBrokerError(RuntimeError):
    """Raised when upstream OAuth discovery, code exchange, or refresh fails."""


class OAuthBroker:
    """Handles upstream OIDC discovery, authorization URL generation, and token exchange."""

    def __init__(self, instance_url: str, discovery_ttl_seconds: int = 3600):
        self.instance_url = (instance_url or "").rstrip("/")
        self._discovery_ttl = discovery_ttl_seconds
        self._lock = threading.Lock()
        self._cached_endpoints: Optional[tuple[str, OAuthEndpoints, float]] = None

    def is_configured(self) -> bool:
        """Return True if OAuth/OIDC browser login is configured via environment variables."""
        return bool(settings.oauth_client_id())

    def get_endpoints(self) -> OAuthEndpoints:
        """Resolve upstream authorization and token endpoints."""
        explicit_auth = settings.oauth_authorize_url()
        explicit_token = settings.oauth_token_url()
        issuer = settings.oidc_issuer_url()

        if explicit_auth and explicit_token:
            return OAuthEndpoints(
                authorization_endpoint=explicit_auth,
                token_endpoint=explicit_token,
                issuer=issuer,
            )

        if issuer:
            now = time.monotonic()
            with self._lock:
                if (
                    self._cached_endpoints
                    and self._cached_endpoints[0] == issuer
                    and self._cached_endpoints[2] > now
                ):
                    return self._cached_endpoints[1]

            discovery_url = f"{issuer}/.well-known/openid-configuration"
            try:
                response = requests.get(
                    discovery_url,
                    timeout=settings.servicenow_timeout(),
                    verify=settings.tls_verify(),
                )
                response.raise_for_status()
                doc = response.json()
            except Exception as e:  # noqa: BLE001
                raise OAuthBrokerError(
                    f"Failed to fetch OIDC discovery document from {discovery_url}: {e}"
                ) from e

            auth_ep = explicit_auth or doc.get("authorization_endpoint")
            token_ep = explicit_token or doc.get("token_endpoint")
            if not auth_ep or not token_ep:
                raise OAuthBrokerError(
                    f"OIDC discovery document at {discovery_url} is missing authorization_endpoint or token_endpoint"
                )
            endpoints = OAuthEndpoints(
                authorization_endpoint=str(auth_ep),
                token_endpoint=str(token_ep),
                issuer=issuer,
            )
            with self._lock:
                self._cached_endpoints = (issuer, endpoints, now + self._discovery_ttl)
            return endpoints

        if not self.instance_url:
            raise OAuthBrokerError("SERVICENOW_INSTANCE_URL is required to build OAuth endpoints.")

        return OAuthEndpoints(
            authorization_endpoint=explicit_auth or f"{self.instance_url}/oauth_auth.do",
            token_endpoint=explicit_token or f"{self.instance_url}/oauth_token.do",
        )

    def default_scopes(self) -> str:
        """Return configured OAUTH_SCOPES or sensible defaults for OIDC vs ServiceNow."""
        configured = settings.oauth_scopes()
        if configured is not None:
            return configured
        if settings.oidc_issuer_url():
            return "openid profile email"
        return ""

    def build_authorize_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
    ) -> str:
        """Build the upstream browser redirect URL for user login."""
        client_id = settings.oauth_client_id()
        if not client_id:
            raise OAuthBrokerError("OAUTH_CLIENT_ID is not configured.")
        endpoints = self.get_endpoints()
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        scopes = self.default_scopes()
        if scopes:
            params["scope"] = scopes
        if code_challenge and settings.oidc_issuer_url():
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method
        return f"{endpoints.authorization_endpoint}?{urlencode(params)}"

    def exchange_code_for_tokens(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> UpstreamTokenResponse:
        """Exchange an upstream authorization code for access and refresh tokens."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier and settings.oidc_issuer_url():
            data["code_verifier"] = code_verifier
        return self._post_token_request(data)

    def refresh_access_token(self, refresh_token: str) -> UpstreamTokenResponse:
        """Exchange a refresh_token for a new access_token."""
        if not refresh_token:
            raise OAuthBrokerError("No refresh_token available to refresh session.")
        return self._post_token_request(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
        )

    def _post_token_request(self, form_data: dict) -> UpstreamTokenResponse:
        client_id = settings.oauth_client_id()
        client_secret = settings.oauth_client_secret()
        if not client_id:
            raise OAuthBrokerError("OAUTH_CLIENT_ID is not configured.")
        endpoints = self.get_endpoints()

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = dict(form_data)
        payload["client_id"] = client_id
        if client_secret:
            auth_str = f"{client_id}:{client_secret}"
            encoded = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
            payload["client_secret"] = client_secret

        try:
            response = requests.post(
                endpoints.token_endpoint,
                headers=headers,
                data=payload,
                timeout=settings.servicenow_timeout(),
                verify=settings.tls_verify(),
            )
        except requests.RequestException as e:
            raise OAuthBrokerError(f"Upstream token request failed: {e}") from e

        logger.debug("Upstream token endpoint status: %s", response.status_code)
        if response.status_code != 200:
            raise OAuthBrokerError(
                f"Upstream token endpoint returned HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as e:
            raise OAuthBrokerError("Upstream token endpoint returned non-JSON response") from e

        access_token = body.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise OAuthBrokerError("Upstream token response did not contain an access_token")

        refresh_token = body.get("refresh_token")
        token_type = body.get("token_type") or "Bearer"
        raw_expires = body.get("expires_in", 1800)
        try:
            expires_in = int(raw_expires)
        except (TypeError, ValueError):
            expires_in = 1800

        id_token = body.get("id_token")
        user_hint = (
            extract_jwt_user_hint(id_token)
            if isinstance(id_token, str)
            else None
        ) or extract_jwt_user_hint(access_token)

        return UpstreamTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token if isinstance(refresh_token, str) else None,
            token_type=str(token_type),
            expires_in=expires_in,
            user_hint=user_hint,
        )
```

Update `src/servicenow_mcp/auth/auth_manager.py`:

```python
"""
Authentication manager for the ServiceNow MCP server.
"""

import base64
import logging
from typing import Dict, Optional

import requests

from servicenow_mcp.auth.oauth_broker import OAuthBroker, OAuthBrokerError
from servicenow_mcp.auth.session_context import get_current_caller_auth
from servicenow_mcp.auth.session_store import OAuthSessionStore
from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import AuthConfig, AuthType

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Authentication manager for ServiceNow API.

    Checks per-request CallerAuth (from ContextVar) first so centralized SSE sessions
    authenticate as the calling user, and falls back to configured service-account
    credentials only when present.
    """

    def __init__(
        self,
        config: Optional[AuthConfig],
        instance_url: Optional[str] = None,
        *,
        session_store: Optional[OAuthSessionStore] = None,
        oauth_broker: Optional[OAuthBroker] = None,
    ):
        self.config = config or AuthConfig(type=AuthType.NONE)
        self.instance_url = instance_url
        self.session_store = session_store
        self.oauth_broker = oauth_broker
        self.token: Optional[str] = None
        self.token_type: Optional[str] = None

    def has_service_account(self) -> bool:
        """Return True if a server-level ServiceNow service account is configured."""
        if not self.config or self.config.type == AuthType.NONE:
            return False
        if self.config.type == AuthType.BASIC:
            return bool(
                self.config.basic
                and self.config.basic.username
                and self.config.basic.password
            )
        if self.config.type == AuthType.OAUTH:
            return bool(
                self.config.oauth
                and self.config.oauth.client_id
                and self.config.oauth.client_secret
            )
        if self.config.type == AuthType.API_KEY:
            return bool(self.config.api_key and self.config.api_key.api_key)
        return False

    def get_headers(self) -> Dict[str, str]:
        """
        Get the authentication headers for API requests.

        Resolves per-request CallerAuth from ContextVar first, refreshing expiring
        OAuth sessions automatically when backed by OAuthSessionStore.
        """
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        caller_auth = get_current_caller_auth()
        if caller_auth is not None and caller_auth.auth_source != "service_account":
            if caller_auth.session_id and self.session_store is not None:
                session = self.session_store.get_session(caller_auth.session_id)
                if session is None:
                    raise ValueError(
                        "MCP session has expired or been revoked. Please re-authenticate at /auth/login."
                    )
                if (
                    session.is_access_token_expiring()
                    and session.refresh_token
                    and self.oauth_broker is not None
                ):
                    with session.refresh_lock:
                        if session.is_access_token_expiring() and session.refresh_token:
                            try:
                                refreshed = self.oauth_broker.refresh_access_token(
                                    session.refresh_token
                                )
                                self.session_store.update_session_tokens(
                                    session.mcp_token,
                                    access_token=refreshed.access_token,
                                    refresh_token=refreshed.refresh_token,
                                    token_type=refreshed.token_type,
                                    expires_in=refreshed.expires_in,
                                    user_hint=refreshed.user_hint,
                                )
                            except OAuthBrokerError as e:
                                logger.warning("Failed to auto-refresh OAuth session token: %s", e)
                headers["Authorization"] = f"{session.token_type} {session.access_token}"
                return headers

            headers.update(caller_auth.headers)
            return headers

        if self.config.type == AuthType.BASIC:
            if not self.config.basic:
                raise ValueError("Basic auth configuration is required")

            auth_str = f"{self.config.basic.username}:{self.config.basic.password}"
            encoded = base64.b64encode(auth_str.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        elif self.config.type == AuthType.OAUTH:
            if not self.token:
                self._get_oauth_token()

            headers["Authorization"] = f"{self.token_type} {self.token}"

        elif self.config.type == AuthType.API_KEY:
            if not self.config.api_key:
                raise ValueError("API key configuration is required")

            headers[self.config.api_key.header_name] = self.config.api_key.api_key

        else:
            raise ValueError(
                "Per-user authentication is required; no user credentials found in request context "
                "and no service account fallback is active."
            )

        return headers

    def _get_oauth_token(self):
        """
        Get an OAuth token from ServiceNow.

        Raises:
            ValueError: If OAuth configuration is missing or token request fails.
        """
        if not self.config.oauth:
            raise ValueError("OAuth configuration is required")
        oauth_config = self.config.oauth

        token_url = oauth_config.token_url
        if not token_url:
            if not self.instance_url:
                raise ValueError("Instance URL is required for OAuth authentication")
            instance_parts = self.instance_url.split(".")
            if len(instance_parts) < 2:
                raise ValueError(f"Invalid instance URL: {self.instance_url}")
            instance_name = instance_parts[0].split("//")[-1]
            token_url = f"https://{instance_name}.service-now.com/oauth_token.do"

        auth_str = f"{oauth_config.client_id}:{oauth_config.client_secret}"
        auth_header = base64.b64encode(auth_str.encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data_client_credentials = {"grant_type": "client_credentials"}

        logger.debug("Attempting client_credentials grant...")
        response = requests.post(
            token_url,
            headers=headers,
            data=data_client_credentials,
            timeout=settings.servicenow_timeout(),
            verify=settings.tls_verify(),
        )

        logger.debug(f"client_credentials response status: {response.status_code}")

        if response.status_code == 200:
            token_data = response.json()
            self.token = token_data.get("access_token")
            self.token_type = token_data.get("token_type", "Bearer")
            return

        if oauth_config.username and oauth_config.password:
            data_password = {
                "grant_type": "password",
                "username": oauth_config.username,
                "password": oauth_config.password,
            }

            logger.debug("Attempting password grant...")
            response = requests.post(
                token_url,
                headers=headers,
                data=data_password,
                timeout=settings.servicenow_timeout(),
                verify=settings.tls_verify(),
            )

            logger.debug(f"password grant response status: {response.status_code}")

            if response.status_code == 200:
                token_data = response.json()
                self.token = token_data.get("access_token")
                self.token_type = token_data.get("token_type", "Bearer")
                return

        raise ValueError(
            "Failed to get OAuth token using both client_credentials and password grants."
        )

    def refresh_token(self):
        """Refresh the OAuth token if using OAuth authentication."""
        if self.config.type == AuthType.OAUTH:
            self._get_oauth_token()
```

Update `_ERROR_HINTS["unauthorized"]` in `src/servicenow_mcp/utils/http.py`:

```python
_ERROR_HINTS = {
    "unauthorized": "ServiceNow rejected the credentials (HTTP 401). "
    "Verify your OAuth/OIDC token, API key, or service account credentials, or re-authenticate via /auth/login.",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_oauth_broker_and_auth_manager.py -v`
Expected: PASS

---

### Task 5: Centralized SSE Multi-Auth Middleware, MCP OAuth 2.1 Endpoints & Self-Service Portal

**Files:**
- Modify: `src/servicenow_mcp/auth/__init__.py`
- Modify: `src/servicenow_mcp/server_sse.py`
- Test: `tests/test_server_sse_multiauth.py`

- [ ] **Step 1: Write the failing test in `tests/test_server_sse_multiauth.py`**

```python
"""Tests for centralized multi-user SSE authentication, OAuth 2.1 broker endpoints, and /auth/login."""

import base64
import hashlib
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from servicenow_mcp.server_sse import create_servicenow_mcp, create_starlette_app


def _pkce_pair(verifier: str = "verifier-for-mcp-ide-client-1234567890"):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def test_create_servicenow_mcp_without_service_account(monkeypatch):
    monkeypatch.delenv("SERVICENOW_USERNAME", raising=False)
    monkeypatch.delenv("SERVICENOW_PASSWORD", raising=False)
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "false")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    client = TestClient(
        create_starlette_app(
            server.mcp_server,
            auth_manager=server.auth_manager,
            session_store=server.session_store,
            oauth_broker=server.oauth_broker,
            require_auth=True,
        )
    )

    # Unauthenticated /sse is rejected with 401 + OAuth discovery metadata
    res = client.get("/sse")
    assert res.status_code == 401
    assert "Bearer" in res.headers["www-authenticate"]
    assert "/.well-known/oauth-protected-resource" in res.headers["www-authenticate"]

    # Discovery endpoints are open
    pr = client.get("/.well-known/oauth-protected-resource")
    assert pr.status_code == 200
    assert "authorization_servers" in pr.json()

    as_meta = client.get("/.well-known/oauth-authorization-server")
    assert as_meta.status_code == 200
    assert as_meta.json()["code_challenge_methods_supported"] == ["S256"]


def test_full_mcp_oauth21_dcr_pkce_and_refresh_flow(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-oauth-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-oauth-secret")
    monkeypatch.setenv("ALLOW_SERVICE_ACCOUNT_FALLBACK", "false")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    # 1. Dynamic Client Registration
    reg = client.post(
        "/oauth/register",
        json={
            "client_name": "Claude Code",
            "redirect_uris": ["http://127.0.0.1:45678/callback"],
        },
    )
    assert reg.status_code == 201
    client_id = reg.json()["client_id"]

    # Reject non-loopback open redirect in /oauth/register
    bad_reg = client.post(
        "/oauth/register",
        json={"client_name": "Evil", "redirect_uris": ["https://evil.example.com/cb"]},
    )
    assert bad_reg.status_code == 400

    # 2. Authorize redirect to ServiceNow
    verifier, challenge = _pkce_pair()
    auth_res = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:45678/callback",
            "state": "ide-state-999",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert auth_res.status_code == 302
    upstream_loc = auth_res.headers["location"]
    assert upstream_loc.startswith("https://acme.service-now.com/oauth_auth.do?")
    upstream_state = parse_qs(urlsplit(upstream_loc).query)["state"][0]

    # 3. Callback from ServiceNow exchanges upstream code and redirects back to IDE
    upstream_token_resp = MagicMock()
    upstream_token_resp.status_code = 200
    upstream_token_resp.json.return_value = {
        "access_token": "sn-user-access-token-1",
        "refresh_token": "sn-user-refresh-token-1",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    with patch("requests.post", return_value=upstream_token_resp):
        cb_res = client.get(
            "/oauth/callback",
            params={"code": "sn-upstream-code", "state": upstream_state},
            follow_redirects=False,
        )
    assert cb_res.status_code == 302
    ide_loc = cb_res.headers["location"]
    assert ide_loc.startswith("http://127.0.0.1:45678/callback?")
    ide_qs = parse_qs(urlsplit(ide_loc).query)
    assert ide_qs["state"] == ["ide-state-999"]
    downstream_code = ide_qs["code"][0]

    # 4. IDE exchanges downstream_code + PKCE verifier at POST /oauth/token
    tok_res = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": downstream_code,
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:45678/callback",
            "code_verifier": verifier,
        },
    )
    assert tok_res.status_code == 200
    tok_body = tok_res.json()
    mcp_token = tok_body["access_token"]
    mcp_refresh = tok_body["refresh_token"]
    assert mcp_token.startswith("mcp_")
    assert mcp_refresh.startswith("mcpr_")

    # 5. Authenticated request with mcp_token passes middleware
    msg_res = client.post(
        "/messages/?session_id=" + "0" * 32,
        headers={"Authorization": f"Bearer {mcp_token}"},
        json={},
    )
    assert msg_res.status_code in (400, 404)

    # 6. Logout revokes the token
    logout_res = client.post("/auth/logout", headers={"Authorization": f"Bearer {mcp_token}"})
    assert logout_res.status_code == 200
    after_logout = client.post(
        "/messages/?session_id=" + "0" * 32,
        headers={"Authorization": f"Bearer {mcp_token}"},
        json={},
    )
    assert after_logout.status_code == 401


def test_self_service_portal_login_and_header_passthrough(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "sn-oauth-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "sn-oauth-secret")

    server = create_servicenow_mcp(instance_url="https://acme.service-now.com")
    app = create_starlette_app(
        server.mcp_server,
        auth_manager=server.auth_manager,
        session_store=server.session_store,
        oauth_broker=server.oauth_broker,
        require_auth=True,
    )
    client = TestClient(app)

    login_res = client.get("/auth/login", follow_redirects=False)
    assert login_res.status_code == 302
    state = parse_qs(urlsplit(login_res.headers["location"]).query)["state"][0]

    upstream_token_resp = MagicMock()
    upstream_token_resp.status_code = 200
    upstream_token_resp.json.return_value = {
        "access_token": "sn-portal-access",
        "refresh_token": "sn-portal-refresh",
        "token_type": "Bearer",
        "expires_in": 1800,
    }
    with patch("requests.post", return_value=upstream_token_resp):
        portal_cb = client.get("/oauth/callback", params={"code": "c1", "state": state})
    assert portal_cb.status_code == 200
    assert "mcp_" in portal_cb.text
    assert "/sse" in portal_cb.text

    # Direct X-ServiceNow-API-Key pass-through also works
    api_key_res = client.post(
        "/messages/?session_id=" + "0" * 32,
        headers={"X-ServiceNow-API-Key": "direct-sn-key"},
        json={},
    )
    assert api_key_res.status_code in (400, 404)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_server_sse_multiauth.py -v`
Expected: FAIL with `TypeError: create_servicenow_mcp() missing 2 required positional arguments: 'username' and 'password'`

- [ ] **Step 3: Update `src/servicenow_mcp/auth/__init__.py` and `src/servicenow_mcp/server_sse.py`**

Update `src/servicenow_mcp/auth/__init__.py`:

```python
"""
Authentication module for the ServiceNow MCP server.
"""

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.auth.oauth_broker import OAuthBroker, OAuthBrokerError
from servicenow_mcp.auth.session_context import (
    CallerAuth,
    SseSessionAuthRegistry,
    caller_auth_context,
    get_current_caller_auth,
)
from servicenow_mcp.auth.session_store import OAuthSessionStore

__all__ = [
    "AuthManager",
    "CallerAuth",
    "OAuthBroker",
    "OAuthBrokerError",
    "OAuthSessionStore",
    "SseSessionAuthRegistry",
    "caller_auth_context",
    "get_current_caller_auth",
]
```

Update `src/servicenow_mcp/server_sse.py`:

```python
"""
ServiceNow MCP Server — Centralized Multi-User HTTP/SSE Entrypoint.

Endpoints:
    GET  /sse                                      MCP SSE event stream
    POST /messages/                                MCP client -> server messages (?session_id=...)
    GET  /healthz                                  Liveness/readiness probe (always open)
    GET  /.well-known/oauth-protected-resource     RFC 9728 OAuth protected resource metadata
    GET  /.well-known/oauth-authorization-server   RFC 8414 OAuth authorization server metadata
    POST /oauth/register                           RFC 7591 Dynamic Client Registration for IDEs
    GET  /oauth/authorize                          OAuth 2.1 Authorization Code + PKCE entry point
    GET  /oauth/callback                           Upstream OIDC / ServiceNow OAuth callback
    POST /oauth/token                              OAuth 2.1 token exchange & refresh endpoint
    GET  /auth/login                               Self-service browser SSO token portal
    POST /auth/logout                              Revoke an issued mcp_ session token
"""

import argparse
import hmac
import html
import json
import logging
import os
import sys
from typing import Dict, Optional, Union
from urllib.parse import parse_qs, urlencode, urlsplit

import uvicorn
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.auth.oauth_broker import OAuthBroker, OAuthBrokerError
from servicenow_mcp.auth.session_context import (
    CallerAuth,
    SseSessionAuthRegistry,
    caller_auth_context,
    extract_jwt_user_hint,
    parse_basic_auth_username,
)
from servicenow_mcp.auth.session_store import (
    OAuthSessionStore,
    validate_client_redirect_uri,
    verify_pkce_challenge,
)
from servicenow_mcp.server import ServiceNowMCP, ToolPackageConfigError
from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig
from servicenow_mcp.utils.logging_setup import configure_logging

logger = logging.getLogger(__name__)

HEALTH_PATH = "/healthz"
PUBLIC_PATHS = {
    HEALTH_PATH,
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/oauth/register",
    "/oauth/authorize",
    "/oauth/callback",
    "/oauth/token",
    "/auth/login",
}


def _external_base_url(request: Request) -> str:
    """Determine the external base URL of this MCP server from MCP_PUBLIC_URL or request headers."""
    configured = settings.mcp_public_url()
    if configured:
        return configured
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "http"
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
        or "localhost:8080"
    )
    return f"{proto}://{host}".rstrip("/")


def _external_base_url_from_scope(scope: dict) -> str:
    configured = settings.mcp_public_url()
    if configured:
        return configured
    headers = Headers(scope=scope)
    proto = headers.get("x-forwarded-proto") or scope.get("scheme") or "http"
    host = headers.get("x-forwarded-host") or headers.get("host")
    if not host:
        server = scope.get("server")
        host = f"{server[0]}:{server[1]}" if server else "localhost:8080"
    return f"{proto}://{host}".rstrip("/")


class BearerAuthMiddleware:
    """
    Legacy static bearer-token ASGI middleware kept for direct unit-test compatibility
    when ``create_starlette_app(mcp_server, auth_token=...)`` is called without multi-auth.
    """

    def __init__(self, app, token: str, exempt_paths=PUBLIC_PATHS):
        self.app = app
        self._token = token.encode("utf-8")
        self._exempt = set(exempt_paths)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in self._exempt:
            await self.app(scope, receive, send)
            return
        authorization = Headers(scope=scope).get("authorization", "")
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            value.strip().encode("utf-8"), self._token
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return
        await self.app(scope, receive, send)


class MultiAuthMiddleware:
    """
    Pure ASGI middleware resolving per-user ServiceNow credentials or OAuth sessions.

    Pure ASGI (not BaseHTTPMiddleware) so streaming SSE responses are never buffered.
    """

    def __init__(
        self,
        app,
        *,
        auth_manager: Optional[AuthManager] = None,
        session_store: Optional[OAuthSessionStore] = None,
        sse_registry: Optional[SseSessionAuthRegistry] = None,
        auth_token: Optional[str] = None,
        exempt_paths=PUBLIC_PATHS,
    ):
        self.app = app
        self.auth_manager = auth_manager
        self.session_store = session_store
        self.sse_registry = sse_registry or SseSessionAuthRegistry()
        self._static_token = auth_token
        self._exempt = set(exempt_paths)

    def _resolve_caller_auth(self, scope: dict) -> Optional[CallerAuth]:
        headers = Headers(scope=scope)
        auth_header = headers.get("authorization", "").strip()
        scheme, _, raw_value = auth_header.partition(" ")
        scheme_lower = scheme.lower()
        value = raw_value.strip()

        static_token = self._static_token or settings.mcp_auth_token()
        allow_fallback = settings.allow_service_account_fallback()
        has_svc = self.auth_manager.has_service_account() if self.auth_manager else False

        # 1. Issued MCP OAuth session token (Bearer mcp_...)
        if scheme_lower == "bearer" and value.startswith("mcp_"):
            if self.session_store is None:
                return None
            session = self.session_store.get_session(value)
            if session is None:
                return None
            return CallerAuth(
                headers={"Authorization": f"{session.token_type} {session.access_token}"},
                auth_source="oauth_session",
                session_id=session.mcp_token,
                user_hint=session.user_hint,
            )

        # 2. Explicit ServiceNow Inbound REST API Key header
        api_key = headers.get("x-servicenow-api-key", "").strip()
        if api_key:
            sn_header = settings.servicenow_api_key_header()
            return CallerAuth(headers={sn_header: api_key}, auth_source="api_key")

        # 3. Explicit ServiceNow Basic Auth pass-through
        basic_b64 = headers.get("x-servicenow-basic", "").strip()
        if not basic_b64 and scheme_lower == "basic" and value:
            basic_b64 = value
        if basic_b64:
            user_hint = parse_basic_auth_username(basic_b64)
            return CallerAuth(
                headers={"Authorization": f"Basic {basic_b64}"},
                auth_source="basic_passthrough",
                user_hint=user_hint,
            )

        # 4. Static MCP_AUTH_TOKEN (for shared service-account fallback)
        if scheme_lower == "bearer" and value and static_token:
            if hmac.compare_digest(value.encode("utf-8"), static_token.encode("utf-8")):
                if allow_fallback and has_svc:
                    return CallerAuth(auth_source="service_account")
                return None

        # 5. Direct OIDC JWT or ServiceNow OAuth Bearer token pass-through
        if scheme_lower == "bearer" and value:
            return CallerAuth(
                headers={"Authorization": f"Bearer {value}"},
                auth_source="bearer_passthrough",
                user_hint=extract_jwt_user_hint(value),
            )

        # 6. Existing SSE session lookup on POST /messages/?session_id=...
        path = scope.get("path", "")
        if path.startswith("/messages"):
            qs = parse_qs((scope.get("query_string") or b"").decode("utf-8", errors="ignore"))
            session_ids = qs.get("session_id") or []
            if session_ids:
                bound = self.sse_registry.get(session_ids[0])
                if bound is not None:
                    return bound

        # 7. Unauthenticated service-account fallback if explicitly enabled & no MCP_AUTH_TOKEN set
        if not static_token and allow_fallback and has_svc:
            return CallerAuth(auth_source="service_account")

        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in self._exempt:
            await self.app(scope, receive, send)
            return

        caller_auth = self._resolve_caller_auth(scope)
        if caller_auth is None:
            base_url = _external_base_url_from_scope(scope)
            resource_meta = f"{base_url}/.well-known/oauth-protected-resource"
            www_auth = f'Bearer resource_metadata="{resource_meta}"'
            body = json.dumps(
                {
                    "error": "unauthorized",
                    "message": (
                        "Authentication required. Sign in via OAuth, visit /auth/login to obtain "
                        "a token, or pass Authorization: Bearer <token> or X-ServiceNow-API-Key."
                    ),
                    "login_url": f"{base_url}/auth/login",
                }
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json; charset=utf-8"),
                        (b"www-authenticate", www_auth.encode("utf-8")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        scope["caller_auth"] = caller_auth
        with caller_auth_context(caller_auth):
            await self.app(scope, receive, send)


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def _render_portal_html(*, base_url: str, mcp_token: str, expires_in: int, user_hint: Optional[str]) -> str:
    safe_url = html.escape(f"{base_url}/sse")
    safe_token = html.escape(mcp_token)
    safe_user = html.escape(user_hint or "Authenticated ServiceNow User")
    cursor_json = html.escape(
        json.dumps(
            {
                "mcpServers": {
                    "servicenow": {
                        "url": f"{base_url}/sse",
                        "headers": {"Authorization": f"Bearer {mcp_token}"},
                    }
                }
            },
            indent=2,
        )
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>ServiceNow MCP — Authenticated</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; color: #1f2937; }}
    pre {{ background: #111827; color: #f9fafb; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }}
    .badge {{ display: inline-block; background: #dcfce7; color: #166534; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>ServiceNow MCP Server</h1>
  <p><span class="badge">Connected</span> Signed in as <strong>{safe_user}</strong> (session valid for {int(expires_in)}s, upstream token auto-refreshed).</p>
  <div class="card">
    <h2>1. Your MCP Bearer Token (for Dify / Web Platforms)</h2>
    <p>SSE Endpoint: <code>{safe_url}</code></p>
    <p>Header: <code>Authorization: Bearer {safe_token}</code></p>
    <pre><code>{safe_token}</code></pre>
  </div>
  <div class="card">
    <h2>2. Cursor / Claude Desktop / VS Code (<code>mcp.json</code>)</h2>
    <pre><code>{cursor_json}</code></pre>
  </div>
</body>
</html>"""


def create_starlette_app(
    mcp_server: Server,
    *,
    debug: bool = False,
    auth_token: Optional[str] = None,
    auth_manager: Optional[AuthManager] = None,
    session_store: Optional[OAuthSessionStore] = None,
    oauth_broker: Optional[OAuthBroker] = None,
    require_auth: bool = False,
) -> Starlette:
    """Create a Starlette application serving MCP over SSE with OAuth 2.1 and multi-user auth."""
    sse = SseServerTransport("/messages/")
    sse_registry = SseSessionAuthRegistry()
    store = session_store or OAuthSessionStore(session_ttl_seconds=settings.session_ttl_seconds())
    broker = oauth_broker

    async def handle_sse(request: Request) -> None:
        caller_auth: Optional[CallerAuth] = request.scope.get("caller_auth")
        bound_session_id: Optional[str] = None

        async def capturing_send(message):
            nonlocal bound_session_id
            if (
                caller_auth is not None
                and bound_session_id is None
                and message.get("type") == "http.response.body"
            ):
                body_bytes = message.get("body", b"")
                if b"session_id=" in body_bytes:
                    text = body_bytes.decode("utf-8", errors="ignore")
                    for line in text.splitlines():
                        if "session_id=" in line:
                            _, _, after = line.partition("session_id=")
                            sid = after.split("&")[0].split()[0].strip()
                            if sid:
                                bound_session_id = sid
                                sse_registry.bind(sid, caller_auth)
                                break
            await request._send(message)  # noqa: SLF001

        try:
            async with sse.connect_sse(
                request.scope,
                request.receive,
                capturing_send,
            ) as (read_stream, write_stream):
                with caller_auth_context(caller_auth):
                    await mcp_server.run(
                        read_stream,
                        write_stream,
                        mcp_server.create_initialization_options(),
                    )
        finally:
            if bound_session_id:
                sse_registry.remove(bound_session_id)

    async def oauth_protected_resource(request: Request) -> JSONResponse:
        base_url = _external_base_url(request)
        return JSONResponse(
            {
                "resource": base_url,
                "authorization_servers": [base_url],
                "bearer_methods_supported": ["header"],
            }
        )

    async def oauth_authorization_server(request: Request) -> JSONResponse:
        base_url = _external_base_url(request)
        return JSONResponse(
            {
                "issuer": base_url,
                "authorization_endpoint": f"{base_url}/oauth/authorize",
                "token_endpoint": f"{base_url}/oauth/token",
                "registration_endpoint": f"{base_url}/oauth/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
                "code_challenge_methods_supported": ["S256"],
            }
        )

    async def oauth_register(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
        try:
            client = store.register_client(
                client_name=str(body.get("client_name") or "MCP Client"),
                redirect_uris=body.get("redirect_uris") or [],
            )
        except ValueError as e:
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": str(e)},
                status_code=400,
            )
        return JSONResponse(
            {
                "client_id": client.client_id,
                "client_name": client.client_name,
                "redirect_uris": client.redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
            status_code=201,
        )

    async def oauth_authorize(request: Request) -> Response:
        if broker is None or not broker.is_configured():
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": "OAuth/OIDC is not configured on this MCP server (set OAUTH_CLIENT_ID).",
                },
                status_code=501,
            )
        params = request.query_params
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        downstream_state = params.get("state", "")
        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "S256")

        if not redirect_uri or not code_challenge:
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri and PKCE code_challenge are required.",
                },
                status_code=400,
            )
        try:
            validated_redirect = validate_client_redirect_uri(redirect_uri)
        except ValueError as e:
            return JSONResponse(
                {"error": "invalid_request", "error_description": str(e)},
                status_code=400,
            )
        registered = store.get_client(client_id) if client_id else None
        if registered and validated_redirect not in registered.redirect_uris:
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "redirect_uri does not match registered client.",
                },
                status_code=400,
            )

        pending = store.create_pending_auth(
            flow_type="mcp_oauth",
            client_id=client_id,
            redirect_uri=validated_redirect,
            downstream_state=downstream_state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        base_url = _external_base_url(request)
        callback_uri = f"{base_url}/oauth/callback"
        try:
            upstream_url = broker.build_authorize_url(
                redirect_uri=callback_uri,
                state=pending.upstream_state,
                code_challenge=pending.upstream_code_challenge,
            )
        except OAuthBrokerError as e:
            return JSONResponse(
                {"error": "server_error", "error_description": str(e)}, status_code=502
            )
        return RedirectResponse(url=upstream_url, status_code=302)

    async def auth_login(request: Request) -> Response:
        base_url = _external_base_url(request)
        if broker is None or not broker.is_configured():
            return HTMLResponse(
                content=(
                    "<!DOCTYPE html><html><body><h1>ServiceNow MCP Server</h1>"
                    "<p>Interactive OAuth/OIDC login is not configured on this server. "
                    "Connect by passing <code>Authorization: Bearer &lt;token&gt;</code> or "
                    "<code>X-ServiceNow-API-Key: &lt;key&gt;</code> in your MCP client headers.</p>"
                    "</body></html>"
                ),
                status_code=200,
            )
        pending = store.create_pending_auth(flow_type="portal")
        callback_uri = f"{base_url}/oauth/callback"
        try:
            upstream_url = broker.build_authorize_url(
                redirect_uri=callback_uri,
                state=pending.upstream_state,
                code_challenge=pending.upstream_code_challenge,
            )
        except OAuthBrokerError as e:
            return HTMLResponse(
                content=f"<h1>OAuth Configuration Error</h1><p>{html.escape(str(e))}</p>",
                status_code=502,
            )
        return RedirectResponse(url=upstream_url, status_code=302)

    async def oauth_callback(request: Request) -> Response:
        if broker is None:
            return JSONResponse({"error": "server_error"}, status_code=501)
        params = request.query_params
        error = params.get("error")
        if error:
            desc = params.get("error_description") or error
            return HTMLResponse(
                content=f"<h1>Authentication Failed</h1><p>{html.escape(desc)}</p>",
                status_code=400,
            )
        code = params.get("code", "")
        state = params.get("state", "")
        pending = store.pop_pending_auth(state)
        if not code or pending is None:
            return HTMLResponse(
                content="<h1>Invalid or Expired Login State</h1><p>Please restart login at <a href='/auth/login'>/auth/login</a>.</p>",
                status_code=400,
            )
        base_url = _external_base_url(request)
        callback_uri = f"{base_url}/oauth/callback"
        try:
            token_resp = broker.exchange_code_for_tokens(
                code=code,
                redirect_uri=callback_uri,
                code_verifier=pending.upstream_code_verifier,
            )
        except OAuthBrokerError as e:
            return HTMLResponse(
                content=f"<h1>Token Exchange Failed</h1><p>{html.escape(str(e))}</p>",
                status_code=502,
            )

        session = store.create_session(
            access_token=token_resp.access_token,
            refresh_token=token_resp.refresh_token,
            token_type=token_resp.token_type,
            expires_in=token_resp.expires_in,
            user_hint=token_resp.user_hint,
        )

        if pending.flow_type == "mcp_oauth" and pending.redirect_uri:
            issued_code = store.issue_auth_code(
                mcp_token=session.mcp_token,
                client_id=pending.client_id,
                redirect_uri=pending.redirect_uri,
                code_challenge=pending.code_challenge,
                code_challenge_method=pending.code_challenge_method,
            )
            q = {"code": issued_code.code}
            if pending.downstream_state:
                q["state"] = pending.downstream_state
            sep = "&" if "?" in pending.redirect_uri else "?"
            return RedirectResponse(
                url=f"{pending.redirect_uri}{sep}{urlencode(q)}", status_code=302
            )

        ttl = int(session.session_expires_at - session.expires_at + token_resp.expires_in)
        return HTMLResponse(
            content=_render_portal_html(
                base_url=base_url,
                mcp_token=session.mcp_token,
                expires_in=ttl,
                user_hint=session.user_hint,
            ),
            status_code=200,
        )

    async def oauth_token(request: Request) -> JSONResponse:
        form = await request.form()
        grant_type = str(form.get("grant_type") or "")

        if grant_type == "authorization_code":
            code = str(form.get("code") or "")
            code_verifier = str(form.get("code_verifier") or "")
            redirect_uri = str(form.get("redirect_uri") or "")
            issued = store.consume_auth_code(code)
            if issued is None:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "Invalid or expired code."},
                    status_code=400,
                )
            if issued.redirect_uri and redirect_uri and issued.redirect_uri != redirect_uri:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "redirect_uri mismatch."},
                    status_code=400,
                )
            if not verify_pkce_challenge(
                code_verifier, issued.code_challenge, issued.code_challenge_method
            ):
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "PKCE verification failed."},
                    status_code=400,
                )
            session = store.get_session(issued.mcp_token)
            if session is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return JSONResponse(
                {
                    "access_token": session.mcp_token,
                    "token_type": "Bearer",
                    "expires_in": max(int(session.session_expires_at - __import__("time").time()), 60),
                    "refresh_token": session.downstream_refresh_token,
                }
            )

        if grant_type == "refresh_token":
            refresh_tok = str(form.get("refresh_token") or "")
            session = store.get_session_by_downstream_refresh_token(refresh_tok)
            if session is None:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "Unknown refresh_token."},
                    status_code=400,
                )
            if session.refresh_token and broker is not None and broker.is_configured():
                try:
                    refreshed = broker.refresh_access_token(session.refresh_token)
                    store.update_session_tokens(
                        session.mcp_token,
                        access_token=refreshed.access_token,
                        refresh_token=refreshed.refresh_token,
                        token_type=refreshed.token_type,
                        expires_in=refreshed.expires_in,
                        user_hint=refreshed.user_hint,
                    )
                except OAuthBrokerError as e:
                    return JSONResponse(
                        {"error": "invalid_grant", "error_description": str(e)},
                        status_code=400,
                    )
            return JSONResponse(
                {
                    "access_token": session.mcp_token,
                    "token_type": "Bearer",
                    "expires_in": max(int(session.session_expires_at - __import__("time").time()), 60),
                    "refresh_token": session.downstream_refresh_token,
                }
            )

        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    async def auth_logout(request: Request) -> JSONResponse:
        caller_auth: Optional[CallerAuth] = request.scope.get("caller_auth")
        if caller_auth and caller_auth.session_id:
            store.revoke_session(caller_auth.session_id)
        return JSONResponse({"status": "logged_out"})

    use_multi_auth = require_auth or (auth_manager is not None)
    if use_multi_auth:
        middleware = [
            Middleware(
                MultiAuthMiddleware,
                auth_manager=auth_manager,
                session_store=store,
                sse_registry=sse_registry,
                auth_token=auth_token,
            )
        ]
    elif auth_token:
        middleware = [Middleware(BearerAuthMiddleware, token=auth_token)]
    else:
        middleware = []

    return Starlette(
        debug=debug,
        routes=[
            Route(HEALTH_PATH, endpoint=healthz),
            Route("/.well-known/oauth-protected-resource", endpoint=oauth_protected_resource),
            Route("/.well-known/oauth-authorization-server", endpoint=oauth_authorization_server),
            Route("/oauth/register", endpoint=oauth_register, methods=["POST"]),
            Route("/oauth/authorize", endpoint=oauth_authorize, methods=["GET"]),
            Route("/oauth/callback", endpoint=oauth_callback, methods=["GET"]),
            Route("/oauth/token", endpoint=oauth_token, methods=["POST"]),
            Route("/auth/login", endpoint=auth_login, methods=["GET"]),
            Route("/auth/logout", endpoint=auth_logout, methods=["POST"]),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
        middleware=middleware,
    )


class ServiceNowSSEMCP(ServiceNowMCP):
    """Centralized HTTP/SSE ServiceNow MCP Server with multi-user authentication."""

    def __init__(self, config: Union[Dict, ServerConfig]):
        super().__init__(config)
        self.session_store = OAuthSessionStore(
            session_ttl_seconds=settings.session_ttl_seconds()
        )
        self.oauth_broker = OAuthBroker(instance_url=self.config.instance_url)
        self.auth_manager.session_store = self.session_store
        self.auth_manager.oauth_broker = self.oauth_broker

    def start(self, host: str = "0.0.0.0", port: int = 8080):
        token = settings.mcp_auth_token()
        allow_fallback = settings.allow_service_account_fallback()
        if self.oauth_broker.is_configured():
            logger.info(
                "OAuth/OIDC login is enabled (/auth/login and /.well-known/oauth-authorization-server)."
            )
        if allow_fallback and self.auth_manager.has_service_account():
            if token:
                logger.info(
                    "Service-account fallback is ENABLED and gated by MCP_AUTH_TOKEN."
                )
            else:
                logger.warning(
                    "ALLOW_SERVICE_ACCOUNT_FALLBACK=true without MCP_AUTH_TOKEN: unauthenticated "
                    "requests will use the ServiceNow service account."
                )
        else:
            logger.info(
                "Per-user ServiceNow authentication is required (OAuth login, Bearer token, or API key)."
            )

        starlette_app = create_starlette_app(
            self.mcp_server,
            debug=False,
            auth_token=token,
            auth_manager=self.auth_manager,
            session_store=self.session_store,
            oauth_broker=self.oauth_broker,
            require_auth=True,
        )

        uvicorn.run(
            starlette_app,
            host=host,
            port=port,
            log_level=settings.log_level().lower(),
        )


def create_servicenow_mcp(
    instance_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: Optional[int] = None,
):
    """
    Create a centralized ServiceNow MCP server.

    If username and password are provided, configures a service account (used when
    ALLOW_SERVICE_ACCOUNT_FALLBACK=true). Otherwise runs in per-user authentication mode.
    """
    if username and password:
        auth_config = AuthConfig(
            type=AuthType.BASIC, basic=BasicAuthConfig(username=username, password=password)
        )
    else:
        auth_config = AuthConfig(type=AuthType.NONE)

    config = ServerConfig(
        instance_url=instance_url.rstrip("/"),
        auth=auth_config,
        timeout=timeout or settings.servicenow_timeout(),
    )
    return ServiceNowSSEMCP(config)


def main():
    load_dotenv()
    configure_logging()

    parser = argparse.ArgumentParser(description="Run ServiceNow MCP SSE-based server")
    parser.add_argument(
        "--host", default=os.getenv("MCP_HOST", "0.0.0.0"), help="Host to bind to (MCP_HOST)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_PORT", "8080")),
        help="Port to listen on (MCP_PORT)",
    )
    args = parser.parse_args()

    instance_url = os.getenv("SERVICENOW_INSTANCE_URL", "").strip()
    if not instance_url:
        logger.error("Missing required environment variable: SERVICENOW_INSTANCE_URL")
        sys.exit(2)

    username = os.getenv("SERVICENOW_USERNAME", "").strip() or None
    password = os.getenv("SERVICENOW_PASSWORD", "") or None

    if settings.allow_service_account_fallback() and not (username and password):
        logger.error(
            "ALLOW_SERVICE_ACCOUNT_FALLBACK=true requires SERVICENOW_USERNAME and SERVICENOW_PASSWORD"
        )
        sys.exit(2)

    try:
        server = create_servicenow_mcp(
            instance_url=instance_url,
            username=username,
            password=password,
        )
    except ToolPackageConfigError as e:
        logger.error("Tool package configuration error: %s", e)
        sys.exit(2)
    except ValueError as e:
        logger.error("Configuration error: %s", e)
        sys.exit(2)
    server.start(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify both new and existing SSE auth tests pass**

Run: `uv run pytest tests/test_server_sse_multiauth.py tests/test_sse_auth.py -v`
Expected: PASS

---

### Task 6: Per-User Identity Resolution in `check_access` & Deployment Docs

**Files:**
- Modify: `src/servicenow_mcp/tools/access_tools.py`
- Modify: `tests/test_check_access.py`
- Modify: `k8s/configmap.yaml`
- Modify: `k8s/secret.example.yaml`
- Modify: `.env.example`
- Modify: `README.md`

- [ ] **Step 1: Add failing per-user identity tests to `tests/test_check_access.py`**

Append the following tests to `tests/test_check_access.py`:

```python
from servicenow_mcp.auth.session_context import CallerAuth, caller_auth_context


def test_check_access_uses_caller_auth_user_hint():
    cfg = ServerConfig(
        instance_url="https://acme.service-now.com",
        auth=AuthConfig(type=AuthType.NONE),
    )
    mgr = AuthManager(cfg.auth, cfg.instance_url)

    def fake_get(url, params=None, **kwargs):
        table = url.rsplit("/", 1)[1]
        if table == "sys_user":
            assert params["sysparm_query"] == "user_name=alice.oidc"
            return make_response(
                200,
                {
                    "result": [
                        {
                            "sys_id": "a" * 32,
                            "user_name": "alice.oidc",
                            "name": "Alice OIDC",
                            "active": "true",
                        }
                    ]
                },
            )
        if table == "sys_user_has_role":
            return make_response(200, {"result": [{"role": "itil"}]})
        return make_response(200, {"result": [{"sys_id": "x"}]}, total=10)

    with caller_auth_context(
        CallerAuth(
            headers={"Authorization": "Bearer user-jwt"},
            auth_source="oauth_session",
            user_hint="alice.oidc",
        )
    ):
        result = _run(cfg, mgr, fake_get)

    assert result["success"] is True
    assert result["user"]["verified"] is True
    assert result["user"]["user_name"] == "alice.oidc"
    assert result["user"]["auth_type"] == "oauth_session"


def test_check_access_falls_back_to_gs_get_user_id_when_no_username():
    cfg = ServerConfig(
        instance_url="https://acme.service-now.com",
        auth=AuthConfig(type=AuthType.NONE),
    )
    mgr = AuthManager(cfg.auth, cfg.instance_url)

    def fake_get(url, params=None, **kwargs):
        table = url.rsplit("/", 1)[1]
        if table == "sys_user":
            assert params["sysparm_query"] == "sys_id=javascript:gs.getUserID()"
            return make_response(
                200,
                {
                    "result": [
                        {
                            "sys_id": "b" * 32,
                            "user_name": "apikey.user",
                            "name": "API Key User",
                            "active": "true",
                        }
                    ]
                },
            )
        if table == "sys_user_has_role":
            return make_response(200, {"result": [{"role": "itil"}]})
        return make_response(200, {"result": [{"sys_id": "x"}]}, total=5)

    with caller_auth_context(
        CallerAuth(headers={"x-sn-apikey": "key-1"}, auth_source="api_key")
    ):
        result = _run(cfg, mgr, fake_get)

    assert result["success"] is True
    assert result["user"]["verified"] is True
    assert result["user"]["user_name"] == "apikey.user"
    assert result["user"]["auth_type"] == "api_key"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_check_access.py -v`
Expected: FAIL on `test_check_access_uses_caller_auth_user_hint` and `test_check_access_falls_back_to_gs_get_user_id_when_no_username`

- [ ] **Step 3: Update `_user_identity` in `src/servicenow_mcp/tools/access_tools.py` and update manifests/docs**

Update `_user_identity` in `src/servicenow_mcp/tools/access_tools.py`:

```python
from servicenow_mcp.auth.session_context import get_current_caller_auth


def _user_identity(config: ServerConfig, auth_manager: AuthManager) -> dict:
    caller_auth = get_current_caller_auth()
    auth = getattr(config, "auth", None)
    basic = getattr(auth, "basic", None)
    username = getattr(basic, "username", None)
    if not username:
        oauth = getattr(auth, "oauth", None)
        username = getattr(oauth, "username", None)
    auth_type_obj = getattr(auth, "type", None)
    auth_type_str = getattr(auth_type_obj, "value", str(auth_type_obj))

    if caller_auth is not None and caller_auth.auth_source != "service_account":
        auth_type_str = caller_auth.auth_source
        username = caller_auth.user_hint

    identity = {
        "configured_username": username,
        "auth_type": auth_type_str,
    }

    if username:
        try:
            field_name = "email" if "@" in username else "user_name"
            query = QueryBuilder().eq(field_name, username).build()
        except QueryInputError as e:
            identity["verified"] = False
            identity["note"] = str(e)
            return identity
    elif caller_auth is not None and caller_auth.auth_source != "service_account":
        query = "sys_id=javascript:gs.getUserID()"
    else:
        identity["verified"] = False
        identity["note"] = "No username configured (API key / client credentials); identity unknown."
        return identity

    result = sn_get(
        config,
        auth_manager,
        "table/sys_user",
        {
            "sysparm_query": query,
            "sysparm_limit": 1,
            "sysparm_fields": "sys_id,user_name,name,active,sys_domain",
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
        },
    )
    identity["lookup_status_code"] = result.status_code
    if not result.ok:
        identity["verified"] = False
        identity["error_type"] = result.error_type
        identity["note"] = result.message
        return identity
    if not result.records:
        identity["verified"] = False
        identity["note"] = (
            "Authenticated (HTTP 200) but the account cannot read its own sys_user record."
        )
        return identity
    user = result.records[0]
    identity.update(
        {
            "verified": True,
            "user_name": display(user.get("user_name")),
            "name": display(user.get("name")),
            "sys_id": display(user.get("sys_id")),
            "active": display(user.get("active")),
            "domain": display(user.get("sys_domain")),
        }
    )

    roles = sn_get(
        config,
        auth_manager,
        "table/sys_user_has_role",
        {
            "sysparm_query": QueryBuilder().eq("user", identity["sys_id"]).build(),
            "sysparm_fields": "role",
            "sysparm_limit": 200,
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
        },
    )
    if roles.ok:
        identity["roles"] = sorted({str(display(r.get("role"))) for r in roles.records})
    else:
        identity["roles"] = None
        identity["roles_note"] = f"Could not read sys_user_has_role (HTTP {roles.status_code})"
    return identity
```

Update `k8s/configmap.yaml`, `k8s/secret.example.yaml`, `.env.example`, and `README.md` with the new OAuth/OIDC and per-user auth configuration variables.

- [ ] **Step 4: Run the full test suite to verify everything passes**

Run: `uv run pytest -v`
Expected: PASS across all test files.
