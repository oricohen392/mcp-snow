# Server Hardening & Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `server_sse.py` to `server_http.py`, modularize OAuth routes and portal rendering, resolve blocking HTTP calls in async handlers, eliminate arbitrary Bearer pass-through vulnerabilities, prevent unauthenticated user eviction in session stores, add refresh token rotation and absolute session lifetimes, add an OAuth consent screen, and perform repo hygiene.

**Architecture:** 
1. Separate concerns: `src/servicenow_mcp/auth/portal.py` (portal HTML rendering), `src/servicenow_mcp/auth/oauth_routes.py` (RFC 8414/9728 discovery, RFC 7591 client registration, consent, authorization, token, callback), `src/servicenow_mcp/server_http.py` (Starlette app assembly, pure-ASGI middlewares, Streamable HTTP and SSE transports), with `server_sse.py` maintained for full backward compatibility.
2. Async safety: Wrap synchronous upstream HTTP calls (`requests.get`/`requests.post`) in `anyio.to_thread.run_sync` so the Starlette asyncio event loop is never blocked by slow IdP responses.
3. Security in depth: Enforce PKCE S256 strictly (reject `plain`), reject arbitrary unverified Bearer tokens unless `ALLOW_BEARER_PASSTHROUGH=true`, rotate downstream refresh tokens upon exchange, enforce absolute session lifetimes, evict only expired sessions without dropping active ones, and add an OAuth client consent screen.

**Tech Stack:** Python 3.10+, Starlette, anyio, requests, pytest, mcp Python SDK.

---

### Task 1: Repo Hygiene & Housekeeping

**Files:**
- Modify: `.gitignore`
- Remove: `debug_workflow_api.py` (keep `examples/debug_workflow_api.py`)
- Modify: `src/servicenow_mcp/auth/auth_manager.py:1-25, 145-170`
- Test: `tests/test_auth_manager.py` (or existing auth tests)

- [ ] **Step 1: Check and update `.gitignore` and untrack `.DS_Store` files**

Ensure `.gitignore` contains `.DS_Store` and untrack any existing `.DS_Store` files:
```bash
git rm --cached .DS_Store src/.DS_Store src/servicenow_mcp/.DS_Store
rm -f debug_workflow_api.py
```

- [ ] **Step 2: Clean up `src/servicenow_mcp/auth/auth_manager.py`**

In `src/servicenow_mcp/auth/auth_manager.py`:
- Remove unused imports: `import os`, `from requests.auth import HTTPBasicAuth`.
- Fix `instance_url: Optional[str] = None` in `__init__`.
- Fix line 154-158 custom domain handling:
  Replace:
  ```python
  instance_parts = self.instance_url.split(".")
  if len(instance_parts) < 2:
      raise ValueError(f"Invalid instance URL: {self.instance_url}")
  instance_name = instance_parts[0].split("//")[-1]
  token_url = f"https://{instance_name}.service-now.com/oauth_token.do"
  ```
  With:
  ```python
  token_url = f"{self.instance_url.rstrip('/')}/oauth_token.do"
  ```
- Strip trailing whitespaces.

- [ ] **Step 3: Run existing auth tests to verify**

Run: `.venv/bin/pytest tests/test_oauth_broker_and_auth_manager.py -v`
Expected: PASS

---

### Task 2: Session Store Hardening (Eviction, PKCE, Rotation, Absolute Expiry)

**Files:**
- Modify: `src/servicenow_mcp/auth/session_store.py`
- Modify: `src/servicenow_mcp/utils/settings.py`
- Test: `tests/test_session_store.py`

- [ ] **Step 1: Write failing tests for S256-only PKCE, no active eviction, refresh rotation, and absolute session lifetime**

Add to `tests/test_session_store.py`:
```python
def test_pkce_rejects_plain():
    verifier = "my-verifier-12345678901234567890"
    # Plain method must be rejected
    assert not verify_pkce_challenge(verifier, verifier, method="plain")
    assert not verify_pkce_challenge(verifier, verifier, method="PLAIN")


def test_session_rotation_and_absolute_expiry():
    store = OAuthSessionStore(session_ttl_seconds=3600, absolute_lifetime_seconds=7200)
    session = store.create_session(
        access_token="sn-acc-1",
        refresh_token="sn-ref-1",
        expires_in=1800,
        client_id="client-test",
    )
    first_downstream_refresh = session.downstream_refresh_token
    assert first_downstream_refresh.startswith("mcpr_")
    assert session.client_id == "client-test"

    # Refresh rotates the downstream refresh token
    updated = store.update_session_tokens(
        session.mcp_token,
        access_token="sn-acc-2",
        refresh_token="sn-ref-2",
        expires_in=1800,
    )
    assert updated is not None
    assert updated.downstream_refresh_token != first_downstream_refresh
    assert updated.downstream_refresh_token.startswith("mcpr_")

    # Old downstream refresh token no longer works
    assert store.get_session_by_downstream_refresh_token(first_downstream_refresh) is None
    # New downstream refresh token works
    assert store.get_session_by_downstream_refresh_token(updated.downstream_refresh_token) is not None

    # Force absolute expiration
    store._sessions[session.mcp_token].absolute_expires_at = time.time() - 1
    expired = store.update_session_tokens(
        session.mcp_token,
        access_token="sn-acc-3",
        refresh_token="sn-ref-3",
    )
    assert expired is None
    assert store.get_session(session.mcp_token) is None


def test_cleanup_does_not_evict_unexpired_pending_or_clients():
    store = OAuthSessionStore(max_pending=2, max_clients=2)
    # Register 2 clients
    c1 = store.register_client("C1", ["http://127.0.0.1:1000/cb"])
    c2 = store.register_client("C2", ["http://127.0.0.1:2000/cb"])
    # 3rd client registration must be rejected with capacity error rather than evicting c1
    with pytest.raises(ValueError, match="Client registration limit reached"):
        store.register_client("C3", ["http://127.0.0.1:3000/cb"])
    assert store.get_client(c1.client_id) is not None
    assert store.get_client(c2.client_id) is not None
```

- [ ] **Step 2: Run test to verify failure**

Run: `.venv/bin/pytest tests/test_session_store.py -k "test_pkce_rejects_plain or test_session_rotation_and_absolute_expiry or test_cleanup_does_not_evict_unexpired_pending_or_clients" -v`
Expected: FAIL

- [ ] **Step 3: Implement hardening in `src/servicenow_mcp/auth/session_store.py` and `settings.py`**

1. In `verify_pkce_challenge`:
   ```python
   if normalized_method != "S256":
       return False
   ```
2. In `OAuthSession`:
   Add `client_id: Optional[str] = None` and `absolute_expires_at: float = 0.0`.
3. In `OAuthSessionStore.__init__`:
   Add `absolute_lifetime_seconds: int = 7 * 86400` (default 7 days).
4. In `create_session`:
   Set `absolute_expires_at = now + (absolute_lifetime_seconds or (self._session_ttl * 7))` and store `client_id`.
5. In `update_session_tokens`:
   Check `if session.absolute_expires_at <= now: self.revoke_session(mcp_token); return None`.
   Set `session.session_expires_at = min(session.absolute_expires_at, now + self._session_ttl)`.
   Rotate downstream refresh token: remove old from `_refresh_index`, generate new `f"mcpr_{secrets.token_urlsafe(32)}"`, index new token.
6. In `_cleanup_locked`:
   Remove while loops that evict unexpired `_pending` and `_clients`.
   Only evict expired ones:
   `expired_pending = [st for st, p in self._pending.items() if p.expires_at <= now]`
   `for st in expired_pending: self._pending.pop(st, None)`
   In `create_pending_auth`:
   If `len(self._pending) >= self._max_pending: raise RuntimeError("Pending login capacity reached. Please try again later.")`
   In `register_client`:
   If `len(self._clients) >= self._max_clients: raise ValueError("Client registration limit reached.")`

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_session_store.py -v`
Expected: PASS

---

### Task 3: OAuth Broker Hardening (Duplicate Auth & Async Non-Blocking HTTP)

**Files:**
- Modify: `src/servicenow_mcp/auth/oauth_broker.py`
- Test: `tests/test_oauth_broker_and_auth_manager.py`

- [ ] **Step 1: Write test for single client auth method in `_post_token_request` and async thread execution**

Add to `tests/test_oauth_broker_and_auth_manager.py`:
```python
def test_broker_does_not_duplicate_client_secret_in_body_when_basic_auth_used(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "my-client")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "my-secret")

    broker = OAuthBroker(instance_url="https://acme.service-now.com")
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {
        "access_token": "acc",
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        broker.exchange_code_for_tokens(code="c1", redirect_uri="http://127.0.0.1/cb")
        assert mock_post.call_count == 1
        _, kwargs = mock_post.call_args
        assert "Authorization" in kwargs["headers"]
        assert kwargs["headers"]["Authorization"].startswith("Basic ")
        # client_secret MUST NOT be present in body when Basic header is present
        assert "client_secret" not in kwargs["data"]
```

- [ ] **Step 2: Run test to verify failure**

Run: `.venv/bin/pytest tests/test_oauth_broker_and_auth_manager.py -k test_broker_does_not_duplicate_client_secret_in_body_when_basic_auth_used -v`
Expected: FAIL

- [ ] **Step 3: Fix `_post_token_request` in `oauth_broker.py`**

In `_post_token_request`:
```python
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if client_secret:
            basic_raw = f"{client_id}:{client_secret}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(basic_raw).decode('ascii')}"
            # RFC 6749 Section 2.3: do NOT duplicate client_secret in form body
```

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_oauth_broker_and_auth_manager.py -v`
Expected: PASS

---

### Task 4: Modularize Portal & OAuth Routes with Consent Page

**Files:**
- Create: `src/servicenow_mcp/auth/portal.py`
- Create: `src/servicenow_mcp/auth/oauth_routes.py`
- Test: `tests/test_oauth_routes.py`

- [ ] **Step 1: Write tests for OAuth consent page, async non-blocking execution, and refresh client_id check**

Create `tests/test_oauth_routes.py`:
- Test consent screen rendering on `GET /oauth/authorize` without `consent=true`.
- Test redirect on `GET /oauth/authorize?consent=true`.
- Test client_id matching on refresh grant.
- Test portal page HTML response includes `Cache-Control: no-store`.

- [ ] **Step 2: Create `src/servicenow_mcp/auth/portal.py`**

Extract `render_portal_html(mcp_token: str, base_url: str, user_hint: Optional[str] = None) -> HTMLResponse`:
- Add `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache`.
- HTML styling and copy button.

- [ ] **Step 3: Create `src/servicenow_mcp/auth/oauth_routes.py`**

Implement:
- `render_consent_html(client_name: str, client_id: str, redirect_uri: str, state: str, code_challenge: str, code_challenge_method: str) -> HTMLResponse`
- Async route handlers:
  - `oauth_protected_resource`
  - `oauth_authorization_server`
  - `oauth_register` (sanitized client name, whitelisted loopback / IDE redirect URIs)
  - `oauth_authorize`:
    - Validates PKCE `code_challenge_method == "S256"` strictly.
    - If `request.query_params.get("consent") != "true"`: returns consent HTML.
    - If `consent == "true"`: calls `await anyio.to_thread.run_sync(broker.build_authorize_url, ...)` and returns 302 redirect.
  - `oauth_callback`:
    - Calls `await anyio.to_thread.run_sync(broker.exchange_code_for_tokens, ...)` in background thread.
    - If downstream IDE auth: issues downstream code and redirects.
    - If portal auth: renders `render_portal_html`.
  - `oauth_token`:
    - For `authorization_code`: validates PKCE S256 verifier, returns session token + refresh token.
    - For `refresh_token`: checks `client_id` if present, calls `await anyio.to_thread.run_sync(broker.refresh_access_token, ...)`, computes remaining TTL directly `max(int(session.session_expires_at - time.time()), 0)`.
  - `auth_login`: redirects to `/oauth/authorize` with portal callback.
  - `auth_logout`: revokes session.

- [ ] **Step 4: Run tests to verify**

Run: `.venv/bin/pytest tests/test_oauth_routes.py -v`
Expected: PASS

---

### Task 5: Server Modularization, Bearer Auth Hardening & Origin Checking (`server_http.py`)

**Files:**
- Create: `src/servicenow_mcp/server_http.py` (migrated and modularized from `server_sse.py`)
- Create / Update: `src/servicenow_mcp/server_sse.py` (backward-compatibility wrapper)
- Modify: `pyproject.toml`
- Modify: `src/servicenow_mcp/utils/settings.py` (add `allow_bearer_passthrough`)
- Test: `tests/test_streamable_http.py`, `tests/test_server_sse_multiauth.py`, `tests/test_sse_auth.py`

- [ ] **Step 1: Write test for Bearer token validation and Origin checking on SSE**

Add to `tests/test_security_hardening.py`:
- `test_unrecognized_bearer_token_rejected_with_401`: Verifies that sending `Authorization: Bearer invalid_junk` is rejected with 401 when `ALLOW_BEARER_PASSTHROUGH` is false.
- `test_origin_header_validation_on_sse_and_messages`: Verifies cross-origin requests from disallowed origins are rejected with 403 on `/sse` and `/messages/`.

- [ ] **Step 2: Implement `src/servicenow_mcp/server_http.py`**

- In `MultiAuthMiddleware`:
  - Rule 5: Direct Bearer pass-through is ONLY accepted if `settings.allow_bearer_passthrough()` is `True` OR if the token is a well-formed JWT whose user hint can be extracted (`extract_jwt_user_hint(token) is not None`). Unrecognized opaque strings return `None` (resulting in HTTP 401).
- In `_is_allowed_origin`:
  - Validate `Origin` header on `/sse` and `/messages/` as well as `/mcp`. If invalid, return 403 Forbidden.
- In `_external_base_url`:
  - If `MCP_PUBLIC_URL` is unset and `X-Forwarded-Host` is used, log a warning: `"MCP_PUBLIC_URL is unset; falling back to X-Forwarded-Host. Set MCP_PUBLIC_URL in production."`
- In `server_sse.py`:
  - Re-export everything from `server_http.py` (`from servicenow_mcp.server_http import *`).
- In `pyproject.toml`:
  - Add `servicenow-mcp-http = "servicenow_mcp.server_http:main"`.

- [ ] **Step 3: Run all test suites to verify**

Run:
```bash
.venv/bin/pytest tests/test_multi_user_settings.py \
                 tests/test_session_context.py \
                 tests/test_session_store.py \
                 tests/test_oauth_broker_and_auth_manager.py \
                 tests/test_server_sse_multiauth.py \
                 tests/test_check_access.py \
                 tests/test_sse_auth.py \
                 tests/test_streamable_http.py \
                 tests/test_security_hardening.py -v
```
Expected: All tests PASS.

---

### Task 6: Documentation & Architecture Verification

**Files:**
- Modify: `README.md`
- Modify: `k8s/configmap.yaml`
- Modify: `.env.example`

- [ ] **Step 1: Update documentation**

In `README.md` and Kubernetes manifests:
- Document single-replica constraint: In-memory session store is scoped to a single process. Multi-replica deployments require sticky sessions or external store.
- Document `MCP_PUBLIC_URL` recommendation for production reverse-proxy deployments.
- Document `ALLOW_BEARER_PASSTHROUGH` and OAuth consent flow.

- [ ] **Step 2: Run all tests and commit & push to branch**

Run full test suite:
```bash
.venv/bin/pytest tests/test_multi_user_settings.py \
                 tests/test_session_context.py \
                 tests/test_session_store.py \
                 tests/test_oauth_broker_and_auth_manager.py \
                 tests/test_server_sse_multiauth.py \
                 tests/test_check_access.py \
                 tests/test_sse_auth.py \
                 tests/test_streamable_http.py \
                 tests/test_security_hardening.py -v
```
Commit and push to `origin/feature/centralized-multi-user-auth`.
Check PR #1 status.
