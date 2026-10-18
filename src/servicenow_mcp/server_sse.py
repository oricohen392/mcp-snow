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
import time
import uuid
from typing import Any, Dict, Optional, Union
from urllib.parse import parse_qs, urlencode, urlsplit

import uvicorn
from dotenv import load_dotenv
import mcp.types as types
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
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


def _is_allowed_origin(origin: Optional[str], request: Request) -> bool:
    """Validate Origin header against allowed hosts to prevent DNS rebinding / CSRF."""
    if not origin:
        return True
    try:
        parsed = urlsplit(origin)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return False
    if hostname in ("localhost", "127.0.0.1", "::1", "[::1]"):
        return True
    req_host = (request.headers.get("host") or "").split(":")[0].lower()
    if req_host and hostname == req_host:
        return True
    pub = settings.mcp_public_url()
    if pub:
        try:
            pub_hostname = (urlsplit(pub).hostname or "").lower()
            if hostname == pub_hostname:
                return True
        except Exception:
            pass
    return False


def _render_portal_html(*, base_url: str, mcp_token: str, expires_in: int, user_hint: Optional[str]) -> str:
    safe_mcp_url = html.escape(f"{base_url}/mcp")
    safe_sse_url = html.escape(f"{base_url}/sse")
    safe_token = html.escape(mcp_token)
    safe_user = html.escape(user_hint or "Authenticated ServiceNow User")
    cursor_json = html.escape(
        json.dumps(
            {
                "mcpServers": {
                    "servicenow": {
                        "url": f"{base_url}/mcp",
                        "headers": {"Authorization": f"Bearer {mcp_token}"},
                    }
                }
            },
            indent=2,
        )
    )
    claude_json = html.escape(
        json.dumps(
            {
                "mcpServers": {
                    "servicenow": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote",
                            f"{base_url}/sse",
                            "--header",
                            f"Authorization: Bearer {mcp_token}",
                        ],
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ServiceNow MCP — Self-Service Token Portal</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0ea5e9;
      --code-bg: #0b1120;
      --badge-bg: #064e3b;
      --badge-text: #34d399;
      --btn-bg: #334155;
      --btn-hover: #475569;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: var(--bg);
      color: var(--text-main);
      line-height: 1.6;
      padding: 2.5rem 1rem;
    }}
    .container {{
      max-width: 860px;
      margin: 0 auto;
    }}
    header {{
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 1.5rem;
    }}
    .logo-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    h1 {{
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    .status-badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--badge-bg);
      color: var(--badge-text);
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 600;
    }}
    .status-dot {{
      width: 8px;
      height: 8px;
      background: var(--badge-text);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--badge-text);
    }}
    .user-info {{
      color: var(--text-muted);
      font-size: 0.95rem;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }}
    .card-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }}
    .card-title {{
      font-size: 1.15rem;
      font-weight: 600;
      color: var(--text-main);
    }}
    .copy-btn {{
      background: var(--btn-bg);
      color: var(--text-main);
      border: 1px solid var(--card-border);
      padding: 0.35rem 0.85rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }}
    .copy-btn:hover {{
      background: var(--btn-hover);
      border-color: var(--text-muted);
    }}
    .copy-btn.copied {{
      background: #064e3b;
      color: #34d399;
      border-color: #34d399;
    }}
    pre {{
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1rem;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      color: #e2e8f0;
      word-break: break-all;
      white-space: pre-wrap;
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--accent);
      background: rgba(56, 189, 248, 0.1);
      padding: 0.15rem 0.35rem;
      border-radius: 4px;
      font-size: 0.88em;
    }}
    pre code {{
      background: transparent;
      padding: 0;
      color: inherit;
    }}
    .meta-list {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 1rem;
    }}
    .meta-item {{
      background: var(--code-bg);
      padding: 0.75rem 1rem;
      border-radius: 8px;
      border: 1px solid var(--card-border);
    }}
    .meta-label {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.25rem;
    }}
    .meta-val {{
      font-family: ui-monospace, monospace;
      font-size: 0.9rem;
      word-break: break-all;
    }}
    .instructions {{
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
    }}
    .logout-bar {{
      display: flex;
      justify-content: flex-end;
      margin-top: 2rem;
    }}
    .logout-btn {{
      background: transparent;
      color: #f87171;
      border: 1px solid #7f1d1d;
      padding: 0.5rem 1.25rem;
      border-radius: 6px;
      font-size: 0.9rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .logout-btn:hover {{
      background: #7f1d1d;
      color: #fef2f2;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-row">
        <h1>ServiceNow MCP Server</h1>
        <div class="status-badge">
          <div class="status-dot"></div>
          Connected
        </div>
      </div>
      <p class="user-info">
        Signed in as <strong>{safe_user}</strong> • Session active for <strong>{int(expires_in)}s</strong> • Upstream token automatically refreshed
      </p>
    </header>

    <div class="card">
      <div class="card-header">
        <span class="card-title">1. Web AI Platforms (Dify / OpenWebUI / Agents)</span>
        <button class="copy-btn" onclick="copyText('{safe_token}', this)">Copy Token</button>
      </div>
      <p class="instructions">Use these values when configuring the MCP tool in Dify or your agent framework:</p>
      <div class="meta-list">
        <div class="meta-item">
          <div class="meta-label">Streamable HTTP URL (Recommended)</div>
          <div class="meta-val">{safe_mcp_url}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Server SSE URL (Legacy)</div>
          <div class="meta-val">{safe_sse_url}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Authorization Header</div>
          <div class="meta-val">Bearer {safe_token[:16]}...</div>
        </div>
      </div>
      <pre><code>{safe_token}</code></pre>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">2. Cursor & Windsurf Configuration</span>
        <button class="copy-btn" onclick="copyId('cursor-code', this)">Copy JSON</button>
      </div>
      <p class="instructions">Paste this into your <code>~/.cursor/mcp.json</code> or workspace <code>.cursor/mcp.json</code>:</p>
      <pre id="cursor-code"><code>{cursor_json}</code></pre>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">3. Claude Desktop Configuration</span>
        <button class="copy-btn" onclick="copyId('claude-code', this)">Copy JSON</button>
      </div>
      <p class="instructions">Paste this into <code>~/Library/Application Support/Claude/claude_desktop_config.json</code>:</p>
      <pre id="claude-code"><code>{claude_json}</code></pre>
    </div>

    <div class="logout-bar">
      <form action="/auth/logout" method="post">
        <button type="submit" class="logout-btn">Log Out & Revoke Token</button>
      </form>
    </div>
  </div>

  <script>
    function copyText(text, btn) {{
      navigator.clipboard.writeText(text).then(() => {{
        const original = btn.innerText;
        btn.innerText = "Copied!";
        btn.classList.add("copied");
        setTimeout(() => {{
          btn.innerText = original;
          btn.classList.remove("copied");
        }}, 2000);
      }});
    }}
    function copyId(id, btn) {{
      const el = document.getElementById(id);
      if (el) {{
        copyText(el.innerText, btn);
      }}
    }}
  </script>
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

    async def handle_mcp(request: Request) -> Response:
        origin = request.headers.get("origin")
        if not _is_allowed_origin(origin, request):
            return Response("Forbidden: Invalid Origin", status_code=403)

        caller_auth: Optional[CallerAuth] = request.scope.get("caller_auth")

        if request.method == "GET":
            accept = request.headers.get("accept", "")
            if "text/event-stream" not in accept:
                return Response(
                    "Method Not Allowed: GET requires Accept: text/event-stream",
                    status_code=405,
                )

            async def sse_ping():
                yield b": connected\n\n"

            return StreamingResponse(sse_ping(), media_type="text/event-stream")

        if request.method == "DELETE":
            return Response(status_code=204)

        if request.method != "POST":
            return Response("Method Not Allowed", status_code=405)

        try:
            body_bytes = await request.body()
            if not body_bytes:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Empty body"},
                    },
                    status_code=400,
                )
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception as e:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                },
                status_code=400,
            )

        session_id = request.headers.get("mcp-session-id") or uuid.uuid4().hex

        is_batch = isinstance(payload, list)
        messages = payload if is_batch else [payload]
        responses = []

        for msg in messages:
            if not isinstance(msg, dict):
                responses.append(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32600,
                            "message": "Invalid Request: message must be an object",
                        },
                    }
                )
                continue

            method = msg.get("method")
            msg_id = msg.get("id")

            # Notification handling (no id)
            if msg_id is None:
                continue

            try:
                if method == "initialize":
                    res = {
                        "protocolVersion": types.LATEST_PROTOCOL_VERSION,
                        "capabilities": {
                            "experimental": {},
                            "tools": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": mcp_server.name,
                            "version": "0.1.0",
                        },
                        "instructions": "ServiceNow MCP server providing read-only and write tools.",
                    }
                    responses.append({"jsonrpc": "2.0", "id": msg_id, "result": res})
                elif method == "ping":
                    responses.append({"jsonrpc": "2.0", "id": msg_id, "result": {}})
                elif method == "tools/list":
                    list_handler = mcp_server.request_handlers.get(types.ListToolsRequest)
                    if not list_handler:
                        responses.append(
                            {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32601,
                                    "message": "tools/list handler not configured",
                                },
                            }
                        )
                    else:
                        with caller_auth_context(caller_auth):
                            req_obj = types.ListToolsRequest(
                                method="tools/list",
                                params=msg.get("params"),
                            )
                            server_res = await list_handler(req_obj)
                        res_dict = server_res.root.model_dump(
                            by_alias=True, exclude_none=True
                        )
                        responses.append(
                            {"jsonrpc": "2.0", "id": msg_id, "result": res_dict}
                        )
                elif method == "tools/call":
                    call_handler = mcp_server.request_handlers.get(types.CallToolRequest)
                    if not call_handler:
                        responses.append(
                            {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32601,
                                    "message": "tools/call handler not configured",
                                },
                            }
                        )
                    else:
                        params = msg.get("params") or {}
                        req_params = types.CallToolRequestParams(**params)
                        with caller_auth_context(caller_auth):
                            server_res = await call_handler(
                                types.CallToolRequest(
                                    method="tools/call", params=req_params
                                )
                            )
                        res_dict = server_res.root.model_dump(
                            by_alias=True, exclude_none=True
                        )
                        responses.append(
                            {"jsonrpc": "2.0", "id": msg_id, "result": res_dict}
                        )
                else:
                    responses.append(
                        {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32601,
                                "message": f"Method '{method}' not found",
                            },
                        }
                    )
            except Exception as e:
                logger.error(
                    f"Error handling MCP method '{method}': {e}", exc_info=True
                )
                responses.append(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32603, "message": str(e)},
                    }
                )

        if not responses and not is_batch:
            return Response(status_code=202, headers={"mcp-session-id": session_id})

        output_payload = responses if is_batch else (responses[0] if responses else {})

        accept = request.headers.get("accept", "")
        if "text/event-stream" in accept and "application/json" not in accept:
            sse_content = f"event: message\ndata: {json.dumps(output_payload)}\n\n"
            return Response(
                sse_content,
                media_type="text/event-stream; charset=utf-8",
                headers={"mcp-session-id": session_id},
            )

        return JSONResponse(output_payload, headers={"mcp-session-id": session_id})

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
            },
            headers={"Access-Control-Allow-Origin": "*"},
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
            },
            headers={"Access-Control-Allow-Origin": "*"},
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
        if client_id:
            registered = store.get_client(client_id)
            if not registered:
                return JSONResponse(
                    {"error": "invalid_client", "error_description": f"Unknown client_id '{client_id}'."},
                    status_code=400,
                )
            if validated_redirect not in registered.redirect_uris:
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
        content_type = (request.headers.get("content-type") or "").lower()
        body_bytes = await request.body()
        data: Dict[str, Any] = {}
        if "application/json" in content_type:
            try:
                data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception:
                data = {}
        else:
            qs = parse_qs(body_bytes.decode("utf-8", errors="ignore"))
            data = {k: v[0] for k, v in qs.items() if v}

        grant_type = str(data.get("grant_type") or "")

        if grant_type == "authorization_code":
            code = str(data.get("code") or "")
            code_verifier = str(data.get("code_verifier") or "")
            redirect_uri = str(data.get("redirect_uri") or "")
            issued = store.consume_auth_code(code)
            if issued is None:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "Invalid or expired code."},
                    status_code=400,
                )
            if issued.redirect_uri and (not redirect_uri or issued.redirect_uri != redirect_uri):
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "redirect_uri mismatch or missing."},
                    status_code=400,
                )
            client_id = str(data.get("client_id") or "")
            if issued.client_id and client_id and issued.client_id != client_id:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "client_id mismatch."},
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
                    "expires_in": max(int(session.session_expires_at - time.time()), 60),
                    "refresh_token": session.downstream_refresh_token,
                }
            )

        if grant_type == "refresh_token":
            refresh_tok = str(data.get("refresh_token") or "")
            session = store.get_session_by_downstream_refresh_token(refresh_tok)
            if session is None:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "Unknown refresh_token."},
                    status_code=400,
                )
            if session.refresh_token and broker is not None and broker.is_configured():
                with session.refresh_lock:
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
                    "expires_in": max(int(session.session_expires_at - time.time()), 60),
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
            Route("/mcp", endpoint=handle_mcp, methods=["GET", "POST", "DELETE"]),
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
