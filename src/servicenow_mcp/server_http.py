"""
ServiceNow MCP Server — Centralized Multi-User HTTP (/mcp and /sse) Entrypoint.

Endpoints:
    POST /mcp                                      Streamable HTTP MCP endpoint (JSON-RPC)
    GET  /mcp                                      SSE ping for Streamable HTTP clients
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
import json
import logging
import os
import sys
import uuid
from typing import Any, Dict, Optional, Set, Union
from urllib.parse import parse_qs, urlsplit

import mcp.types as types
import uvicorn
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import (
    JSONResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.auth.oauth_broker import OAuthBroker
from servicenow_mcp.auth.oauth_routes import create_oauth_routes
from servicenow_mcp.auth.session_context import (
    CallerAuth,
    SseSessionAuthRegistry,
    caller_auth_context,
    extract_jwt_user_hint,
    parse_basic_auth_username,
)
from servicenow_mcp.auth.session_store import OAuthSessionStore
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
    "/auth/logout",
}

_warned_mcp_public_url = False


def _log_mcp_public_url_warning_once() -> None:
    global _warned_mcp_public_url
    if not _warned_mcp_public_url:
        logger.warning(
            "MCP_PUBLIC_URL is not set. Falling back to Host/Forwarded headers. "
            "In production, setting MCP_PUBLIC_URL is strongly recommended to "
            "prevent host header injection."
        )
        _warned_mcp_public_url = True


def _external_base_url(request: Request) -> str:
    """Determine the external base URL of this MCP server from MCP_PUBLIC_URL or request headers."""
    configured = settings.mcp_public_url()
    if configured:
        return configured
    _log_mcp_public_url_warning_once()
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "http"
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
        or "localhost:8080"
    )
    return f"{proto}://{host}".rstrip("/")


def _external_base_url_from_scope(scope: Scope) -> str:
    configured = settings.mcp_public_url()
    if configured:
        return configured
    _log_mcp_public_url_warning_once()
    headers = Headers(scope=scope)
    proto = headers.get("x-forwarded-proto") or scope.get("scheme") or "http"
    host = headers.get("x-forwarded-host") or headers.get("host")
    if not host:
        server = scope.get("server")
        host = f"{server[0]}:{server[1]}" if server else "localhost:8080"
    return f"{proto}://{host}".rstrip("/")


def _is_allowed_origin_scope(origin: Optional[str], scope: Scope) -> bool:
    """Validate Origin header against allowed hosts to prevent DNS rebinding / CSRF."""
    if not origin:
        return True
    try:
        parsed = urlsplit(origin)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return False

    # Always allow local development loopback addresses
    if hostname in ("localhost", "127.0.0.1", "::1", "[::1]"):
        return True

    # If MCP_PUBLIC_URL is configured, strictly enforce its hostname (do not trust request Host)
    pub = settings.mcp_public_url()
    if pub:
        try:
            pub_hostname = (urlsplit(pub).hostname or "").lower()
            return hostname == pub_hostname
        except Exception:
            return False

    # When MCP_PUBLIC_URL is unset, fall back to matching the request Host
    headers = Headers(scope=scope)
    raw_host = headers.get("host") or ""
    try:
        req_host = (urlsplit(f"//{raw_host}").hostname or "").lower()
    except Exception:
        req_host = raw_host.split(":")[0].lower()
    return bool(req_host and hostname == req_host)


def _is_allowed_origin(origin: Optional[str], request: Request) -> bool:
    """Validate Origin header against allowed hosts to prevent DNS rebinding / CSRF."""
    return _is_allowed_origin_scope(origin, request.scope)


class BearerAuthMiddleware:
    """
    Legacy static bearer-token ASGI middleware kept for direct unit-test compatibility
    when ``create_starlette_app(mcp_server, auth_token=...)`` is called without multi-auth.
    """

    def __init__(
        self,
        app: Any,
        token: str,
        exempt_paths: Set[str] = PUBLIC_PATHS,
    ) -> None:
        self.app = app
        self._token = token.encode("utf-8")
        self._exempt = set(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
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


MAX_REQUEST_BODY_BYTES = 4 * 1024 * 1024  # 4 MB payload cap to prevent memory exhaustion DoS


class SecurityHeadersMiddleware:
    """
    Pure ASGI middleware injecting HTTP security hardening headers, enforcing Origin validation,
    and enforcing max body size.
    """

    def __init__(self, app: Any, max_body_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self._max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)

        # Enforce Origin check unconditionally across all HTTP requests
        origin = headers.get("origin")
        if origin and not _is_allowed_origin_scope(origin, scope):
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"Forbidden: Invalid Origin"})
            return

        cl_str = headers.get("content-length")
        if cl_str:
            try:
                if int(cl_str) > self._max_body_bytes:
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 413,
                            "headers": [
                                (b"content-type", b"application/json; charset=utf-8"),
                                (b"x-content-type-options", b"nosniff"),
                                (b"x-frame-options", b"DENY"),
                                (b"referrer-policy", b"no-referrer"),
                            ],
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": (
                                b'{"error":"payload_too_large",'
                                b'"message":"Payload exceeds 4MB limit"}'
                            ),
                        }
                    )
                    return
            except (ValueError, TypeError):
                pass

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                resp_headers = list(message.get("headers", []))
                resp_headers.append((b"x-content-type-options", b"nosniff"))
                resp_headers.append((b"x-frame-options", b"DENY"))
                resp_headers.append((b"referrer-policy", b"no-referrer"))
                resp_headers.append(
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self' 'unsafe-inline'; "
                        b"style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                    )
                )

                path = scope.get("path", "")
                if (
                    path in ("/mcp", "/sse", "/auth/login", "/auth/logout")
                    or path.startswith("/oauth/")
                    or path.startswith("/messages")
                ):
                    resp_headers.append((b"cache-control", b"no-store, no-cache, must-revalidate"))
                    resp_headers.append((b"pragma", b"no-cache"))

                proto = headers.get("x-forwarded-proto") or scope.get("scheme")
                if proto == "https":
                    resp_headers.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )

                message["headers"] = resp_headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


class MultiAuthMiddleware:
    """
    Pure ASGI middleware resolving per-user ServiceNow credentials or OAuth sessions.

    Pure ASGI (not BaseHTTPMiddleware) so streaming SSE responses are never buffered.
    """

    def __init__(
        self,
        app: Any,
        *,
        auth_manager: Optional[AuthManager] = None,
        session_store: Optional[OAuthSessionStore] = None,
        sse_registry: Optional[SseSessionAuthRegistry] = None,
        auth_token: Optional[str] = None,
        exempt_paths: Set[str] = PUBLIC_PATHS,
    ) -> None:
        self.app = app
        self.auth_manager = auth_manager
        self.session_store = session_store
        self.sse_registry = sse_registry or SseSessionAuthRegistry()
        self._static_token = auth_token
        self._exempt = set(exempt_paths)

    def _resolve_caller_auth(self, scope: Scope) -> Optional[CallerAuth]:
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
            jwt_hint = extract_jwt_user_hint(value)
            if jwt_hint is not None or settings.allow_bearer_passthrough():
                return CallerAuth(
                    headers={"Authorization": f"Bearer {value}"},
                    auth_source="bearer_passthrough",
                    user_hint=jwt_hint,
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

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
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
    """Create a Starlette application serving MCP over HTTP and SSE with multi-user auth."""
    sse = SseServerTransport("/messages/")
    sse_registry = SseSessionAuthRegistry()
    store = session_store or OAuthSessionStore(
        session_ttl_seconds=settings.session_ttl_seconds(),
        absolute_lifetime_seconds=settings.session_absolute_lifetime_seconds(),
    )
    broker = oauth_broker

    async def handle_mcp(request: Request) -> Response:
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
                        "instructions": (
                            "ServiceNow MCP server providing read-only and write tools."
                        ),
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
                        res_dict = server_res.root.model_dump(by_alias=True, exclude_none=True)
                        responses.append({"jsonrpc": "2.0", "id": msg_id, "result": res_dict})
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
                                types.CallToolRequest(method="tools/call", params=req_params)
                            )
                        res_dict = server_res.root.model_dump(by_alias=True, exclude_none=True)
                        responses.append({"jsonrpc": "2.0", "id": msg_id, "result": res_dict})
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
                logger.error(f"Error handling MCP method '{method}': {e}", exc_info=True)
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

    oauth_routes = create_oauth_routes(
        store=store,
        broker=broker,
        external_base_url_fn=_external_base_url,
    )

    use_multi_auth = require_auth or (auth_manager is not None)
    middleware = [Middleware(SecurityHeadersMiddleware)]
    if use_multi_auth:
        middleware.append(
            Middleware(
                MultiAuthMiddleware,
                auth_manager=auth_manager,
                session_store=store,
                sse_registry=sse_registry,
                auth_token=auth_token,
            )
        )
    elif auth_token:
        middleware.append(Middleware(BearerAuthMiddleware, token=auth_token))

    return Starlette(
        debug=debug,
        routes=[
            Route(HEALTH_PATH, endpoint=healthz),
            *oauth_routes,
            Route("/mcp", endpoint=handle_mcp, methods=["GET", "POST", "DELETE"]),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
        middleware=middleware,
    )


class ServiceNowHTTPMCP(ServiceNowMCP):
    """Centralized HTTP/SSE ServiceNow MCP Server with multi-user authentication."""

    def __init__(self, config: Union[Dict[str, Any], ServerConfig]) -> None:
        super().__init__(config)
        self.session_store = OAuthSessionStore(
            session_ttl_seconds=settings.session_ttl_seconds(),
            absolute_lifetime_seconds=settings.session_absolute_lifetime_seconds(),
        )
        self.oauth_broker = OAuthBroker(instance_url=self.config.instance_url)
        self.auth_manager.session_store = self.session_store
        self.auth_manager.oauth_broker = self.oauth_broker

    def start(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        if not settings.mcp_public_url():
            _log_mcp_public_url_warning_once()
        token = settings.mcp_auth_token()
        allow_fallback = settings.allow_service_account_fallback()
        if self.oauth_broker.is_configured():
            logger.info(
                "OAuth/OIDC login is enabled "
                "(/auth/login and /.well-known/oauth-authorization-server)."
            )
        if allow_fallback and self.auth_manager.has_service_account():
            if token:
                logger.info("Service-account fallback is ENABLED and gated by MCP_AUTH_TOKEN.")
            else:
                logger.warning(
                    "ALLOW_SERVICE_ACCOUNT_FALLBACK=true without MCP_AUTH_TOKEN: unauthenticated "
                    "requests will use the ServiceNow service account."
                )
        else:
            logger.info(
                "Per-user ServiceNow authentication is required "
                "(OAuth login, Bearer token, or API key)."
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


ServiceNowSSEMCP = ServiceNowHTTPMCP


def create_servicenow_mcp(
    instance_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: Optional[int] = None,
) -> ServiceNowHTTPMCP:
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
    return ServiceNowHTTPMCP(config)


def main() -> None:
    load_dotenv()
    configure_logging()

    parser = argparse.ArgumentParser(description="Run ServiceNow MCP HTTP/SSE server")
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
            "ALLOW_SERVICE_ACCOUNT_FALLBACK=true requires "
            "SERVICENOW_USERNAME and SERVICENOW_PASSWORD"
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
