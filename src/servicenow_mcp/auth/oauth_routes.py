"""
OAuth 2.1 & Self-Service Token Portal HTTP Routes for Starlette/SSE Server.

Modular route definitions handling:
- RFC 9728 OAuth Protected Resource Metadata (/.well-known/oauth-protected-resource)
- RFC 8414 Authorization Server Metadata (/.well-known/oauth-authorization-server)
- RFC 7591 Dynamic Client Registration (/oauth/register)
- OAuth 2.1 Authorization Code + PKCE entry point (/oauth/authorize) with consent support
- OAuth Upstream IdP Callback (/oauth/callback)
- OAuth 2.1 Token Exchange & Refresh (/oauth/token)
- Interactive Developer Login Portal (/auth/login)
- Token Revocation / Logout (/auth/logout)
"""

import html
import json
import logging
import time
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, urlencode

import anyio.to_thread
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from servicenow_mcp.auth.oauth_broker import OAuthBroker, OAuthBrokerError
from servicenow_mcp.auth.portal import render_consent_response, render_portal_response
from servicenow_mcp.auth.session_context import CallerAuth
from servicenow_mcp.auth.session_store import (
    OAuthSessionStore,
    validate_client_redirect_uri,
    verify_pkce_challenge,
)
from servicenow_mcp.utils import settings

logger = logging.getLogger(__name__)


def create_oauth_routes(
    store: OAuthSessionStore,
    broker: Optional[OAuthBroker],
    external_base_url_fn: Callable[[Request], str],
) -> list[Route]:
    """
    Create all Starlette Routes for OAuth 2.1, OIDC Discovery, and the self-service developer portal.

    Args:
        store: OAuthSessionStore tracking active sessions, pending authorizations, and registered clients.
        broker: Upstream OAuthBroker resolving IdP endpoints and coordinating token requests.
        external_base_url_fn: Callable returning the public external base URL of the MCP server.

    Returns:
        list of Starlette Route objects.
    """

    async def oauth_protected_resource(request: Request) -> JSONResponse:
        base_url = external_base_url_fn(request)
        return JSONResponse(
            {
                "resource": base_url,
                "authorization_servers": [base_url],
                "bearer_methods_supported": ["header"],
            },
            headers={"Access-Control-Allow-Origin": "*"},
        )

    async def oauth_authorization_server(request: Request) -> JSONResponse:
        base_url = external_base_url_fn(request)
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
        response_type = params.get("response_type")
        if response_type != "code":
            return JSONResponse(
                {
                    "error": "unsupported_response_type",
                    "error_description": f"Unsupported response_type '{response_type}'. Only 'code' is supported.",
                },
                status_code=400,
            )

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

        client_name = client_id or "MCP Client"
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
            client_name = registered.client_name

        # Check interactive consent requirement
        needs_consent = settings.require_oauth_consent() or params.get("prompt") == "consent"
        consent_ticket = params.get("consent_ticket")
        is_consent_valid = False
        if needs_consent and consent_ticket:
            is_consent_valid = store.consume_consent_ticket(
                consent_ticket,
                client_id=client_id,
                redirect_uri=validated_redirect,
                code_challenge=code_challenge,
            )

        if needs_consent and not is_consent_valid:
            new_ticket = store.create_consent_ticket(
                client_id=client_id,
                redirect_uri=validated_redirect,
                code_challenge=code_challenge,
            )
            approve_params = dict(params)
            approve_params.pop("consent", None)
            approve_params["consent_ticket"] = new_ticket
            approve_url = f"/oauth/authorize?{urlencode(approve_params)}"

            deny_params = {"error": "access_denied", "error_description": "User denied authorization."}
            if downstream_state:
                deny_params["state"] = downstream_state
            sep = "&" if "?" in validated_redirect else "?"
            deny_url = f"{validated_redirect}{sep}{urlencode(deny_params)}"

            return render_consent_response(
                client_name=client_name,
                client_id=client_id or "unregistered",
                redirect_uri=validated_redirect,
                approve_url=approve_url,
                deny_url=deny_url,
            )

        pending = store.create_pending_auth(
            flow_type="mcp_oauth",
            client_id=client_id,
            redirect_uri=validated_redirect,
            downstream_state=downstream_state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        base_url = external_base_url_fn(request)
        callback_uri = f"{base_url}/oauth/callback"
        try:
            upstream_url = await broker.async_build_authorize_url(
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
        base_url = external_base_url_fn(request)
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
            upstream_url = await broker.async_build_authorize_url(
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
        base_url = external_base_url_fn(request)
        callback_uri = f"{base_url}/oauth/callback"
        try:
            token_resp = await broker.async_exchange_code_for_tokens(
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

        ttl = max(int(session.session_expires_at - time.time()), 60)
        return render_portal_response(
            base_url=base_url,
            mcp_token=session.mcp_token,
            expires_in=ttl,
            user_hint=session.user_hint,
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
                def _sync_refresh():
                    with session.refresh_lock:
                        return broker.refresh_access_token(session.refresh_token)

                try:
                    refreshed = await anyio.to_thread.run_sync(_sync_refresh)
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

    async def auth_logout(request: Request) -> Response:
        caller_auth: Optional[CallerAuth] = request.scope.get("caller_auth")
        session_id = caller_auth.session_id if caller_auth else None
        if not session_id:
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
                if token.startswith("mcp_"):
                    session_id = token
        if not session_id:
            body_bytes = await request.body()
            if body_bytes:
                content_type = (request.headers.get("content-type") or "").lower()
                if "application/x-www-form-urlencoded" in content_type:
                    form = parse_qs(body_bytes.decode("utf-8", errors="ignore"))
                    raw_tok = (form.get("token") or form.get("mcp_token") or [""])[0].strip()
                    if raw_tok.startswith("mcp_"):
                        session_id = raw_tok

        if session_id:
            store.revoke_session(session_id)

        accept = (request.headers.get("accept") or "").lower()
        if "text/html" in accept:
            return HTMLResponse(
                content=(
                    "<!DOCTYPE html><html><head><title>Logged Out</title></head>"
                    "<body style='font-family: -apple-system, BlinkMacSystemFont, sans-serif; "
                    "background: #0f172a; color: #f8fafc; padding: 3rem; text-align: center;'>"
                    "<h1>Logged Out</h1>"
                    "<p style='color: #94a3b8; margin: 1rem 0 2rem;'>Your ServiceNow MCP session has been revoked.</p>"
                    "<a href='/auth/login' style='color: #38bdf8; text-decoration: none; "
                    "background: #1e293b; padding: 0.75rem 1.5rem; border-radius: 8px; border: 1px solid #334155;'>Sign in again</a>"
                    "</body></html>"
                ),
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
                status_code=200,
            )
        return JSONResponse({"status": "logged_out"})

    return [
        Route("/.well-known/oauth-protected-resource", endpoint=oauth_protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", endpoint=oauth_authorization_server, methods=["GET"]),
        Route("/oauth/register", endpoint=oauth_register, methods=["POST"]),
        Route("/oauth/authorize", endpoint=oauth_authorize, methods=["GET"]),
        Route("/oauth/callback", endpoint=oauth_callback, methods=["GET"]),
        Route("/oauth/token", endpoint=oauth_token, methods=["POST"]),
        Route("/auth/login", endpoint=auth_login, methods=["GET"]),
        Route("/auth/logout", endpoint=auth_logout, methods=["POST"]),
    ]
