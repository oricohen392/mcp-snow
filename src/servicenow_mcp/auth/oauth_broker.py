"""
Upstream OAuth 2.0 / OIDC broker for ServiceNow and external Identity Providers.

Supports:
- OIDC Discovery (`{OIDC_ISSUER_URL}/.well-known/openid-configuration`) with TTL caching
- ServiceNow native OAuth endpoints (`{instance_url}/oauth_auth.do` & `/oauth_token.do`)
- Explicit endpoint overrides (`OAUTH_AUTHORIZE_URL` & `OAUTH_TOKEN_URL`)
- Authorization URL construction with PKCE (S256)
- Authorization code exchange and refresh token grant
"""

import base64
import functools
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import quote_plus, urlencode

import anyio.to_thread
import requests

from servicenow_mcp.auth.session_context import extract_jwt_user_hint
from servicenow_mcp.utils import settings

logger = logging.getLogger(__name__)


class OAuthBrokerError(RuntimeError):
    """Raised when upstream OAuth/OIDC discovery or token exchange fails."""


@dataclass(frozen=True)
class OAuthEndpoints:
    """Resolved upstream OAuth 2.0 / OIDC authorization and token endpoints."""

    authorization_endpoint: str
    token_endpoint: str
    issuer: Optional[str] = None


@dataclass(frozen=True)
class UpstreamTokenResponse:
    """Normalized token response from the upstream OAuth / OIDC token endpoint."""

    access_token: str = field(repr=False)
    refresh_token: Optional[str] = field(repr=False, default=None)
    token_type: str = "Bearer"
    expires_in: int = 1800
    user_hint: Optional[str] = None


class OAuthBroker:
    """
    Coordinates OAuth 2.0 Authorization Code + PKCE and Refresh Token flows
    against either an external OIDC Identity Provider or ServiceNow's native OAuth server.
    """

    def __init__(self, instance_url: Optional[str] = None, discovery_ttl_seconds: int = 3600):
        self.instance_url = (instance_url or "").strip().rstrip("/")
        self._discovery_ttl = discovery_ttl_seconds
        self._lock = threading.Lock()
        self._cached_discovery: Optional[tuple[str, OAuthEndpoints, float]] = None

    def is_configured(self) -> bool:
        """Return True when OAUTH_CLIENT_ID and an upstream endpoint source are configured."""
        client_id = settings.oauth_client_id()
        if not client_id:
            return False
        has_endpoints = bool(
            self.instance_url
            or settings.oidc_issuer_url()
            or (settings.oauth_authorize_url() and settings.oauth_token_url())
        )
        return has_endpoints

    def default_scopes(self) -> Optional[str]:
        """Return configured OAUTH_SCOPES, or default OIDC scopes when OIDC_ISSUER_URL is set."""
        configured = settings.oauth_scopes()
        if configured:
            return configured
        if settings.oidc_issuer_url():
            return "openid profile email"
        return None

    def get_endpoints(self) -> OAuthEndpoints:
        """
        Resolve upstream authorization and token endpoints.

        Priority:
        1. Explicit OAUTH_AUTHORIZE_URL and OAUTH_TOKEN_URL overrides
        2. OIDC Discovery from {OIDC_ISSUER_URL}/.well-known/openid-configuration (cached)
        3. ServiceNow native /oauth_auth.do and /oauth_token.do on instance_url
        """
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
            discovered = self._discover_oidc_endpoints(issuer)
            return OAuthEndpoints(
                authorization_endpoint=explicit_auth or discovered.authorization_endpoint,
                token_endpoint=explicit_token or discovered.token_endpoint,
                issuer=issuer,
            )

        if not self.instance_url and not (explicit_auth and explicit_token):
            raise OAuthBrokerError(
                "Cannot resolve OAuth endpoints: configure SERVICENOW_INSTANCE_URL, "
                "OIDC_ISSUER_URL, or OAUTH_AUTHORIZE_URL and OAUTH_TOKEN_URL."
            )

        return OAuthEndpoints(
            authorization_endpoint=explicit_auth or f"{self.instance_url}/oauth_auth.do",
            token_endpoint=explicit_token or f"{self.instance_url}/oauth_token.do",
            issuer=None,
        )

    def _discover_oidc_endpoints(self, issuer: str) -> OAuthEndpoints:
        now = time.monotonic()
        with self._lock:
            if self._cached_discovery is not None:
                cached_issuer, cached_endpoints, expires_at = self._cached_discovery
                if cached_issuer == issuer and now < expires_at:
                    return cached_endpoints

        discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        try:
            response = requests.get(
                discovery_url,
                timeout=settings.servicenow_timeout(),
                verify=settings.tls_verify(),
            )
        except requests.RequestException as exc:
            raise OAuthBrokerError(
                f"Failed to fetch OIDC discovery document from {discovery_url}: {exc}"
            ) from exc

        if response.status_code != 200:
            raise OAuthBrokerError(
                f"OIDC discovery endpoint {discovery_url} returned HTTP {response.status_code}"
            )

        try:
            doc = response.json()
        except ValueError as exc:
            raise OAuthBrokerError(
                f"OIDC discovery endpoint {discovery_url} returned invalid JSON"
            ) from exc

        auth_ep = doc.get("authorization_endpoint") if isinstance(doc, dict) else None
        token_ep = doc.get("token_endpoint") if isinstance(doc, dict) else None
        if not auth_ep or not token_ep:
            raise OAuthBrokerError(
                f"OIDC discovery document at {discovery_url} is missing "
                "authorization_endpoint or token_endpoint"
            )

        endpoints = OAuthEndpoints(
            authorization_endpoint=str(auth_ep),
            token_endpoint=str(token_ep),
            issuer=issuer,
        )
        with self._lock:
            self._cached_discovery = (issuer, endpoints, time.monotonic() + self._discovery_ttl)
        return endpoints

    def build_authorize_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
        scope: Optional[str] = None,
    ) -> str:
        """Build the upstream browser authorization URL."""
        client_id = settings.oauth_client_id()
        if not client_id:
            raise OAuthBrokerError("OAUTH_CLIENT_ID is not configured")

        endpoints = self.get_endpoints()
        params: Dict[str, str] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method or "S256"

        effective_scope = scope if scope is not None else self.default_scopes()
        if effective_scope:
            params["scope"] = effective_scope

        separator = "&" if "?" in endpoints.authorization_endpoint else "?"
        return f"{endpoints.authorization_endpoint}{separator}{urlencode(params)}"

    def exchange_code_for_tokens(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> UpstreamTokenResponse:
        """Exchange an authorization code for upstream access and refresh tokens."""
        if not code:
            raise OAuthBrokerError("Authorization code is required")
        data: Dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        return self._post_token_request(data)

    def refresh_access_token(self, refresh_token: str) -> UpstreamTokenResponse:
        """Exchange a refresh_token for a fresh upstream access_token."""
        if not refresh_token:
            raise OAuthBrokerError("refresh_token is required")
        data: Dict[str, Any] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        return self._post_token_request(data, fallback_refresh_token=refresh_token)

    async def async_get_endpoints(self) -> OAuthEndpoints:
        """Resolve upstream authorization and token endpoints asynchronously."""
        return await anyio.to_thread.run_sync(self.get_endpoints)

    async def async_build_authorize_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
        scope: Optional[str] = None,
    ) -> str:
        """Build the upstream browser authorization URL asynchronously."""
        func = functools.partial(
            self.build_authorize_url,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
        )
        return await anyio.to_thread.run_sync(func)

    async def async_exchange_code_for_tokens(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> UpstreamTokenResponse:
        """Exchange an authorization code asynchronously without blocking the event loop."""
        func = functools.partial(
            self.exchange_code_for_tokens,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        return await anyio.to_thread.run_sync(func)

    async def async_refresh_access_token(self, refresh_token: str) -> UpstreamTokenResponse:
        """Exchange a refresh_token for a fresh access_token asynchronously."""
        return await anyio.to_thread.run_sync(self.refresh_access_token, refresh_token)


    def _post_token_request(
        self,
        data: Dict[str, Any],
        fallback_refresh_token: Optional[str] = None,
    ) -> UpstreamTokenResponse:
        client_id = settings.oauth_client_id()
        if not client_id:
            raise OAuthBrokerError("OAUTH_CLIENT_ID is not configured")
        client_secret = settings.oauth_client_secret()

        endpoints = self.get_endpoints()
        form_data = dict(data)
        form_data["client_id"] = client_id

        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if client_secret:
            quoted_id = quote_plus(client_id)
            quoted_secret = quote_plus(client_secret)
            basic_raw = f"{quoted_id}:{quoted_secret}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(basic_raw).decode('ascii')}"

        try:
            response = requests.post(
                endpoints.token_endpoint,
                headers=headers,
                data=form_data,
                timeout=settings.servicenow_timeout(),
                verify=settings.tls_verify(),
            )
        except requests.RequestException as exc:
            raise OAuthBrokerError(f"Upstream token request failed: {exc}") from exc

        logger.debug("Upstream token endpoint returned HTTP %s", response.status_code)
        if response.status_code != 200:
            raise OAuthBrokerError(
                f"Upstream token endpoint rejected request with HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise OAuthBrokerError("Upstream token endpoint returned non-JSON response") from exc

        if not isinstance(payload, dict) or not payload.get("access_token"):
            raise OAuthBrokerError("Upstream token response did not include an access_token")

        access_token = str(payload["access_token"])
        refresh_token_val = payload.get("refresh_token") or fallback_refresh_token
        refresh_token = str(refresh_token_val) if refresh_token_val else None
        token_type = str(payload.get("token_type") or "Bearer")

        expires_in_raw = payload.get("expires_in", 1800)
        try:
            expires_in = int(expires_in_raw)
        except (TypeError, ValueError):
            expires_in = 1800

        id_token = payload.get("id_token")
        raw_user_name = payload.get("user_name")
        user_name_val = (
            raw_user_name.strip()
            if isinstance(raw_user_name, str) and raw_user_name.strip()
            else None
        )
        user_hint = (
            (extract_jwt_user_hint(id_token) if isinstance(id_token, str) else None)
            or extract_jwt_user_hint(access_token)
            or user_name_val
        )

        return UpstreamTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type,
            expires_in=expires_in,
            user_hint=user_hint,
        )
