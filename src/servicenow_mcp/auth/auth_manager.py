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

    This class handles authentication with the ServiceNow API using
    per-user request context (CallerAuth) or service-account fallback.
    """

    def __init__(
        self,
        config: AuthConfig,
        instance_url: Optional[str] = None,
        session_store: Optional[OAuthSessionStore] = None,
        oauth_broker: Optional[OAuthBroker] = None,
    ):
        """
        Initialize the authentication manager.

        Args:
            config: Authentication configuration.
            instance_url: ServiceNow instance URL.
            session_store: Optional store for centralized OAuth/OIDC user sessions.
            oauth_broker: Optional upstream OAuth/OIDC broker for token refresh.
        """
        self.config = config
        self.instance_url = instance_url
        self.session_store = session_store
        self.oauth_broker = oauth_broker
        self.token: Optional[str] = None
        self.token_type: Optional[str] = None

    def has_service_account(self) -> bool:
        """Return True when a fallback service account is configured."""
        return self.config is not None and self.config.type != AuthType.NONE

    def get_headers(self) -> Dict[str, str]:
        """
        Get the authentication headers for API requests.

        Returns:
            Dict[str, str]: Headers to include in API requests.
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
                        "OAuth session has expired or was not found. Please re-authenticate via /auth/login."
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
                                updated = self.session_store.update_session_tokens(
                                    session.mcp_token,
                                    access_token=refreshed.access_token,
                                    refresh_token=refreshed.refresh_token,
                                    token_type=refreshed.token_type,
                                    expires_in=refreshed.expires_in,
                                    user_hint=refreshed.user_hint,
                                )
                                if updated is not None:
                                    session = updated
                            except OAuthBrokerError as exc:
                                raise ValueError(
                                    f"Failed to refresh expiring OAuth access token: {exc}"
                                ) from exc

                headers["Authorization"] = f"{session.token_type} {session.access_token}"
                return headers

            headers.update(caller_auth.headers)
            return headers

        if self.config.type == AuthType.NONE:
            raise ValueError(
                "Per-user authentication is required; no user credentials found in request context "
                "and no service account fallback is active."
            )

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

        # Determine token URL
        token_url = oauth_config.token_url
        if not token_url:
            if not self.instance_url:
                raise ValueError("Instance URL is required for OAuth authentication")
            token_url = f"{self.instance_url.rstrip('/')}/oauth_token.do"

        # Prepare Authorization header
        auth_str = f"{oauth_config.client_id}:{oauth_config.client_secret}"
        auth_header = base64.b64encode(auth_str.encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Try client_credentials grant first
        data_client_credentials = {
            "grant_type": "client_credentials"
        }

        logger.debug("Attempting client_credentials grant...")
        response = requests.post(
            token_url,
            headers=headers,
            data=data_client_credentials,
            timeout=settings.servicenow_timeout(),
            verify=settings.tls_verify(),
        )

        # Never log the response body: it contains the access token.
        logger.debug(f"client_credentials response status: {response.status_code}")

        if response.status_code == 200:
            token_data = response.json()
            self.token = token_data.get("access_token")
            self.token_type = token_data.get("token_type", "Bearer")
            return

        # Try password grant if client_credentials failed
        if oauth_config.username and oauth_config.password:
            data_password = {
                "grant_type": "password",
                "username": oauth_config.username,
                "password": oauth_config.password
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

        raise ValueError("Failed to get OAuth token using both client_credentials and password grants.")

    def refresh_token(self):
        """Refresh the OAuth token if using OAuth authentication."""
        if self.config.type == AuthType.OAUTH:
            self._get_oauth_token()
