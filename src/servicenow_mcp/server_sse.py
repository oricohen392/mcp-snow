"""
ServiceNow MCP Server

This module provides the SSE (HTTP) entrypoint of the ServiceNow MCP server.

Endpoints:
    GET  /sse         event stream (MCP SSE transport)
    POST /messages/   client -> server messages (?session_id=...)
    GET  /healthz     liveness/readiness probe, no ServiceNow call, never authenticated

Security: if MCP_AUTH_TOKEN is set, /sse and /messages/ require
``Authorization: Bearer <MCP_AUTH_TOKEN>``. If it is NOT set the endpoints are
unauthenticated: anyone who can reach the port can call the tools with the
ServiceNow service account. Restrict network access (NetworkPolicy) in that case.
"""

import argparse
import hmac
import logging
import os
import sys
from typing import Dict, Optional, Union

import uvicorn
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from servicenow_mcp.server import ServiceNowMCP, ToolPackageConfigError
from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig
from servicenow_mcp.utils.logging_setup import configure_logging

logger = logging.getLogger(__name__)

HEALTH_PATH = "/healthz"


class BearerAuthMiddleware:
    """
    Pure ASGI middleware requiring 'Authorization: Bearer <token>'.

    Pure ASGI (not BaseHTTPMiddleware) so streaming SSE responses are not buffered.
    The health endpoint is exempt so Kubernetes probes work without the token.
    """

    def __init__(self, app, token: str, exempt_paths=(HEALTH_PATH,)):
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


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def create_starlette_app(
    mcp_server: Server, *, debug: bool = False, auth_token: Optional[str] = None
) -> Starlette:
    """Create a Starlette application that can serve the provided mcp server with SSE."""
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,  # noqa: SLF001
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                mcp_server.create_initialization_options(),
            )

    middleware = [Middleware(BearerAuthMiddleware, token=auth_token)] if auth_token else []
    return Starlette(
        debug=debug,
        routes=[
            Route(HEALTH_PATH, endpoint=healthz),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
        middleware=middleware,
    )


class ServiceNowSSEMCP(ServiceNowMCP):
    """
    ServiceNow MCP Server implementation.

    This class provides a Model Context Protocol (MCP) server for ServiceNow,
    allowing LLMs to interact with ServiceNow data and functionality.
    """

    def __init__(self, config: Union[Dict, ServerConfig]):
        """
        Initialize the ServiceNow MCP server.

        Args:
            config: Server configuration, either as a dictionary or ServerConfig object.
        """
        super().__init__(config)

    def start(self, host: str = "0.0.0.0", port: int = 8080):
        """
        Start the MCP server with SSE transport using Starlette and Uvicorn.

        Args:
            host: Host address to bind to
            port: Port to listen on
        """
        token = settings.mcp_auth_token()
        if token:
            logger.info("MCP_AUTH_TOKEN is set: /sse and /messages/ require a Bearer token.")
        else:
            logger.warning(
                "MCP_AUTH_TOKEN is not set: /sse and /messages/ are UNAUTHENTICATED. Anyone who "
                "can reach %s:%s can call the tools as the ServiceNow service account. Restrict "
                "access with a NetworkPolicy or set MCP_AUTH_TOKEN.",
                host,
                port,
            )

        # Create Starlette app with SSE transport (debug=False: no tracebacks to clients)
        starlette_app = create_starlette_app(self.mcp_server, debug=False, auth_token=token)

        # Run using uvicorn
        uvicorn.run(
            starlette_app,
            host=host,
            port=port,
            log_level=settings.log_level().lower(),
        )


def create_servicenow_mcp(
    instance_url: str, username: str, password: str, timeout: Optional[int] = None
):
    """
    Create a ServiceNow MCP server with minimal configuration.

    This is a simplified factory function that creates a pre-configured
    ServiceNow MCP server with basic authentication.

    Args:
        instance_url: ServiceNow instance URL
        username: ServiceNow username
        password: ServiceNow password
        timeout: HTTP timeout in seconds (default SERVICENOW_TIMEOUT or 30)

    Returns:
        A configured ServiceNowMCP instance ready to use

    Example:
        ```python
        from servicenow_mcp.server import create_servicenow_mcp

        # Create an MCP server for ServiceNow
        mcp = create_servicenow_mcp(
            instance_url="https://instance.service-now.com",
            username="admin",
            password="password"
        )

        # Start the server
        mcp.start()
        ```
    """

    # Create basic auth config
    auth_config = AuthConfig(
        type=AuthType.BASIC, basic=BasicAuthConfig(username=username, password=password)
    )

    # Create server config
    config = ServerConfig(
        instance_url=instance_url.rstrip("/"),
        auth=auth_config,
        timeout=timeout or settings.servicenow_timeout(),
    )

    # Create and return server
    return ServiceNowSSEMCP(config)


REQUIRED_ENV = ("SERVICENOW_INSTANCE_URL", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD")


def main():
    load_dotenv()
    configure_logging()

    # Parse command line arguments
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

    missing = [name for name in REQUIRED_ENV if not os.getenv(name, "").strip()]
    if missing:
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        sys.exit(2)

    try:
        server = create_servicenow_mcp(
            instance_url=os.environ["SERVICENOW_INSTANCE_URL"].strip(),
            username=os.environ["SERVICENOW_USERNAME"],
            password=os.environ["SERVICENOW_PASSWORD"],
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
