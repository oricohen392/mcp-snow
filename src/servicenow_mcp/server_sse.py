"""
Backward-compatible re-export module for ServiceNow MCP HTTP/SSE server.
The server has been renamed to server_http.py to reflect Streamable HTTP (/mcp) support.
"""

from servicenow_mcp.server_http import *  # noqa: F403
from servicenow_mcp.server_http import (
    ServiceNowHTTPMCP,
    ServiceNowSSEMCP,
    create_servicenow_mcp,
    create_starlette_app,
    main,
)

__all__ = [
    "ServiceNowHTTPMCP",
    "ServiceNowSSEMCP",
    "create_servicenow_mcp",
    "create_starlette_app",
    "main",
]
