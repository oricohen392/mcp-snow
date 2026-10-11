"""
Discovery tools: search_groups (find real assignment group names).
"""

import logging

from pydantic import BaseModel, Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.ticket_query import EMPTY_RESULT_HINT, display
from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import ServerConfig
from servicenow_mcp.utils.http import sn_get
from servicenow_mcp.utils.query import QueryBuilder, QueryInputError

logger = logging.getLogger(__name__)


class SearchGroupsParams(BaseModel):
    """Parameters for searching assignment groups."""

    name_part: str = Field(
        ...,
        description=(
            "Part of the group name, partial and case-insensitive (nameLIKE). "
            "Example: 'NOC' finds 'INOC_1', 'NOC Tier 2'. Use the returned exact 'name' "
            "with assignment_group_exact, or the fragment with assignment_group."
        ),
    )
    active_only: bool = Field(True, description="Only active groups (default true).")
    limit: int = Field(
        20,
        ge=1,
        description="Maximum groups to return (default 20, capped by the server's MAX_LIMIT).",
    )


def search_groups(
    config: ServerConfig, auth_manager: AuthManager, params: SearchGroupsParams
) -> dict:
    """Find sys_user_group records whose name contains name_part."""
    try:
        builder = QueryBuilder().like("name", params.name_part)
        if params.active_only:
            builder.eq("active", "true")
        query = builder.order_by("name").build()
    except QueryInputError as e:
        return {
            "success": False,
            "status_code": None,
            "error_type": "invalid_input",
            "message": f"Failed to search groups: {e}",
            "groups": [],
        }

    limit = min(params.limit, settings.max_limit())
    result = sn_get(
        config,
        auth_manager,
        "table/sys_user_group",
        {
            "sysparm_query": query,
            "sysparm_limit": limit,
            "sysparm_fields": "sys_id,name,description,active,manager,email",
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
        },
    )
    if not result.ok:
        response = result.error_dict("Failed to search groups")
        response.update({"groups": [], "query_used": query})
        return response

    groups = [
        {
            "sys_id": display(g.get("sys_id")),
            "name": display(g.get("name")),
            "description": display(g.get("description")),
            "active": display(g.get("active")),
            "manager": display(g.get("manager")),
            "email": display(g.get("email")),
        }
        for g in result.records
    ]
    response = {
        "success": True,
        "message": f"Found {len(groups)} groups",
        "groups": groups,
        "query_used": query,
        "total_count": result.total_count,
        "returned": len(groups),
        "limit": limit,
    }
    if not groups:
        response["hint"] = EMPTY_RESULT_HINT
    return response
