"""
Discovery tools: search_groups (find real assignment group names) and
check_access (who are we, and what can this account see per table).
"""

import logging
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.ticket_query import EMPTY_RESULT_HINT, display, group_name_query
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
            "Part of the group name, partial and case-insensitive. Every word must appear "
            "in the name, in any order: 'NOC' finds 'INOC_1' and 'NOC Tier 2'; 'cloud infra' "
            "finds 'Infrastructure - Cloud'. Use the returned exact 'name' with "
            "assignment_group_exact, or the fragment with assignment_group."
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
        query = group_name_query(params.name_part, params.active_only).build()
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


ACCESS_CHECK_TABLES = (
    "incident",
    "change_request",
    "sc_request",
    "sc_req_item",
    "sys_user_group",
    "sys_choice",
)


class CheckAccessParams(BaseModel):
    """check_access takes no parameters."""


def _user_identity(config: ServerConfig, auth_manager: AuthManager) -> dict:
    auth = getattr(config, "auth", None)
    basic = getattr(auth, "basic", None)
    username = getattr(basic, "username", None)
    if not username:
        oauth = getattr(auth, "oauth", None)
        username = getattr(oauth, "username", None)
    auth_type = getattr(auth, "type", None)
    identity = {
        "configured_username": username,
        "auth_type": getattr(auth_type, "value", str(auth_type)),
    }
    if not username:
        identity["verified"] = False
        identity["note"] = "No username configured (API key / client credentials); identity unknown."
        return identity

    try:
        query = QueryBuilder().eq("user_name", username).build()
    except QueryInputError as e:
        identity["verified"] = False
        identity["note"] = str(e)
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


def check_access(
    config: ServerConfig, auth_manager: AuthManager, params: CheckAccessParams = None
) -> dict:
    """Report who the server authenticates as and what each ITSM table shows to that account."""
    tables = {}
    any_unauthorized = False
    first_error = None
    for table in ACCESS_CHECK_TABLES:
        result = sn_get(
            config,
            auth_manager,
            f"table/{table}",
            {"sysparm_limit": 1, "sysparm_fields": "sys_id"},
        )
        entry = {"status_code": result.status_code, "readable": result.ok}
        if result.ok:
            entry["visible_count"] = result.total_count
            if not result.total_count:
                entry["note"] = (
                    "Readable but 0 visible rows: the table is empty, or row-level ACLs / "
                    "domain separation hide every row from this account."
                )
        else:
            entry["error_type"] = result.error_type
            entry["note"] = result.message
            any_unauthorized = any_unauthorized or result.error_type == "unauthorized"
            first_error = first_error or result
        tables[table] = entry

    host = urlsplit(getattr(config, "instance_url", "") or "").hostname
    reachable = any(entry["readable"] for entry in tables.values())
    response = {
        "success": reachable,
        "instance_host": host,
        "authenticated": reachable and not any_unauthorized,
        "tables": tables,
    }
    if reachable:
        response["user"] = _user_identity(config, auth_manager)
        response["message"] = (
            "visible_count comes from X-Total-Count for an unfiltered query and is what this "
            "account can see, not necessarily the whole table."
        )
    else:
        # Nothing readable at all: report it as a real failure, not as "0 rows".
        response.update(first_error.error_dict("check_access failed for every table"))
        response["success"] = False
    return response
