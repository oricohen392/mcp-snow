"""
count_records: exact counts (optionally grouped) for the task tables through
the Aggregate API, with a plain-language description of what was counted.

Counting through a list tool (limit + total_count of a filtered list) is how
an LLM ends up reporting "1598 incidents ever" for "1598 open incidents"; this
tool counts every state by default and says so in scope_description.
"""

import dataclasses
import logging
from typing import Any, Dict, Optional

from pydantic import Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.ticket_query import (
    CHANGE_REQUEST,
    INCIDENT,
    INCIDENT_SCOPE_NOTE,
    SC_REQ_ITEM,
    SC_REQUEST,
    GroupLookupError,
    TaskFilterParams,
    aggregate_count,
    build_query,
    choice_description,
    query_error_response,
    status_scope_description,
)
from servicenow_mcp.utils.config import ServerConfig
from servicenow_mcp.utils.query import QueryInputError

logger = logging.getLogger(__name__)

COUNT_TABLES = {
    spec.table: spec for spec in (INCIDENT, CHANGE_REQUEST, SC_REQUEST, SC_REQ_ITEM)
}
CHOICE_FILTERS = ("state", "priority", "category", "type", "risk", "request_state", "stage")
GROUP_BY_REFERENCES = ("assignment_group", "assigned_to")

LOW_COUNT_NOTE = (
    "Counts only include records the ServiceNow account of this server can read: ACLs, "
    "domain separation and query business rules (for example, without the itil role the "
    "incident query rule limits a user to its own incidents) reduce them without an error. "
    "If the number looks too low, run check_access and compare visible_count and roles."
)


class CountRecordsParams(TaskFilterParams):
    """Parameters for counting task records."""

    table: str = Field(
        "incident",
        description=(
            "What to count: 'incident', 'change_request' (changes / activities), "
            "'sc_request' (REQ) or 'sc_req_item' (RITM). Default 'incident'."
        ),
    )
    status_scope: Optional[str] = Field(
        None,
        description=status_scope_description(
            "all", " For counts the default is 'all' on every table." + INCIDENT_SCOPE_NOTE
        ),
    )
    group_by: Optional[str] = Field(
        None,
        description=(
            "Optional breakdown: 'state', 'priority', 'assignment_group', 'assigned_to', "
            "'category' (incident, change_request), 'type' or 'risk' (change_request), "
            "'request_state' (sc_request), 'stage' (sc_req_item). Returns one count per value."
        ),
    )
    number: Optional[str] = Field(
        None, description="Exact record number(s), comma-separated, e.g. 'INC0010001'."
    )
    state: Optional[str] = Field(
        None, description=choice_description("state", "Examples: 'New', 'In Progress', '2'.")
    )
    priority: Optional[str] = Field(
        None, description=choice_description("priority", "Examples: '1 - Critical', 'High', '1'.")
    )
    category: Optional[str] = Field(
        None, description=choice_description("category", "incident and change_request only.")
    )
    type: Optional[str] = Field(
        None, description=choice_description("change type", "change_request only, e.g. 'normal'.")
    )
    risk: Optional[str] = Field(
        None, description=choice_description("risk", "change_request only, e.g. 'High'.")
    )
    request_state: Optional[str] = Field(
        None, description=choice_description("request_state", "sc_request only, e.g. 'Approved'.")
    )
    stage: Optional[str] = Field(
        None, description=choice_description("stage", "sc_req_item only, e.g. 'Fulfillment'.")
    )


def _username(config: Any) -> Optional[str]:
    auth = getattr(config, "auth", None)
    for kind in ("basic", "oauth"):
        username = getattr(getattr(auth, kind, None), "username", None)
        if username:
            return username
    return None


def _invalid(message: str) -> Dict[str, Any]:
    return {
        "success": False,
        "status_code": None,
        "error_type": "invalid_input",
        "message": f"Cannot count records: {message}",
    }


def count_records(
    config: ServerConfig, auth_manager: AuthManager, params: CountRecordsParams
) -> Dict[str, Any]:
    """Count records of one task table matching the filters."""
    table = (params.table or "").strip().lower()
    spec = COUNT_TABLES.get(table)
    if spec is None:
        return _invalid(f"table '{params.table}' is not supported. Allowed: {', '.join(COUNT_TABLES)}")
    unsupported = [
        name for name in CHOICE_FILTERS if getattr(params, name) and name not in spec.choice_params
    ]
    if unsupported:
        return _invalid(f"{', '.join(unsupported)} cannot be used with table '{table}'")

    group_by = (params.group_by or "").strip() or None
    allowed_group_by = GROUP_BY_REFERENCES + tuple(spec.choice_params)
    if group_by and group_by not in allowed_group_by:
        return _invalid(
            f"group_by '{group_by}' is not allowed for {table}. Allowed: {', '.join(allowed_group_by)}"
        )

    # Counts default to every state, whatever the table's list default is.
    count_spec = dataclasses.replace(spec, default_status_scope="all")
    try:
        built = build_query(config, auth_manager, count_spec, params)
    except (QueryInputError, GroupLookupError) as e:
        return query_error_response(e, "Cannot count records")

    logger.info("count %s query=%s group_by=%s", table, built.filter_query, group_by)
    counted = aggregate_count(config, auth_manager, table, built.filter_query, group_by)
    meta: Dict[str, Any] = {
        "table": table,
        "query_used": built.filter_query,
        "filters_description": f"{table}: " + "; ".join(built.filter_parts),
        "status_scope": built.status_scope,
    }
    if built.matched_groups:
        meta["matched_groups"] = built.matched_groups
    warnings = built.warnings + (counted.warnings if counted.ok else [])
    if warnings:
        meta["warnings"] = warnings
    if not counted.ok:
        response = dict(counted.error or {"success": False, "message": "Count failed"})
        response.update(meta)
        return response

    user = _username(config) or "unknown"
    response: Dict[str, Any] = {
        "success": True,
        "count": counted.count,
        "scope_description": (
            f"{counted.count} {spec.plural} visible to ServiceNow user '{user}' match: "
            + "; ".join(built.filter_parts)
        ),
        "message": f"{counted.count} {spec.plural} counted",
        "source": counted.source,
        **meta,
        "note": LOW_COUNT_NOTE,
    }
    if group_by:
        response["group_by"] = group_by
        response["groups"] = counted.groups
    return response
