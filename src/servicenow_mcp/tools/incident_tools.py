"""
Incident tools for the ServiceNow MCP server.

This module provides tools for managing incidents in ServiceNow.
"""

import logging
from typing import Optional, List, Any

import requests
from pydantic import BaseModel, Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.ticket_query import (
    INCIDENT,
    TaskListParamsBase,
    choice_description,
    order_description,
    number_description,
    run_get_by_number,
    run_list,
)
from servicenow_mcp.utils.config import ServerConfig
from servicenow_mcp.utils.query import QueryBuilder, QueryInputError
from servicenow_mcp.utils.url import safe_table_url, SafeUrlError

logger = logging.getLogger(__name__)


class CreateIncidentParams(BaseModel):
    """Parameters for creating an incident."""

    short_description: str = Field(..., description="Short description of the incident")
    description: Optional[str] = Field(None, description="Detailed description of the incident")
    caller_id: Optional[str] = Field(None, description="User who reported the incident")
    category: Optional[str] = Field(None, description="Category of the incident")
    subcategory: Optional[str] = Field(None, description="Subcategory of the incident")
    priority: Optional[str] = Field(None, description="Priority of the incident")
    impact: Optional[str] = Field(None, description="Impact of the incident")
    urgency: Optional[str] = Field(None, description="Urgency of the incident")
    assigned_to: Optional[str] = Field(None, description="User assigned to the incident")
    assignment_group: Optional[str] = Field(None, description="Group assigned to the incident")


class UpdateIncidentParams(BaseModel):
    """Parameters for updating an incident."""

    incident_id: str = Field(..., description="Incident ID or sys_id")
    short_description: Optional[str] = Field(None, description="Short description of the incident")
    description: Optional[str] = Field(None, description="Detailed description of the incident")
    state: Optional[str] = Field(None, description="State of the incident")
    category: Optional[str] = Field(None, description="Category of the incident")
    subcategory: Optional[str] = Field(None, description="Subcategory of the incident")
    priority: Optional[str] = Field(None, description="Priority of the incident")
    impact: Optional[str] = Field(None, description="Impact of the incident")
    urgency: Optional[str] = Field(None, description="Urgency of the incident")
    assigned_to: Optional[str] = Field(None, description="User assigned to the incident")
    assignment_group: Optional[str] = Field(None, description="Group assigned to the incident")
    work_notes: Optional[str] = Field(None, description="Work notes to add to the incident")
    close_notes: Optional[str] = Field(None, description="Close notes to add to the incident")
    close_code: Optional[str] = Field(None, description="Close code for the incident")


class AddCommentParams(BaseModel):
    """Parameters for adding a comment to an incident."""

    incident_id: str = Field(..., description="Incident ID or sys_id")
    comment: str = Field(..., description="Comment to add to the incident")
    is_work_note: bool = Field(False, description="Whether the comment is a work note")


class ResolveIncidentParams(BaseModel):
    """Parameters for resolving an incident."""

    incident_id: str = Field(..., description="Incident ID or sys_id")
    resolution_code: str = Field(..., description="Resolution code for the incident")
    resolution_notes: str = Field(..., description="Resolution notes for the incident")


class ListIncidentsParams(TaskListParamsBase):
    """Parameters for listing incidents."""

    number: Optional[str] = Field(None, description=number_description(INCIDENT))
    state: Optional[str] = Field(
        None,
        description=choice_description(
            "incident state",
            "Typical out-of-box labels: 'New', 'In Progress', 'On Hold', 'Resolved', 'Closed', "
            "'Canceled' (values '1','2','3','6','7','8'); your instance's own labels apply.",
        ),
    )
    priority: Optional[str] = Field(
        None,
        description=choice_description(
            "priority",
            "Examples: '1 - Critical', 'Critical', 'High' or value '1'..'5'.",
        ),
    )
    category: Optional[str] = Field(
        None,
        description=choice_description(
            "category", "Examples: 'Network', 'Software', 'Hardware', 'Inquiry / Help'."
        ),
    )
    order_by: Optional[str] = Field(None, description=order_description(INCIDENT.order_fields))


class GetIncidentByNumberParams(BaseModel):
    """Parameters for fetching an incident by its number."""

    incident_number: str = Field(
        ..., description="Exact incident number, INC followed by digits, e.g. 'INC0010001'."
    )


class IncidentResponse(BaseModel):
    """Response from incident operations."""

    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Message describing the result")
    incident_id: Optional[str] = Field(None, description="ID of the affected incident")
    incident_number: Optional[str] = Field(None, description="Number of the affected incident")


def create_incident(
    config: ServerConfig,
    auth_manager: AuthManager,
    params: CreateIncidentParams,
) -> IncidentResponse:
    """
    Create a new incident in ServiceNow.

    Args:
        config: Server configuration.
        auth_manager: Authentication manager.
        params: Parameters for creating the incident.

    Returns:
        Response with the created incident details.
    """
    try:
        api_url = safe_table_url(config.api_url, "incident")

        # Build request data
        data = {
            "short_description": params.short_description,
        }

        if params.description:
            data["description"] = params.description
        if params.caller_id:
            data["caller_id"] = params.caller_id
        if params.category:
            data["category"] = params.category
        if params.subcategory:
            data["subcategory"] = params.subcategory
        if params.priority:
            data["priority"] = params.priority
        if params.impact:
            data["impact"] = params.impact
        if params.urgency:
            data["urgency"] = params.urgency
        if params.assigned_to:
            data["assigned_to"] = params.assigned_to
        if params.assignment_group:
            data["assignment_group"] = params.assignment_group

        response = requests.post(
            api_url,
            json=data,
            headers=auth_manager.get_headers(),
            timeout=config.timeout,
        )
        response.raise_for_status()

        result = response.json().get("result", {})

        return IncidentResponse(
            success=True,
            message="Incident created successfully",
            incident_id=result.get("sys_id"),
            incident_number=result.get("number"),
        )

    except (requests.RequestException, SafeUrlError, QueryInputError) as e:
        logger.error(f"Failed to create incident: {e}")
        return IncidentResponse(
            success=False,
            message=f"Failed to create incident: {str(e)}",
        )


def update_incident(
    config: ServerConfig,
    auth_manager: AuthManager,
    params: UpdateIncidentParams,
) -> IncidentResponse:
    """
    Update an existing incident in ServiceNow.

    Args:
        config: Server configuration.
        auth_manager: Authentication manager.
        params: Parameters for updating the incident.

    Returns:
        Response with the updated incident details.
    """
    try:
        # Determine if incident_id is a number or sys_id
        incident_id = params.incident_id
        if len(incident_id) == 32 and all(c in "0123456789abcdef" for c in incident_id):
            # This is likely a sys_id
            api_url = safe_table_url(config.api_url, "incident", incident_id)
        else:
            # This is likely an incident number
            # First, we need to get the sys_id
            query_url = safe_table_url(config.api_url, "incident")
            query_params = {
                "sysparm_query": QueryBuilder().eq("number", incident_id).build(),
                "sysparm_limit": 1,
            }

            response = requests.get(
                query_url,
                params=query_params,
                headers=auth_manager.get_headers(),
                timeout=config.timeout,
            )
            response.raise_for_status()

            result = response.json().get("result", [])
            if not result:
                return IncidentResponse(
                    success=False,
                    message=f"Incident not found: {incident_id}",
                )

            incident_id = result[0].get("sys_id")
            api_url = safe_table_url(config.api_url, "incident", incident_id)

        # Build request data
        data = {}

        if params.short_description:
            data["short_description"] = params.short_description
        if params.description:
            data["description"] = params.description
        if params.state:
            data["state"] = params.state
        if params.category:
            data["category"] = params.category
        if params.subcategory:
            data["subcategory"] = params.subcategory
        if params.priority:
            data["priority"] = params.priority
        if params.impact:
            data["impact"] = params.impact
        if params.urgency:
            data["urgency"] = params.urgency
        if params.assigned_to:
            data["assigned_to"] = params.assigned_to
        if params.assignment_group:
            data["assignment_group"] = params.assignment_group
        if params.work_notes:
            data["work_notes"] = params.work_notes
        if params.close_notes:
            data["close_notes"] = params.close_notes
        if params.close_code:
            data["close_code"] = params.close_code

        response = requests.put(
            api_url,
            json=data,
            headers=auth_manager.get_headers(),
            timeout=config.timeout,
        )
        response.raise_for_status()

        result = response.json().get("result", {})

        return IncidentResponse(
            success=True,
            message="Incident updated successfully",
            incident_id=result.get("sys_id"),
            incident_number=result.get("number"),
        )

    except (requests.RequestException, SafeUrlError, QueryInputError) as e:
        logger.error(f"Failed to update incident: {e}")
        return IncidentResponse(
            success=False,
            message=f"Failed to update incident: {str(e)}",
        )


def add_comment(
    config: ServerConfig,
    auth_manager: AuthManager,
    params: AddCommentParams,
) -> IncidentResponse:
    """
    Add a comment to an incident in ServiceNow.

    Args:
        config: Server configuration.
        auth_manager: Authentication manager.
        params: Parameters for adding the comment.

    Returns:
        Response with the result of the operation.
    """
    try:
        # Determine if incident_id is a number or sys_id
        incident_id = params.incident_id
        if len(incident_id) == 32 and all(c in "0123456789abcdef" for c in incident_id):
            # This is likely a sys_id
            api_url = safe_table_url(config.api_url, "incident", incident_id)
        else:
            # This is likely an incident number
            # First, we need to get the sys_id
            query_url = safe_table_url(config.api_url, "incident")
            query_params = {
                "sysparm_query": QueryBuilder().eq("number", incident_id).build(),
                "sysparm_limit": 1,
            }

            response = requests.get(
                query_url,
                params=query_params,
                headers=auth_manager.get_headers(),
                timeout=config.timeout,
            )
            response.raise_for_status()

            result = response.json().get("result", [])
            if not result:
                return IncidentResponse(
                    success=False,
                    message=f"Incident not found: {incident_id}",
                )

            incident_id = result[0].get("sys_id")
            api_url = safe_table_url(config.api_url, "incident", incident_id)

        # Build request data
        data = {}

        if params.is_work_note:
            data["work_notes"] = params.comment
        else:
            data["comments"] = params.comment

        response = requests.put(
            api_url,
            json=data,
            headers=auth_manager.get_headers(),
            timeout=config.timeout,
        )
        response.raise_for_status()

        result = response.json().get("result", {})

        return IncidentResponse(
            success=True,
            message="Comment added successfully",
            incident_id=result.get("sys_id"),
            incident_number=result.get("number"),
        )

    except (requests.RequestException, SafeUrlError, QueryInputError) as e:
        logger.error(f"Failed to add comment: {e}")
        return IncidentResponse(
            success=False,
            message=f"Failed to add comment: {str(e)}",
        )


def resolve_incident(
    config: ServerConfig,
    auth_manager: AuthManager,
    params: ResolveIncidentParams,
) -> IncidentResponse:
    """
    Resolve an incident in ServiceNow.

    Args:
        config: Server configuration.
        auth_manager: Authentication manager.
        params: Parameters for resolving the incident.

    Returns:
        Response with the result of the operation.
    """
    try:
        # Determine if incident_id is a number or sys_id
        incident_id = params.incident_id
        if len(incident_id) == 32 and all(c in "0123456789abcdef" for c in incident_id):
            # This is likely a sys_id
            api_url = safe_table_url(config.api_url, "incident", incident_id)
        else:
            # This is likely an incident number
            # First, we need to get the sys_id
            query_url = safe_table_url(config.api_url, "incident")
            query_params = {
                "sysparm_query": QueryBuilder().eq("number", incident_id).build(),
                "sysparm_limit": 1,
            }

            response = requests.get(
                query_url,
                params=query_params,
                headers=auth_manager.get_headers(),
                timeout=config.timeout,
            )
            response.raise_for_status()

            result = response.json().get("result", [])
            if not result:
                return IncidentResponse(
                    success=False,
                    message=f"Incident not found: {incident_id}",
                )

            incident_id = result[0].get("sys_id")
            api_url = safe_table_url(config.api_url, "incident", incident_id)

        # Build request data
        data = {
            "state": "6",  # Resolved
            "close_code": params.resolution_code,
            "close_notes": params.resolution_notes,
            "resolved_at": "now",
        }

        response = requests.put(
            api_url,
            json=data,
            headers=auth_manager.get_headers(),
            timeout=config.timeout,
        )
        response.raise_for_status()

        result = response.json().get("result", {})

        return IncidentResponse(
            success=True,
            message="Incident resolved successfully",
            incident_id=result.get("sys_id"),
            incident_number=result.get("number"),
        )

    except (requests.RequestException, SafeUrlError, QueryInputError) as e:
        logger.error(f"Failed to resolve incident: {e}")
        return IncidentResponse(
            success=False,
            message=f"Failed to resolve incident: {str(e)}",
        )


def list_incidents(
    config: ServerConfig,
    auth_manager: AuthManager,
    params: ListIncidentsParams,
) -> dict:
    """
    List incidents from ServiceNow.

    Args:
        config: Server configuration.
        auth_manager: Authentication manager.
        params: Parameters for listing incidents.

    Returns:
        Dictionary with the incidents plus query_used, total_count, returned,
        limit and offset; a hint when nothing matched.
    """
    return run_list(
        config,
        auth_manager,
        INCIDENT,
        params,
        records_key="incidents",
        error_prefix="Failed to list incidents",
    )


def get_incident_by_number(
    config: ServerConfig,
    auth_manager: AuthManager,
    params: GetIncidentByNumberParams,
) -> dict:
    """
    Fetch a single incident from ServiceNow by its number.

    Args:
        config: Server configuration.
        auth_manager: Authentication manager.
        params: Parameters for fetching the incident.

    Returns:
        Dictionary with the incident details.
    """
    return run_get_by_number(
        config, auth_manager, INCIDENT, params.incident_number, record_key="incident"
    )


def get_incident(
    config: ServerConfig,
    auth_manager: AuthManager,
    params: Any,
) -> dict:
    """
    Fetch a single incident from ServiceNow.

    Convenience wrapper that accepts GetIncidentByNumberParams, a dict, or string/object,
    and delegates to get_incident_by_number or queries by sys_id.

    Args:
        config: Server configuration.
        auth_manager: Authentication manager.
        params: Parameters for fetching the incident.

    Returns:
        Dictionary with the incident details.
    """
    try:
        if isinstance(params, GetIncidentByNumberParams):
            return get_incident_by_number(config, auth_manager, params)

        if isinstance(params, str):
            if params.startswith("INC"):
                return get_incident_by_number(
                    config, auth_manager, GetIncidentByNumberParams(incident_number=params)
                )
            target_id = params
        elif isinstance(params, dict):
            if "incident_number" in params and params["incident_number"]:
                return get_incident_by_number(
                    config, auth_manager, GetIncidentByNumberParams(incident_number=params["incident_number"])
                )
            if "number" in params and params["number"]:
                return get_incident_by_number(
                    config, auth_manager, GetIncidentByNumberParams(incident_number=params["number"])
                )
            target_id = params.get("incident_id") or params.get("sys_id") or ""
        elif hasattr(params, "incident_number") and getattr(params, "incident_number"):
            return get_incident_by_number(
                config, auth_manager, GetIncidentByNumberParams(incident_number=getattr(params, "incident_number"))
            )
        elif hasattr(params, "number") and getattr(params, "number"):
            return get_incident_by_number(
                config, auth_manager, GetIncidentByNumberParams(incident_number=getattr(params, "number"))
            )
        elif hasattr(params, "incident_id") and getattr(params, "incident_id"):
            target_id = getattr(params, "incident_id")
        else:
            target_id = str(params)

        if not target_id:
            return {"success": False, "message": "Incident identifier is required"}

        if target_id.startswith("INC"):
            return get_incident_by_number(
                config, auth_manager, GetIncidentByNumberParams(incident_number=target_id)
            )

        # Validate target_id with safe_table_url (catches path traversal etc.)
        api_url = safe_table_url(config.api_url, "incident", target_id)
        response = requests.get(
            api_url,
            params={"sysparm_display_value": "true", "sysparm_exclude_reference_link": "true"},
            headers=auth_manager.get_headers(),
            timeout=config.timeout,
        )
        response.raise_for_status()
        result = response.json().get("result", {})
        if not result:
            return {"success": False, "message": f"Incident not found: {target_id}"}
        return {
            "success": True,
            "message": f"Incident {target_id} found",
            "incident": result,
        }
    except (requests.RequestException, SafeUrlError, QueryInputError) as e:
        logger.error(f"Failed to get incident: {e}")
        return {
            "success": False,
            "message": f"Failed to get incident: {str(e)}",
        }

