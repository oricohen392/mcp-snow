"""
Change management tools for the ServiceNow MCP server.

This module provides tools for managing change requests in ServiceNow.
"""

import logging
from typing import Any, Dict, List, Optional, Type, TypeVar

import requests
from pydantic import BaseModel, Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.ticket_query import (
    CHANGE_REQUEST,
    TaskListParamsBase,
    choice_description,
    date_description,
    number_description,
    order_description,
    run_list,
    status_scope_description,
    validate_numbers,
)
from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import ServerConfig
from servicenow_mcp.utils.dates import utc_now_string
from servicenow_mcp.utils.http import sn_get
from servicenow_mcp.utils.query import QueryBuilder, QueryInputError, is_sys_id

logger = logging.getLogger(__name__)

# Type variable for Pydantic models
T = TypeVar('T', bound=BaseModel)


class CreateChangeRequestParams(BaseModel):
    """Parameters for creating a change request."""

    short_description: str = Field(..., description="Short description of the change request")
    description: Optional[str] = Field(None, description="Detailed description of the change request")
    type: str = Field(..., description="Type of change (normal, standard, emergency)")
    risk: Optional[str] = Field(None, description="Risk level of the change")
    impact: Optional[str] = Field(None, description="Impact of the change")
    category: Optional[str] = Field(None, description="Category of the change")
    requested_by: Optional[str] = Field(None, description="User who requested the change")
    assignment_group: Optional[str] = Field(None, description="Group assigned to the change")
    start_date: Optional[str] = Field(None, description="Planned start date (YYYY-MM-DD HH:MM:SS)")
    end_date: Optional[str] = Field(None, description="Planned end date (YYYY-MM-DD HH:MM:SS)")


class UpdateChangeRequestParams(BaseModel):
    """Parameters for updating a change request."""

    change_id: str = Field(..., description="Change request ID or sys_id")
    short_description: Optional[str] = Field(None, description="Short description of the change request")
    description: Optional[str] = Field(None, description="Detailed description of the change request")
    state: Optional[str] = Field(None, description="State of the change request")
    risk: Optional[str] = Field(None, description="Risk level of the change")
    impact: Optional[str] = Field(None, description="Impact of the change")
    category: Optional[str] = Field(None, description="Category of the change")
    assignment_group: Optional[str] = Field(None, description="Group assigned to the change")
    start_date: Optional[str] = Field(None, description="Planned start date (YYYY-MM-DD HH:MM:SS)")
    end_date: Optional[str] = Field(None, description="Planned end date (YYYY-MM-DD HH:MM:SS)")
    work_notes: Optional[str] = Field(None, description="Work notes to add to the change request")


class ListChangeRequestsParams(TaskListParamsBase):
    """Parameters for listing change requests."""

    status_scope: Optional[str] = Field(None, description=status_scope_description("open"))
    number: Optional[str] = Field(None, description=number_description(CHANGE_REQUEST))
    state: Optional[str] = Field(
        None,
        description=choice_description(
            "change state",
            "Typical out-of-box labels: 'New', 'Assess', 'Authorize', 'Scheduled', "
            "'Implement', 'Review', 'Closed', 'Canceled' (values '-5','-4','-3','-2','-1',"
            "'0','3','4'); your instance's own labels apply.",
        ),
    )
    type: Optional[str] = Field(
        None,
        description=choice_description(
            "change type", "Typical values: 'normal', 'standard', 'emergency'."
        ),
    )
    risk: Optional[str] = Field(
        None,
        description=choice_description(
            "risk", "Typical labels: 'High', 'Moderate', 'Low' (values '2','3','4')."
        ),
    )
    priority: Optional[str] = Field(
        None,
        description=choice_description(
            "priority", "Examples: '1 - Critical', 'High' or value '1'..'4'."
        ),
    )
    category: Optional[str] = Field(
        None,
        description=choice_description(
            "category", "Examples: 'Hardware', 'Software', 'Network', 'Other'."
        ),
    )
    start_after: Optional[str] = Field(
        None, description=date_description("Planned start_date", "at or after", ">=")
    )
    start_before: Optional[str] = Field(
        None, description=date_description("Planned start_date", "before", "<")
    )
    end_after: Optional[str] = Field(
        None, description=date_description("Planned end_date", "at or after", ">=")
    )
    end_before: Optional[str] = Field(
        None, description=date_description("Planned end_date", "before", "<")
    )
    timeframe: Optional[str] = Field(
        None,
        description=(
            "Relative to now (UTC): 'upcoming' (start_date in the future), 'in-progress' "
            "(started, not yet ended) or 'completed' (end_date in the past)."
        ),
    )
    order_by: Optional[str] = Field(
        None, description=order_description(CHANGE_REQUEST.order_fields)
    )


class GetChangeRequestDetailsParams(BaseModel):
    """Parameters for getting change request details."""

    change_id: str = Field(
        ...,
        description="Change request number (e.g. 'CHG0030001') or 32-character sys_id.",
    )


class AddChangeTaskParams(BaseModel):
    """Parameters for adding a task to a change request."""

    change_id: str = Field(..., description="Change request ID or sys_id")
    short_description: str = Field(..., description="Short description of the task")
    description: Optional[str] = Field(None, description="Detailed description of the task")
    assigned_to: Optional[str] = Field(None, description="User assigned to the task")
    planned_start_date: Optional[str] = Field(None, description="Planned start date (YYYY-MM-DD HH:MM:SS)")
    planned_end_date: Optional[str] = Field(None, description="Planned end date (YYYY-MM-DD HH:MM:SS)")


class SubmitChangeForApprovalParams(BaseModel):
    """Parameters for submitting a change request for approval."""

    change_id: str = Field(..., description="Change request ID or sys_id")
    approval_comments: Optional[str] = Field(None, description="Comments for the approval request")


class ApproveChangeParams(BaseModel):
    """Parameters for approving a change request."""

    change_id: str = Field(..., description="Change request ID or sys_id")
    approver_id: Optional[str] = Field(None, description="ID of the approver")
    approval_comments: Optional[str] = Field(None, description="Comments for the approval")


class RejectChangeParams(BaseModel):
    """Parameters for rejecting a change request."""

    change_id: str = Field(..., description="Change request ID or sys_id")
    approver_id: Optional[str] = Field(None, description="ID of the approver")
    rejection_reason: str = Field(..., description="Reason for rejection")


def _unwrap_and_validate_params(params: Any, model_class: Type[T], required_fields: List[str] = None) -> Dict[str, Any]:
    """
    Helper function to unwrap and validate parameters.
    
    Args:
        params: The parameters to unwrap and validate.
        model_class: The Pydantic model class to validate against.
        required_fields: List of required field names.
        
    Returns:
        A tuple of (success, result) where result is either the validated parameters or an error message.
    """
    # Handle case where params might be wrapped in another dictionary
    if isinstance(params, dict) and len(params) == 1 and "params" in params and isinstance(params["params"], dict):
        logger.warning("Detected params wrapped in a 'params' key. Unwrapping...")
        params = params["params"]
    
    # Handle case where params might be a Pydantic model object
    if not isinstance(params, dict):
        try:
            # Try to convert to dict if it's a Pydantic model
            logger.warning("Params is not a dictionary. Attempting to convert...")
            params = params.dict() if hasattr(params, "dict") else dict(params)
        except Exception as e:
            logger.error(f"Failed to convert params to dictionary: {e}")
            return {
                "success": False,
                "message": f"Invalid parameters format. Expected a dictionary, got {type(params).__name__}",
            }
    
    # Validate required parameters are present
    if required_fields:
        for field in required_fields:
            if field not in params:
                return {
                    "success": False,
                    "message": f"Missing required parameter '{field}'",
                }
    
    try:
        # Validate parameters against the model
        validated_params = model_class(**params)
        return {
            "success": True,
            "params": validated_params,
        }
    except Exception as e:
        logger.error(f"Error validating parameters: {e}")
        return {
            "success": False,
            "message": f"Error validating parameters: {str(e)}",
        }


def _get_instance_url(auth_manager: AuthManager, server_config: ServerConfig) -> Optional[str]:
    """
    Helper function to get the instance URL from either server_config or auth_manager.
    
    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        
    Returns:
        The instance URL if found, None otherwise.
    """
    if hasattr(server_config, 'instance_url'):
        return server_config.instance_url
    elif hasattr(auth_manager, 'instance_url'):
        return auth_manager.instance_url
    else:
        logger.error("Cannot find instance_url in either server_config or auth_manager")
        return None


def _get_headers(auth_manager: Any, server_config: Any) -> Optional[Dict[str, str]]:
    """
    Helper function to get headers from either auth_manager or server_config.
    
    Args:
        auth_manager: The authentication manager or object passed as auth_manager.
        server_config: The server configuration or object passed as server_config.
        
    Returns:
        The headers if found, None otherwise.
    """
    # Try to get headers from auth_manager
    if hasattr(auth_manager, 'get_headers'):
        return auth_manager.get_headers()
    
    # If auth_manager doesn't have get_headers, try server_config
    if hasattr(server_config, 'get_headers'):
        return server_config.get_headers()
    
    # If neither has get_headers, check if auth_manager is actually a ServerConfig
    # and server_config is actually an AuthManager (parameters swapped)
    if hasattr(server_config, 'get_headers') and not hasattr(auth_manager, 'get_headers'):
        return server_config.get_headers()
    
    logger.error("Cannot find get_headers method in either auth_manager or server_config")
    return None


def create_change_request(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a new change request in ServiceNow.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for creating the change request.

    Returns:
        The created change request.
    """
    # Unwrap and validate parameters
    result = _unwrap_and_validate_params(
        params, 
        CreateChangeRequestParams, 
        required_fields=["short_description", "type"]
    )
    
    if not result["success"]:
        return result
    
    validated_params = result["params"]
    
    # Prepare the request data
    data = {
        "short_description": validated_params.short_description,
        "type": validated_params.type,
    }
    
    # Add optional fields if provided
    if validated_params.description:
        data["description"] = validated_params.description
    if validated_params.risk:
        data["risk"] = validated_params.risk
    if validated_params.impact:
        data["impact"] = validated_params.impact
    if validated_params.category:
        data["category"] = validated_params.category
    if validated_params.requested_by:
        data["requested_by"] = validated_params.requested_by
    if validated_params.assignment_group:
        data["assignment_group"] = validated_params.assignment_group
    if validated_params.start_date:
        data["start_date"] = validated_params.start_date
    if validated_params.end_date:
        data["end_date"] = validated_params.end_date
    
    # Get the instance URL
    instance_url = _get_instance_url(auth_manager, server_config)
    if not instance_url:
        return {
            "success": False,
            "message": "Cannot find instance_url in either server_config or auth_manager",
        }
    
    # Get the headers
    headers = _get_headers(auth_manager, server_config)
    if not headers:
        return {
            "success": False,
            "message": "Cannot find get_headers method in either auth_manager or server_config",
        }
    
    # Add Content-Type header
    headers["Content-Type"] = "application/json"
    
    # Make the API request
    url = f"{instance_url}/api/now/table/change_request"
    
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        return {
            "success": True,
            "message": "Change request created successfully",
            "change_request": result["result"],
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating change request: {e}")
        return {
            "success": False,
            "message": f"Error creating change request: {str(e)}",
        }


def update_change_request(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Update an existing change request in ServiceNow.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for updating the change request.

    Returns:
        The updated change request.
    """
    # Unwrap and validate parameters
    result = _unwrap_and_validate_params(
        params, 
        UpdateChangeRequestParams, 
        required_fields=["change_id"]
    )
    
    if not result["success"]:
        return result
    
    validated_params = result["params"]
    
    # Prepare the request data
    data = {}
    
    # Add fields if provided
    if validated_params.short_description:
        data["short_description"] = validated_params.short_description
    if validated_params.description:
        data["description"] = validated_params.description
    if validated_params.state:
        data["state"] = validated_params.state
    if validated_params.risk:
        data["risk"] = validated_params.risk
    if validated_params.impact:
        data["impact"] = validated_params.impact
    if validated_params.category:
        data["category"] = validated_params.category
    if validated_params.assignment_group:
        data["assignment_group"] = validated_params.assignment_group
    if validated_params.start_date:
        data["start_date"] = validated_params.start_date
    if validated_params.end_date:
        data["end_date"] = validated_params.end_date
    if validated_params.work_notes:
        data["work_notes"] = validated_params.work_notes
    
    # Get the instance URL
    instance_url = _get_instance_url(auth_manager, server_config)
    if not instance_url:
        return {
            "success": False,
            "message": "Cannot find instance_url in either server_config or auth_manager",
        }
    
    # Get the headers
    headers = _get_headers(auth_manager, server_config)
    if not headers:
        return {
            "success": False,
            "message": "Cannot find get_headers method in either auth_manager or server_config",
        }
    
    # Add Content-Type header
    headers["Content-Type"] = "application/json"
    
    # Make the API request
    url = f"{instance_url}/api/now/table/change_request/{validated_params.change_id}"
    
    try:
        response = requests.put(url, json=data, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        return {
            "success": True,
            "message": "Change request updated successfully",
            "change_request": result["result"],
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating change request: {e}")
        return {
            "success": False,
            "message": f"Error updating change request: {str(e)}",
        }


def _split_config_and_auth(first: Any, second: Any):
    """
    Return (server_config, auth_manager) whatever order they were passed in.

    The change tools are declared (auth_manager, server_config, params) but the
    MCP server calls every tool as (config, auth_manager, params).
    """
    if hasattr(first, "get_headers") and not hasattr(second, "get_headers"):
        return second, first
    return first, second


TIMEFRAMES = ("upcoming", "in-progress", "completed")


def _change_timeframe(builder: QueryBuilder, params: ListChangeRequestsParams) -> None:
    timeframe = params.timeframe
    if not timeframe:
        return
    if timeframe not in TIMEFRAMES:
        raise QueryInputError(
            f"timeframe '{timeframe}' is not valid. Allowed: {', '.join(TIMEFRAMES)}"
        )
    now = utc_now_string()
    if timeframe == "upcoming":
        builder.where("start_date", ">", now)
    elif timeframe == "in-progress":
        builder.where("start_date", "<", now).where("end_date", ">", now)
    else:
        builder.where("end_date", "<", now)


def list_change_requests(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    List change requests from ServiceNow.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for listing change requests.

    Returns:
        The change requests plus count/total (total = X-Total-Count when
        available), query_used, returned, limit and offset.
    """
    result = _unwrap_and_validate_params(params, ListChangeRequestsParams)
    if not result["success"]:
        return result
    validated_params = result["params"]

    config, auth = _split_config_and_auth(server_config, auth_manager)
    response = run_list(
        config,
        auth,
        CHANGE_REQUEST,
        validated_params,
        records_key="change_requests",
        error_prefix="Error listing change requests",
        extra=_change_timeframe,
    )
    if response.get("success"):
        response["count"] = response["returned"]
        total = response.get("total_count")
        response["total"] = total if total is not None else response["returned"]
    return response


def get_change_request_details(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Get details of a change request (by number or sys_id) and its change tasks.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for getting change request details.

    Returns:
        The change request details.
    """
    result = _unwrap_and_validate_params(
        params,
        GetChangeRequestDetailsParams,
        required_fields=["change_id"],
    )
    if not result["success"]:
        return result
    validated_params = result["params"]
    config, auth = _split_config_and_auth(server_config, auth_manager)

    change_id = validated_params.change_id.strip()
    try:
        if is_sys_id(change_id):
            query = QueryBuilder().eq("sys_id", change_id.lower()).build()
        else:
            number = validate_numbers(CHANGE_REQUEST, change_id)[0]
            query = QueryBuilder().eq("number", number).build()
    except QueryInputError as e:
        return {
            "success": False,
            "status_code": None,
            "error_type": "invalid_input",
            "message": f"Error getting change request details: {e}",
        }

    record = sn_get(
        config,
        auth,
        "table/change_request",
        {"sysparm_query": query, "sysparm_limit": 1, "sysparm_display_value": "true"},
    )
    if not record.ok:
        response = record.error_dict("Error getting change request details")
        response["query_used"] = query
        return response
    if not record.records:
        return {
            "success": False,
            "message": f"Change request not found: {change_id}",
            "query_used": query,
            "hint": "No row returned: the change does not exist or this account cannot read it "
            "(ACL / domain separation). Run check_access.",
        }
    change = record.records[0]
    sys_id = change.get("sys_id")
    if isinstance(sys_id, dict):
        sys_id = sys_id.get("value")

    tasks_query = QueryBuilder().eq("change_request", sys_id).build()
    tasks = sn_get(
        config,
        auth,
        "table/change_task",
        {
            "sysparm_query": tasks_query,
            "sysparm_display_value": "true",
            "sysparm_limit": settings.max_limit(),
        },
    )
    response = {
        "success": True,
        "change_request": change,
        "tasks": tasks.records if tasks.ok else [],
        "query_used": query,
    }
    if not tasks.ok:
        response["tasks_error"] = tasks.error_dict("Could not load change tasks")
    return response


def add_change_task(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Add a task to a change request in ServiceNow.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for adding a change task.

    Returns:
        The created change task.
    """
    # Unwrap and validate parameters
    result = _unwrap_and_validate_params(
        params, 
        AddChangeTaskParams,
        required_fields=["change_id", "short_description"]
    )
    
    if not result["success"]:
        return result
    
    validated_params = result["params"]
    
    # Prepare the request data
    data = {
        "change_request": validated_params.change_id,
        "short_description": validated_params.short_description,
    }
    
    # Add optional fields if provided
    if validated_params.description:
        data["description"] = validated_params.description
    if validated_params.assigned_to:
        data["assigned_to"] = validated_params.assigned_to
    if validated_params.planned_start_date:
        data["planned_start_date"] = validated_params.planned_start_date
    if validated_params.planned_end_date:
        data["planned_end_date"] = validated_params.planned_end_date
    
    # Get the instance URL
    instance_url = _get_instance_url(auth_manager, server_config)
    if not instance_url:
        return {
            "success": False,
            "message": "Cannot find instance_url in either server_config or auth_manager",
        }
    
    # Get the headers
    headers = _get_headers(auth_manager, server_config)
    if not headers:
        return {
            "success": False,
            "message": "Cannot find get_headers method in either auth_manager or server_config",
        }
    
    # Add Content-Type header
    headers["Content-Type"] = "application/json"
    
    # Make the API request
    url = f"{instance_url}/api/now/table/change_task"
    
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        return {
            "success": True,
            "message": "Change task added successfully",
            "change_task": result["result"],
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error adding change task: {e}")
        return {
            "success": False,
            "message": f"Error adding change task: {str(e)}",
        }


def submit_change_for_approval(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Submit a change request for approval in ServiceNow.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for submitting a change request for approval.

    Returns:
        The result of the submission.
    """
    # Unwrap and validate parameters
    result = _unwrap_and_validate_params(
        params, 
        SubmitChangeForApprovalParams,
        required_fields=["change_id"]
    )
    
    if not result["success"]:
        return result
    
    validated_params = result["params"]
    
    # Prepare the request data
    data = {
        "state": "assess",  # Set state to "assess" to submit for approval
    }
    
    # Add approval comments if provided
    if validated_params.approval_comments:
        data["work_notes"] = validated_params.approval_comments
    
    # Get the instance URL
    instance_url = _get_instance_url(auth_manager, server_config)
    if not instance_url:
        return {
            "success": False,
            "message": "Cannot find instance_url in either server_config or auth_manager",
        }
    
    # Get the headers
    headers = _get_headers(auth_manager, server_config)
    if not headers:
        return {
            "success": False,
            "message": "Cannot find get_headers method in either auth_manager or server_config",
        }
    
    # Add Content-Type header
    headers["Content-Type"] = "application/json"
    
    # Make the API request
    url = f"{instance_url}/api/now/table/change_request/{validated_params.change_id}"
    
    try:
        response = requests.patch(url, json=data, headers=headers)
        response.raise_for_status()
        
        # Now, create an approval request
        approval_url = f"{instance_url}/api/now/table/sysapproval_approver"
        approval_data = {
            "document_id": validated_params.change_id,
            "source_table": "change_request",
            "state": "requested",
        }
        
        approval_response = requests.post(approval_url, json=approval_data, headers=headers)
        approval_response.raise_for_status()
        
        approval_result = approval_response.json()
        
        return {
            "success": True,
            "message": "Change request submitted for approval successfully",
            "approval": approval_result["result"],
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error submitting change for approval: {e}")
        return {
            "success": False,
            "message": f"Error submitting change for approval: {str(e)}",
        }


def approve_change(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Approve a change request in ServiceNow.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for approving a change request.

    Returns:
        The result of the approval.
    """
    # Unwrap and validate parameters
    result = _unwrap_and_validate_params(
        params, 
        ApproveChangeParams,
        required_fields=["change_id"]
    )
    
    if not result["success"]:
        return result
    
    validated_params = result["params"]
    
    # Get the instance URL
    instance_url = _get_instance_url(auth_manager, server_config)
    if not instance_url:
        return {
            "success": False,
            "message": "Cannot find instance_url in either server_config or auth_manager",
        }
    
    # Get the headers
    headers = _get_headers(auth_manager, server_config)
    if not headers:
        return {
            "success": False,
            "message": "Cannot find get_headers method in either auth_manager or server_config",
        }
    
    # First, find the approval record
    approval_query_url = f"{instance_url}/api/now/table/sysapproval_approver"
    
    query_params = {
        "sysparm_query": f"document_id={validated_params.change_id}",
        "sysparm_limit": 1,
    }
    
    try:
        approval_response = requests.get(approval_query_url, headers=headers, params=query_params)
        approval_response.raise_for_status()
        
        approval_result = approval_response.json()
        
        if not approval_result.get("result") or len(approval_result["result"]) == 0:
            return {
                "success": False,
                "message": "No approval record found for this change request",
            }
        
        approval_id = approval_result["result"][0]["sys_id"]
        
        # Now, update the approval record to approved
        approval_update_url = f"{instance_url}/api/now/table/sysapproval_approver/{approval_id}"
        headers["Content-Type"] = "application/json"
        
        approval_data = {
            "state": "approved",
        }
        
        if validated_params.approval_comments:
            approval_data["comments"] = validated_params.approval_comments
        
        approval_update_response = requests.patch(approval_update_url, json=approval_data, headers=headers)
        approval_update_response.raise_for_status()
        
        # Finally, update the change request state to "implement"
        change_url = f"{instance_url}/api/now/table/change_request/{validated_params.change_id}"
        
        change_data = {
            "state": "implement",  # This may vary depending on ServiceNow configuration
        }
        
        change_response = requests.patch(change_url, json=change_data, headers=headers)
        change_response.raise_for_status()
        
        return {
            "success": True,
            "message": "Change request approved successfully",
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error approving change: {e}")
        return {
            "success": False,
            "message": f"Error approving change: {str(e)}",
        }


def reject_change(
    auth_manager: AuthManager,
    server_config: ServerConfig,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Reject a change request in ServiceNow.

    Args:
        auth_manager: The authentication manager.
        server_config: The server configuration.
        params: The parameters for rejecting a change request.

    Returns:
        The result of the rejection.
    """
    # Unwrap and validate parameters
    result = _unwrap_and_validate_params(
        params, 
        RejectChangeParams,
        required_fields=["change_id", "rejection_reason"]
    )
    
    if not result["success"]:
        return result
    
    validated_params = result["params"]
    
    # Get the instance URL
    instance_url = _get_instance_url(auth_manager, server_config)
    if not instance_url:
        return {
            "success": False,
            "message": "Cannot find instance_url in either server_config or auth_manager",
        }
    
    # Get the headers
    headers = _get_headers(auth_manager, server_config)
    if not headers:
        return {
            "success": False,
            "message": "Cannot find get_headers method in either auth_manager or server_config",
        }
    
    # First, find the approval record
    approval_query_url = f"{instance_url}/api/now/table/sysapproval_approver"
    
    query_params = {
        "sysparm_query": f"document_id={validated_params.change_id}",
        "sysparm_limit": 1,
    }
    
    try:
        approval_response = requests.get(approval_query_url, headers=headers, params=query_params)
        approval_response.raise_for_status()
        
        approval_result = approval_response.json()
        
        if not approval_result.get("result") or len(approval_result["result"]) == 0:
            return {
                "success": False,
                "message": "No approval record found for this change request",
            }
        
        approval_id = approval_result["result"][0]["sys_id"]
        
        # Now, update the approval record to rejected
        approval_update_url = f"{instance_url}/api/now/table/sysapproval_approver/{approval_id}"
        headers["Content-Type"] = "application/json"
        
        approval_data = {
            "state": "rejected",
            "comments": validated_params.rejection_reason,
        }
        
        approval_update_response = requests.patch(approval_update_url, json=approval_data, headers=headers)
        approval_update_response.raise_for_status()
        
        # Finally, update the change request state to "canceled"
        change_url = f"{instance_url}/api/now/table/change_request/{validated_params.change_id}"
        
        change_data = {
            "state": "canceled",  # This may vary depending on ServiceNow configuration
            "work_notes": f"Change request rejected: {validated_params.rejection_reason}",
        }
        
        change_response = requests.patch(change_url, json=change_data, headers=headers)
        change_response.raise_for_status()
        
        return {
            "success": True,
            "message": "Change request rejected successfully",
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Error rejecting change: {e}")
        return {
            "success": False,
            "message": f"Error rejecting change: {str(e)}",
        } 