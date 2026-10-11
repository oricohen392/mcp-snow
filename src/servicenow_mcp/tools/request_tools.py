"""
Service request tools: sc_request (REQ...) and sc_req_item (RITM...).

Read-only list/get tools built on the shared task query engine.
"""

from typing import Optional

from pydantic import BaseModel, Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.ticket_query import (
    SC_REQ_ITEM,
    SC_REQUEST,
    TaskListParamsBase,
    choice_description,
    number_description,
    order_description,
    run_get_by_number,
    run_list,
)
from servicenow_mcp.utils.config import ServerConfig

TASK_STATE_EXAMPLES = (
    "Typical out-of-box task labels: 'Open', 'Work in Progress', 'Closed Complete', "
    "'Closed Incomplete', 'Closed Skipped' (values '1','2','3','4','7'); your instance's "
    "own labels apply."
)


class ListRequestsParams(TaskListParamsBase):
    """Parameters for listing service catalog requests (sc_request)."""

    number: Optional[str] = Field(None, description=number_description(SC_REQUEST))
    state: Optional[str] = Field(
        None, description=choice_description("request state", TASK_STATE_EXAMPLES)
    )
    request_state: Optional[str] = Field(
        None,
        description=choice_description(
            "request_state (the request's own lifecycle field)",
            "Typical values: 'requested', 'in_process', 'closed_complete', "
            "'closed_incomplete', 'closed_cancelled', 'closed_rejected'.",
        ),
    )
    priority: Optional[str] = Field(
        None,
        description=choice_description(
            "priority", "Examples: '1 - Critical', 'High' or value '1'..'5'."
        ),
    )
    order_by: Optional[str] = Field(None, description=order_description(SC_REQUEST.order_fields))


class ListRequestItemsParams(TaskListParamsBase):
    """Parameters for listing requested items (sc_req_item)."""

    number: Optional[str] = Field(None, description=number_description(SC_REQ_ITEM))
    state: Optional[str] = Field(
        None, description=choice_description("requested item state", TASK_STATE_EXAMPLES)
    )
    stage: Optional[str] = Field(
        None,
        description=choice_description(
            "stage",
            "Typical values: 'request_approved', 'fulfillment', 'delivery', 'complete', "
            "'Request Cancelled'.",
        ),
    )
    priority: Optional[str] = Field(
        None,
        description=choice_description(
            "priority", "Examples: '1 - Critical', 'High' or value '1'..'5'."
        ),
    )
    order_by: Optional[str] = Field(
        None, description=order_description(SC_REQ_ITEM.order_fields)
    )


class GetRequestByNumberParams(BaseModel):
    """Parameters for fetching one request by number."""

    request_number: str = Field(
        ..., description="Exact request number, REQ followed by digits, e.g. 'REQ0010001'."
    )


class GetRequestItemByNumberParams(BaseModel):
    """Parameters for fetching one requested item by number."""

    request_item_number: str = Field(
        ...,
        description="Exact requested item number, RITM followed by digits, e.g. 'RITM0010001'.",
    )


def list_requests(
    config: ServerConfig, auth_manager: AuthManager, params: ListRequestsParams
) -> dict:
    """List service catalog requests (sc_request)."""
    return run_list(
        config,
        auth_manager,
        SC_REQUEST,
        params,
        records_key="requests",
        error_prefix="Failed to list requests",
    )


def list_request_items(
    config: ServerConfig, auth_manager: AuthManager, params: ListRequestItemsParams
) -> dict:
    """List requested items (sc_req_item)."""
    return run_list(
        config,
        auth_manager,
        SC_REQ_ITEM,
        params,
        records_key="request_items",
        error_prefix="Failed to list requested items",
    )


def get_request_by_number(
    config: ServerConfig, auth_manager: AuthManager, params: GetRequestByNumberParams
) -> dict:
    """Fetch one sc_request by number."""
    return run_get_by_number(
        config, auth_manager, SC_REQUEST, params.request_number, record_key="request"
    )


def get_request_item_by_number(
    config: ServerConfig, auth_manager: AuthManager, params: GetRequestItemByNumberParams
) -> dict:
    """Fetch one sc_req_item by number."""
    return run_get_by_number(
        config, auth_manager, SC_REQ_ITEM, params.request_item_number, record_key="request_item"
    )
