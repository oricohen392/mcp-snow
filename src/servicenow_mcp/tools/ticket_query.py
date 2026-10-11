"""
Shared list/get engine for task tables: incident, change_request, sc_request, sc_req_item.

Builds a sanitized encoded query from tool parameters, resolves choice labels
via sys_choice, converts dates to UTC, caps the limit, and returns a response
that always states what was sent (``query_used``) and how much matched
(``total_count`` from X-Total-Count). Errors are reported as success=false with
the HTTP status; they are never presented as "0 results".
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator

from servicenow_mcp.utils import settings
from servicenow_mcp.utils.choices import CHOICES
from servicenow_mcp.utils.dates import to_servicenow_utc
from servicenow_mcp.utils.http import sn_get
from servicenow_mcp.utils.query import (
    QueryBuilder,
    QueryInputError,
    is_sys_id,
    sanitize_value,
    split_list,
)

logger = logging.getLogger(__name__)

EMPTY_RESULT_HINT = (
    "ServiceNow answered HTTP 200 with no rows. Either no record matches query_used, "
    "or the ServiceNow account is not allowed to see the matching records (row-level ACLs "
    "and domain separation hide rows without returning an error). Run check_access to see "
    "what this account can read, use search_groups to find exact group names, or loosen "
    "the filters."
)


# ---------------------------------------------------------------------------
# Parameter models
# ---------------------------------------------------------------------------


def _list_to_text(value: Any) -> Any:
    """Allow list input for comma-separated string parameters (kept as type string in the schema)."""
    if isinstance(value, (list, tuple)):
        return json.dumps([str(v) for v in value])
    return value


GROUP_DESC = (
    "Assignment group name, PARTIAL and case-insensitive match on the group name "
    "(assignment_group.nameLIKE...). Example: 'NOC' matches 'INOC_1' and 'NOC Tier 2'. "
    "Several groups: comma-separated, any of them matches (OR), e.g. 'NOC, Service Desk'. "
    "A 32-character sys_id is matched exactly. Use search_groups to discover real names."
)
GROUP_EXACT_DESC = (
    "Assignment group name, EXACT match (assignment_group.name=...). "
    "Comma-separated for OR, e.g. 'Network Operations, Service Desk'."
)
ASSIGNED_TO_DESC = (
    "Assignee: partial, case-insensitive match on the user's full name, or an exact "
    "user_name / sys_id. Example: 'cohen' or 'jsmith'. Comma-separated for OR."
)
ACTIVE_DESC = (
    "true = only open/active records (not closed/canceled), false = only inactive. "
    "Use active=true for 'open tickets' instead of a state label."
)
NUMBER_DESC_TMPL = (
    "Exact record number(s), {prefix} followed by digits, e.g. '{example}'. "
    "Comma-separated for several: '{example},{example2}'."
)
QUERY_DESC = (
    "Free-text search: partial, case-insensitive match in short_description OR description. "
    "Example: 'vpn'. The '^' character is not allowed."
)
DATE_DESC_TMPL = (
    "{what} {rel} this moment ({op}). ISO-8601 date or datetime: '2024-05-01', "
    "'2024-05-01T08:30:00', '2024-05-01T08:30:00Z' or with offset '+03:00'. "
    "Without an offset the 'timezone' parameter (or DEFAULT_TIMEZONE, default UTC) is used; "
    "converted to UTC before querying. Date-only means midnight at the start of that day."
)
TIMEZONE_DESC = (
    "IANA timezone for dates given without an offset, e.g. 'Asia/Jerusalem', 'UTC'. "
    "Defaults to the server's DEFAULT_TIMEZONE (UTC if unset)."
)
LIMIT_DESC = (
    "Maximum records to return (default 10). Values above the server's MAX_LIMIT "
    "(default 100) are capped; see limit_capped in the response."
)
OFFSET_DESC = "Number of records to skip, for paging (default 0). Use with total_count."
DESCENDING_DESC = "Sort descending (newest first) when true (default true)."


def choice_description(field_name: str, examples: str) -> str:
    return (
        f"Filter by {field_name}: label or internal value, resolved against this instance's "
        f"sys_choice table (case-insensitive). {examples} "
        "Comma-separated for OR. An unknown label returns an error listing the valid labels."
    )


def date_description(what: str, rel: str, op: str) -> str:
    return DATE_DESC_TMPL.format(what=what, rel=rel, op=op)


def order_description(fields: Tuple[str, ...]) -> str:
    return (
        "Field to sort by. Allowed: " + ", ".join(fields) + ". Default sys_created_on."
    )


class TaskListParamsBase(BaseModel):
    """Filters shared by all task list tools."""

    limit: int = Field(10, ge=1, description=LIMIT_DESC)
    offset: int = Field(0, ge=0, description=OFFSET_DESC)
    active: Optional[bool] = Field(None, description=ACTIVE_DESC)
    assignment_group: Optional[str] = Field(None, description=GROUP_DESC)
    assignment_group_exact: Optional[str] = Field(None, description=GROUP_EXACT_DESC)
    assigned_to: Optional[str] = Field(None, description=ASSIGNED_TO_DESC)
    created_after: Optional[str] = Field(None, description=date_description("Created", "at or after", ">="))
    created_before: Optional[str] = Field(None, description=date_description("Created", "before", "<"))
    updated_after: Optional[str] = Field(None, description=date_description("Last updated", "at or after", ">="))
    updated_before: Optional[str] = Field(None, description=date_description("Last updated", "before", "<"))
    timezone: Optional[str] = Field(None, description=TIMEZONE_DESC)
    query: Optional[str] = Field(None, description=QUERY_DESC)
    descending: bool = Field(True, description=DESCENDING_DESC)

    @field_validator(
        "assignment_group",
        "assignment_group_exact",
        "assigned_to",
        "number",
        "state",
        "priority",
        "category",
        "type",
        "risk",
        "request_state",
        "stage",
        mode="before",
        check_fields=False,
    )
    @classmethod
    def _accept_lists(cls, value: Any) -> Any:
        return _list_to_text(value)


# ---------------------------------------------------------------------------
# Table specifications
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChoiceParam:
    field: str
    numeric: bool


@dataclass(frozen=True)
class TableSpec:
    table: str
    noun: str  # "incident"
    plural: str  # "incidents"
    number_prefix: str
    number_example: str
    choice_params: Dict[str, ChoiceParam]
    order_fields: Tuple[str, ...]
    date_params: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    text_fields: Tuple[str, ...] = ("short_description", "description")
    mapper: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None


BASE_DATE_PARAMS = {
    "created_after": ("sys_created_on", ">="),
    "created_before": ("sys_created_on", "<"),
    "updated_after": ("sys_updated_on", ">="),
    "updated_before": ("sys_updated_on", "<"),
}
BASE_ORDER = ("sys_created_on", "sys_updated_on", "opened_at", "number", "priority", "state")


def display(value: Any) -> Any:
    """Return the display value of a field that may be a reference dict."""
    if isinstance(value, dict):
        return value.get("display_value", value.get("value"))
    return value


def pick(record: Dict[str, Any], mapping: Dict[str, str]) -> Dict[str, Any]:
    return {out: display(record.get(src)) for out, src in mapping.items()}


def map_incident(record: Dict[str, Any]) -> Dict[str, Any]:
    return pick(
        record,
        {
            "sys_id": "sys_id",
            "number": "number",
            "short_description": "short_description",
            "description": "description",
            "state": "state",
            "priority": "priority",
            "assigned_to": "assigned_to",
            "assignment_group": "assignment_group",
            "category": "category",
            "subcategory": "subcategory",
            "created_on": "sys_created_on",
            "updated_on": "sys_updated_on",
        },
    )


def map_request(record: Dict[str, Any]) -> Dict[str, Any]:
    return pick(
        record,
        {
            "sys_id": "sys_id",
            "number": "number",
            "short_description": "short_description",
            "description": "description",
            "state": "state",
            "request_state": "request_state",
            "approval": "approval",
            "priority": "priority",
            "requested_for": "requested_for",
            "opened_by": "opened_by",
            "assignment_group": "assignment_group",
            "assigned_to": "assigned_to",
            "opened_at": "opened_at",
            "due_date": "due_date",
            "created_on": "sys_created_on",
            "updated_on": "sys_updated_on",
        },
    )


def map_request_item(record: Dict[str, Any]) -> Dict[str, Any]:
    return pick(
        record,
        {
            "sys_id": "sys_id",
            "number": "number",
            "short_description": "short_description",
            "description": "description",
            "state": "state",
            "stage": "stage",
            "approval": "approval",
            "priority": "priority",
            "cat_item": "cat_item",
            "request": "request",
            "requested_for": "requested_for",
            "assignment_group": "assignment_group",
            "assigned_to": "assigned_to",
            "opened_at": "opened_at",
            "due_date": "due_date",
            "created_on": "sys_created_on",
            "updated_on": "sys_updated_on",
        },
    )


INCIDENT = TableSpec(
    table="incident",
    noun="incident",
    plural="incidents",
    number_prefix="INC",
    number_example="INC0010001",
    choice_params={
        "state": ChoiceParam("state", numeric=True),
        "priority": ChoiceParam("priority", numeric=True),
        "category": ChoiceParam("category", numeric=False),
    },
    order_fields=BASE_ORDER,
    date_params=dict(BASE_DATE_PARAMS),
    mapper=map_incident,
)

CHANGE_REQUEST = TableSpec(
    table="change_request",
    noun="change request",
    plural="change requests",
    number_prefix="CHG",
    number_example="CHG0030001",
    choice_params={
        "state": ChoiceParam("state", numeric=True),
        "priority": ChoiceParam("priority", numeric=True),
        "category": ChoiceParam("category", numeric=False),
        "type": ChoiceParam("type", numeric=False),
        "risk": ChoiceParam("risk", numeric=True),
    },
    order_fields=BASE_ORDER + ("start_date", "end_date"),
    date_params={
        **BASE_DATE_PARAMS,
        "start_after": ("start_date", ">="),
        "start_before": ("start_date", "<"),
        "end_after": ("end_date", ">="),
        "end_before": ("end_date", "<"),
    },
    mapper=None,  # change tools historically return the raw records
)

SC_REQUEST = TableSpec(
    table="sc_request",
    noun="request",
    plural="requests",
    number_prefix="REQ",
    number_example="REQ0010001",
    choice_params={
        "state": ChoiceParam("state", numeric=True),
        "request_state": ChoiceParam("request_state", numeric=False),
        "priority": ChoiceParam("priority", numeric=True),
    },
    order_fields=BASE_ORDER + ("due_date",),
    date_params=dict(BASE_DATE_PARAMS),
    mapper=map_request,
)

SC_REQ_ITEM = TableSpec(
    table="sc_req_item",
    noun="requested item",
    plural="requested items",
    number_prefix="RITM",
    number_example="RITM0010001",
    choice_params={
        "state": ChoiceParam("state", numeric=True),
        "stage": ChoiceParam("stage", numeric=False),
        "priority": ChoiceParam("priority", numeric=True),
    },
    order_fields=BASE_ORDER + ("due_date",),
    date_params=dict(BASE_DATE_PARAMS),
    mapper=map_request_item,
)


def number_description(spec: TableSpec) -> str:
    digits = spec.number_example[len(spec.number_prefix):]
    example2 = spec.number_prefix + str(int(digits) + 1).zfill(len(digits))
    return NUMBER_DESC_TMPL.format(
        prefix=spec.number_prefix, example=spec.number_example, example2=example2
    )


# ---------------------------------------------------------------------------
# Query building
# ---------------------------------------------------------------------------


@dataclass
class BuiltQuery:
    query: str
    limit: int
    offset: int
    limit_capped: bool
    warnings: List[str]


def validate_numbers(spec: TableSpec, raw: Any) -> List[str]:
    numbers = [n.upper() for n in split_list(raw, "number")]
    pattern = re.compile(rf"^{spec.number_prefix}\d+$")
    for n in numbers:
        if not pattern.match(n):
            raise QueryInputError(
                f"number '{n}' is not a {spec.noun} number: expected {spec.number_prefix} "
                f"followed by digits, e.g. {spec.number_example}"
            )
    return numbers


def _person_or_group_conditions(base: str, items: List[str], name_field: str, exact_alt: Optional[str]):
    conditions = []
    for item in items:
        if is_sys_id(item):
            conditions.append((base, "=", item.lower()))
            continue
        conditions.append((f"{base}.{name_field}", "LIKE", item))
        if exact_alt:
            conditions.append((f"{base}.{exact_alt}", "=", item))
    return conditions


def build_query(
    config: Any,
    auth_manager: Any,
    spec: TableSpec,
    params: BaseModel,
    extra: Optional[Callable[[QueryBuilder, BaseModel], None]] = None,
) -> BuiltQuery:
    """Translate tool params into a sanitized encoded query. Raises QueryInputError."""
    builder = QueryBuilder()
    warnings: List[str] = []
    get = lambda name: getattr(params, name, None)  # noqa: E731

    if get("number"):
        builder.in_("number", validate_numbers(spec, get("number")))

    for param_name, choice in spec.choice_params.items():
        raw = get(param_name)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            continue
        items = split_list(raw, param_name)
        if not items:
            continue
        resolution = CHOICES.resolve(
            config, auth_manager, spec.table, choice.field, items, numeric=choice.numeric
        )
        warnings.extend(resolution.warnings)
        builder.in_(choice.field, resolution.values)

    if get("active") is not None:
        builder.eq("active", "true" if get("active") else "false")

    if get("assignment_group"):
        items = split_list(get("assignment_group"), "assignment_group")
        if items:
            builder.or_group(_person_or_group_conditions("assignment_group", items, "name", None))

    if get("assignment_group_exact"):
        items = split_list(get("assignment_group_exact"), "assignment_group_exact")
        if items:
            builder.or_group([("assignment_group.name", "=", item) for item in items])

    if get("assigned_to"):
        items = split_list(get("assigned_to"), "assigned_to")
        if items:
            builder.or_group(
                _person_or_group_conditions("assigned_to", items, "name", "user_name")
            )

    for param_name, (field_name, operator) in spec.date_params.items():
        raw = get(param_name)
        if raw:
            builder.where(field_name, operator, to_servicenow_utc(raw, get("timezone"), param_name))

    if get("query"):
        text = sanitize_value(get("query"), "query")
        builder.or_group([(f, "LIKE", text) for f in spec.text_fields])

    if extra is not None:
        extra(builder, params)

    order_by = get("order_by") or "sys_created_on"
    if order_by not in spec.order_fields:
        raise QueryInputError(
            f"order_by '{order_by}' is not allowed. Allowed: {', '.join(spec.order_fields)}"
        )
    descending = get("descending")
    builder.order_by(order_by, descending=True if descending is None else bool(descending))

    requested = get("limit") or 10
    cap = settings.max_limit()
    limit = min(int(requested), cap)
    offset = int(get("offset") or 0)
    return BuiltQuery(
        query=builder.build(),
        limit=limit,
        offset=offset,
        limit_capped=int(requested) > cap,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _input_error(message: str, error_prefix: str) -> Dict[str, Any]:
    return {
        "success": False,
        "status_code": None,
        "error_type": "invalid_input",
        "message": f"{error_prefix}: {message}",
    }


def run_list(
    config: Any,
    auth_manager: Any,
    spec: TableSpec,
    params: BaseModel,
    records_key: str,
    error_prefix: str,
    extra: Optional[Callable[[QueryBuilder, BaseModel], None]] = None,
) -> Dict[str, Any]:
    """Run a list query and build the transparent response."""
    try:
        built = build_query(config, auth_manager, spec, params, extra)
    except QueryInputError as e:
        response = _input_error(str(e), error_prefix)
        response[records_key] = []
        return response

    sysparms = {
        "sysparm_query": built.query,
        "sysparm_limit": built.limit,
        "sysparm_offset": built.offset,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true",
    }
    logger.info("list %s query_used=%s limit=%d offset=%d", spec.table, built.query, built.limit, built.offset)
    result = sn_get(config, auth_manager, f"table/{spec.table}", sysparms)

    meta = {
        "query_used": built.query,
        "limit": built.limit,
        "offset": built.offset,
    }
    if built.limit_capped:
        meta["limit_capped"] = True
    if built.warnings:
        meta["warnings"] = built.warnings

    if not result.ok:
        response = result.error_dict(error_prefix)
        response[records_key] = []
        response.update(meta)
        return response

    records = [spec.mapper(r) for r in result.records] if spec.mapper else result.records
    response: Dict[str, Any] = {
        "success": True,
        "message": f"Found {len(records)} {spec.plural}",
        records_key: records,
        "returned": len(records),
        "total_count": result.total_count,
        **meta,
    }
    if not records:
        response["hint"] = EMPTY_RESULT_HINT
    elif (
        result.total_count is not None
        and len(records) < built.limit
        and result.total_count > built.offset + len(records)
    ):
        response["hint"] = (
            f"X-Total-Count reports {result.total_count} matching rows but only "
            f"{len(records)} were returned from offset {built.offset}; some rows may be hidden "
            "by row-level ACLs."
        )
    return response


def run_get_by_number(
    config: Any,
    auth_manager: Any,
    spec: TableSpec,
    number: str,
    record_key: str,
) -> Dict[str, Any]:
    """Fetch exactly one record by number."""
    try:
        numbers = validate_numbers(spec, number)
        if len(numbers) != 1:
            raise QueryInputError(f"exactly one {spec.noun} number is required")
        query = QueryBuilder().eq("number", numbers[0]).build()
    except QueryInputError as e:
        return _input_error(str(e), f"Invalid {spec.noun} number")

    result = sn_get(
        config,
        auth_manager,
        f"table/{spec.table}",
        {
            "sysparm_query": query,
            "sysparm_limit": 1,
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
        },
    )
    if not result.ok:
        response = result.error_dict(f"Failed to fetch {spec.noun}")
        response["query_used"] = query
        return response
    if not result.records:
        return {
            "success": False,
            "message": f"{spec.noun[0].upper() + spec.noun[1:]} not found: {numbers[0]}",
            "query_used": query,
            "total_count": result.total_count,
            "returned": 0,
            "hint": EMPTY_RESULT_HINT,
        }
    record = result.records[0]
    return {
        "success": True,
        "message": f"{spec.noun[0].upper() + spec.noun[1:]} {numbers[0]} found",
        record_key: spec.mapper(record) if spec.mapper else record,
        "query_used": query,
    }
