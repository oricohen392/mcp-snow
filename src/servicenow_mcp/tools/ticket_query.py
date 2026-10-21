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
    "Assignment group name, PARTIAL and case-insensitive. Every word must appear in the group "
    "name, in any order: 'NOC' matches 'NOC' and 'INOC_1'; 'cloud infra' matches "
    "'Cloud Infrastructure' and 'Infra - Cloud Tier2'. "
    "All matching groups are included and listed in matched_groups in the response; check it. "
    "Several groups: comma-separated, any of them matches (OR), e.g. 'NOC, Service Desk'. "
    "A 32-character sys_id is matched exactly. Use the group's own language (e.g. Hebrew names "
    "as they appear in ServiceNow); if unsure, call search_groups first."
)
CHILD_GROUPS_DESC = (
    "Also include child groups (sys_user_group.parent) of the matched groups, up to 3 levels "
    "(default false)."
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
    "Same as status_scope: true = 'open', false = 'closed'. Prefer status_scope."
)
STATUS_SCOPE_DESC_TMPL = (
    "Which records by lifecycle: 'open' = EVERY active (not closed/canceled) state, "
    "'closed' = closed/canceled only, 'all' = any state. Use this, not state labels, when the "
    "user says open / active / current / in progress overall / closed / all. "
    "Default: '{default}'{default_note}. The default is not applied when number or state is given. "
    "The response shows count_ignoring_status, so records in other statuses are never hidden "
    "silently.{extra}"
)
INCIDENT_SCOPE_NOTE = " Note for incidents: Resolved is still active (open) until Closed."


def status_scope_description(default: str, extra: str = "") -> str:
    note = " (open and closed)" if default == "all" else " (all activities in any active state)"
    return STATUS_SCOPE_DESC_TMPL.format(default=default, default_note=note, extra=extra)
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


class TaskFilterParams(BaseModel):
    """Filters shared by all task list and count tools."""

    status_scope: Optional[str] = Field(None, description=status_scope_description("all"))
    active: Optional[bool] = Field(None, description=ACTIVE_DESC)
    assignment_group: Optional[str] = Field(None, description=GROUP_DESC)
    include_child_groups: bool = Field(False, description=CHILD_GROUPS_DESC)
    assignment_group_exact: Optional[str] = Field(None, description=GROUP_EXACT_DESC)
    assigned_to: Optional[str] = Field(None, description=ASSIGNED_TO_DESC)
    created_after: Optional[str] = Field(None, description=date_description("Created", "at or after", ">="))
    created_before: Optional[str] = Field(None, description=date_description("Created", "before", "<"))
    updated_after: Optional[str] = Field(None, description=date_description("Last updated", "at or after", ">="))
    updated_before: Optional[str] = Field(None, description=date_description("Last updated", "before", "<"))
    timezone: Optional[str] = Field(None, description=TIMEZONE_DESC)
    query: Optional[str] = Field(None, description=QUERY_DESC)

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


class TaskListParamsBase(TaskFilterParams):
    """Filters plus paging/sorting shared by all task list tools."""

    limit: int = Field(10, ge=1, description=LIMIT_DESC)
    offset: int = Field(0, ge=0, description=OFFSET_DESC)
    descending: bool = Field(True, description=DESCENDING_DESC)


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
    default_status_scope: str = "all"


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
    default_status_scope="open",  # "all activities" = every change in an active state
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
    matched_groups: List[Dict[str, Any]] = field(default_factory=list)
    status_scope: str = "all"
    filter_query: str = ""  # the query without ORDERBY (for counting)
    query_without_status: Optional[str] = None  # set when a status filter narrowed the list
    filters_description: str = ""
    filter_parts: List[str] = field(default_factory=list)  # description without sorting


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


# ---------------------------------------------------------------------------
# Assignment group resolution
# ---------------------------------------------------------------------------

GROUP_MATCH_LIMIT = 100
CHILD_GROUP_DEPTH = 3
GROUP_FIELDS = "sys_id,name,active"
_GROUP_TOKEN_SPLIT = re.compile(r"[\s\-_/|:()]+")


class NoMatchingGroupError(QueryInputError):
    """No sys_user_group name contains every word of the requested group."""

    error_type = "no_matching_group"


class GroupLookupError(Exception):
    """sys_user_group could not be queried (auth, network, ...); carries the SnResult."""

    def __init__(self, result: Any):
        super().__init__(result.message)
        self.result = result


def group_name_tokens(term: str) -> List[str]:
    """Split a group name fragment into words; each must appear in the group name."""
    text = sanitize_value(term, "assignment_group")
    tokens = [t for t in _GROUP_TOKEN_SPLIT.split(text) if t]
    return tokens or [text]


def group_name_query(term: str, active_only: bool) -> QueryBuilder:
    """nameLIKE<word1>^nameLIKE<word2>...: word order and separators do not matter."""
    builder = QueryBuilder()
    for token in group_name_tokens(term):
        builder.like("name", token)
    if active_only:
        builder.eq("active", "true")
    return builder.order_by("name")


def _group_row(record: Dict[str, Any]) -> Dict[str, Any]:
    row = {"name": display(record.get("name")), "sys_id": display(record.get("sys_id"))}
    if str(display(record.get("active"))).lower() == "false":
        row["active"] = False
    return row


def _query_groups(config: Any, auth_manager: Any, query: str):
    return sn_get(
        config,
        auth_manager,
        "table/sys_user_group",
        {
            "sysparm_query": query,
            "sysparm_limit": GROUP_MATCH_LIMIT,
            "sysparm_fields": GROUP_FIELDS,
            "sysparm_exclude_reference_link": "true",
        },
    )


def resolve_groups(
    config: Any,
    auth_manager: Any,
    term: str,
    include_children: bool,
    warnings: List[str],
) -> Optional[List[Dict[str, Any]]]:
    """
    Find every group whose name contains all words of ``term``.

    Active groups first; inactive ones only when no active group matches.
    Returns None when the caller should fall back to a dot-walked
    assignment_group.nameLIKE filter (sys_user_group not readable, or too many
    matches). Raises NoMatchingGroupError or GroupLookupError.
    """
    groups: List[Dict[str, Any]] = []
    result = None
    for active_only in (True, False):
        query = group_name_query(term, active_only).build()
        result = _query_groups(config, auth_manager, query)
        if not result.ok:
            if result.error_type == "forbidden":
                warnings.append(
                    f"sys_user_group is not readable (HTTP 403); assignment_group '{term}' was "
                    "matched with assignment_group.nameLIKE on the whole text instead."
                )
                return None
            raise GroupLookupError(result)
        groups = [_group_row(r) for r in result.records if display(r.get("sys_id"))]
        if groups:
            break
    if not groups:
        raise NoMatchingGroupError(
            f"no assignment group name contains all of {group_name_tokens(term)} (active or "
            f"inactive). Call search_groups with one word, e.g. '{group_name_tokens(term)[0]}', "
            "to see the real group names, then retry with one of them."
        )
    if (result.total_count or 0) > GROUP_MATCH_LIMIT:
        warnings.append(
            f"assignment_group '{term}' matches {result.total_count} groups (more than "
            f"{GROUP_MATCH_LIMIT}); matched with assignment_group.nameLIKE instead. Use a more "
            "specific name."
        )
        return None

    if include_children:
        seen = {g["sys_id"] for g in groups}
        frontier = list(seen)
        for _ in range(CHILD_GROUP_DEPTH):
            query = QueryBuilder().in_("parent", frontier).eq("active", "true").build()
            children = _query_groups(config, auth_manager, query)
            if not children.ok:
                warnings.append(
                    f"child groups of '{term}' could not be loaded ({children.message}); "
                    "only the matched groups are included."
                )
                break
            new = [_group_row(r) for r in children.records]
            new = [g for g in new if g["sys_id"] and g["sys_id"] not in seen]
            if not new:
                break
            for g in new:
                g["child_of_match"] = True
                seen.add(g["sys_id"])
            groups.extend(new)
            frontier = [g["sys_id"] for g in new]
    return groups


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


STATUS_SCOPES = ("open", "closed", "all")
# Choice parameters that describe where a record is in its lifecycle. When one of
# them (or status_scope/active) filters the list, the response also reports how
# many records match the other filters in any status.
STATUS_CHOICE_PARAMS = ("state", "request_state", "stage")
STATUS_SCOPE_TEXT = {
    "open": "status: open = any active state (active=true)",
    "closed": "status: closed/canceled (active=false)",
    "all": "status: any (open and closed)",
}


def effective_status_scope(spec: TableSpec, params: BaseModel) -> Tuple[str, bool]:
    """
    Return (scope, explicit) from status_scope / active / the table default.

    The table default is not applied when a record number or an explicit state
    is given: asking for CHG0030001 or state=Closed must not be narrowed to
    open records.
    """
    get = lambda name: getattr(params, name, None)  # noqa: E731
    scope = get("status_scope")
    if scope is not None and str(scope).strip():
        scope = str(scope).strip().lower()
        if scope not in STATUS_SCOPES:
            raise QueryInputError(
                f"status_scope '{scope}' is not valid. Allowed: {', '.join(STATUS_SCOPES)}"
            )
    else:
        scope = None
    active = get("active")
    if active is not None:
        implied = "open" if active else "closed"
        if scope is not None and scope != implied:
            raise QueryInputError(
                f"active={str(active).lower()} contradicts status_scope='{scope}'; pass only one"
            )
        return implied, True
    if scope is not None:
        return scope, True
    if get("number") or any(get(p) for p in STATUS_CHOICE_PARAMS if p in spec.choice_params):
        return "all", False
    return spec.default_status_scope, False


def build_query(
    config: Any,
    auth_manager: Any,
    spec: TableSpec,
    params: BaseModel,
    extra: Optional[Callable[[QueryBuilder, BaseModel], None]] = None,
) -> BuiltQuery:
    """Translate tool params into a sanitized encoded query. Raises QueryInputError."""
    builder = QueryBuilder()  # the full query
    rest = QueryBuilder()  # the same filters without any status condition
    both = (builder, rest)
    warnings: List[str] = []
    described: List[str] = []
    status_filtered = False
    get = lambda name: getattr(params, name, None)  # noqa: E731

    if get("number"):
        numbers = validate_numbers(spec, get("number"))
        for b in both:
            b.in_("number", numbers)
        described.append(f"number in [{', '.join(numbers)}]")

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
        is_status = param_name in STATUS_CHOICE_PARAMS
        for b in (builder,) if is_status else both:
            b.in_(choice.field, resolution.values)
        status_filtered = status_filtered or is_status
        described.append(
            f"{param_name} in [{', '.join(items)}] (values {', '.join(resolution.values)})"
        )

    scope, scope_explicit = effective_status_scope(spec, params)
    if scope != "all":
        builder.eq("active", "true" if scope == "open" else "false")
        status_filtered = True
    scope_text = STATUS_SCOPE_TEXT[scope]
    if not scope_explicit and scope != "all":
        scope_text += f" [default for {spec.plural}; status_scope='all' includes closed]"
    described.append(scope_text)

    matched_groups: List[Dict[str, Any]] = []
    if get("assignment_group"):
        items = split_list(get("assignment_group"), "assignment_group")
        if items:
            group_ids: List[str] = []
            fallback_items: List[str] = []
            for item in items:
                if is_sys_id(item):
                    group_ids.append(item.lower())
                    continue
                found = resolve_groups(
                    config, auth_manager, item, bool(get("include_child_groups")), warnings
                )
                if found is None:
                    fallback_items.append(item)
                    continue
                for group in found:
                    if group["sys_id"] not in group_ids:
                        group_ids.append(group["sys_id"])
                        matched_groups.append(group)
            conditions = []
            if group_ids:
                conditions.append(("assignment_group", "IN", group_ids))
            conditions.extend(("assignment_group.name", "LIKE", item) for item in fallback_items)
            for b in both:
                b.or_group(conditions)
            names = [g["name"] for g in matched_groups]
            names += [i for i in items if is_sys_id(i)]
            names += [f"name contains '{i}'" for i in fallback_items]
            described.append(f"assignment group in [{', '.join(names)}]")

    if get("assignment_group_exact"):
        items = split_list(get("assignment_group_exact"), "assignment_group_exact")
        if items:
            for b in both:
                b.or_group([("assignment_group.name", "=", item) for item in items])
            described.append(f"assignment group name is exactly one of [{', '.join(items)}]")

    if get("assigned_to"):
        items = split_list(get("assigned_to"), "assigned_to")
        if items:
            for b in both:
                b.or_group(_person_or_group_conditions("assigned_to", items, "name", "user_name"))
            described.append(f"assigned to matches [{', '.join(items)}]")

    for param_name, (field_name, operator) in spec.date_params.items():
        raw = get(param_name)
        if raw:
            value = to_servicenow_utc(raw, get("timezone"), param_name)
            for b in both:
                b.where(field_name, operator, value)
            described.append(f"{field_name} {operator} {value} UTC")

    if get("query"):
        text = sanitize_value(get("query"), "query")
        for b in both:
            b.or_group([(f, "LIKE", text) for f in spec.text_fields])
        described.append(f"text '{text}' in {' or '.join(spec.text_fields)}")

    if extra is not None:
        for b in both:
            extra(b, params)
        if get("timeframe"):
            described.append(f"timeframe {get('timeframe')} (relative to now, UTC)")

    order_by = get("order_by") or "sys_created_on"
    if order_by not in spec.order_fields:
        raise QueryInputError(
            f"order_by '{order_by}' is not allowed. Allowed: {', '.join(spec.order_fields)}"
        )
    descending = get("descending")
    descending = True if descending is None else bool(descending)
    builder.order_by(order_by, descending=descending)
    filter_parts = list(described)
    described.append(f"sorted by {order_by} {'descending' if descending else 'ascending'}")

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
        matched_groups=matched_groups,
        status_scope=scope,
        filter_query="^".join(builder.terms),
        query_without_status="^".join(rest.terms) if status_filtered else None,
        filters_description=f"{spec.table}: " + "; ".join(described),
        filter_parts=filter_parts,
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _input_error(message: str, error_prefix: str, error_type: str = "invalid_input") -> Dict[str, Any]:
    return {
        "success": False,
        "status_code": None,
        "error_type": error_type,
        "message": f"{error_prefix}: {message}",
    }


def query_error_response(exc: Exception, error_prefix: str) -> Dict[str, Any]:
    """Failure payload for an error raised while building a query."""
    if isinstance(exc, GroupLookupError):
        response = exc.result.error_dict(f"{error_prefix} (assignment group lookup)")
        return response
    return _input_error(str(exc), error_prefix, getattr(exc, "error_type", "invalid_input"))


@dataclass
class CountResult:
    ok: bool
    count: Optional[int] = None
    groups: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "aggregate_api"  # or "x_total_count"
    warnings: List[str] = field(default_factory=list)
    error: Optional[Dict[str, Any]] = None


def _stats_count(stats: Any) -> Optional[int]:
    try:
        return int(str((stats or {}).get("count")))
    except (TypeError, ValueError):
        return None


def aggregate_count(
    config: Any,
    auth_manager: Any,
    table: str,
    query: str,
    group_by: Optional[str] = None,
) -> CountResult:
    """
    Count records with the Aggregate API (GET /api/now/stats/<table>).

    Without group_by, an Aggregate API 403/404 falls back to X-Total-Count of a
    one-row Table API query. The count is what the integration account can see.
    """
    params: Dict[str, Any] = {"sysparm_count": "true", "sysparm_query": query}
    if group_by:
        params["sysparm_group_by"] = group_by
        params["sysparm_display_value"] = "all"
    result = sn_get(config, auth_manager, f"stats/{table}", params)
    if result.ok:
        if not group_by:
            count = _stats_count(result.records[0].get("stats")) if result.records else None
            if count is not None:
                return CountResult(ok=True, count=count)
        else:
            groups = []
            for row in result.records:
                count = _stats_count(row.get("stats"))
                fields = row.get("groupby_fields") or [{}]
                value = fields[0].get("value")
                if count is None:
                    break
                groups.append(
                    {
                        "value": value,
                        "display": fields[0].get("display_value") or value or "(empty)",
                        "count": count,
                    }
                )
            else:
                groups.sort(key=lambda g: g["count"], reverse=True)
                return CountResult(
                    ok=True, count=sum(g["count"] for g in groups), groups=groups
                )
        return CountResult(
            ok=False,
            error={
                "success": False,
                "status_code": result.status_code,
                "error_type": "invalid_response",
                "message": "Aggregate API answered without a usable stats.count.",
            },
        )

    if result.error_type in ("forbidden", "not_found") and not group_by:
        fallback = sn_get(
            config,
            auth_manager,
            f"table/{table}",
            {"sysparm_query": query, "sysparm_limit": 1, "sysparm_fields": "sys_id"},
        )
        if fallback.ok and fallback.total_count is not None:
            return CountResult(
                ok=True,
                count=fallback.total_count,
                source="x_total_count",
                warnings=[
                    f"Aggregate API not available (HTTP {result.status_code}); counted with "
                    "the Table API X-Total-Count header instead."
                ],
            )
        if not fallback.ok:
            return CountResult(ok=False, error=fallback.error_dict("Count failed"))
    return CountResult(ok=False, error=result.error_dict("Count failed"))


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
    except (QueryInputError, GroupLookupError) as e:
        response = query_error_response(e, error_prefix)
        response[records_key] = []
        return response

    # Count the same filters in any status first, so a status filter never hides
    # records silently ("9 match, 6 of them open").
    count_ignoring_status = None
    if built.query_without_status is not None:
        other = aggregate_count(config, auth_manager, spec.table, built.query_without_status)
        if other.ok:
            count_ignoring_status = other.count

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
        "filters_description": built.filters_description,
        "status_scope": built.status_scope,
        "limit": built.limit,
        "offset": built.offset,
    }
    if built.matched_groups:
        meta["matched_groups"] = built.matched_groups
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
    if count_ignoring_status is not None:
        response["count_ignoring_status"] = count_ignoring_status
        total = result.total_count
        if total is not None and count_ignoring_status > total:
            response["status_note"] = (
                f"{count_ignoring_status - total} more {spec.plural} match the same filters in "
                f"other statuses ({total} shown by the status filter, {count_ignoring_status} in "
                "any status). Use status_scope='all' to include them."
            )
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
