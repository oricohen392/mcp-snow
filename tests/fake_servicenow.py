"""
A tiny fake of the ServiceNow Table API for unit tests (patches requests.get).

Serves sys_choice rows from a dict and records every request so tests can
assert on the exact sysparm_query that was sent.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

import requests

DEFAULT_CHOICES: Dict[Tuple[str, str], List[Dict[str, str]]] = {
    ("incident", "state"): [
        {"value": "1", "label": "New"},
        {"value": "2", "label": "In Progress"},
        {"value": "3", "label": "On Hold"},
        {"value": "6", "label": "Resolved"},
        {"value": "7", "label": "Closed"},
        {"value": "8", "label": "Canceled"},
    ],
    ("task", "priority"): [
        {"value": "1", "label": "1 - Critical"},
        {"value": "2", "label": "2 - High"},
        {"value": "3", "label": "3 - Moderate"},
        {"value": "4", "label": "4 - Low"},
        {"value": "5", "label": "5 - Planning"},
    ],
    ("incident", "category"): [
        {"value": "network", "label": "Network"},
        {"value": "software", "label": "Software"},
    ],
    ("change_request", "state"): [
        {"value": "-5", "label": "New"},
        {"value": "-1", "label": "Implement"},
        {"value": "3", "label": "Closed"},
    ],
    ("change_request", "type"): [
        {"value": "normal", "label": "Normal"},
        {"value": "emergency", "label": "Emergency"},
    ],
    ("change_request", "risk"): [
        {"value": "2", "label": "High"},
        {"value": "3", "label": "Moderate"},
        {"value": "4", "label": "Low"},
    ],
    ("task", "state"): [
        {"value": "1", "label": "Open"},
        {"value": "2", "label": "Work in Progress"},
        {"value": "3", "label": "Closed Complete"},
    ],
    ("sc_request", "request_state"): [
        {"value": "in_process", "label": "Approved"},
        {"value": "requested", "label": "Pending Approval"},
    ],
    ("sc_req_item", "stage"): [
        {"value": "fulfillment", "label": "Fulfillment"},
    ],
}


def gid(n: int) -> str:
    """Deterministic 32-hex sys_id for test groups."""
    return f"{n:032x}"


DEFAULT_GROUPS: List[Dict[str, str]] = [
    {"sys_id": gid(1), "name": "NOC", "active": "true", "parent": ""},
    {"sys_id": gid(2), "name": "INOC_1", "active": "true", "parent": ""},
    {"sys_id": gid(3), "name": "Service Desk", "active": "true", "parent": ""},
    {"sys_id": gid(4), "name": "DBA", "active": "true", "parent": ""},
    {"sys_id": gid(5), "name": "IT Support", "active": "true", "parent": ""},
    {"sys_id": gid(6), "name": "תשתיות ענן", "active": "true", "parent": ""},
    {"sys_id": gid(7), "name": "ענן - תשתיות Tier2", "active": "true", "parent": ""},
    {"sys_id": gid(8), "name": "Linux Team", "active": "true", "parent": gid(6)},
    {"sys_id": gid(9), "name": "Old NOC", "active": "false", "parent": ""},
    {"sys_id": gid(10), "name": "Linux Night Shift", "active": "true", "parent": gid(8)},
    {"sys_id": gid(11), "name": "Legacy Mainframe", "active": "false", "parent": ""},
]


def _filter_groups(groups: List[Dict[str, str]], query: str) -> List[Dict[str, str]]:
    """Evaluate the small subset of encoded-query syntax used for sys_user_group lookups."""
    rows = list(groups)
    for term in query.split("^"):
        if not term or term.startswith("ORDERBY"):
            continue
        if term.startswith("nameLIKE"):
            needle = term[len("nameLIKE"):].casefold()
            rows = [g for g in rows if needle in g["name"].casefold()]
        elif term == "active=true":
            rows = [g for g in rows if g["active"] == "true"]
        elif term.startswith("parentIN"):
            parents = set(term[len("parentIN"):].split(","))
            rows = [g for g in rows if g.get("parent") in parents]
        elif term.startswith("parent="):
            rows = [g for g in rows if g.get("parent") == term[len("parent="):]]
        else:
            raise AssertionError(f"fake sys_user_group cannot evaluate {term!r}")
    return rows


def make_response(
    status: int = 200,
    body: Any = None,
    total: Optional[int] = None,
    url: str = "https://example.service-now.com/api/now/table/x",
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.reason = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 500: "Server Error"}.get(
        status, "Status"
    )
    if body is None:
        body = {"result": []}
    response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    if total is not None:
        response.headers["X-Total-Count"] = str(total)
    return response


class FakeServiceNow:
    def __init__(
        self,
        records=None,
        total=None,
        choices=None,
        status=200,
        body=None,
        groups=None,
        stats_status=200,
        stats_count=None,
        stats_groups=None,
    ):
        """
        groups: sys_user_group rows (see DEFAULT_GROUPS) evaluated against the
            query; None serves ``records`` for sys_user_group like any table.
        stats_status / stats_count / stats_groups: Aggregate API (/stats) behaviour;
            stats_groups is a list of (value, display_value, count).
        """
        self.records = records or []
        self.total = total if total is not None else len(self.records)
        self.choices = DEFAULT_CHOICES if choices is None else choices
        self.status = status
        self.body = body
        self.groups = groups
        self.stats_status = stats_status
        self.stats_count = stats_count
        self.stats_groups = stats_groups
        self.calls: List[Dict[str, Any]] = []

    def table_calls(self, table: str) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["url"].endswith(f"/table/{table}")]

    def stats_calls(self, table: str) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["url"].endswith(f"/stats/{table}")]

    def last_query(self, table: str) -> str:
        return self.table_calls(table)[-1]["params"]["sysparm_query"]

    def __call__(self, url, params=None, headers=None, timeout=None, verify=None, **kwargs):
        self.calls.append({"url": url, "params": dict(params or {}), "timeout": timeout})
        if url.endswith("/table/sys_choice") and "sysparm_query" in (params or {}):
            query = params["sysparm_query"]
            name = query.split("name=")[1].split("^")[0]
            element = query.split("element=")[1].split("^")[0]
            rows = self.choices.get((name, element), [])
            return make_response(200, {"result": rows}, total=len(rows), url=url)
        if self.status != 200:
            body = self.body or {
                "error": {"message": "Denied", "detail": "fake detail"},
                "status": "failure",
            }
            return make_response(self.status, body, url=url)
        if "/stats/" in url:
            return self._stats(url, params or {})
        if url.endswith("/table/sys_user_group") and self.groups is not None:
            rows = _filter_groups(self.groups, (params or {}).get("sysparm_query", ""))
            limit = int((params or {}).get("sysparm_limit", len(rows)) or len(rows))
            return make_response(200, {"result": rows[:limit]}, total=len(rows), url=url)
        return make_response(200, self.body or {"result": self.records}, total=self.total, url=url)

    def _stats(self, url: str, params: Dict[str, Any]) -> requests.Response:
        if self.stats_status != 200:
            return make_response(
                self.stats_status, {"error": {"message": "stats denied"}}, url=url
            )
        if params.get("sysparm_group_by"):
            field = params["sysparm_group_by"]
            rows = [
                {
                    "stats": {"count": str(count)},
                    "groupby_fields": [
                        {"field": field, "value": value, "display_value": display_value}
                    ],
                }
                for value, display_value, count in (self.stats_groups or [])
            ]
            return make_response(200, {"result": rows}, url=url)
        count = self.stats_count if self.stats_count is not None else self.total
        return make_response(200, {"result": {"stats": {"count": str(count)}}}, url=url)
