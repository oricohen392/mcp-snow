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
    def __init__(self, records=None, total=None, choices=None, status=200, body=None):
        self.records = records or []
        self.total = total if total is not None else len(self.records)
        self.choices = DEFAULT_CHOICES if choices is None else choices
        self.status = status
        self.body = body
        self.calls: List[Dict[str, Any]] = []

    def table_calls(self, table: str) -> List[Dict[str, Any]]:
        return [c for c in self.calls if c["url"].endswith(f"/table/{table}")]

    def last_query(self, table: str) -> str:
        return self.table_calls(table)[-1]["params"]["sysparm_query"]

    def __call__(self, url, params=None, headers=None, timeout=None, verify=None, **kwargs):
        self.calls.append({"url": url, "params": dict(params or {}), "timeout": timeout})
        if url.endswith("/table/sys_choice"):
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
        return make_response(200, self.body or {"result": self.records}, total=self.total, url=url)
