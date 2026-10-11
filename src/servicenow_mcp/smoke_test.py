"""
Smoke test to run inside the pod (or anywhere with the same env vars).

    servicenow-mcp-smoke                     # ServiceNow checks via the tool functions
    servicenow-mcp-smoke --group NOC --limit 3
    servicenow-mcp-smoke --mcp-url http://localhost:8080/sse   # also list tools over MCP/SSE
    servicenow-mcp-smoke --mcp-only --mcp-url http://servicenow-mcp.ns.svc:8080/sse

ServiceNow part: check_access, search_groups(<group>), and one list call per
table (incident, change_request, sc_request, sc_req_item). For each it prints
success / HTTP status, query_used, total_count and returned. Secrets are never
printed. Exit code 0 when every call succeeded, 1 otherwise.

MCP part (--mcp-url): connects like Dify does (SSE), runs initialize and
tools/list, and prints the tool names. Uses MCP_AUTH_TOKEN (or --token) as a
Bearer token when set.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Callable, Dict, List, Tuple

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.access_tools import (
    CheckAccessParams,
    SearchGroupsParams,
    check_access,
    search_groups,
)
from servicenow_mcp.tools.change_tools import list_change_requests
from servicenow_mcp.tools.incident_tools import ListIncidentsParams, list_incidents
from servicenow_mcp.tools.request_tools import (
    ListRequestItemsParams,
    ListRequestsParams,
    list_request_items,
    list_requests,
)
from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig


def _config_from_env() -> ServerConfig:
    missing = [
        n
        for n in ("SERVICENOW_INSTANCE_URL", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD")
        if not os.getenv(n, "").strip()
    ]
    if missing:
        raise SystemExit(f"Missing environment variables: {', '.join(missing)}")
    return ServerConfig(
        instance_url=os.environ["SERVICENOW_INSTANCE_URL"].strip().rstrip("/"),
        auth=AuthConfig(
            type=AuthType.BASIC,
            basic=BasicAuthConfig(
                username=os.environ["SERVICENOW_USERNAME"],
                password=os.environ["SERVICENOW_PASSWORD"],
            ),
        ),
        timeout=settings.servicenow_timeout(),
    )


def _status(result: Dict[str, Any]) -> str:
    if result.get("success"):
        return "OK"
    code = result.get("status_code")
    return f"FAILED (HTTP {code}, {result.get('error_type')})" if code else (
        f"FAILED ({result.get('error_type')})"
    )


def _print_list_result(title: str, result: Dict[str, Any], key: str) -> None:
    print(f"\n== {title}: {_status(result)}")
    print(f"   query_used : {result.get('query_used')}")
    print(f"   total_count: {result.get('total_count')}   returned: {result.get('returned')}")
    if not result.get("success"):
        print(f"   message    : {result.get('message')}")
    for warning in result.get("warnings", []) or []:
        print(f"   warning    : {warning}")
    if result.get("hint"):
        print(f"   hint       : {result['hint']}")
    for record in (result.get(key) or [])[:5]:
        label = record.get("number") or record.get("name")
        extra = record.get("short_description") or record.get("description") or ""
        print(f"   - {label}: {str(extra)[:80]}")


def run_servicenow_checks(group: str, limit: int) -> bool:
    config = _config_from_env()
    auth = AuthManager(config.auth, config.instance_url)
    ok = True

    access = check_access(config, auth, CheckAccessParams())
    print(f"== check_access: {_status(access)}")
    print(f"   instance_host: {access.get('instance_host')}")
    user = access.get("user") or {}
    print(
        f"   user         : {user.get('user_name') or user.get('configured_username')} "
        f"(verified={user.get('verified')}, domain={user.get('domain')})"
    )
    if user.get("roles") is not None:
        print(f"   roles        : {', '.join(user['roles']) or '-'}")
    for table, entry in (access.get("tables") or {}).items():
        print(
            f"   {table:<15} status={entry.get('status_code')} readable={entry.get('readable')} "
            f"visible_count={entry.get('visible_count')}"
        )
    if not access.get("success"):
        print(f"   message      : {access.get('message')}")
        ok = False

    checks: List[Tuple[str, Callable[[], Dict[str, Any]], str]] = [
        (
            f"search_groups('{group}')",
            lambda: search_groups(config, auth, SearchGroupsParams(name_part=group, limit=limit)),
            "groups",
        ),
        (
            "list_incidents",
            lambda: list_incidents(config, auth, ListIncidentsParams(limit=limit)),
            "incidents",
        ),
        (
            "list_change_requests",
            lambda: list_change_requests(auth, config, {"limit": limit}),
            "change_requests",
        ),
        (
            "list_requests",
            lambda: list_requests(config, auth, ListRequestsParams(limit=limit)),
            "requests",
        ),
        (
            "list_request_items",
            lambda: list_request_items(config, auth, ListRequestItemsParams(limit=limit)),
            "request_items",
        ),
        (
            f"list_incidents(assignment_group='{group}')",
            lambda: list_incidents(
                config, auth, ListIncidentsParams(limit=limit, assignment_group=group)
            ),
            "incidents",
        ),
    ]
    for title, call, key in checks:
        result = call()
        _print_list_result(title, result, key)
        ok = ok and bool(result.get("success"))
    return ok


async def _list_tools_over_mcp(url: str, token: str) -> bool:
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    headers = {"Authorization": f"Bearer {token}"} if token else None
    async with sse_client(url, headers=headers) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init = await session.initialize()
            print(f"\n== MCP {url}: connected (protocol {init.protocolVersion})")
            tools = (await session.list_tools()).tools
            print(f"   tools/list returned {len(tools)} tools")
            for tool in tools:
                schema_text = json.dumps(tool.inputSchema)
                flag = "  [schema uses anyOf]" if "anyOf" in schema_text else ""
                print(f"   - {tool.name}{flag}")
            packages = await session.call_tool("list_tool_packages", {})
            for content in packages.content:
                print(f"   list_tool_packages: {getattr(content, 'text', content)}")
            return len(tools) > 0


def run_mcp_check(url: str, token: str) -> bool:
    try:
        return asyncio.run(_list_tools_over_mcp(url, token))
    except Exception as e:  # noqa: BLE001 - report any connection problem
        while isinstance(e, BaseExceptionGroup) and e.exceptions:
            e = e.exceptions[0]  # anyio wraps the real error (e.g. HTTP 401) in a group
        print(f"\n== MCP {url}: FAILED ({type(e).__name__}: {e})")
        return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ServiceNow MCP smoke test")
    parser.add_argument("--group", default="NOC", help="Group name fragment for search_groups")
    parser.add_argument("--limit", type=int, default=3, help="Records per list call")
    parser.add_argument("--mcp-url", help="Also connect over MCP/SSE, e.g. http://localhost:8080/sse")
    parser.add_argument(
        "--token", default=os.getenv("MCP_AUTH_TOKEN", ""), help="Bearer token (default MCP_AUTH_TOKEN)"
    )
    parser.add_argument(
        "--mcp-only", action="store_true", help="Skip the direct ServiceNow checks"
    )
    args = parser.parse_args(argv)

    ok = True
    if not args.mcp_only:
        ok = run_servicenow_checks(args.group, args.limit) and ok
    if args.mcp_url:
        ok = run_mcp_check(args.mcp_url, args.token) and ok
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
