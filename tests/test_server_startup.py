"""
Server startup behaviour: READ_ONLY filtering, loud failures for bad package
config, packaged config lookup and Dify-friendly tool schemas.
"""

import asyncio
import pathlib
import shutil

import pytest

import servicenow_mcp.server as server_module
from servicenow_mcp.server import ServiceNowMCP, ToolPackageConfigError
from servicenow_mcp.utils.tool_utils import is_read_tool

CONFIG = {
    "instance_url": "https://example.service-now.com",
    "auth": {"type": "basic", "basic": {"username": "u", "password": "p"}},
}
REPO_CONFIG = pathlib.Path(__file__).resolve().parents[1] / "config" / "tool_packages.yaml"

ITSM_TOOLS = [
    "list_incidents",
    "get_incident_by_number",
    "list_change_requests",
    "get_change_request_details",
    "list_requests",
    "list_request_items",
    "get_request_by_number",
    "get_request_item_by_number",
    "search_groups",
    "check_access",
]


def tool_names(server):
    return [t.name for t in asyncio.run(server._list_tools_impl())]


def test_read_only_is_default(monkeypatch):
    server = ServiceNowMCP(CONFIG)
    names = tool_names(server)
    assert server.read_only is True
    for name in ITSM_TOOLS:
        assert name in names
    for write_tool in ("create_incident", "update_incident", "resolve_incident", "approve_change"):
        assert write_tool not in names
        assert write_tool in server.hidden_write_tools
    assert all(is_read_tool(n) or n == "list_tool_packages" for n in names)


def test_read_only_false_exposes_write_tools(monkeypatch):
    monkeypatch.setenv("READ_ONLY", "false")
    server = ServiceNowMCP(CONFIG)
    names = tool_names(server)
    assert "create_incident" in names and "list_incidents" in names
    assert server.hidden_write_tools == []


def test_invalid_read_only_value_fails(monkeypatch):
    monkeypatch.setenv("READ_ONLY", "maybe")
    with pytest.raises(ValueError):
        ServiceNowMCP(CONFIG)


def test_hidden_write_tool_call_is_explained():
    server = ServiceNowMCP(CONFIG)
    with pytest.raises(ValueError) as exc:
        asyncio.run(server._call_tool_impl("create_incident", {"short_description": "x"}))
    assert "READ_ONLY" in str(exc.value)


def test_unknown_package_fails_loudly(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_PACKAGE", "servicedesk")
    with pytest.raises(ToolPackageConfigError) as exc:
        ServiceNowMCP(CONFIG)
    assert "service_desk" in str(exc.value)


def test_missing_config_fails_loudly(monkeypatch, tmp_path):
    monkeypatch.setenv("TOOL_PACKAGE_CONFIG_PATH", str(tmp_path / "missing.yaml"))
    with pytest.raises(ToolPackageConfigError):
        ServiceNowMCP(CONFIG)


def test_invalid_config_fails_loudly(monkeypatch, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a list\n")
    monkeypatch.setenv("TOOL_PACKAGE_CONFIG_PATH", str(bad))
    with pytest.raises(ToolPackageConfigError):
        ServiceNowMCP(CONFIG)


def test_packaged_config_used_when_repo_copy_absent(monkeypatch, tmp_path):
    """Simulates a wheel install: no repo config/ next to the package."""
    pkg_dir = tmp_path / "site-packages" / "servicenow_mcp"
    (pkg_dir / "config").mkdir(parents=True)
    shutil.copy(REPO_CONFIG, pkg_dir / "config" / "tool_packages.yaml")
    monkeypatch.setattr(server_module, "__file__", str(pkg_dir / "server.py"))
    monkeypatch.setattr(server_module.resources, "files", lambda package: pkg_dir)
    path = server_module._resolve_package_config_path()
    assert path == str(pkg_dir / "config" / "tool_packages.yaml")
    assert "list_incidents" in tool_names(ServiceNowMCP(CONFIG))


def test_none_package_still_valid(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_PACKAGE", "none")
    assert tool_names(ServiceNowMCP(CONFIG)) == []


def test_service_desk_package(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_PACKAGE", "service_desk")
    names = tool_names(ServiceNowMCP(CONFIG))
    for name in ITSM_TOOLS:
        assert name in names


def test_schemas_have_no_null_unions_and_describe_every_parameter():
    server = ServiceNowMCP(CONFIG)
    tools = {t.name: t for t in asyncio.run(server._list_tools_impl())}
    for name in ITSM_TOOLS + ["list_tool_packages"]:
        schema = tools[name].inputSchema
        assert schema["type"] == "object"
        text = str(schema)
        assert "anyOf" not in text and "'null'" not in text and "oneOf" not in text, name
        for prop_name, prop in schema["properties"].items():
            assert prop.get("type") in ("string", "integer", "boolean", "number"), (name, prop_name)
            assert len(prop.get("description", "")) > 20, (name, prop_name)
    assert tools["list_tool_packages"].inputSchema.get("required", []) == []
    group = tools["list_incidents"].inputSchema["properties"]["assignment_group"]
    assert "NOC" in group["description"] and "INOC_1" in group["description"]


def test_every_tool_is_classified():
    server = ServiceNowMCP(CONFIG)
    for name in server.tool_definitions:
        if name.startswith(("create_", "update_", "delete_", "add_", "remove_", "resolve_",
                            "approve_", "reject_", "submit_", "publish_", "commit_",
                            "activate_", "deactivate_", "reorder_", "move_", "execute_")):
            assert not is_read_tool(name), name


def test_read_tools_reject_query_separator_in_any_argument():
    server = ServiceNowMCP(CONFIG)
    with pytest.raises(ValueError) as exc:
        asyncio.run(server._call_tool_impl("list_knowledge_bases", {"query": "x^NQactive=true"}))
    assert "'^'" in str(exc.value)


def test_list_tool_packages_reports_read_only():
    import json

    server = ServiceNowMCP(CONFIG)
    result = asyncio.run(server._call_tool_impl("list_tool_packages", {}))
    data = json.loads(result[0].text)
    assert data["read_only"] is True and "create_incident" in data["hidden_write_tools"]
