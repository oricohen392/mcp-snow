"""
ServiceNow MCP Server

This module provides the main implementation of the ServiceNow MCP server.
"""

import json
import logging
import os
from importlib import resources
from typing import Any, Dict, List, Optional, Union

import mcp.types as types
import yaml
from mcp.server.lowlevel import Server
from pydantic import ValidationError

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.knowledge_base import (
    create_category as create_kb_category_tool,
)
from servicenow_mcp.tools.knowledge_base import (
    list_categories as list_kb_categories_tool,
)
from servicenow_mcp.utils import settings
from servicenow_mcp.utils.config import ServerConfig
from servicenow_mcp.utils.tool_utils import get_tool_definitions, is_read_tool

# Logging is configured by the entrypoints (cli.py / server_sse.py) from LOG_LEVEL.
logger = logging.getLogger(__name__)

# Path of the tool package configuration. When TOOL_PACKAGE_CONFIG_PATH is not set,
# the repository copy (config/tool_packages.yaml, for source checkouts / editable
# installs) is used, then the copy packaged inside the wheel.
TOOL_PACKAGE_CONFIG_PATH = os.getenv("TOOL_PACKAGE_CONFIG_PATH", "config/tool_packages.yaml")
_DEFAULT_CONFIG_RELATIVE = "config/tool_packages.yaml"


class ToolPackageConfigError(ValueError):
    """The tool package configuration is missing, invalid or selects an unknown package."""


def _resolve_package_config_path() -> str:
    configured = os.getenv("TOOL_PACKAGE_CONFIG_PATH") or TOOL_PACKAGE_CONFIG_PATH
    explicit = bool(os.getenv("TOOL_PACKAGE_CONFIG_PATH")) or (
        configured != _DEFAULT_CONFIG_RELATIVE
    )
    candidates: List[str] = []
    if os.path.isabs(configured):
        candidates.append(configured)
    else:
        repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        candidates.append(os.path.abspath(os.path.join(repo_root, configured)))
    if not explicit:
        packaged = resources.files("servicenow_mcp").joinpath(_DEFAULT_CONFIG_RELATIVE)
        candidates.append(str(packaged))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    raise ToolPackageConfigError(
        f"Tool package config not found (tried: {', '.join(candidates)}). "
        "Set TOOL_PACKAGE_CONFIG_PATH or reinstall the package; without it no tools can be served."
    )


def _schema_without_nulls(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Make a pydantic JSON schema friendlier for MCP clients with simple parsers.

    ``Optional[X] = None`` is emitted by pydantic as
    ``{"anyOf": [X, {"type": "null"}], "default": null, "title": ...}``. Some
    clients only read a property's top-level ``type``; collapse that to ``X``,
    drop ``default: null`` and the auto-generated titles. Required/optional is
    still expressed by the schema's ``required`` list.
    """
    schema = dict(schema)
    schema.pop("title", None)
    properties = {}
    for name, prop in schema.get("properties", {}).items():
        prop = dict(prop)
        prop.pop("title", None)
        any_of = prop.get("anyOf")
        if isinstance(any_of, list):
            non_null = [p for p in any_of if p.get("type") != "null"]
            if len(non_null) == 1 and len(non_null) < len(any_of):
                prop.pop("anyOf")
                merged = dict(non_null[0])
                merged.pop("title", None)
                merged.update(prop)
                prop = merged
        if "default" in prop and prop["default"] is None:
            prop.pop("default")
        properties[name] = prop
    if "properties" in schema:
        schema["properties"] = properties
    return schema


def serialize_tool_output(result: Any, tool_name: str) -> str:
    """Serializes tool output to a string, preferably JSON indented."""
    try:
        if isinstance(result, str):
            # If it's already a string, assume it's intended as such
            # Try to parse/re-dump JSON for consistent formatting if it looks like JSON
            try:
                parsed = json.loads(result)
                return json.dumps(parsed, indent=2)
            except json.JSONDecodeError:
                return result  # Return as is if not valid JSON
        elif isinstance(result, dict):
            # Dump dicts to JSON
            return json.dumps(result, indent=2)
        elif hasattr(result, "model_dump_json"):  # Pydantic v2
            # Prefer Pydantic v2 model_dump_json
            # The indent argument might not be supported by all versions/models,
            # so we might need to dump to dict first if indent is crucial.
            try:
                return result.model_dump_json(indent=2)
            except TypeError:  # Handle case where indent is not supported
                return json.dumps(result.model_dump(), indent=2)
        elif hasattr(result, "model_dump"):  # Pydantic v2 fallback
            # Fallback to Pydantic v2 model_dump -> dict -> json
            return json.dumps(result.model_dump(), indent=2)
        elif hasattr(result, "dict"):  # Pydantic v1
            # Fallback to Pydantic v1 dict -> json
            return json.dumps(result.dict(), indent=2)
        else:
            # Absolute fallback: convert to string
            logger.warning(
                f"Could not serialize result for tool '{tool_name}' to JSON, falling back to str(). Type: {type(result)}"
            )
            return str(result)
    except Exception as e:
        logger.error(f"Error during serialization for tool '{tool_name}': {e}", exc_info=True)
        # Return an error message string formatted as JSON
        return json.dumps(
            {"error": f"Serialization failed for tool {tool_name}", "details": str(e)}, indent=2
        )


def _reject_query_separators(tool_name: str, arguments: Dict[str, Any]) -> None:
    """
    Defense in depth for read tools: no string argument may contain '^'.

    Several older list tools still interpolate arguments into sysparm_query;
    '^' would let a caller append encoded-query conditions (e.g. '^NQ').
    """
    for key, value in arguments.items():
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, str) and "^" in item:
                raise ValueError(
                    f"Invalid argument '{key}' for tool '{tool_name}': the character '^' is not "
                    "allowed (it is the ServiceNow encoded-query separator)."
                )


class ServiceNowMCP:
    """
    ServiceNow MCP Server implementation.

    This class provides a Model Context Protocol (MCP) server for ServiceNow,
    allowing LLMs to interact with ServiceNow data and functionality.
    It supports loading specific tool packages via the MCP_TOOL_PACKAGE env var.
    """

    def __init__(self, config: Union[Dict, ServerConfig]):
        """
        Initialize the ServiceNow MCP server.

        Args:
            config: Server configuration, either as a dictionary or ServerConfig object.
        """
        if isinstance(config, dict):
            self.config = ServerConfig(**config)
        else:
            self.config = config

        self.auth_manager = AuthManager(self.config.auth, self.config.instance_url)
        self.mcp_server = Server("ServiceNow")  # Use low-level Server
        self.name = "ServiceNow"

        self.package_definitions: Dict[str, List[str]] = {}
        self.enabled_tool_names: List[str] = []
        self.hidden_write_tools: List[str] = []
        self.current_package_name: str = "none"
        self.read_only: bool = settings.read_only()

        # Get tool definitions, passing the aliased KB tool functions if needed
        self.tool_definitions = get_tool_definitions(
            create_kb_category_tool, list_kb_categories_tool
        )

        self._load_package_config()
        self._determine_enabled_tools()

        self._register_handlers()

    def _register_handlers(self):
        """Register the list_tools and call_tool handlers."""
        self.mcp_server.list_tools()(self._list_tools_impl)
        self.mcp_server.call_tool()(self._call_tool_impl)
        logger.info("Registered list_tools and call_tool handlers.")

    def _load_package_config(self):
        """
        Load tool package definitions from the YAML configuration file.

        Raises ToolPackageConfigError when the file is missing or invalid: a
        server without package definitions would accept connections but serve
        zero tools, which is much harder to diagnose than a failed startup.
        """
        config_path = _resolve_package_config_path()
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded_config = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            raise ToolPackageConfigError(
                f"Cannot read tool package config {config_path}: {e}"
            ) from e
        if not isinstance(loaded_config, dict) or not all(
            isinstance(v, list) for v in loaded_config.values()
        ):
            raise ToolPackageConfigError(
                f"Invalid format in {config_path}: expected a mapping of package name -> list "
                "of tool names."
            )
        self.package_definitions = loaded_config
        logger.info(f"Loaded tool package config from {config_path}")

    def _determine_enabled_tools(self):
        """
        Determine which tools to enable from MCP_TOOL_PACKAGE and READ_ONLY.

        An unknown package name raises ToolPackageConfigError (fail at startup).
        With READ_ONLY=true (the default) only read tools (list_/get_/search_/
        check_) are enabled; write tools need READ_ONLY=false explicitly.
        """
        requested_package = os.getenv("MCP_TOOL_PACKAGE", "full").strip() or "full"
        if requested_package not in self.package_definitions:
            raise ToolPackageConfigError(
                f"MCP_TOOL_PACKAGE '{requested_package}' is not a valid package name. "
                f"Valid packages: {sorted(self.package_definitions)}."
            )
        self.current_package_name = requested_package

        package_tools = list(dict.fromkeys(self.package_definitions[requested_package] or []))
        undefined = [t for t in package_tools if t not in self.tool_definitions]
        if undefined:
            logger.warning(
                f"Package '{requested_package}' lists {len(undefined)} tools that do not exist "
                f"in this server and are ignored: {undefined}"
            )
        defined = [t for t in package_tools if t in self.tool_definitions]

        if self.read_only:
            self.enabled_tool_names = [t for t in defined if is_read_tool(t)]
            self.hidden_write_tools = [t for t in defined if not is_read_tool(t)]
        else:
            self.enabled_tool_names = defined
            self.hidden_write_tools = []

        logger.info(
            f"Tool package '{self.current_package_name}': {len(self.enabled_tool_names)} tools "
            f"enabled, READ_ONLY={'true' if self.read_only else 'false'}"
            + (
                f", {len(self.hidden_write_tools)} write tools hidden"
                if self.hidden_write_tools
                else ""
            )
            + "."
        )
        if not self.read_only:
            logger.warning(
                "READ_ONLY=false: write tools (create/update/resolve/approve...) are exposed."
            )

    async def _list_tools_impl(self) -> List[types.Tool]:
        """Implementation for the list_tools MCP endpoint."""
        tool_list: List[types.Tool] = []

        # Add the introspection tool if not 'none' package
        if self.current_package_name != "none":
            tool_list.append(
                types.Tool(
                    name="list_tool_packages",
                    description=(
                        "Lists available tool packages, the currently loaded one and whether "
                        "the server is read-only. Takes no arguments."
                    ),
                    inputSchema={"type": "object", "properties": {}},
                )
            )

        # Iterate through defined tools and add enabled ones
        for tool_name, definition in self.tool_definitions.items():
            if tool_name in self.enabled_tool_names:
                _impl_func, params_model, _return_annotation, description, _serialization = (
                    definition
                )
                try:
                    schema = _schema_without_nulls(params_model.model_json_schema())
                    tool_list.append(
                        types.Tool(name=tool_name, description=description, inputSchema=schema)
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to generate schema for tool '{tool_name}': {e}", exc_info=True
                    )

        logger.debug(f"Listing {len(tool_list)} tools for package '{self.current_package_name}'.")
        return tool_list

    async def _call_tool_impl(self, name: str, arguments: dict) -> list[types.TextContent]:
        """
        Implementation for the call_tool MCP endpoint.
        Handles argument parsing, tool execution, result serialization (to string),
        and returning a list containing a single TextContent object.

        Args:
            name: The name of the tool to call.
            arguments: The arguments for the tool as a dictionary.

        Returns:
            A list containing a single TextContent object with the tool output.

        Raises:
            ValueError: If the tool is unknown, disabled, or if arguments are invalid.
            RuntimeError: If tool execution or serialization fails.
        """
        logger.info(f"Received call_tool request for tool '{name}'")
        # Handle the introspection tool separately
        if name == "list_tool_packages":
            if self.current_package_name == "none":
                raise ValueError(
                    "Tool 'list_tool_packages' is not available in the 'none' package."
                )
            result_dict = self._list_tool_packages_impl()
            serialized_string = json.dumps(result_dict, indent=2)
            # Return a list with a TextContent object
            return [types.TextContent(type="text", text=serialized_string)]

        # Check if the tool exists and is enabled
        if name not in self.tool_definitions:
            raise ValueError(f"Unknown tool: {name}")
        if name in self.hidden_write_tools:
            raise ValueError(
                f"Tool '{name}' modifies ServiceNow and is disabled because the server runs with "
                "READ_ONLY=true. Set READ_ONLY=false to enable write tools."
            )
        if name not in self.enabled_tool_names:
            raise ValueError(
                f"Tool '{name}' is not enabled in the current package '{self.current_package_name}'."
            )
        if is_read_tool(name):
            _reject_query_separators(name, arguments or {})

        # Get tool definition (we don't need the serialization hint anymore)
        definition = self.tool_definitions[name]
        impl_func, params_model, _return_annotation, _description, _serialization = definition

        # Validate and parse arguments using the Pydantic model
        try:
            params = params_model(**arguments)
            logger.debug(f"Parsed arguments for tool '{name}': {params}")
        except ValidationError as e:
            logger.error(f"Invalid arguments for tool '{name}': {e}", exc_info=True)
            raise ValueError(f"Invalid arguments for tool '{name}': {e}") from e
        except Exception as e:
            logger.error(
                f"Unexpected error parsing arguments for tool '{name}': {e}", exc_info=True
            )
            raise ValueError(f"Failed to parse arguments for tool '{name}': {e}")

        # Execute the tool implementation function
        try:
            result = impl_func(self.config, self.auth_manager, params)
            logger.debug(f"Raw result type from tool '{name}': {type(result)}")
        except Exception as e:
            logger.error(f"Error executing tool '{name}': {e}", exc_info=True)
            raise RuntimeError(f"Error during execution of tool '{name}': {e}") from e

        # Serialize the result to a string (preferably JSON) using the helper
        serialized_string = serialize_tool_output(result, name)
        logger.debug(f"Serialized value for tool '{name}': {serialized_string[:500]}...")

        # Return a list with a TextContent object
        return [types.TextContent(type="text", text=serialized_string)]

    def _list_tool_packages_impl(self) -> Dict[str, Any]:
        """Implementation logic for the list_tool_packages tool."""
        available_packages = list(self.package_definitions.keys())
        return {
            "current_package": self.current_package_name,
            "available_packages": available_packages,
            "read_only": self.read_only,
            "hidden_write_tools": self.hidden_write_tools,
            "message": (
                f"Currently loaded package: '{self.current_package_name}'. "
                f"Set MCP_TOOL_PACKAGE env var to one of {available_packages} to switch."
            ),
        }

    def start(self) -> Server:
        """
        Prepares and returns the configured low-level MCP Server instance.

        The caller (e.g., cli.py) is responsible for obtaining the server
        instance from this method and running it within an appropriate
        async transport context (e.g., mcp.server.stdio.stdio_server).

        Returns:
            The configured mcp.server.lowlevel.Server instance.
        """
        logger.info(
            "ServiceNowMCP instance configured. Returning low-level server instance for external execution."
        )
        # The actual running of the server (server.run(...)) must happen
        # within an async context managed by the caller (e.g., using anyio
        # and a specific transport like stdio_server or SseServerTransport).
        return self.mcp_server
