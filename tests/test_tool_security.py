"""
Security tests for tool handlers across ServiceNow MCP server.

Verifies:
1. Path traversal attempts in sys_ids and resource IDs are rejected safely
   without raising uncaught exceptions (returning success=False).
2. Encoded query injection attempts (e.g. ^OR, ^NQ, control chars) in list tools
   are cleanly rejected/caught via QueryInputError without raising uncaught exceptions.
"""

import unittest
from unittest.mock import MagicMock

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.catalog_tools import (
    GetCatalogItemParams,
    ListCatalogItemsParams,
    get_catalog_item,
    list_catalog_items,
)
from servicenow_mcp.tools.catalog_variables import (
    CatalogItemVariableResponse,
    ListCatalogItemVariablesParams,
    ListCatalogItemVariablesResponse,
    UpdateCatalogItemVariableParams,
    list_catalog_item_variables,
    update_catalog_item_variable,
)
from servicenow_mcp.tools.changeset_tools import list_changesets
from servicenow_mcp.tools.epic_tools import list_epics, update_epic
from servicenow_mcp.tools.incident_tools import (
    GetIncidentByNumberParams,
    get_incident,
    get_incident_by_number,
)
from servicenow_mcp.tools.project_tools import list_projects, update_project
from servicenow_mcp.tools.script_include_tools import (
    GetScriptIncludeParams,
    get_script_include,
)
from servicenow_mcp.tools.scrum_task_tools import list_scrum_tasks, update_scrum_task
from servicenow_mcp.tools.story_tools import list_stories, update_story
from servicenow_mcp.tools.user_tools import (
    GetUserParams,
    ListGroupsParams,
    ListUsersParams,
    get_user,
    list_groups,
    list_users,
)
from servicenow_mcp.utils.config import AuthConfig, AuthType, BasicAuthConfig, ServerConfig


class TestToolSecurity(unittest.TestCase):
    """Test security boundaries and error handling on tool handlers."""

    def setUp(self):
        auth_config = AuthConfig(
            type=AuthType.BASIC,
            basic=BasicAuthConfig(
                username="test_user",
                password="test_password"
            )
        )
        self.server_config = ServerConfig(
            instance_url="https://dev12345.service-now.com",
            auth=auth_config,
        )
        self.auth_manager = MagicMock(spec=AuthManager)
        self.auth_manager.get_headers.return_value = {"Authorization": "Bearer test"}

    # =========================================================================
    # Path Traversal Tests
    # =========================================================================

    def test_get_catalog_item_path_traversal(self):
        """get_catalog_item must catch SafeUrlError on path traversal and return success=False."""
        for bad_id in ["../../incident", r"..\sys_user", "foo/bar"]:
            params = GetCatalogItemParams(item_id=bad_id)
            res = get_catalog_item(self.server_config, self.auth_manager, params)
            self.assertFalse(res.success)
            self.assertIn("Validation error", res.message)

    def test_get_incident_path_traversal(self):
        """get_incident must catch SafeUrlError on path traversal sys_ids."""
        for bad_id in ["../../incident", r"..\sys_user", "foo/bar"]:
            res = get_incident(self.server_config, self.auth_manager, bad_id)
            self.assertFalse(res["success"])
            self.assertIn("Failed to get incident", res["message"])

    def test_get_incident_by_number_traversal(self):
        """get_incident_by_number must reject non-incident numbers."""
        for bad_num in ["../../incident", "INC001^OR1=1"]:
            params = GetIncidentByNumberParams(incident_number=bad_num)
            res = get_incident_by_number(self.server_config, self.auth_manager, params)
            self.assertFalse(res["success"])

    def test_get_user_path_traversal(self):
        """get_user must safely reject or catch invalid characters without crashing."""
        for bad_id in ["user^ORactive=true", "user\nname", "user\x00admin"]:
            params = GetUserParams(user_name=bad_id)
            res = get_user(self.server_config, self.auth_manager, params)
            self.assertFalse(res["success"])
            self.assertIn("Failed to get user", res["message"])

    def test_get_script_include_path_traversal(self):
        """get_script_include must safely catch SafeUrlError on sys_id prefix path traversal."""
        for bad_id in ["sys_id:../../incident", r"sys_id:..\sys_user"]:
            params = GetScriptIncludeParams(script_include_id=bad_id)
            res = get_script_include(self.server_config, self.auth_manager, params)
            self.assertFalse(res["success"])
            self.assertIn("Error getting script include", res["message"])

    def test_update_epic_path_traversal(self):
        """update_epic must catch SafeUrlError on path traversal in epic_id."""
        res = update_epic(self.auth_manager, self.server_config, {"epic_id": "../../epic"})
        self.assertFalse(res["success"])
        self.assertIn("Validation error updating epic", res["message"])

    def test_update_project_path_traversal(self):
        """update_project must catch SafeUrlError on path traversal in project_id."""
        res = update_project(self.auth_manager, self.server_config, {"project_id": "../../project"})
        self.assertFalse(res["success"])
        self.assertIn("Error updating project", res["message"])

    def test_update_scrum_task_path_traversal(self):
        """update_scrum_task must catch SafeUrlError on path traversal in scrum_task_id."""
        res = update_scrum_task(self.auth_manager, self.server_config, {"scrum_task_id": "../../task"})
        self.assertFalse(res["success"])
        self.assertIn("Error updating scrum task", res["message"])

    def test_update_story_path_traversal(self):
        """update_story must catch SafeUrlError on path traversal in story_id."""
        res = update_story(self.auth_manager, self.server_config, {"story_id": "../../story"})
        self.assertFalse(res["success"])
        self.assertIn("Error updating story", res["message"])

    def test_update_catalog_variable_path_traversal(self):
        """update_catalog_item_variable must catch SafeUrlError on path traversal in variable_id."""
        params = UpdateCatalogItemVariableParams(
            variable_id="../../hack",
            label="Updated Label",
        )
        res = update_catalog_item_variable(self.server_config, self.auth_manager, params)
        self.assertIsInstance(res, CatalogItemVariableResponse)
        self.assertFalse(res.success)

    # =========================================================================
    # Query Injection Tests
    # =========================================================================

    def test_list_catalog_items_query_injection(self):
        """list_catalog_items rejects '^' query injection in category."""
        params = ListCatalogItemsParams(category="Software^ORactive=true")
        res = list_catalog_items(self.server_config, self.auth_manager, params)
        self.assertFalse(res["success"])
        self.assertIn("Validation error", res["message"])

    def test_list_users_query_injection(self):
        """list_users rejects query injection via QueryBuilder."""
        params = ListUsersParams(query="admin^ORactive=true")
        res = list_users(self.server_config, self.auth_manager, params)
        self.assertFalse(res["success"])
        self.assertIn("Failed to list users", res["message"])

    def test_list_groups_query_injection(self):
        """list_groups rejects query injection via QueryBuilder."""
        params = ListGroupsParams(query="Network^NQsys_id!=1")
        res = list_groups(self.server_config, self.auth_manager, params)
        self.assertFalse(res["success"])
        self.assertIn("Failed to list groups", res["message"])

    def test_list_changesets_query_injection(self):
        """list_changesets rejects query injection."""
        params = {"state": "in_progress^ORstate=closed"}
        res = list_changesets(self.auth_manager, self.server_config, params)
        self.assertFalse(res["success"])
        self.assertIn("listing changesets", res["message"])

    def test_list_projects_query_injection(self):
        """list_projects rejects query injection."""
        params = {"status": "green^OR1=1"}
        res = list_projects(self.auth_manager, self.server_config, params)
        self.assertFalse(res["success"])
        self.assertIn("Error listing projects", res["message"])

    def test_list_stories_query_injection(self):
        """list_stories rejects query injection."""
        params = {"state": "2^NQsys_id!=1"}
        res = list_stories(self.auth_manager, self.server_config, params)
        self.assertFalse(res["success"])
        self.assertIn("Error listing stories", res["message"])

    def test_list_scrum_tasks_query_injection(self):
        """list_scrum_tasks rejects query injection."""
        params = {"state": "1^ORactive=true"}
        res = list_scrum_tasks(self.auth_manager, self.server_config, params)
        self.assertFalse(res["success"])
        self.assertIn("Error listing scrum tasks", res["message"])

    def test_list_epics_query_injection(self):
        """list_epics rejects query injection."""
        params = {"priority": "1^ORpriority=2"}
        res = list_epics(self.auth_manager, self.server_config, params)
        self.assertFalse(res["success"])
        self.assertIn("Validation error listing epics", res["message"])

    def test_list_catalog_variables_query_injection(self):
        """list_catalog_item_variables rejects query injection in catalog_item_id."""
        params = ListCatalogItemVariablesParams(catalog_item_id="cat^OR1=1")
        res = list_catalog_item_variables(self.server_config, self.auth_manager, params)
        self.assertIsInstance(res, ListCatalogItemVariablesResponse)
        self.assertFalse(res.success)


if __name__ == "__main__":
    unittest.main()
