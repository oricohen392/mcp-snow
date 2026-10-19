"""
Tests for project tools.

This module contains tests for the project tools in the ServiceNow MCP server.
"""

import unittest
from unittest.mock import MagicMock, patch

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.project_tools import (
    create_project,
    update_project,
    list_projects,
)
from servicenow_mcp.utils.config import ServerConfig, AuthConfig, AuthType, BasicAuthConfig


class TestProjectTools(unittest.TestCase):
    """Tests for the project tools."""

    def setUp(self):
        """Set up test fixtures."""
        auth_config = AuthConfig(
            type=AuthType.BASIC,
            basic=BasicAuthConfig(
                username="test_user",
                password="test_password"
            )
        )
        self.server_config = ServerConfig(
            instance_url="https://test.service-now.com",
            auth=auth_config,
        )
        self.auth_manager = MagicMock(spec=AuthManager)
        self.auth_manager.get_headers.return_value = {"Authorization": "Bearer test"}

    @patch("servicenow_mcp.tools.project_tools.requests.post")
    def test_create_project_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "proj123",
                "short_description": "Cloud Migration",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        params = {
            "short_description": "Cloud Migration",
            "status": "green",
            "state": "2",
        }
        result = create_project(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["project"]["sys_id"], "proj123")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/pm_project")
        self.assertEqual(kwargs["json"]["short_description"], "Cloud Migration")

    def test_create_project_missing_required(self):
        result = create_project(self.auth_manager, self.server_config, {})
        self.assertFalse(result["success"])
        self.assertIn("Missing required parameter", result["message"])

    @patch("servicenow_mcp.tools.project_tools.requests.put")
    def test_update_project_success(self, mock_put):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "proj123",
                "short_description": "Updated Cloud Migration",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_put.return_value = mock_response

        params = {
            "project_id": "proj123",
            "short_description": "Updated Cloud Migration",
            "status": "yellow",
        }
        result = update_project(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["project"]["short_description"], "Updated Cloud Migration")

    @patch("servicenow_mcp.tools.project_tools.requests.get")
    def test_list_projects_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": [
                {
                    "sys_id": "proj123",
                    "short_description": "Project 1",
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        params = {
            "limit": 5,
            "offset": 0,
            "state": "2",
            "status": "green",
            "phase": "execution",
            "project_manager": "pm_user",
            "assignment_group": "PMO",
            "query": "cloud",
        }
        result = list_projects(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["projects"]), 1)

        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/pm_project")
        query = kwargs["params"]["sysparm_query"]
        self.assertIn("state=2", query)
        self.assertIn("status=green", query)
        self.assertIn("phase=execution", query)
        self.assertIn("project_manager=pm_user", query)
        self.assertIn("assignment_group=PMO", query)
        self.assertIn("short_descriptionLIKEcloud^ORdescriptionLIKEcloud", query)


if __name__ == "__main__":
    unittest.main()
