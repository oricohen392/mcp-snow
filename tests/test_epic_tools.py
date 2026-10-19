"""
Tests for epic tools.

This module contains tests for the epic tools in the ServiceNow MCP server.
"""

import unittest
from unittest.mock import MagicMock, patch

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.epic_tools import (
    create_epic,
    update_epic,
    list_epics,
)
from servicenow_mcp.utils.config import ServerConfig, AuthConfig, AuthType, BasicAuthConfig


class TestEpicTools(unittest.TestCase):
    """Tests for the epic tools."""

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

    @patch("servicenow_mcp.tools.epic_tools.requests.post")
    def test_create_epic_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "epic123",
                "short_description": "New Epic",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        params = {
            "short_description": "New Epic",
            "description": "Epic description",
            "priority": "1",
        }
        result = create_epic(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["epic"]["sys_id"], "epic123")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/rm_epic")
        self.assertEqual(kwargs["json"]["short_description"], "New Epic")

    def test_create_epic_missing_required(self):
        result = create_epic(self.auth_manager, self.server_config, {})
        self.assertFalse(result["success"])
        self.assertIn("Missing required parameter", result["message"])

    @patch("servicenow_mcp.tools.epic_tools.requests.put")
    def test_update_epic_success(self, mock_put):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "epic123",
                "short_description": "Updated Epic",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_put.return_value = mock_response

        params = {
            "epic_id": "epic123",
            "short_description": "Updated Epic",
        }
        result = update_epic(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["epic"]["short_description"], "Updated Epic")

    @patch("servicenow_mcp.tools.epic_tools.requests.get")
    def test_list_epics_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": [
                {
                    "sys_id": "epic123",
                    "short_description": "Epic 1",
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        params = {
            "limit": 5,
            "offset": 0,
            "state": "2",
            "priority": "1",
            "assignment_group": "Development",
            "query": "core",
        }
        result = list_epics(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["epics"]), 1)

        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/rm_epic")
        query = kwargs["params"]["sysparm_query"]
        self.assertIn("state=2", query)
        self.assertIn("priority=1", query)
        self.assertIn("assignment_group=Development", query)
        self.assertIn("short_descriptionLIKEcore^ORdescriptionLIKEcore", query)


if __name__ == "__main__":
    unittest.main()
