"""
Tests for scrum task tools.

This module contains tests for the scrum task tools in the ServiceNow MCP server.
"""

import unittest
from unittest.mock import MagicMock, patch

import requests

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.scrum_task_tools import (
    create_scrum_task,
    update_scrum_task,
    list_scrum_tasks,
)
from servicenow_mcp.utils.config import ServerConfig, AuthConfig, AuthType, BasicAuthConfig


class TestScrumTaskTools(unittest.TestCase):
    """Tests for the scrum task tools."""

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

    @patch("servicenow_mcp.tools.scrum_task_tools.requests.post")
    def test_create_scrum_task_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "stask123",
                "short_description": "Implement Unit Tests",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        params = {
            "story": "story123",
            "short_description": "Implement Unit Tests",
            "priority": "2",
        }
        result = create_scrum_task(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["scrum_task"]["sys_id"], "stask123")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/rm_scrum_task")
        self.assertEqual(kwargs["json"]["story"], "story123")

    def test_create_scrum_task_missing_required(self):
        result = create_scrum_task(self.auth_manager, self.server_config, {})
        self.assertFalse(result["success"])
        self.assertIn("Missing required parameter", result["message"])

    @patch("servicenow_mcp.tools.scrum_task_tools.requests.put")
    def test_update_scrum_task_success(self, mock_put):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "stask123",
                "short_description": "Updated Unit Tests",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_put.return_value = mock_response

        params = {
            "scrum_task_id": "stask123",
            "short_description": "Updated Unit Tests",
        }
        result = update_scrum_task(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["scrum_task"]["short_description"], "Updated Unit Tests")

    @patch("servicenow_mcp.tools.scrum_task_tools.requests.get")
    def test_list_scrum_tasks_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": [
                {
                    "sys_id": "stask123",
                    "short_description": "Task 1",
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        params = {
            "limit": 5,
            "offset": 0,
            "story_id": "story123",
            "state": "2",
            "assigned_to": "dev_user",
            "assignment_group": "Backend",
            "query": "test",
        }
        result = list_scrum_tasks(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["scrum_tasks"]), 1)

        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/rm_scrum_task")
        query = kwargs["params"]["sysparm_query"]
        self.assertIn("story=story123", query)
        self.assertIn("state=2", query)
        self.assertIn("assigned_to=dev_user", query)
        self.assertIn("assignment_group=Backend", query)
        self.assertIn("short_descriptionLIKEtest^ORdescriptionLIKEtest", query)

    @patch("servicenow_mcp.tools.scrum_task_tools.requests.get")
    def test_list_scrum_tasks_error_message(self, mock_get):
        """Verify error message says 'Error listing scrum tasks' (no typo)."""
        mock_get.side_effect = requests.exceptions.RequestException("Connection failed")
        result = list_scrum_tasks(self.auth_manager, self.server_config, {})
        self.assertFalse(result["success"])
        self.assertIn("Error listing scrum tasks", result["message"])
        self.assertNotIn("Error listing stories", result["message"])


if __name__ == "__main__":
    unittest.main()
