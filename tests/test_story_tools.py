"""
Tests for story tools.

This module contains tests for the story tools in the ServiceNow MCP server.
"""

import unittest
from unittest.mock import MagicMock, patch

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.tools.story_tools import (
    create_story,
    update_story,
    list_stories,
    list_story_dependencies,
    create_story_dependency,
    delete_story_dependency,
)
from servicenow_mcp.utils.config import ServerConfig, AuthConfig, AuthType, BasicAuthConfig


class TestStoryTools(unittest.TestCase):
    """Tests for the story tools."""

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

    @patch("servicenow_mcp.tools.story_tools.requests.post")
    def test_create_story_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "story123",
                "short_description": "User Login Feature",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        params = {
            "short_description": "User Login Feature",
            "acceptance_criteria": "Given valid creds, user can log in",
            "story_points": 5,
        }
        result = create_story(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["story"]["sys_id"], "story123")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/rm_story")
        self.assertEqual(kwargs["json"]["short_description"], "User Login Feature")

    def test_create_story_missing_required(self):
        result = create_story(self.auth_manager, self.server_config, {"short_description": "Only Title"})
        self.assertFalse(result["success"])
        self.assertIn("Missing required parameter", result["message"])

    @patch("servicenow_mcp.tools.story_tools.requests.put")
    def test_update_story_success(self, mock_put):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "story123",
                "short_description": "Updated Login Feature",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_put.return_value = mock_response

        params = {
            "story_id": "story123",
            "short_description": "Updated Login Feature",
        }
        result = update_story(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["story"]["short_description"], "Updated Login Feature")

    @patch("servicenow_mcp.tools.story_tools.requests.get")
    def test_list_stories_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": [
                {
                    "sys_id": "story123",
                    "short_description": "Story 1",
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        params = {
            "limit": 5,
            "offset": 0,
            "sprint_id": "sprint1",
            "epic_id": "epic1",
            "state": "2",
            "assigned_to": "dev_user",
            "assignment_group": "Team A",
            "query": "login",
        }
        result = list_stories(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["stories"]), 1)

        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/rm_story")
        query = kwargs["params"]["sysparm_query"]
        self.assertIn("sprint=sprint1", query)
        self.assertIn("epic=epic1", query)
        self.assertIn("state=2", query)
        self.assertIn("assigned_to=dev_user", query)
        self.assertIn("assignment_group=Team A", query)
        self.assertIn("short_descriptionLIKElogin^ORdescriptionLIKElogin", query)

    @patch("servicenow_mcp.tools.story_tools.requests.get")
    def test_list_story_dependencies_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": [
                {
                    "sys_id": "dep123",
                    "story": "story123",
                    "prerequisite_story": "story001",
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        params = {
            "story_id": "story123",
            "prerequisite_story_id": "story001",
        }
        result = list_story_dependencies(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["story_dependencies"]), 1)
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/m2m_story_dependencies")
        query = kwargs["params"]["sysparm_query"]
        self.assertIn("story=story123", query)
        self.assertIn("prerequisite_story=story001", query)

    @patch("servicenow_mcp.tools.story_tools.requests.post")
    def test_create_story_dependency_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "sys_id": "dep123",
                "dependent_story": "story123",
                "prerequisite_story": "story001",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        params = {
            "dependent_story": "story123",
            "prerequisite_story": "story001",
        }
        result = create_story_dependency(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        self.assertEqual(result["story_dependency"]["sys_id"], "dep123")

    @patch("servicenow_mcp.tools.story_tools.requests.delete")
    def test_delete_story_dependency_success(self, mock_delete):
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_response.raise_for_status.return_value = None
        mock_delete.return_value = mock_response

        params = {
            "dependency_id": "dep123",
        }
        result = delete_story_dependency(self.auth_manager, self.server_config, params)
        self.assertTrue(result["success"])
        mock_delete.assert_called_once()
        args, _ = mock_delete.call_args
        self.assertEqual(args[0], "https://test.service-now.com/api/now/table/m2m_story_dependencies/dep123")


if __name__ == "__main__":
    unittest.main()
