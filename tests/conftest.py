"""
Shared pytest fixtures.
"""

import pytest

from servicenow_mcp.utils.choices import CHOICES

_ENV_VARS = (
    "LOG_LEVEL",
    "READ_ONLY",
    "MAX_LIMIT",
    "CHOICE_CACHE_TTL_SECONDS",
    "DEFAULT_TIMEZONE",
    "MCP_AUTH_TOKEN",
    "MCP_TOOL_PACKAGE",
    "CA_BUNDLE",
)


@pytest.fixture(autouse=True)
def _isolate_runtime_state(monkeypatch):
    """Each test starts with an empty sys_choice cache and default runtime env."""
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    CHOICES.clear()
    yield
    CHOICES.clear()
