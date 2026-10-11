"""
Logging configuration honoring the LOG_LEVEL environment variable.
"""

import logging
from typing import Optional

from servicenow_mcp.utils import settings

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def configure_logging(level: Optional[str] = None) -> int:
    """
    Configure root logging from LOG_LEVEL (or the given level).

    Returns the numeric level that was applied. Unknown level names raise
    ValueError so a typo fails at startup instead of silently logging at INFO.
    """
    name = (level or settings.log_level()).upper()
    numeric = logging.getLevelName(name)
    if not isinstance(numeric, int):
        raise ValueError(f"LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, got {name!r}")
    logging.basicConfig(level=numeric, format=LOG_FORMAT, force=True)
    # urllib3 at DEBUG logs full URLs only (no headers); keep it at WARNING to avoid noise.
    logging.getLogger("urllib3").setLevel(max(numeric, logging.WARNING))
    return numeric
