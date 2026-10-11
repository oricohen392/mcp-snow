#!/usr/bin/env python3
"""
Smoke test wrapper. In the container the same thing is installed as
`servicenow-mcp-smoke`, e.g.:

    oc exec deploy/servicenow-mcp -- servicenow-mcp-smoke --group NOC \
        --mcp-url http://localhost:8080/sse

From a source checkout:

    PYTHONPATH=src python scripts/smoke_test.py --group NOC

See servicenow_mcp/smoke_test.py for details.
"""

import sys

from servicenow_mcp.smoke_test import main

if __name__ == "__main__":
    sys.exit(main())
