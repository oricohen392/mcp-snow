# ServiceNow MCP server (SSE) - multi-stage, non-root, OpenShift restricted-SCC friendly.
#
# Online build:   docker build -t servicenow-mcp .
# Offline build:  ./scripts/download_wheels.sh   (on a machine with internet)
#                 docker build --build-arg OFFLINE=1 -t servicenow-mcp .
#
# The final image contains only /opt/venv (no source tree, no .git, no secrets).

ARG PYTHON_IMAGE=python:3.11-slim

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS build

ARG OFFLINE=0
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
# wheelhouse/ only holds a .gitkeep unless scripts/download_wheels.sh was run
COPY wheelhouse/ /wheelhouse/
COPY requirements.lock pyproject.toml README.md LICENSE ./
COPY config/ ./config/
COPY src/ ./src/

# OpenShift runs the container with a random UID in group 0, so group 0 gets the
# owner's permissions on the venv. Done here so the final stage has no extra layer.
RUN set -eux; \
    if [ "$OFFLINE" = "1" ]; then PIP_SOURCE="--no-index --find-links /wheelhouse"; else PIP_SOURCE=""; fi; \
    python -m venv /opt/venv; \
    /opt/venv/bin/pip install $PIP_SOURCE -r requirements.lock; \
    /opt/venv/bin/pip wheel $PIP_SOURCE --no-deps --wheel-dir /dist .; \
    /opt/venv/bin/pip install --no-index --no-deps /dist/*.whl; \
    /opt/venv/bin/python -c "import servicenow_mcp.server_sse"; \
    test -f /opt/venv/lib/python3.11/site-packages/servicenow_mcp/config/tool_packages.yaml; \
    find /opt/venv -name '__pycache__' -prune -exec rm -rf {} +; \
    chgrp -R 0 /opt/venv; \
    chmod -R g=u /opt/venv

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.title="servicenow-mcp" \
      org.opencontainers.image.description="ServiceNow MCP server (SSE transport)"

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080 \
    READ_ONLY=true \
    LOG_LEVEL=INFO

# Readable by group 0 (see build stage); nothing is written outside /tmp at runtime.
COPY --from=build /opt/venv /opt/venv

WORKDIR /tmp
USER 1001

EXPOSE 8080

CMD ["servicenow-mcp-sse"]
