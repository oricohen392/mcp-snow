#!/usr/bin/env bash
# Pre-download every wheel needed to build the image without internet access.
#
# Run on a machine WITH internet access, from the repository root. The most
# reliable way is inside the same base image as the Docker build:
#
#   docker run --rm -v "$PWD:/w" -w /w python:3.11-slim bash scripts/download_wheels.sh
#
# Then copy the repository (including wheelhouse/) to the air-gapped build
# host and run:
#
#   docker build --build-arg OFFLINE=1 -t servicenow-mcp .
#
# or, without Docker:
#
#   pip install --no-index --find-links wheelhouse -r requirements.lock
#   pip install --no-index --find-links wheelhouse wheelhouse/servicenow_mcp-*.whl
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
PY_VERSION="${PY_VERSION:-3.11}"
# Wheel platform tags accepted (glibc x86_64; python:3.11-slim is Debian with glibc 2.36).
# pip does not expand a manylinux tag to older glibc tags, so list them explicitly.
PLATFORMS="${PLATFORMS:-manylinux_2_28_x86_64 manylinux_2_17_x86_64 manylinux2014_x86_64}"
DEST="${DEST:-wheelhouse}"

mkdir -p "$DEST"

download() {
  local platform_args=()
  local platform
  for platform in $PLATFORMS; do
    platform_args+=(--platform "$platform")
  done
  "$PYTHON" -m pip download \
    --dest "$DEST" \
    --only-binary=:all: \
    "${platform_args[@]}" \
    --python-version "$PY_VERSION" \
    --implementation cp \
    "$@"
}

# Runtime dependencies, pinned by requirements.lock (exported from uv.lock)
download -r requirements.lock

# Build backend, needed to build the servicenow-mcp wheel itself offline
download "hatchling==1.27.0"

# The project wheel (pure Python), for installs without Docker
"$PYTHON" -m pip wheel --no-deps --wheel-dir "$DEST" .

echo "Wheels in $DEST:"
ls -1 "$DEST" | grep -v '^.gitkeep$'
