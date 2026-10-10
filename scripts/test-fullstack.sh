#!/usr/bin/env bash
# Requires Java 21, Python with agent/requirements.txt, and the Gradle wrapper.
# No Docker, .env, external database, live model, or real credentials are used.
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${PYTHON:-python3}" scripts/test_fullstack.py "$@"
