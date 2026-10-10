#!/usr/bin/env bash
# Real child JVM kills and PostgreSQL stop/restart; synthetic fixtures only.
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${PYTHON:-python3}" scripts/test_process_recovery.py "$@"
