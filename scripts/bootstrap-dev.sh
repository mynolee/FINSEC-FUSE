#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
exec python3 scripts/bootstrap_dev.py
