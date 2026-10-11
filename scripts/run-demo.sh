#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo 'Run scripts/bootstrap-dev.sh first.'; exit 1; }
set -a; source .env; set +a
python3 scripts/run_demo.py
