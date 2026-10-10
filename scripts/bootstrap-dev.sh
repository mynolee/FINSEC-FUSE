#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
# Prepares private base files only. Follow docs/runtime-security.md for explicit
# durable token provisioning and approved handoff; never auto-provision here.
exec python3 scripts/bootstrap_dev.py
