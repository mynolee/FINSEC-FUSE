#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo 'DemoSeed initializes registered mock customers/evidence on first backend startup.'
echo 'This command starts the stack without overwriting existing records or volumes.'
docker compose up -d postgres agent backend
