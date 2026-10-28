#!/bin/bash
# One command: docs/VIDEO-SCRIPT.md + record.spec.ts -> docs/video/out/agentpg-kit.mp4 and .srt (see README.md for the setup).
#   APGKIT_REC_PG_PORT=<port of a throwaway UTF-8 Postgres> APGKIT_REC_PORT=<free port for the app> ./build.sh
set -euo pipefail
cd "$(dirname "$0")"
[ -d node_modules ] || npm install
exec python3 build.py "$@"
