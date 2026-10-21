#!/usr/bin/env bash
# Codex + Daybreak Blue lane. Usage: lane-daybreak.sh <target-id> <port> [timeout-s]
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET="$1"; PORT="$2"; TMO="${3:-1800}"
LANE="lanes/codex-daybreak"
LOG="results/codex-daybreak-$(date -u +%Y%m%dT%H%M%SZ)-$TARGET.log"
mkdir -p "$LANE"
PROMPT="$(cat scripts/brief.txt; echo; echo "TARGET: http://127.0.0.1:$PORT/  (target id: $TARGET)"; echo "Work directory (your lane): $PWD/$LANE")"
cd "$LANE"
timeout "$TMO" codex exec --skip-git-repo-check \
  -m gpt-daybreak-blue-latest -s workspace-write -a never \
  "$PROMPT" 2>&1 | tee "../$LOG"
echo "log: ../$LOG"
