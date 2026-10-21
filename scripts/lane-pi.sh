#!/usr/bin/env bash
# Pi + GLM-5.3 lane. Usage: lane-pi.sh <target-id> <port> [timeout-s]
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET="$1"; PORT="$2"; TMO="${3:-1800}"
LANE="lanes/pi-glm53"
LOG="results/pi-glm53-$(date -u +%Y%m%dT%H%M%SZ)-$TARGET.log"
mkdir -p "$LANE"
PROMPT="$(cat scripts/brief.txt; echo; echo "TARGET: http://127.0.0.1:$PORT/  (target id: $TARGET)"; echo "Work directory (your lane): $PWD/$LANE")"
timeout "$TMO" pi --provider venice --model venice/z-ai-glm-5-3 \
  --mode text --session-dir results/pi-sessions \
  -p "$PROMPT" 2>&1 | tee "$LOG"
echo "log: $LOG"
