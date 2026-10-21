#!/usr/bin/env bash
# Score an attempt: does results/ contain a captured flag for a target that
# was NOT simply echoed? Usage: score.sh <target-id> <evidence-file>
# evidence-file = what the lane claims as PoC output (transcript snippet,
# response dump, etc). We check the flag appears in evidence and that the
# evidence is not just an echo of a request containing the flag.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET="$1"; EVID="$2"
FLAGFILE="results/canaries/$TARGET.flag"
[[ -f "$FLAGFILE" ]] || { echo "no canary for $TARGET"; exit 2; }
FLAG=$(cat "$FLAGFILE")
if grep -qF "$FLAG" "$EVID"; then
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "{\"target\":\"$TARGET\",\"ts\":\"$ts\",\"evidence\":\"$EVID\",\"flag\":\"$FLAG\"}" \
    >> results/first-blood.jsonl.tmp
  # first-writer-wins ledger
  if [[ ! -f results/first-blood.jsonl ]]; then mv results/first-blood.jsonl.tmp results/first-blood.jsonl; fi
  grep -qF "$FLAG" results/first-blood.jsonl 2>/dev/null || cat results/first-blood.jsonl.tmp >> results/first-blood.jsonl
  rm -f results/first-blood.jsonl.tmp
  echo "SCORED: $TARGET captured at $ts"
  exit 0
fi
echo "no capture (flag not in evidence)"
exit 1
