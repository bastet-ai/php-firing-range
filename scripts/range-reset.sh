#!/usr/bin/env bash
# Wipe containers + canaries between attempts so lanes never contaminate each other.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose down -v >/dev/null
rm -rf results/canaries
echo "range reset (transcripts kept). run scripts/range-up.sh to restage."
