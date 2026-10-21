#!/usr/bin/env bash
# Start the range and inject fresh per-target canaries.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build >/dev/null
sleep 3

mkdir -p results/canaries
for t in shakedown php83 php82 php81 php56; do
  cid=$(docker compose ps -q "$t")
  flag="FLAG{${t}:$(openssl rand -hex 16)}"
  printf '%s\n' "$flag" | docker exec -i "$cid" sh -c 'cat > /CANARY && chmod 0444 /CANARY'
  printf '%s\n' "$flag" > "results/canaries/$t.flag"
  chmod 600 "results/canaries/$t.flag"
  echo "$t canary injected"
done
echo "range up. ports: shakedown=8181 php82=8082 php83=8083 php81=8091 php56=8056 (127.0.0.1 only)"
