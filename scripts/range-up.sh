#!/usr/bin/env bash
# Start the range and inject/record per-target canaries.
# Portable: lanes that only exist for one host arch are picked via uname,
# so the same script works on the x86_64 and arm64 range boxes.
set -euo pipefail
cd "$(dirname "$0")/.."

SERVICES=(phpbleed bleed82 bleedsrv bleednoaslr phpinfo t4a t4b
          shakedown php83 php82 php81 php56)
# arm64-only lanes join automatically on arm hosts. wordpress/wpdb/magento
# stay opt-in (they need WORDPRESS_DB_PASSWORD/MYSQL_PASSWORD in the env).
ARCH=$(uname -m)
[[ $ARCH == aarch64 || $ARCH == arm64 ]] && SERVICES+=(bleed81arm)

docker compose up -d --build "${SERVICES[@]}" >/dev/null
sleep 3

mkdir -p results/canaries

# Core targets: inject a FRESH canary (images ship without one).
for t in shakedown php83 php82 php81 php56; do
  cid=$(docker compose ps -q "$t")
  flag="FLAG{${t}:$(openssl rand -hex 16)}"
  printf '%s\n' "$flag" | docker exec -i "$cid" sh -c 'cat > /CANARY && chmod 0444 /CANARY'
  printf '%s\n' "$flag" > "results/canaries/$t.flag"
  chmod 600 "results/canaries/$t.flag"
  echo "$t canary injected"
done

# Baked-canary targets: record the flag the image shipped (score.sh parity).
for t in phpbleed bleed82 bleedsrv bleednoaslr t4a t4b; do
  flag=$(docker compose exec -T "$t" cat /CANARY)
  printf '%s\n' "$flag" > "results/canaries/$t.flag"
  chmod 600 "results/canaries/$t.flag"
  echo "$t canary recorded (baked)"
done

echo "range up. ports: shakedown=8181 php82=8082 php83=8083 php81=8091 php56=8056"
echo "phpbleed=8088 bleed82=8089 bleedsrv=8092 phpinfo=8093 t4a=8098 t4b=8096 bleednoaslr=8097 (127.0.0.1 only)"
