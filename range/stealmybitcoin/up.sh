#!/usr/bin/env bash
# bring up the clone (print-flag builds multi-stage inside the image)
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d --build "$@"
mkdir -p ../results/canaries
sleep 6
for pair in "smb-php-vuln:8151:vuln" "smb-php-ctrl:8152:ctrl"; do
  svc="${pair%%:*}"; rest="${pair#*:}"; port="${rest%%:*}"; kind="${rest##*:}"
  cid=$(docker compose ps -q "$svc")
  key="FLAG{wallet:${kind}:$(openssl rand -hex 16)}"
  docker exec -u root "$cid" sh -c "printf '%s\n' '$key' > /root/wallet.key && chmod 600 /root/wallet.key"
  printf '%s' "$key" > "../results/canaries/smb-${kind}.flag"
  chmod 600 "../results/canaries/smb-${kind}.flag"
done
mkdir -p ../results/canaries
echo "clone up. probe: curl -s -X POST -d message=ping http://127.0.0.1:8151/ping.php"
