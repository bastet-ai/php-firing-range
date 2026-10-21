#!/usr/bin/env bash
# Fleet keeper: launches 4 ASan libFuzzer workers (detached) then waits on
# them so this script's session lifetime == fleet lifetime.
cd /home/user/php-firing-range/research/src/php-src-83 || exit 1
R=/home/user/php-firing-range/research/fuzz/fuzz-results
PIDS=()
for i in 1 2 3 4; do
  ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=1 \
  UBSAN_OPTIONS=halt_on_error=0 \
  ./sapi/fuzzer/php-fuzz-multipart \
    -dict=/home/user/php-firing-range/research/fuzz/multipart.dict \
    -artifact_prefix=$R/ -max_total_time=14400 -rss_limit_mb=6144 \
    -max_len=65536 -timeout=60 $R/fz$i > $R/worker$i.log 2>&1 < /dev/null &
  PIDS+=($!)
done
echo "fleet pids: ${PIDS[*]}"
wait "${PIDS[@]}"
echo "fleet done $(date -u +%H:%MZ)"
