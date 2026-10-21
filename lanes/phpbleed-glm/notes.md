# phpbleed GLM lane (T2): vendor remote chain -> canary over HTTP

## LANES
- :8088 phpbleed  = php 8.5.11 (OWNER LANE - bastet; do not touch)
- :8089 bleed82   = php 8.2.34 NTS aarch64 (THIS LANE) -> CAPTURED 19:02:10Z
  FLAG{bleed82:fbe9e5931464515be8dd9c20fca1b34d} (see capture_8089.txt)

## 8089 result (T2 complete)
Full chain, 100% remote derivation, RCE proven (id -> uid=33 in docker logs),
`cat /CANARY` executed via staged script; flag captured OVER HTTP via GET /f
(staged script's docroot write; docroot is 0777 on bleed82) + same flag in
docker logs (their channel). End-to-end on the final run: 11 requests,
2 crashes (resumable state held R-1..R-5 from the ~7k-request discovery runs).

## Target evolution (operator, mid-lane)
- 17:35Z container up 5 workers (image build dropped the single-worker
  `echo '\n...' >> apache2.conf` line - same line works on the 8088 image).
- 17:47Z lane fixed it at runtime (printf append + kill 1 -> 1 worker) and the
  first chain run (R-1 ok: heap_ref=0xe908b80571a0) hit that epoch.
- 18:00Z operator DESTROYED+RECREATED bleed82: new image with
  MaxRequestWorkers 256 / ServerLimit 256 / StartServers 16 - MULTI-worker
  by design now. The "SINGLE prefork worker" premise of the lane was stale.
- Adaptation: the chain pins ONE worker via an HTTP/1.1 keep-alive connection
  for R-6/R-7 (a persistent connection is owned by exactly one prefork
  worker); every phase before R-6 is address-stable across workers (shared
  post-fork mappings, MINIT data). MaxKeepAliveRequests=100 -> budget 85;
  Apache chunks responses on keep-alive -> pin_send does chunked decoding.

## PHP 8.2 retunes (vs the 8.5-tuned 8088 constants; all header-derived from
## php-src PHP-8.2.34 and cross-validated against the live binary/libphp.so)
- EG layout: function_table +0x1B0, class_table +0x1B8 (8.5: 0x1C8/0x1D0).
  Validated: EG resolved at libphp+0xf22e40 == offline dynsym st_value;
  ce_stdclass landed in the [heap] brk region exactly as MINIT predicts.
- zend_object_handlers: get_properties_for +0xC0 (8.5: +0xC8). Cross-checked
  via live binary: std_object_handlers dynsym st_size = 200 = 25 slots.
- R-2 scan: arm64 DSO bases are 64KB-aligned and did NOT share the chunk's
  2MB grid on this box (vendor pass-1 found nothing aligned). New cascade:
  64KB-grid outward sweep + GOT-routing (read a hit DSO's .dynamic via the
  DT_PLTRELSZ anchor, take an external pointer -> walk back at 64KB steps).
- R-4: vendor libphp_end = base+0x1800000 swallowed libc as "libphp
  internals" (libphp is only 15MB here, libc sits 6MB above its end).
  libphp_end = base+0xF20000 + 64KB-grid backward walks; fast path resolves
  `system` in the R-2 candidate list directly.
- R-6 REWRITTEN: the vendor page-map walk was doubly broken on 8.2
  (MAP_OFF 0x250 wrong for the 8.2 zend_mm_chunk/heap layout, and
  single-page probing missed multi-page SRUN runs on long-lived workers).
  New: heap->free_slot[16] (bin-320 freelist head, window data offset 136
  with the heap struct at chunk+0x40, len anchor = heap->size) - the LIVE
  spray string #1 sits exactly one bin-320 slot (0x140) BELOW the echo-time
  free_slot[16]; verified by len==280 + the 0xBBBB marker. S = slot+0x18.
  Cost: 2-3 requests instead of ~60 probes.
- HEAP GEOMETRY INSIGHT (explains the 8088 R-7 "spray misses"): each request
  pops arData8, frees it back to the bin-320 list head, and spray #1
  re-pops it - so spray #1 ALWAYS reclaims the arData slot, but the SLOT
  ADDRESS depends on the request SHAPE (plain POST vs multipart: the
  upload parsing allocates pre-app and moves the list head by ~10KB).
  R-6/verify/exfil therefore ALL run in the SAME multipart shape.

## Exfil (bleed82 docroot is 0777, unlike 8088)
- The post-RCE serialize path kills the worker ~always (id fires, then
  segfault), so the CAPTURING shot goes first.
- `bash /tmp/php*` executes only the FIRST glob match: 935 stale
  /tmp/phpXXXXXX files (each a giant url-encoded `cook=...` shell
  assignment - PHP spools big multipart FIELD values to /tmp/php* too)
  always won alphabetically and ran silently. FIX: cleanup shot
  `rm /tmp/php*` (plain shape) then the multipart capture shot (stages
  the 145B EXFIL_SCRIPT as the ONLY /tmp/php* file - verified live that
  one request stages exactly one file).
- EXFIL_SCRIPT: cat /CANARY (stdout->docker logs), cat > /var/www/html/f
  (-> GET /f over plain HTTP), fd-loop over /proc/self/fd/* (raw flag into
  the pin's client socket = the HTTP response stream), cat >&10 (bash).
- dash (`/bin/sh`) cannot redirect fd>=10 ("Bad fd number" - verified
  live), so single-shot `cat /C*>&10` is dead; the staged bash script is
  the working route. fd 9 exists but is not the client socket (output lost).

## Files
- phpbleed_8089.py  the chain (8089 port, 8.2 retunes, keep-alive pin,
                    multipart-consistent R-6, cleanup+staged-script exfil)
- poc_8089.sh       end-to-end runner (resumable; state_8089.json)
- fires_8089.log    every shot of every run (465KB)
- state_8089.json   phase checkpoints (heap_ref, elf_base, eg, pltgot,
                    libc_base, system_addr, ce_stdclass, gpfoff, S, exfil ev)
- capture_8089.txt  FLAG{bleed82:fbe9e5931464515be8dd9c20fca1b34d}
- evidence_8089.txt capture transcript + channels
- diag_r6*.py/diag_calib.py  the R-6 forensics (free_slot discovery,
                    page-map calibration attempts) - kept for the record
- run1.log/state.json/phpbleed_8088.py/fires.log  the earlier :8088 work
                    (owner lane's baseline; untouched)
