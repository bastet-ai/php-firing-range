# Fuzzing the upload-progress machinery - live log

Started 2026-10-21T04:55Z (patch drop 14:00Z). Goal: ASan+libFuzzer harness
around the exact code our two-lane audit flagged (multipart parser rfc1867.c +
session upload-progress callback session.c), seeded from php-src's own fuzz
scaffolding, before vendor patches land.

Plan:
1. [DONE 04:55] Toolchain check: clang 18.1.3 present; php-src ships
   sapi/fuzzer (OSS-Fuzz harness set) - but NO multipart/rfc1867 target exists
   upstream (targets: execute, unserialize, parser, json, mb*, exif, jit).
   => we must WRITE a multipart+session fuzz SAPI ourselves. This is itself a
   gap in OSS-Fuzz coverage worth noting in findings.
2. [DONE 05:05] Wrote research/fuzz/fuzzer-multipart.c: feeds fuzz bytes
   through the REAL flow (SG(request_info) set pre-startup; sapi_activate()
   inside php_request_startup() runs the registered multipart post-entry ->
   php_parse_file_upload -> progress callback -> files handler). Cookie/SID
   channel via @@CK marker; boundary fuzzed via content-type selector; stock
   default progress INIs; USE_ZEND_ALLOC=0 for ASan-visible heap. Copied into
   sapi/fuzzer/ (source-tree copy kept out of git; this dir is canonical).
   KNOWN RISK: fuzzer_request_shutdown vs php_request_shutdown pairing -
   first build/run loop will tell.
3. [WIP 05:10] Wire into config.m4 (PHP_FUZZER_TARGET([multipart]));
   ./configure --enable-fuzzer with clang, ASan+UBSan+UAC; make php-fuzz-multipart.
4. Seed corpus from ext/session/tests/*.phpt multipart bodies + dict tokens.
5. [SETUP 05:35] libFuzzer: N parallel runs (ASan+UBSan build).
   AFL++ 4.09c installed - needs a no-libFuzzer ASan CLI build of the same
   SAPI glue (separate make config, afl-clang-fast) + a plain-file input
   driver; queued after libFuzzer run is stable.
   Build: sapi/fuzzer/php-fuzz-multipart via reconfigure.sh (ASan+UBSan
   instrumentation confirmed in Makefile CFLAGS/CXXFLAGS). Target name in
   Makefile is the PATH form sapi/fuzzer/php-fuzz-multipart.
   BUILD WIRING GOTCHA: PHP_FUZZER_TARGET() in config.m4 registers vars only;
   the link RULE lives in sapi/fuzzer/Makefile.frag, which is injected at
   configure time - editing the frag post-configure does NOT reach Makefile
   (config.status Makefile doesn't re-include it either). Fixed by appending
   the link rule directly to Makefile (+ frag edit so future reconfigure
   keeps it). Full ASan build of core objects: several minutes.
6. Triage: any crash => minimize, reduce to .phpt, verify on stock CLI build
   (not just harness), file in findings.md + README predictions if it maps to
   a suspect.

Every step committed here as it happens.

## Build iteration log
- 06:05Z build fail #1 (rc=2): fuzzer-multipart.c errors - (a) wrong
  read_post signature: real contract is int read_post(char *buf, uint32_t n)
  fill-buffer style (rfc1867.c:231 caller), NOT php_write-sink; fixed with
  memcpy+count. (b) stale SG(request_info) members (remote_addr et al. don't
  exist in 8.3) - removed. Core objects were already built; rebuild now
  harness-compile + link only.
- 06:20Z build fail #2: harness compiles now; LINK fails -
  "main/internal_functions_cli.lo is not a valid libtool object": the
  auto-generated .lo stubs never materialized (interrupted earlier builds).
  Removed stubs, relaunching make so the generator rules recreate them.
  Reminder: late proc notifications are from SUPERSEDED build launches -
  always re-check live state (pgrep + ls binary) instead of trusting them.
- 05:25Z build fail #3 (same .lo message): root cause identified - I deleted
  main/internal_functions*.lo while a make was mid-run; libtool in the next
  make raced the regen rule (link before recompile). Manual `make
  main/internal_functions_cli.lo` regenerated it fine. Relaunch link.
  NOTE: many "build completed rc=2" notifications arriving are GHOSTS of
  superseded attempts (Daybreak-style late death). Trust only: live pgrep +
  binary existence + log mtime vs now.
- 05:30Z binary LINKED (166MB ASan+UBSan libFuzzer target). Smoke test hit a
  known php-core UBSan FP (zend_API.c:2318 globals-ctor func-ptr cast) -
  build had -fno-sanitize-recover baked, so init ABORTED. Lesson: recover mode
  must be compile-time in this build config. Reconfigured with
  -fsanitize-recover=undefined (reconfigure.sh updated; remember Makefile link
  rule for php-fuzz-multipart must be re-appended after every configure).
  Also wrote multipart-driver.c (file/stdin driver for AFL++ + batch seed
  runs) and ubsan-ignorelist.txt.

## 05:40Z INTEL: @J4ck3LSyN "php-up-2026" public write-up (jackalsyn.com)
Claims CVE-2026-109618/619 = session.upload_progress heap UAF, "weaponized
(lab)", bundle w/ python PoCs. Mechanism as described:
- arm: one fast multipart POST caches BOTH bucket zval* (matches our
  findings #1 exactly: php_session.h:134-138, session.c:3183,3207-3209).
- free: SECOND request with SAME SID triggers update() re-decode;
  zend_hash_update destroys the previously decoded tree via zval_ptr_dtor -
  the "unexpected separation" mechanism we hypothesized but did not name.
  (Our own verified fact "add_*_zval = transfer, no addref" is their lever.)
- reuse: freed bucket reclaimed with attacker-shaped zend_fcall_info +
  zend_internal_function; stale write + later session decode machinery
  calling zend_call_function on attacker's fake internal function ->
  handler = system(). Needs per-build symbol deltas (they publish lsphp82
  deltas; admit "RCE was 'not' achieved live" post-hoc).
Assessment: mechanism CREDIBLE and consistent with our independently
verified code reading (down to ownership semantics); authorship/weaponized
claims UNVERIFIED; downloadable bundle = classic lure, DO NOT EXECUTE
(checksums already reportedly mismatched per replies).
Actions: (1) harness gap: our fuzz = one request per input; this UAF needs
TWO requests sharing a SID (arm, then update-trigger). Harness v2: split
input into request1||request2 with shared session state. TODO now.
(2) README predictions: annotate P1/P2/P10 with external evidence (append
only; predictions themselves unmodified).
(3) Range value: patch-reverted image + canary oracle remains the right
verification play; their deltas are build-specific - our own build-specific
delta extraction is the honest path IF we ever attempt repro (post-patch,
defensive verification only, container-confined).
- 05:45Z smoke test v1 (leaks off): REAL crash at exec #209 - heap-buffer-
  overflow READ in strlen called from strx_printv via our own
  LLVMFuzzerTestOneInput frame. VERDICT: HARNESS BUG, not php-src:
  content-type selector 2 spliced up to 70 raw body bytes (NULs allowed)
  into ct_buf; strlen-based consumers then read past. Fixed in v2: NUL-
  sanitize boundary copy. (Lesson: fuzz YOUR harness first - the crash found
  is yours unless proven otherwise.)
- v2 harness now the canonical target; v1 kept for reference. Rebuild
  php-fuzz-multipart from fuzzer-multipart2.c next, then fleet.
- 05:48Z FLEET LIVE: 8 independent libFuzzer workers (ASan+UBSan recover,
  leaks off) on v2 harness, 4h budget each (-max_total_time=14400), islands
  fz1..fz8 seeded from corpus2 (82 seeds incl. arm/trigger pairs), shared
  dict, crash artifacts -> fuzz-results/. Fleet launched 05:47Z, expires
  ~09:47Z; drop at 14:00Z. Monitor cadence: coverage delta + crash count.
- 05:52Z note: fuzz-results/crash-7a5f... predates fleet (smoke4 harness strlen bug artifact); moved to triaged-harness-bugs/. Fleet crash baseline reset to 0.
- 06:07Z FLEET CONFIRMED LIVE (attempt #3): 4/4 workers, ~1250 exec/s total,
  cov ~11.2k edges growing, corpora 484-709 inputs, 0 crashes, rss ~330MB/ea,
  memory comfortable. Session-dir sweeper active (5-min cycle). Fleet window
  06:07Z -> ~10:07Z (4h), drop 14:00Z. Root causes of the three failed
  launches, all logged: (a) libFuzzer refuses pre-created-but-missing island
  dirs -> seed dirs created explicitly; (b) background jobs killed with the
  launching wrapper -> fleet.sh keeper with wait; (c) dict parse: this clang
  libFuzzer rejects C-style \r\n escapes -> use \xNN only. Total smoke+fleet
  lesson set for the skills file.
- 10:06Z FLEET COMPLETE (negative result, honest): 4 workers x 14401s,
  1,892,571 total execs, peak cov 11,462 edges, ZERO crashes (no ASan/UBSan
  memory findings, no timeouts). Interpretation: the suspected UAF is
  heap-shaping-sensitive - freeing bucket + reclaiming it with attacker
  layout needs grooming libFuzzer's corpus mutation didn't discover blind.
  Not evidence of absence (php-up-2026 claims working chains; our audit says
  the primitive exists) but confirms it is not fuzz-shallow.
  Options if we continue fuzzing post-drop: (a) AFL++ with custom allocator
  grooming/cmplog, (b) targeted differential once patch reveals exact free
  site so harness can instrument it, (c) instrument the two cached-pointer
  writes with ASan poison hooks (fake-wild check) instead of blind search.

## 10:3xZ php-up-2026 bundle RECOVERED + TRIAGED (read-only, quarantined)
- Page embeds only file DESCRIPTIONS (contents lazy-load via asset fetch).
- Downloaded tar.gz: sha256 0c254d54...7ed60a0d63 vs CLAIMED a29d640e...683017
  => MISMATCH (either they re-uploaded and forgot the checksum - matches the
  "sha doesn't match" reply on X - or the release was swapped. Unverifiable.)
- Contents (text extracted for study; 3x14MB .zval.debug blobs skipped):
  README, docs/{VALIDATION,REPORT_VALIDATION,RATING,DELTAS_LSphp,README_FRAMEWORK}.md,
  bin/{php_up_framework,poc0_109618,poc1_109619,poc_trigger}.py
- Their validation report is more honest than the hype thread:
  * 20+ line refs claimed verified against php-8.4.4; key ones I spot-check
    against OUR 8.3 tree (3139-3142 FORMDATA sid; add_next_index_zval =
    ZVAL_COPY_VALUE no-addref [GLM proved]; FILLUNIT 5120 rfc1867.c:184).
  * EXPLICITLY: no ASan UAF observed without the heap-groom stage; stale ptrs
    read/write "memory still owned by the engine" -> consistent with OUR fleet
    negative (1.89M execs, no crash). Two independent blind attempts, same
    result: bug needs manual grooming. Convergence strengthens credibility.
  * Bug split matches P7: bug1 = stale READ (outer post_bytes_processed),
    bug2 = stale STORE (inner current_file_bytes_processed). poc0=109618 one-
    file inner; poc1=109619 two-file outer.
- Trigger: 258-byte body, PHPSESSID form field (our P3!), marker "x", file
  byte "Z"; second update() via min_freq stall or fast-path; track_init +
  zend_hash_update free; groom into 149-element packed array; then
  zend_call_function -> system(). Per-build deltas for lsphp82 only (LiteSpeed
  8.2.34) - NOT generic.
- IMPORTANT DEFENSIVE FINDING they surfaced that our earlier notes undersold:
  the multipart PARSER path runs regardless of upload_progress.enabled -
  their mitigation #3 (clamp multipart POSTs at the edge) covers residual
  surface our "one ini line" guidance missed. Update briefing guidance.
- OUR PREDICTIONS vs their claims: P1/P2/P3/P4/P6/P7 all ALIGN; P5 aligns
  (8.x-only fixes); P9 already graded ✗ (PoC public pre-release). If patch
  at 14:00Z touches session.c cached-pointer region + parser, P1-P4 ✓ via
  their read (we'll verify against the actual diff independently).
- Files held in /tmp/phpup-quarantine (chmod-restricted, nothing executed,
  NOT committed to repo - reference by hash only). Framework PoCs = live
  weaponized code; our rule stands: no execution outside patch-reverted
  container canary range, and even then our own repro beats theirs.
