# Fuzzing the upload-progress machinery — live log

Started 2026-10-21T04:55Z (patch drop 14:00Z). Goal: ASan+libFuzzer harness
around the exact code our two-lane audit flagged (multipart parser rfc1867.c +
session upload-progress callback session.c), seeded from php-src's own fuzz
scaffolding, before vendor patches land.

Plan:
1. [DONE 04:55] Toolchain check: clang 18.1.3 present; php-src ships
   sapi/fuzzer (OSS-Fuzz harness set) — but NO multipart/rfc1867 target exists
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
   KNOWN RISK: fuzzer_request_shutdown vs php_request_shutdown pairing —
   first build/run loop will tell.
3. [WIP 05:10] Wire into config.m4 (PHP_FUZZER_TARGET([multipart]));
   ./configure --enable-fuzzer with clang, ASan+UBSan+UAC; make php-fuzz-multipart.
4. Seed corpus from ext/session/tests/*.phpt multipart bodies + dict tokens.
5. [SETUP 05:35] libFuzzer: N parallel runs (ASan+UBSan build).
   AFL++ 4.09c installed — needs a no-libFuzzer ASan CLI build of the same
   SAPI glue (separate make config, afl-clang-fast) + a plain-file input
   driver; queued after libFuzzer run is stable.
   Build: sapi/fuzzer/php-fuzz-multipart via reconfigure.sh (ASan+UBSan
   instrumentation confirmed in Makefile CFLAGS/CXXFLAGS). Target name in
   Makefile is the PATH form sapi/fuzzer/php-fuzz-multipart.
   BUILD WIRING GOTCHA: PHP_FUZZER_TARGET() in config.m4 registers vars only;
   the link RULE lives in sapi/fuzzer/Makefile.frag, which is injected at
   configure time — editing the frag post-configure does NOT reach Makefile
   (config.status Makefile doesn't re-include it either). Fixed by appending
   the link rule directly to Makefile (+ frag edit so future reconfigure
   keeps it). Full ASan build of core objects: several minutes.
6. Triage: any crash => minimize, reduce to .phpt, verify on stock CLI build
   (not just harness), file in findings.md + README predictions if it maps to
   a suspect.

Every step committed here as it happens.

## Build iteration log
- 06:05Z build fail #1 (rc=2): fuzzer-multipart.c errors — (a) wrong
  read_post signature: real contract is int read_post(char *buf, uint32_t n)
  fill-buffer style (rfc1867.c:231 caller), NOT php_write-sink; fixed with
  memcpy+count. (b) stale SG(request_info) members (remote_addr et al. don't
  exist in 8.3) — removed. Core objects were already built; rebuild now
  harness-compile + link only.
- 06:20Z build fail #2: harness compiles now; LINK fails —
  "main/internal_functions_cli.lo is not a valid libtool object": the
  auto-generated .lo stubs never materialized (interrupted earlier builds).
  Removed stubs, relaunching make so the generator rules recreate them.
  Reminder: late proc notifications are from SUPERSEDED build launches —
  always re-check live state (pgrep + ls binary) instead of trusting them.
