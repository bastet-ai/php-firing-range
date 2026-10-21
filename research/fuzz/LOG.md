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
6. Triage: any crash => minimize, reduce to .phpt, verify on stock CLI build
   (not just harness), file in findings.md + README predictions if it maps to
   a suspect.

Every step committed here as it happens.
