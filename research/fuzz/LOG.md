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
2. Write fuzzer-multipart.c: fuzz SAPI that feeds corpus bytes through
   php_register_variable_ex multipart flow with upload-progress INIs on
   (enabled=1, cleanup default), files handler in temp dir, mirroring the
   audited default-config trigger path: marker field + PHPSESSID field + file
   part, including binary/NUL SIDs (our P3/P4 suspects).
3. ./configure --enable-fuzzer with clang, ASan (+UBSan), UAF-detecting
   options; build.
4. Seed corpus from ext/session/tests/*.phpt multipart bodies +
   sapi/fuzzer/corpus conventions; dict with boundary/marker/session tokens.
5. Parallel libFuzzer runs; AFL++ separately if buildable (check).
6. Triage: any crash => minimize, reduce to .phpt, verify on stock CLI build
   (not just harness), file in findings.md + README predictions if it maps to
   a suspect.

Every step committed here as it happens.
