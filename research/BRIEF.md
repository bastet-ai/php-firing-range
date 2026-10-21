# Research brief: PHP session.upload_progress attack surface (DEFENSIVE source review)

Context: PHP emergency security release Wed 2026-10-21 14:00 UTC fixes two critical
CVSS 9.2 vulns (CVE-2026-109618/619, RCE, details embargoed). A trusted hint says
`session.upload_progress.enabled = Off` mitigates "this bug" — so the vulnerable code
is very likely in the upload-progress machinery (ext/session/, rfc1867 progress).

This is AUTHORIZED DEFENSIVE RESEARCH on open-source code we host locally, ahead of
vendor disclosure, so we can build detections and hardening guidance the moment
patches land. We are NOT attacking any third party.

Sources (read-only): ~/php-src-83 (PHP 8.3 branch), ~/php-src-74 (PHP 7.4 branch).

Primary files:
- ext/session/session.c                 (upload progress entry/teardown, INI)
- main/SAPI.c, main/rfc1867.c           (progress naming, upload event flow)
- Zend/zend_operators.c, ext/session/session.c heuristics
- ext/phar/phar_object.c                (historic progress-triggered path: phar)
- HISTORY, NEWS, UPGRADING.INTERNALS for past progress CVEs (CVE-2012-0831 etc.)

Your job:
1. Read the upload-progress implementation end to end. How does a multipart upload
   create/locate/destroy its progress session entry? What strings/metadata from the
   CLIENT (filename, form field names) reach session keys, MM heap, or flags without
   sanitization? Track lifetime: what outlives what?
2. Enumerate every way an unauthenticated remote request reaches this code without
   any ini other than the default (progress.enabled=1, freq_bytes=0, name prefix
   default). Note defaults per branch (7.4 vs 8.3) — the hint implies the bug lives
   in code paths enabled by DEFAULT.
3. For each finding: root cause hypothesis, memory-safety plausibility (what corrupts
   what), trigger preconditions, and detection/hardening value. "Could this chain to
   RCE via $_SESSION state read back in another extension?" is a fair question to
   log, but stay in notes: no exploit code, no PoC binaries here.
4. DIFF the two branches in these files — behavior deltas narrow the suspect window.

Collaboration protocol (both agents share this directory):
- Notes live in ~/firing-research/shared/. Append-only, one file per topic:
  notes-upload-progress-core.md, notes-string-handling.md, notes-lifetime.md,
  ideas-chaining.md, questions-for-peer.md
- Sign entries: [GLM] or [DAYBREAK], ISO timestamp, file:line refs REQUIRED.
- If you find a peer entry extending or contradicting yours, respond in-thread;
  do not overwrite. Build on each other's leads explicitly ("re: [GLM 02:55]").
- End with a consolidated findings.md ranked by exploit-plausibility x coverage.
