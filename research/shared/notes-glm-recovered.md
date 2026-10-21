# [GLM] Recovered findings — transcript salvage (Bastet extraction, verified against src)

[GLM via transcript salvage] 2026-10-21T04:20Z — GLM's second run died on a
provider stream-limit before it could write notes; Bastet extracted these from
its session transcript and spot-verified every citation below against
./src/php-src-83 and ./src/php-src-74 (verification marks: ✓). Cross-references
to [DAYBREAK] entries included where they agree.

## Primary lead: SID handling asymmetry in the progress path ✓
- `php_session_start()` sanitizes `PS(id)` against `\r\n\t <>'"\` before
  initialize (8.3 `ext/session/session.c:1625-1629` ✓).
- `php_session_initialize()` validates the sid only when
  `session.use_strict_mode` is on (default off).
- The upload-progress FORMDATA branch sets `progress->sid` **directly from raw
  client bytes** (`ext/session/session.c:3139-3142` ✓) — a multipart form field
  named exactly the session name (default `PHPSESSID`) — and this branch has NO
  `use_only_cookies` guard, unlike the GET/POST sid paths in
  `php_session_start()` which are gated on `!use_only_cookies`.
- AGREES with [DAYBREAK 2026-10-20T20:30] state-machine note: unauthenticated
  remote request can select its own SID under stock defaults via multipart form
  field even with `use_only_cookies=1`.
- Consequence chain both agents independently reached: attacker-chosen raw sid
  bytes (unsanitized by the strpbrk filter above) flow into
  `php_session_initialize()` → save-handler file key + serialized session
  content mid-upload.

## Serializer angle
- `session.serialize_handler` compiled default = **"php"** in BOTH branches
  (legacy pipe-delimited key framing).
- Progress state lets client bytes influence $_SESSION keys/content; php
  serializer encode in 8.3 rejects keys containing `|` AFTER appending (worth
  re-checking exact ordering); decode differs 7.4 (silently SUCCESS on
  truncated tail) vs 8.3 (FAILURE) — a real behavioral delta in the shared
  window.

## Lifetime findings
- `php_rinit_session_globals()` does `ZVAL_UNDEF(&PS(http_session_vars))`
  without dtor — invoked mid-request by progress FILE_START via
  `php_rinit_session(0)`.
- POST parsing (`php_hash_environment()`) runs BEFORE
  `zend_activate_modules()` → progress machinery executes with
  not-yet-RINIT'd session module globals (stale across requests in NTS builds).
- `add_*_zval` ownership is transfer (no addref) → progress array ownership
  graph itself coherent (ruled out as bug source).
- `php_session_initialize()` can trigger GC and `php_session_track_init()`
  mid-upload; `php_session_reset_id` runs on EVERY progress initialize (SID
  constant rebuild + trans_sid application from raw PS(id)).

## String-handling / parser findings
- 7.4 `next_line` buffer-full path: `self->buf_begin = ptr;` where ptr is NULL
  (failed memchr) — transient UB, fixed in 8.3 (`main/rfc1867.c:351` in 7.4 ✓).
- `substring_conf` bounds-safe in 8.3 (len+1 alloc).
- Progress `name` stores the RAW client path — basename normalization happens
  later at `main/rfc1867.c:1132` ✓, AFTER both FILE events fire (matches
  [DAYBREAK]'s pre-basename filename capture note at session.c:3198-3199).
  Phar-deserialization-family entry condition retained in both branches.
- May 2026 commit touched the Content-Disposition parsing chain (both trees
  have .git; suspect window for recent churn).

## Precedent in this exact machinery
- CVE-2020-7062 (bug #79221): NPD when file part lacks `name=` →
  FILE_START with NULL field name → `add_assoc_string_ex(NULL)`; fix
  synthesizes anonymous names. Reproduced via in-tree test.
- GH-16998: UBSAN warning in rfc1867 (8.3 NEWS).
- Both upload_progress INI entries commented out in bundled php.ini files →
  compiled defaults (enabled=1) apply in practice.

## Ranked hypotheses (GLM view, for consolidation)
1. Attacker-controlled raw SID bytes through the unguarded FORMDATA progress
   branch into save-handler key path + mid-upload session cycles (agrees with
   DAYBREAK; strongest pre-auth primitive).
2. Mid-request rinit/undef + stale-globals ordering (NTS) lifetime bug.
3. php-serializer framing with client-influenced keys/content.
4. Residual parser edge cases in header extraction chain (recent-churn area).
