# Consolidated findings — PHP session upload progress

[DAYBREAK] 2026-10-20T20:40:31-07:00 — ranked by exploit plausibility × default coverage. No `[GLM]` entries were present in `shared/` at consolidation time; this is therefore a DAYBREAK-only interim consolidation and should be extended append-only when peer results arrive.

## 1. Cached pointers into mutable nested HashTables (high interest, broad coverage; hypothesis)

The progress object caches raw `zval *` bucket pointers for overall and current-file byte counts (`src/php-src-83/ext/session/php_session.h:134-138`), obtains them once (`src/php-src-83/ext/session/session.c:3183,3207-3209`), then writes through them on later FILE_DATA/FILE_END events (`src/php-src-83/ext/session/session.c:3222-3223,3242`). Normal session flush retains a progress-owned reference, so no UAF was demonstrated (`src/php-src-83/ext/session/session.c:3073-3083`), but mutation/reentrancy or unexpected separation could stale a cached bucket. The logic is identical in 7.4 (`src/php-src-74/ext/session/php_session.h:137-141`; `src/php-src-74/ext/session/session.c:3253-3315`). Preconditions are default-enabled progress plus marker, attacker-supplied SID, and a file; extra serializer/save-handler behavior may be required. Memory-safety consequence if stale: attacker-timed writes of integer zvals into freed/reused request-heap buckets. Detection: crashes/ASan reports at the two writes during multipart requests; hardening: `session.upload_progress.enabled=Off`, or vendor-side re-lookup before each write.

## 2. Event handlers trust state initialized by FILE_START (medium-high interest, broad parser exposure; hypothesis)

FILE_DATA and FILE_END test only SID+key before dereferencing `current_file_bytes_processed`, `post_bytes_processed`, and `current_file` (`src/php-src-83/ext/session/session.c:3215-3244`). The stock parser nominally emits successful FILE_START first (`src/php-src-83/main/rfc1867.c:957-969,1005-1018,1076-1085`), so no current violating path was proven. Historical malformed-header regression coverage and the guarded END path show this subsystem has previously mishandled partial event state (`src/php-src-83/ext/session/tests/bug79221.phpt:23-47`; `src/php-src-83/ext/session/session.c:3253-3259`). If a parser/error/callback path violates ordering, the plausible result is null/stale-pointer write and crash, potentially stronger heap corruption depending on pointer state. Detection: malformed multipart followed by worker crashes; hardening: disable progress and reject malformed Content-Disposition early.

## 3. Default unauthenticated session-write surface (high confidence, very broad coverage; primitive, not memory corruption)

Progress is enabled by default in both branches (`src/php-src-83/ext/session/session.c:849-859`; `src/php-src-74/ext/session/session.c:818-828`). Every accepted multipart POST invokes START (`src/php-src-83/main/rfc1867.c:759-766`), and an attacker can provide a Cookie SID under default strict_mode=0 or directly supply multipart `PHPSESSID`, whose direct branch ignores `use_only_cookies` (`src/php-src-83/ext/session/session.c:837-839,3022-3033,3139-3149`). A later file causes repeated session read/write cycles (`src/php-src-83/ext/session/session.c:3163-3212`). Default cleanup deletes the final key, but intermediate state is observable to concurrent same-SID requests (`src/php-src-83/ext/session/session.c:3052-3095,3250-3253`). This is the coverage amplifier for findings 1–2 and a race/session-poisoning surface. Detect requests containing the default marker plus any PHP session identifier, especially to endpoints not expected to process uploads; harden by disabling progress globally and enabling strict mode.

## 4. Binary SID validation/length mismatch in 8.3 files handler (medium confidence, 8.3-specific; integrity/aliasing)

Upload initialization copies multipart SID with explicit length and bypasses the normal session-start character gate (`src/php-src-83/ext/session/session.c:3139-3141,3185-3186` versus `src/php-src-83/ext/session/session.c:1625-1627`). The files handler validates through a C string but sizes/copies the path with full Zend-string length (`src/php-src-83/ext/session/mod_files.c:107-130,168-175`). Embedded NUL therefore creates disagreeing identities: validation/OS path see a prefix while Zend bookkeeping sees the full string. PHP 7.4 uses C-string length consistently (`src/php-src-74/ext/session/mod_files.c:109-136,156-178`). No out-of-bounds access was found; likely impact is session aliasing/collision or unusual handler state. Detect/reject NUL/control bytes in all SID sources; vendor fix should validate explicit length.

## 5. Unbounded client metadata enters persistent session serialization (medium confidence, broad coverage; chaining/DoS)

The marker value becomes the session key suffix byte-for-byte (`src/php-src-83/ext/session/session.c:3142-3146`), and file field name/full client filename are copied into the progress value (`src/php-src-83/ext/session/session.c:3195-3200`). The multipart body reader passes explicit field lengths (`src/php-src-83/main/rfc1867.c:839-870`), while field/filename copies use NUL-terminated APIs. Serialization is length-aware, so direct corruption was not found, but very large values increase allocation/session-write pressure and binary strings can expose downstream C-string assumptions. 8.3 limits total body parts (`src/php-src-83/main/rfc1867.c:666-692,785-788`); 7.4 lacks that limiter around `src/php-src-74/main/rfc1867.c:685-790`. Cap multipart field/header lengths and log lengths/hashes rather than raw values.

## 6. Same-key `cancel_upload` race (high confidence, narrower impact; DoS)

Before overwriting the progress entry, PHP reads an existing same-key session value and treats literal boolean `cancel_upload` as authoritative (`src/php-src-83/ext/session/session.c:3036-3049,3073-3082`). A concurrent request able to write the same SID/key can force callback failure, which RFC1867 converts to upload error X (`src/php-src-83/main/rfc1867.c:1015-1017,1082-1084`). This is cancellation/availability impact, not RCE.

## Branch narrowing and chain assessment

The core callback is behaviorally identical across 7.4 and 8.3 (`src/php-src-74/ext/session/session.c:3072-3350`; `src/php-src-83/ext/session/session.c:3001-3279`), so a vulnerability affecting both likely resides in shared ownership/event-state assumptions. 8.3 adds multipart-parts and boundary limits (`src/php-src-83/main/rfc1867.c:684-737,785-788`) and stronger SAPI teardown nulling (`src/php-src-83/main/SAPI.c:528-552`; `src/php-src-83/main/rfc1867.c:168-177`), reducing some malformed-input/heap-shaping possibilities without changing the minimal trigger.

No direct Phar invocation or object deserialization chain was found in this path. The session callback is the only in-tree assignment to `php_rfc1867_callback` (`src/php-src-83/ext/session/session.c:2902`; invocation sites `src/php-src-83/main/rfc1867.c:759-1263`). Any RCE through Phar or another extension would require an external consumer of the briefly persisted fixed-shape session record; retain as a question, not a finding.

## Immediate defensive guidance

Set `session.upload_progress.enabled=Off` wherever progress is unused; this exits before progress-state allocation/use (`src/php-src-83/ext/session/session.c:3103-3108`). Also enable `session.use_strict_mode=1`, reject unexpected multipart requests/marker fields at the edge, allowlist SID bytes and length, cap body/header/field sizes, and alert on worker crashes during multipart parsing. These controls cover the default pre-auth surface while awaiting the vendor patch.

---

# Two-lane consolidation (Bastet merge, 2026-10-21T04:25Z)

GLM's results arrived post-consolidation via transcript salvage — see
`notes-glm-recovered.md` (citations independently re-verified against src).
Merged ranking below; provenance tags [D]=Daybreak, [G]=GLM, [D∩G]=independent agreement.

## Convergence (strongest signal in the whole exercise)
- **[D∩G] Unguarded FORMDATA SID branch** — `session.c:3139-3142`: multipart
  form field named `PHPSESSID` sets `progress->sid` from raw client bytes with
  no `use_only_cookies` gate and no `strpbrk("\r\n\t <>'\"\\")` filter (that
  filter exists only in `php_session_start()` at `1625-1629`, [G]); sid validity
  is only enforced under `use_strict_mode` (default off, [G]). Found
  independently via different reading paths. This is finding #3's amplifier
  core and #4's entry point.
- **[D∩G] Pre-basename raw client filename persists into progress session
  state** (session.c:3195-3200 [D]; rfc1867.c:1132 basename happens AFTER both
  FILE events [G]) — retained phar-family-shaped consumer input, though neither
  lane found an in-tree consumer chain (keep as question, [D] framing stands).
- **[D∩G] Shared-code suspicion** — identical callback 7.4↔8.3 ⇒ if the
  embargoed bug "affects PHP 5-8" (watchTowr claim), it lives in this shared
  state/event/ownership logic. Both branch-diffs independently agree.

## Merged ranking (plausibility × default coverage)
1. [D1 + D3 + G-primary] Cached zval* bucket writes (#1) sitting inside the
   default-enabled, attacker-SID-choosable, mid-request lifecycle surface
   (#3/[G]lead1). The SID findings make #1's preconditions trivially reachable;
   GLM's stale-globals ordering (`php_hash_environment()` before module RINIT;
   `ZVAL_UNDEF` without dtor in `php_rinit_session_globals`, mid-request via
   FILE_START) [G] is a concrete mechanism candidate for how #1's "unexpected
   separation" could occur, especially NTS.
2. [D4 + G] Binary/NUL SID aliasing, 8.3-specific: explicit-length copy vs
   C-string validation in mod_files (`mod_files.c:107-130,168-175`) — GLM's raw
   unsanitized sid bytes are what let NUL/odd bytes reach that handler at all.
   Integrity/aliasing rather than OOB, but this is exactly the shape of a
   "hidden invariant break" a CVSS 9.2 chain could use.
3. [D2] Event-state trust with historical precedent (CVE-2020-7062, GH-16998,
   7.4 next_line NULL `buf_begin` UB [G]) — ordering violations produce
   null/stale writes.
4. [G] php serializer (compiled default) framing under client-influenced
   keys + 7.4/8.3 decode-tail divergence — poisoning/aliasing surface, lower
   memory-safety plausibility.
5. [D5] Oversized metadata into persistent serialization (7.4 lacks 8.3's
   parts limiter) — DoS/pressure.
6. [D6] cancel_upload race — DoS only.

## Open questions for patch-diff confirmation at release (07:00 PDT)
- Does the fix add a sid sanitization/validation call in the FORMDATA progress
  branch, or re-lookup instead of caching `zval*` in FILE_DATA/END? Either one
  names the bug.
- Does it move/tighten `php_session_reset_id`/`initialize` mid-upload behavior
  (GLM's stale-globals ordering)?
- mod_files length-consistency fix ⇒ confirms #2.
- If the fix touches ONLY rfc1867.c parser limits, the shared-callback theory
  weakens and D2/G-parser leads rise.

## Attribution corrections (repo history honesty)
- Commit "first shared notes (GLM core read + ...)" was mis-attributed: all
  initial shared/ files were Daybreak-r3's; GLM produced zero shared notes in
  either run (first: budget mismanagement — all thinking, no writing; second:
  provider 900s stream cap on the resumed session). GLM's substantive
  contribution exists only because its transcript was salvaged. Note for
  future lane briefs: hard "write within N tool calls, append per discovery"
  framing is mandatory for pi/GLM.


## Live-fire verdict on jackalsyn PoCs vs firing range (11:05Z, pre-patch)
**Answer to "do the PoCs get a shell in our range?" — NO, and precisely why:**
- Static audit clean (no callbacks except local subprocess for symbol-dump;
  shell=True _sh unused in PoC flow; --dry body-build safe & tested).
- Their forged-body builder runs verbatim on our box: 62,929-byte body,
  PHPSESSID-field sid (P3 ✓), FILLUNIT stall, 149x packed t[] groom, stale
  FILE_DATA store stage — full chain serialized exactly per their docs.
- Delivered through a local TLS relay to a staged lab sink (session_start +
  slow handler, mirroring their webrootF lab semantics) on php83-8.3.35
  mod_php: request COMPLETED. No shell, no segfault, no sanitizer hit.
- Why it can't work against our targets as-shipped:
  1. `--dtor/--call` = leaked zval_ptr_dtor of THEIR lsphp builds
     (delta 0x43EF0 per-build). Our php83 php.ini has different symbol
     addresses; forging a garbage handler ptr only lands if the reclaim
     takes — and no crash means the groom never reclaimed the freed bucket
     under mod_php's allocator stream (their deltas are LiteSpeed-class
     specific; their own RATING.md admits groom tuning).
  2. SAPI mismatch: published deltas for lsphp only; fpm path exists in
     framework but lab-only; mod_php (our stack) not covered.
  3. Their own VALIDATION.md: no UAF without manual groom, stale write
     lands in still-owned memory — matches our 1.89M-exec fleet negative.
- CONCLUSION: the PoC is real machinery pointed at a target it doesn't own.
  "Shell on OUR range" requires porting groom constants to our build's
  allocator profile = OUR OWN exploit work, which is exactly what the
  14:00Z patch-revert race will test the honest way.
- Lab sink + autostart ini REMOVED post-test; range restored to stock.

## php2shell-bastet.py + hardening from the leaked-tool run trace
Trace of the working exploit (Dean, 12:0xZ) revealed the missing stages our
live-fire lacked:
1. LEAK-FIRST: it leaks {main_heap, stale_reference, zval_ptr_dtor,
   zend_call_function} at runtime, derives call = dtor - 0x43EF0 (profile
   delta). Our no-crash ambiguity was partly a garbage hardcoded --call;
   we now leak PIE bias from OUR lab oracle + nm offset from OUR binary.
2. PROFILE REGISTRY keyed per distro build ("ubuntu2604-php85",
   package-build range pinned). Our PROFILES dict + hard gate now mirrors it.
3. ADAPTIVE RETRY ENVELOPE (attempts=8, 25s timeout). We do 8 attempts with
   groom-count jitter +/-6 and fresh random sid per attempt.
4. BLIND CHANNEL: their payload wrote a file (uploads/pwned.txt) rather
   than trusting stdout; we added --verify-url fetch-back for the same.
5. ARCH PORTING TRAP (biggest one): their ABI is x86-64; THIS host is
   aarch64. offsetof probe against our headers: zend_fcall_info identical
   (size 64, fn.val@8, type@16, param_count@48) BUT zend_internal_function
   handler sits at +72 on aarch64 vs +88 x86 - a silently wrong handler
   pointer is exactly the kind of bug that makes a chain "deliver 200 OK
   forever". aarch64-php8x profile added with real offsets.
6. Their SAPI is Apache mod_php with WordPress sink + uploads dir writable
   for blind verify; our lab sink mirrors session semantics; canary oracle
   remains the only scoring channel.

## Two-platform doctrine (from the 8-attempt aarch64 run, 05:13Z)
Our tool ran clean leak-first (bias stable per worker, call VA correct,
handler offset aarch64 +72, groom 145..151 jitter): 8/8 attempts delivered,
all 200 OK, ZERO ASan reports, zero shell. Root insight:
**ASan is a detector, not an exploitation platform.** USE_ZEND_ALLOC=0
routes every allocation through ASan's malloc, whose quarantine+poison
design GUARANTEES a freed 320-byte bin is never handed to a later
allocation. The reclaim stage of this chain is therefore structurally
impossible on an ASan target — silence on ASan proves nothing about the
groom's quality, only about ASan's quarantine. Split the rig:
  * CORRUPTION DETECTION: ASan build + targeted tripwire instrumentation
    (poison hooks on the two cached-pointer writes) - not blind exploit.
  * EXPLOIT EXECUTION: plain (non-ASan) build in Docker; scoring is the
    canary oracle, so no sanitizer needed to PROVE a shell.
php2shell-bastet.py belongs to the second platform; the fuzz fleet + a
future instrumented tripwire build to the first. This resolves the whole
"ASan confirms corruption?" thread: not with a reclaim chain, by design;
and our earlier "no UAF" negatives must be read with that caveat (their
lsphp target was likewise stock-Zend-MM, doubly blind).
