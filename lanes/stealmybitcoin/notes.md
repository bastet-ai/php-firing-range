# Lane SMB1 notes — stealmybitcoin clone :8151 vuln / :8152 ctrl

Rung log. All commits prefixed `smb:`. Canary replant 2026-10-25 19:0x
(orchestrator-verified containers were recreated afterwards; /root/wallet.key
gone from BOTH php containers + results/canaries/smb-*.flag missing ->
replanted exactly per range/stealmybitcoin/up.sh, print-flag re-verified
as nobody on :8151-equivalent and :8152-equivalent containers).

## Q2 ANSWER — is `php -S` fork-uniform? (measured, benign: scripts/smb_q2_cli_server.py + smb_q2_followups.py, raw log q2-cli-server.log)

NO — and the question dissolves: cli-server does not fork at all.

1. PROCESS MODEL: single process, single thread (Threads: 1), PID stable
   across every request (pid 7 unchanged through the whole series; no
   children during a trickling request; PHP_CLI_SERVER_WORKERS unset =
   no worker pool). NOT mod_php fork-uniform (nothing shares a post-fork
   layout) and NOT fpm (no per-child recycling): ONE long-lived process,
   heap + ASLR set once at exec.
2. CONCURRENCY: requests fully SERIALIZED. 8MB POSTs direct at phpsrv:
   n=1 63ms, n=4 167ms, n=8 327ms (≈41ms/req regardless of parallelism;
   extra connections queue in backlog). No concurrent request pairs are
   possible -> no cross-request races; also producer/consumer "same
   child" pinning is trivial (every request is THE process), but a
   stalled request BLOCKS the whole server.
3. ASLR (assisted /proc reads via SYS_PTRACE helper; in-container root
   lacks CAP_SYS_PTRACE — wpbleed helper precedent): PIE base of
   /usr/local/bin/php CONSTANT across the request series
   (0xb1c553e60000 through 15 benign requests + multiparts); re-rolled
   at every exec: 3 keepalive restarts -> 0xaafea5690000,
   0xb4c08dc30000, 0xb0b85a940000. Recovery after pkill = ~3.2s end-to-end
   (keepalive sleep 3 + spawn).
   Q2->Q1 LINK: a crash-oracle bias brute is STRUCTURALLY IMPOSSIBLE on
   cli-server — every bad forge kills the process and the next exec
   re-rolls the bias; you can never test a base twice against the same
   layout. Any forged-pointer chain must leak the bias non-fatally and
   land before the next crash — or find a channel that survives death.
4. HEAP: single arena lives across requests; RSS stable ~23MB
   (allocator reuse, no per-request reset). Cross-request grooming is
   deterministic (serialized requests on one arena) — unlike fpm's
   which-child uncertainty.
5. SESSION SURFACE: session_start pages create /tmp/sess_* as nobody:600;
   upload_progress.enabled=On, cleanup=On, freq=1%, min_freq=1s, FILLUNIT
   chunking (rfc1867 update callbacks fire per 5120B of file data).
   Benign observability NIL at the file level: progress data never hits
   the session file mid-flight (memory-only until shutdown; cleanup wipes
   the key before write). The 619 decode path is only provable via the
   fatal producer (Q1) or in-memory reads.
6. FIXTURE REALISM — stock nginx defaults measured on :8151, likely the
   real crowd-blockers on the live CTF too:
   a. client_max_body_size = 1m (default): 1.5MB POST -> 413 from nginx,
      php never sees it. 0.9MB passes fine.
   b. proxy_request_buffering = on (default): during a 4s mid-body
      pause there is NO ESTABLISHED connection to phpsrv:8080 (only
      TIME_WAIT) -> nginx swallows the whole body before contacting
      upstream. Attacker-controlled mid-request STALLS DO NOT REACH php
      through :8151. => the groom route's 1.4s two-chunk stall (its
      618 double-update timing primitive, >min_freq gap) is DEAD through
      nginx: php parses the whole multipart in one burst, second
      rfc1867 update is min_freq-throttled, no dtor, no UAF.
   c. => the only live producer through :8151 is the 619 session-decode
      path (staged session file, tiny request, no timing dependence).
      Direct-at-phpsrv attacks (no buffering, no 1MB cap) need a network
      position inside the compose — out of scope for the modeled
      remote attacker.

## Q1 — can php2shell land without killing the server? (in progress)
Next: fatal-window measurement (619 OOM producer -> 502 window, bias
re-roll confirmation, stale-state death), then zero-fatal phasing.

## Q1 ANSWER (core) — does an OOM-fatal kill cli-server? NO. The window is a SEGV-only phenomenon.

Measured (scripts/smb_q1_fatal_window.py + smb_q1_grid.py, logs
q1-fatal-window.log / q1-grid.log):

1. THE BRIEF'S PREMISE IS WRONG for the 618/619 class: the 619 OOM
   producer (staged 75MB session `poc|a:2:{i:0;s:3:"abc";i:1;s:75000000:...}`
   + tiny multipart; decode fires inside php_session_rfc1867_update's
   session init during BODY PARSE) returns a clean 500 in ~40-100ms and
   php -S KEEPS SERVING: PID and PIE bias UNCHANGED across 3 consecutive
   producer fires, 200s immediately after each. VmHWM proves the OOM
   (19.8MB -> 92.9MB peak = the 75MB session read; the second 75MB inner
   alloc exceeds memory_limit 128M -> bailout mid-decode). The bailout is
   a REQUEST-LEVEL fatal: cli-server runs request shutdown and continues,
   exactly like mod_php and UNLIKE our fpm-child-exit-70 finding. The
   "502 window until keepalive restart" exists ONLY for SEGV-class
   kills (bad forges), not for OOM bailouts.
   => ZERO-FATAL PHASING IS NOT REQUIRED. The producer is a repeatable,
   server-surviving OOM; the PIE bias stays valid across producer fires
   (Q2's re-roll only happens on real crashes). The leak->forge chain has
   no pre-fatal window problem on cli-server: leak via the stale state
   left by a SURVIVED fatal, forge when ready, and even a missed forge
   costs only ~3.2s restart (plus bias re-roll).
2. POST-FATAL SHUTDOWN RUNS ON CLI-SERVER: after each OOM fatal the
   staged session file is UNLINKED (empty-session write at corrupted
   shutdown -> unlink) for 75MB producers; for 200MB (read itself OOMs)
   and 60MB (OOM at ~137MB peak) the file survives. Shutdown touching
   the corrupted state = the 618 advisory's susceptible path, live here.
3. STALE-STATE DIVERGENCE OBSERVED THROUGH HTTP: with stale BG state
   already present (after earlier fatals, no restart), the same 12-marker
   producer request returned 200 and TRUNCATED the session file to 0
   (decode completed "successfully" producing nothing) instead of the
   fresh-process 500+unlink. State-dependent behavior change = the 619
   remnant is REAL on cli-server and changes the next decode's outcome.
4. FIRST WALK-ORACLE (R:14 self-resolve, wpbleed WALK_TOKEN) did NOT
   resolve post-fatals -> the exact slot arithmetic differs on 8.4.26
   (their anchors: fpm/php8.2.34) or the remnant needs the producer's
   marker head at fire time. NEXT: BG(unserialize) runtime-diff probe
   (stripped binary; RW-segment before/after diff, glm4 LW technique)
   to read the stale pointer directly, then R-index sweep.
5. CTRL :8152 (8.4.27 patched) ALSO 500s on the same OOM (OOM fatal is
   not the bug; the patch is about state corruption) and SURVIVES; ctrl
   did NOT fall; walk did not resolve there either. Canary intact.

## SMB1 attempt-1 observations — 619 state on cli-server (scripts/smb_619_state.py, logs sweep-r1-24.log)

TOOLING: /proc reader fixed (scripts/memread.php): helper = the target's
own php image run with --cap-add SYS_PTRACE --pid=container (native
arm64). busybox dd silently returns ZEROS on /proc/PID/mem (alpine
helper); the box's debian:bookworm-slim is x86_64-QEMU (useless). php's
own streams (fseek+fread on /proc/PID/mem) read correctly.

1. PRODUCER RECIPE FIXED: my 12-marker edit had introduced a missing ';'
   (s:3:"abc"i:1;) -> every "producer" fire after the edit was a CLEAN
   parse failure (200, session destroyed, NO stale state). The REAL
   producer (12 markers + `poc|a:2:{i:0;s:3:"abc";i:1;s:75000000:...`)
   -> 500 via the >=64MiB string-alloc bailout inside the rfc1867-init
   session decode, reliably, and the process SURVIVES (pid+base stable).
   ALSO learned: huge (>2^26) string allocs do NOT respect memory_limit
   (c65: 149MB at 128M limit decodes fine in CLI); the 618-class producer
   needs the >=64MiB alloc-bailout, not a limit-OOOM. 1-byte-short staged
   files change the class completely (clean "Unexpected end" failure) —
   session-file staging must be byte-exact (WG gotcha #3 again).
2. BSS IS CLEAN AFTER THE PRODUCER: full RW-image-segment diff before/
   after a real producer = 0 changed qwords (reader verified against the
   zend heap: 373 changed qwords across a benign request). On cli-server
   the shutdown zeroes BG(unserialize)/PS bss state (differs from fpm,
   where the stale BG pointer survives per wpbleed's evidence). The
   surviving corruption lives in HEAP STATE, not bss.
3. THE POISONED-NEXT-DECODE LAW (24/24 + 4/4 reproducible): after a real
   producer fire, the NEXT request that session-decodes ANYTHING segfaults
   the process: trivial k|i:42;, plain strings/arrays, and every R:1..R:24
   — all 502 with process death (keepalive restart ~3.2s). On a FRESH
   process the same consumers fail cleanly (200, warning, session
   destroyed). So the producer leaves a heap corruption that the next
   session init/decode walks into. This IS the 618 "shutdown reads/branches
   on invalid state" made visible: on cli-server the corrupted state is
   NOT rideable as a passive remnant (bss-clean) — it CRASHES the next
   decode unless the chunk it walks is OURS (groomed). The SEGV-vs-resolve
   is a steerable primitive: shape the recycled chunk => the walk reads
   attacker bytes (the WP lane's a2/a3 session-file-groom chain is the
   built machinery for exactly this; its remaining "per-child calibration"
   problem is DISSOLVED on cli-server: one process, stable heap, and the
   process survives the producer).
4. Consequence for Q1's zero-fatal phasing: the producer fatal is free
   (server survives, bias stable), but the consumer is exactly ONE
   request: the next session decode either walks our groom (prize) or
   garbage (SEGV + 3.2s restart + bias re-roll). One shot per producer.
5. Debug-server evidence (in-container php -S :8081, display_errors on):
   the decode failure path prints "PHP Request Startup: Failed to decode
   session object. Session has been destroyed" + repeated "Failed to write
   session data (files)" — post-cancel state is visibly broken (the 619
   half-mutated globals), yet the request completes 200 (bailout swallowed
   in request startup, never propagating as a request fatal) on the CLEAN
   failure path.

## SMB1 attempt-2 — gdb triage of the poisoned-next-decode SEGV (gdb-triage.log)

gdb 16.3 attached via SYS_PTRACE helper (image smb-gdb-helper = alpine
+ gdb; attach AFTER producer, consumer fired under it):
- Crash: SIGSEGV at pc = php_base + 0x37FC34, instruction `ldr x2, [x1]`
  with x1 = 0x24 (small-int-as-pointer: a corrupted structure field
  dereferenced), followed by `cmp x2, #0xfe` — the pipe-format session
  decoder scan shape (`while (*q != PS_DELIMITER)` / parser char class).
  x22/x20/x21 = zend-heap pointers (0xfeb5814571a0 region), x2 = x22+1.
- The consumer walked producer-corrupted heap state and dereferenced 0x24.
- Next rung: rebuild php 8.4.26 (official image config) to symbolize
  0x37FC34 and derive the offset table (stripped target binary; crash
  bytes at the site can be byte-compared target-vs-rebuild to validate
  symbol fidelity BEFORE trusting any offset).

## SMB1 attempt-2b — the poison is in the RFC1867 path, NOT session decode

Producer -> consumer via PLAIN POST (script session_start, no multipart,
no progress fields): trivial k|i:42; decodes AND WRITE-BACKS fine (200,
sess file re-encoded 7 bytes, process alive); R:14 walk clean-fails
(fresh context, expected). The poisoned-next-decode law applies ONLY to
multipart-with-progress consumers (the rfc1867 update machinery walking
producer-corrupted heap). MODEL CORRECTION for cli-server: no rideable
BG(unserialize) remnant (bss cleaned + fresh decode context) — the
exploitable surface is the 618 progress-path corruption the next update
walks, i.e. the php2shell GROOM-route class (stale FILE_DATA store /
reclaimed progress-tree chunks), cross-request instead of intra-request
(the intra-request two-update stall is timing-dead through nginx
buffering). The consumer groom = shape the chunks the next update walks.

## SMB1 attempt-2c — crash trigger localized to the FILE_DATA update (the 618 groom-route surface, cross-request)

Consumer-shape matrix after a real producer (fresh restart each trial):
  no-progress + file part        -> 200 (alive)
  progress field, NO file part   -> 200 (alive)
  progress + file part (mp_min)  -> 502 SEGV (dead)
So the SEGV fires in the rfc1867 update called for FILE DATA processing
— php_session_rfc1867_update's file-data store, the exact function pair
whose intra-request double-call is the php2shell groom-route UAF. On
cli-server the window opens CROSS-REQUEST instead: producer corrupts,
the next update's file-data store walks the corrupted chunk. NO
TIMING/STALL NEEDED => nginx request buffering is IRRELEVABLE to this
variant => the groom route is ALIVE on :8151 (the Q2 'groom-route DEAD'
conclusion applied only to the intra-request stall variant).
Weaponization path = the tool's own groom route adapted cross-request:
consumer multipart = progress field + t[] reclaim fields (shape the
corrupted bins) + file part (the update walks OUR bytes). Consumer
fields parse BEFORE the file part, so consumer-controlled allocations
land in the corrupted window BEFORE the walk.

## SMB1 attempt-3 — crash structure dumped under gdb (gdb-triage.log)

php 8.4.26 dbg rebuild (smb-php-dbg image; exact official configure line;
unstripped, 20K symbols) — NOTE: rebuild codegen differs from the
target's Sep-2026 build (byte-pattern NOT found; per-symbol fidelity
must be re-validated before trusting any rebuild-derived runtime offset;
struct layouts from source are fine).

Crash (consumer mp_min post-producer, gdb attached): pc = base+0x47FC34
(corr.earlier 0x37FC34 was a my-arithmetic bug), `ldr x2,[x1]; cmp x2,#0xfe`
= php_var_serialize family (rebuild neighborhood: php_var_serialize_
try_add_sleep_prop / zend_get_typed_property_info_for_slot — object/
property-info serialization path), x1 = 0x24 (stale zval value
dereferenced as a pointer).

STRUCTURE (gdb x/16gx of x19..x22):
- x21 region (0x...869018): THE CONSUMER'S OWN ps_read buffer — the
  staged walk token `k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:14;}` is VISIBLE
  there, followed immediately by the consumer's fresh var_entries
  (array of zval pointers 0x...c010, c020, c030...). The consumer's
  session content lands ADJACENT to the structures the update walks.
- x22 region (0x...857180-7200): the RECYCLED POISONED CHUNK the
  serializer walks: zval-shaped qwords (0x1600000001...), self-
  referential bucket pairs {0x...571e0, 0x80000000005978e6},
  {0x...57200, 0x80000000005978e7} — a HashTable arData/bucket run with
  stale zvals from the producer's aborted tree; one slot's value = 0x24
  (small-int-as-ptr) -> SEGV when serialized.

INTERPRETATION: the consumer's fresh progress tree allocates into the
poisoned/freed bins; the FILE_DATA update's session re-encode walks the
tree incl. stale slots => deref of stale zval values. The stale-slot
values are RECLAIM-GROOMABLE (consumer multipart part values land in
the same freed bins BEFORE the file part) — this is the php2shell groom
route's own mechanism (t[] reclaim of the freed progress-tree bins),
operating CROSS-REQUEST on cli-server: producer request corrupts+frees,
consumer request's groom fields reclaim, the file-data update walks the
forged zvals/fcall. NEXT RUNG: post-producer heap snapshot of the freed
bin classes (gdb/memread) -> pick consumer groom part sizes -> forged
zval {TARGET-0x10, IS_STRING} leak oracle via the serialize writeback.
