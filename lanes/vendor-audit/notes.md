# notes.md — GLM6 vendor-audit lane (Percivalll/php2shell-wp), durable state

Audit in progress. Repo under audit: /home/user/vendor-audit/php2shell-wp
(READ-ONLY, never executed). Our chain references: phpbleed-bastet.py (forge
dispatch RCE, :8088 proven), scripts/a3_*.py (N-oracle), TODO.md §PROVEN.

## Ladder progress
- [x] rung 1 pipeline reconstruction → recon.md (commit 25fb6db)
- [x] rung 2 leak channel → "set-cookie-oob" below
- [ ] rung 3 worker pinning
- [ ] rung 4 RCE route (serializer vs fcall_info)
- [ ] rung 5 rejected primitives
- [ ] rung 6 ASLR gate
- [ ] rung 7 integration (claim map, adaptations, TODO, compose action)

## set-cookie-oob (rung 2 — their 4KiB leak channel vs ours)

### Their mechanism (code citations)

Stage A — leave stale PS(id):
- big_a.py driven by A_ARGS (run_ext.py:23): ~66MB multipart groom,
  PHPSESSID=\0, progress=k, file part; at FILE_START
  php_session_send_cookie→php_url_encode's 4096B page alloc OOMs
  (REPORT §4.1). Worker survives (E_ERROR is non-fatal to the child),
  leaving PS(id)=stale/controlled zend_string + PS(send_cookie)=1.
- Caveat they note: the first A on a worker also compiles index.php and
  parks its op_array at the ZendMM chunk head — that is what makes the
  OOB window contain libphp handler pointers (run_ext.py:196-204
  comment; REPORT §4.4). opcache-cached index.php zeroes the window.

Stage B — forge + OOB read (b_leak20.py:1-68, profiles.py:88-96):
- b_leak20.py:24-27 forges a 63B value: `struct.pack_into("<Q",
  fake, 0x10, LEAK)` → the value string's zend_string.len field
  (data starts at +0x18 of the zend_string header; a 63B value spans
  header+len of the NEXT slot) = 0x1000; bytes +0x18 = "P2SFAKE1".
- Groom: 31 field names of 32B with empty values fill bin7 slots 0..61
  (b_leak20.py:29-31, REPORT §4.2); the 63B value lands in slot 62;
  php_session_initialize() during cleanup allocates the 32-char session
  id → hits slot 62 → the new PS(id) header overlaps the forged len.
- php_session_send_cookie() calls php_url_encode(PS(id)) with
  PS(id)->len=0x1000 → encodes 4096B of adjacent heap into
  `Set-Cookie: PHPSESSID=...` → 4104B decoded window (REPORT §4.2-4.3).
- Client-side parse (run_ext.py:44-119): libphp base = page-aligned
  vote over 16 known offsets (min 4 votes) + 4 fixed qword anchors;
  chunk = dominant (q & ~0x1FFFFF) 2MiB bucket; H=chunk+0x6a000.

Strength properties:
- ONE request produces base + chunk together, in-band, 200-status
  delivery, no second resolving request.
- No session-file staging required for the leak itself (unlike ours
  where the producer needs a staged session file to OOM).
- But it requires: same-worker discipline (pin or the layout resets),
  a prior A request on that worker (op_array at chunk head), and the
  bin7 slot-62 landing — i.e. a heap groom of similar fragility to
  our symmetric groom, only at 63-byte scale rather than 2MB scale.

### Comparison with our channels

| property | their Set-Cookie OOB | our OOM-fatal in-band + N-oracle |
|---|---|---|
| data per fire | 4096B contiguous window (base+chunk at once) | 2MB dump (wpdump) or ONE qword per fire (N-oracle) |
| transport status | 200 OK, Set-Cookie body | fatal-error message text (593B dual-fatal in-band) |
| needs staged session file | NO | YES (producer = unauth multipart + staged session file) |
| needs same worker | YES (A leaves the layout; rotate kills it) | walk oracle handles stale children (R:n self-resolve) |
| arbitrary-target read | NO — reads heap adjacent to PS(id) only; arbitrary length via LEAK knob but always from that one stale string | YES — N-oracle reads ANY qword (BG(unserialize).data proven; env secrets tiled) |
| primitives needed | forge ONE zend_string len (63B value) + groom bin7 slots | full OOM-fatal producer + precise regroom + fake-zval encode-append |
| failure mode | no cookie / <0x1000 raw → retry in place | oracle silence → regroom |
| which structs leaked | ZendMM chunk head: op_array, handler ptrs, data ptrs | arbitrary, but one qword at a time |

### Verdict (their leak vs ours)

- STRONGER on: volume (4KiB contiguous vs 1 qword/fire), zero staging,
  single-request closure of BOTH unknowns (base + heap chunk), and it
  is per-process-safe (each B is a fresh 200; does not depend on
  fork-uniform d).
- WEAKER on: not arbitrary read — it is a fixed window at a groomed
  location; and it is layout-fragile (slot-62 landing, op_array head
  requirement, opcache zeroing).
- COMPLEMENTARY: their B-forge is essentially a lighter-weight version
  of our a3 fake-zval: where we forge a whole zval to redirect the
  encode append, they forge only len in an existing stale string and
  let the NORMAL cookie path do the read. Adaptation candidate for our
  chain: use a stale-PS(id) len forge to replace the N-oracle's
  bootstrapping step (leak d / bias discovery), keeping the N-oracle
  for arbitrary qwords. See rung 7b.
- Note the asymmetry to remember: our N-oracle target
  basic_globals+0x350 returned BG(unserialize).data — their equivalent
  unknown H (BG.data after arm) is instead derived deterministically
  as chunk+0x6a000 from the leak, because their arm CHOOSES H (emalloc
  0x2018 from the dummy's freed page) rather than discovering it.

## worker-pinning (rung 3 — their chunked-POST pin vs our child-lottery wall)

### Their mechanism (code citations)

Two pin modes (run_ext.py:130-171):
- FIXED (pin_slow_pause.py): opens exactly workers-1 (default 149)
  connections, each an UNFINISHED chunked POST
  (`Transfer-Encoding: chunked`, one 4KiB chunk sent, terminating
  zero-chunk NEVER sent, pin_slow_pause.py:16-27). Holds them for
  `hold` seconds, re-sending 4KiB/s per socket (lines 55-66), replacing
  dropped pins until a pause-file appears.
- ADAPTATIVE (pin_adaptive.py, the default): opens pins one at a time
  (20ms apart), probing each time with `GET /readme.html` (static file,
  no PHP); when the probe times out the pool is saturated
  (pin_adaptive.py:74-79); then closes pins from the TAIL until a probe
  succeeds → exactly one free worker (lines 82-94). Reports "dropped N"
  if any pin connection dies during the chain (lines 103-107).

Why a chunked-body pin and not keep-alive: a mid-body POST is BUSY, so
MPM MaxSpareServers reaping (10 idle max) cannot reclaim it (REPORT §3).
Their rate-hardening finding (pin_adaptive.py:16-21 comment): Debian's
mod_reqtimeout `body=10,minrate=500` closed 512B/s pins on jitter;
4KiB/s = 8x minimum survives. Their fixed-149 mode failed silently
exactly this way before the fix (REPORT §12 row "Pin holds fewer
workers").

### Does the pin survive the OOM fatal? How is child death verified?

- The OOM fatal (E_ERROR) only kills the REQUEST; mod_php child survives.
  The pin sockets live in OTHER children — untouched by the free
  worker's fatal. When rotate() deliberately kills the free worker via
  an oversized OOB read (SIGSEGV), 149 workers remain busy → prefork
  must immediately fork a replacement for the demand → the single-free-
  worker invariant is maintained THROUGH the fatal and the refork.
- Child death verification is purely IN-BAND: rotate() (run_ext.py:253-275)
  accepts ONLY `resp 0` / no status line from b_leak20.py as death; a
  complete response (any 200/500) means survival → escalate the read
  (0x800000 → 0xC00000 → 0x1800000), 3 tries each. No /proc, no gdb,
  no docker exec (run_ext.py:3-8 docstring). REPORT §6.1.

### Comparison to our findings

| question | our status | their answer |
|---|---|---|
| stale-child consumption under load | cb-B: 0/15 at 30-concurrent flood, window ~0s, pure child-lottery (glm5 notes 24-Oct, :8104) | SOLVED BY CONSTRUCTION: pin leaves exactly 1 free worker → every attack request lands on the same child; no lottery, no flood needed |
| idle delivery | lottery p≈1/#children (glm5) | pin makes p=1; also makes "retry in place" (leak) valid, which our walk-oracle design forbids (we rotate via R:n self-resolve instead) |
| SIGSTOP-pin gotcha (glm4 arm64, TODO: "never SIGSTOP-pin before exec staging"; lane-hang postmortem) | host/container-level pin froze the lane | theirs is pure HTTP — no exec, no signals, no lane-freeze risk; also no flock interaction |
| flock pinning (our tooling serializes fires) | flocks serialize OUR OWN tools per target | orthogonal: their pin doesn't touch session files, no flock window interaction |
| fpm children EXIT on the fatal (glm5 :8103, code 70) | stale-global persistence fails on fpm | pin still works on fpm topology in principle (busy children can't be reaped), but their whole chain rides mod_php child-survival; fpm remains open for them too |
| worker count discovery | N/A (we assumed) | adaptive probe-and-close — works on ANY prefork count, no config read; directly answers our ":8099 has how many children" class of unknowns |

### Verdict

The chunked-POST pin is SUPERIOR to every same-worker technique we have
tried (flood-based discrimination, R:n walk oracle, SIGSTOP). It is the
clean fix for the cb-B under-load wall: our 0/15 was because the
consumer competed with flood traffic for random children; pinning N-1
workers removes the competition entirely. Adaptation is low-risk:
loopback, no /proc, no exec, Apache-only (mod_php AND fpm topologies
both have busy-worker semantics), and the reqtimeout rate floor
(4KiB/s × ~150 pins ≈ 600KB/s loopback) is trivially affordable. Design
sketch in adaptations.md (rung 7b).

## rce-route (rung 4 — fake ps_serializer vs our forged zend_fcall_info)

### Their route (stage_rce.py:38-62, REPORT §7-§8)

Primitives consumed:
1. leak: base + chunk + H (one B request).
2. heap placement: arm forces BG.data = H by RECLAIMING a chosen page
   (dummy 1MiB filename buffer freed right before the 0x2018 emalloc at
   FILE_START — arm_file2.py docstring). H is CHOSEN, not discovered.
3. ONE pointer write: R1's var_push wrap-write
   (stage_rce.py:47: N0 = (psg+0x148-(H+0x200)-0x10)//8, 64-bit negative
   wrap) lands PS(serializer) = H+0x310. Value written = pointer into
   their own fake var_entries (no arbitrary-value gadget needed — the
   value is `rval`, the dtor temp zval address they planted).
4. call frame: NOT forged in memory — it is the SESSION FILE CONTENT.
   sess_trig2 = 0x4000B key = fake zend_execute_data (num_args=1,
   arg1.value=H+str_off, arg1.type=IS_STRING — stage_rce.py:69-77), read
   verbatim as `val` by ps_read and handed to
   PS(serializer)->decode(val) = zif_system(execute_data=val).
5. The fake zend_string (cmd) lives INSIDE the R2 900-field re-plant of
   H (fake_r2, stage_rce.py:65-74: gc=1|0x106<<32, len, data).

So the total forged-state bill: one var_entries table + one zval-sized
serializer struct + one zend_string + one call frame in a file. NO
fcall_info, NO ce->__unserialize dance, NO execute_internal dispatch
trick, NO LOCK-0x1C destroy gate.

### Our route (phpbleed R-7, per TODO §4)

Consumes: last_dtor=LOCK-0x1C unconditional destroy gate, dup-key u2=2
→ Z_OBJCE_P → ce->__unserialize → zend_call_known_function, fake
function E=.data.rel.ro F=E-64 handler=zif_highlight_file relocated,
type-218 internal-dispatch trick, param fake zend_string "/CANARY".
More machinery, and the one unresolved variable is the per-CHILD
session-buffer page (per-fire calibration).

### Primitive-count verdict

Their route needs FEWER exploit primitives in the classic sense (one
wrap-write + file-content call frame) BUT more setup dependencies:
- TWO staged session files, one of them 30MiB (post_max_size bypassed
  via chunked TE — REPORT §5.1), written on a FRESH fork each;
- the R1 wrap-write only works because BG.data=H is chosen by reclaim,
  so the arithmetic is deterministic — this is the elegant core;
- per-build constants: ps_globals, zif_system, PS(serializer) field
  offset, N0 arithmetic, +0x6a000. All five are build-fragile.

### Writable-target check on OUR builds (read-only, range containers)

- Their offsets (8.3.35 image): ps_globals=base+0x10432a0, zif_system=
  base+0x3ac080, PS(serializer)=psg+0x148 (stage_rce.py:11-12, REPORT §9).
- OUR wordpress-x86 container (PHP 8.2.34, /usr/lib/apache2/modules/
  libphp.so, `readelf -sW` 24-Oct): ps_globals = vaddr 0xf0c998,
  symbol type B (.bss — WRITABLE, not .data.rel.ro), 432 bytes;
  zif_system = 0x36ff48 (local FUNC). Both anchors EXIST on our 8.2
  build. The +0x148 serializer field offset is an 8.3.35 measurement;
  8.2's php_session_globals field order differs (verified struct
  layout drift in ext/session/php_session.h vs 8.3-plain source) —
  per-build derivation required (disasm of php_session_decode's PS
  (serializer) load). NOT a blocker: the target is a .bss POINTER
  field, no RELRO to defeat — same class as our basic_globals+0x350
  N-oracle target.
- ps_serializer struct: {name, encode, decode} = +0x00/+0x08/+0x10
  (php-src-83-plain ext/session/php_session.h:222-226) — matches their
  +0x310/+0x318/+0x320 fake layout exactly.

### The "line 195 / neither" sentence (REPORT §15.3)

Answer to the brief's question: the sentence is about the FATAL-ERROR
BACKTRACE alternative primitive. `last_fatal_error_backtrace` and the
`fatal_error_backtraces` INI were added in PHP **8.5**; "PHP 8.3/8.4,
including this image's 8.3.35, contain neither" the stale backtrace
field nor the setting. Their assessment: on 8.5 the backtrace route is
the confirmed mod_php path (display_errors=Off does not block it;
mitigation = fatal_error_backtraces=0). So the main chain (serializer)
is 8.3.35; the backtrace alternative is 8.5-ONLY and ABSENT on 8.3/8.4
— this version-gates their rejected-primitive #3, not their shipped
chain. For us: no 8.5 lane exists yet; backtrace route is moot on
8.2.34/8.3.35 boxes.

### Interaction with our known walls

- Their route sidesteps our last-mile wall entirely: it never needs the
  session-buffer page to cover a leaked d — BG.data is PLANTED by
  reclaim. Our per-child map calibration problem (TODO §4 REMAINING)
  does not exist in their design because H is deterministic
  (chunk+0x6a000, fork-stable).
- Their route still needs the same "fresh fork for each memory-hungry
  producer" discipline (real_size carry-over — REPORT §12), matching
  our producer-freshness practice.

## rejected-primitives (rung 5 — commit 907ceb5 doc additions vs our walls)

Their three documented rejections (REPORT §15, added in 907ceb5):

### 15.1 PG(auto_prepend_file) overwrite — REJECTED (value-shape wall)
- Write target reachable: core_globals=base+0x1059100, runtime INI
  mh_arg1/2 resolve auto_prepend_file to base+0x10591a0; the fake
  var_entries wrap-write REACHES it (write not the problem).
- Wall: var_push/var_push_dtor write a ZVAL SLOT (dtor temp zval), not
  a string; PG(auto_prepend_file) would receive a pointer, and any path
  planted at H+0x310 is clobbered by the dtor before use.
- Layout walls: 326B session file → buffer lands AT H → SIGSEGV at
  base+0x3fa1fe (var_tmp_var deref of 326); 5MiB progress key breaks
  the 64-field H re-plant (crash at base+0x4b7d4b); upload-progress
  stores only ONE file entry, no controllable post-name allocation.
- Conclusion: needs a raw 8-byte arbitrary-value write.

### 15.2 OPcache type confusion — REJECTED (capacity wall)
- Measured: 1513 webroot scripts = 52.3/128 MiB opcache; needs ~3700
  scripts; the persist failure is a SHARED-MEMORY alloc failure, NOT a
  request memory_limit OOM → ordinary OOM requests cannot substitute.
- No unauth way to add thousands of unique PHP files.

### 15.3 Fatal-error backtrace — VERSION-GATED OUT
- 8.5-only field+INI; 8.3/8.4 "contain neither" (see rung 4 note).

### Comparison to our negative results

| their rejection | our corresponding wall | match? |
|---|---|---|
| var_push writes a zval slot, not a value; dtor clobbers planted data | SAME family: our destroy-gate/last_dtor work exists precisely because the dtor/var_destroy consumes planted state; our u2=2 dup-key write also lands slot-shaped data | MATCHES mechanism; they stopped at the value-shape wall, we engineered the destroy-gate to weaponize the clobber instead (phpbleed route) — a 3rd-party confirmation that the var_push primitive family is value-constrained |
| 326B session file → ps_read buffer lands at H and shifts geometry | our gotchas #7/#8/#9: raw-body pre-allocation + zend_string +0x18 header shift; same "carrier size determines buffer placement" physics | MATCHES |
| 5MiB carrier breaks a 64-slot groom → crash | our 128M oversized-carrier wall + "same-class fillers re-take the freed hole" (gotcha #7); symmetric-groom misses on arm64 (glm5: markers never appear at d) | MATCHES — both sides found carrier-size↔groom-position coupling |
| opcache SMEM persist ≠ request OOM | (we have no opcache-route notes — new info to us) | NEW-TO-US; closes off any opcache route on default WP without plugin-level script injection |
| 8.5 backtrace gate | n/a for us (no 8.5 lane) | NEW-TO-US; version-gates a future primitive |
| cross-request bleed | they do NOT document a cross-request stale-data bleed NEGATIVE — their whole chain IS cross-request residue by design (BG.data, PS(id), PS(serializer) persistence) | DIVERGES from our framing: we tested "cross-request bleed" as data-content bleed and got NEGATIVE; they never needed content bleed — only STRUCTURAL residue (globals). Consistent once distinguished: content-bleed NEGATIVE (ours), structure-residue POSITIVE (both). |

Verdict: their rejection surface CONFIRMS our walls (value-shape,
carrier-placement coupling) and adds two hard negative results we had
not measured (opcache capacity math; 8.5 version gate). The PG overwrite
rejection is the mirror image of our destroy-gate success: where they
hit the zval-slot value wall and stopped, our LOCK-0x1C/var_destroy
route weaponizes exactly the destruction path that blocked them.
