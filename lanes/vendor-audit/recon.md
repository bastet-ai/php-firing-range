# recon.md — Rung 1: pipeline reconstruction of Percivalll/php2shell-wp

Static audit only (READ-ONLY, nothing executed). Source tree:
/home/user/vendor-audit/php2shell-wp @ main (907ceb5). All file:line refs
are against that tree. Cross-ref: their REPORT.md sections.

## 0. Target claim (per REPORT.md §0-§1)

wordpress:7.1.2 digest e04cf657…, PHP 8.3.35 NTS mod_php, Apache 2.4.68
prefork, StartServers 5 / MaxSpareServers 10 / MaxRequestWorkers 150,
memory_limit=128M, post_max_size=8M, max_input_vars=1000,
session.upload_progress.enabled=On, cleanup=On, use_strict_mode=Off,
opcache.enable=On. 9/9 fresh containers, 24-26s each, one ASLR gate
(`0x7c` byte in the fake-string pointer). All HTTP-only; no /proc, gdb,
or docker exec.

## 1. Orchestrator: run_ext.py (397 lines)

main() (run_ext.py:298-397) executes this exact sequence:

| # | step | tool | purpose | lines |
|---|---|---|---|---|
| 0 | pin | pin_adaptive.py (default) or pin_slow_pause.py --workers 150 | saturate all prefork workers with unfinished chunked POSTs, free exactly one | 130-171 |
| 1 | leak loop (≤12 attempts, in place, same worker) | big_a.py (fixed A_ARGS) then b_leak20.py LEAK=0x1000 | forge PS(id) len=0x1000 → 4KiB Set-Cookie OOB read → libphp base (votes over 16 known offsets + 4 fixed anchors) + ZendMM chunk (dominant 2MiB bucket) | 196-236 |
| 1b | derived | H = chunk + 0x6a000; str_off = first 0x100-aligned H+offset whose pointer bytes avoid 0x7C ('\|') | ASLR gate check happens HERE, pre-arm | 238-249 |
| 2 | rotate | big_a + b_leak20 LEAK=0x800000→0xC00000→0x1800000, 3 tries each | oversized OOB read walks into unmapped page → SIGSEGV kills the free worker; only "resp 0"/no status = success | 253-275 |
| 3 | producer-bigfn | stage_rce.py producer-bigfn (fresh worker!) | write /tmp/sess_r1big = 30MiB filename + 322B overhead; trailing 120MiB field OOMs AFTER session flush; bailout skips rfc1867 cleanup → file persists | 284-291 |
| 4 | producer-frame | stage_rce.py producer-frame | write /tmp/sess_trig2 (16,697B): key = 0x4000B fake zend_execute_data (num_args=1, arg1.value=H+str_off, arg1.type=IS_STRING); file must contain no '\|' | 277-283 |
| 5 | arm ×3 max | early_ok.py (producer: bgsid, 30MB key + 120MB → raises real_size, writes sess_bgsid) then arm_file2.py (trigger: 34MB big + 1MB dummy filename + progress + file part) | at FILE_START emalloc(0x2018)=H from dummy's freed page; 30MB key init OOMs mid-decode → bailout leaves BG.data=H, BG.level=1; **500 = success oracle**, 302 = retry after rotate | 293-301, 209-218 |
| 6 | R1 | stage_rce.py r1: PHPSESSID=r1big, progress=pwn, 38MB big, 64×0x2017 fake php_unserialize_data, file part | reads 30MiB sess_r1big (value-side OOM via filename), BG.data=H, level 2; var_push wrap-write N0 lands PS(serializer)=psg+0x148 = H+0x310 (fake serializer name; +0x318 encode=0; +0x320 decode=zif_system) | 168-178 |
| 7 | R2 | stage_rce.py r2: PHPSESSID=trig2, progress=pwn, 900×fake fields (re-plant H), file part | FILE_START ps_read(sess_trig2) → php_session_decode → PS(serializer)->decode(val) = zif_system(fake_execute_data) with arg1 = fake zend_string at H+str_off = shell cmd; proof written even if child dies | 180-189 |
| 8 | proof | raw GET /pwn.txt until "uid=" | | 277-296, 320-344 |

Key run_ext.py details:
- leak() comment (196-204): must leak BEFORE any request executing
  index.php (first A compile leaves op_array at ZendMM chunk head →
  the 4KiB window contains libphp opcode-handler pointers); retry IN
  PLACE (round 2-3), never rotate during leak; opcache-cached
  index.php zeroes the window permanently (their 4.4, verified logic
  at REPORT.md:§4.4).
- parse_leak() (44-119): base from page-aligned vote (min 4 votes)
  with fixed anchors at raw offsets 0x1A1048/0x1A3048/0x1AF000/0x1AF008;
  chunk = most-common (q & ~0x1FFFFF) 2MiB bucket; fallback 2MiB read
  supplies base but NOT chunk (chunk must come from the 4KiB window).
- rotate() (253-275): worker death verified ONLY by absence of a
  response ("resp 0" / "status \n" in b_leak20 output, run_ext.py:268);
  a 200 means survival → escalate read size. This is their "verifies
  that the previous child really died" mechanism — no /proc, purely
  in-band.
- A_ARGS (run_ext.py:23) drives big_a.py's groom: F=0 S=62 NB=235
  BL=255000 X=204 FL=103 PAD=0 … K2=280 K2L=4000 LATE=1 W64=1 CTPAD=10 …
  31 bin6 fillers + 62 g-fillers + 6 dups … 4000B ctype + 10×4000B
  header pads. Matches profiles.build_a() exactly.

## 2. Per-stage purpose summary (what state each step leaves)

| stage | leaves in worker / on disk |
|---|---|
| pin | 149 workers busy (each in mid-chunked-POST, 4KiB/s > mod_reqtimeout 500B/s min); 1 free worker = all attack traffic same child |
| A (big_a) | 500; stale PS(id)=\0-controlled string, PS(send_cookie)=1, SAPI header state dirty; op_array of index.php at chunk head (leak-enabling) |
| B (b_leak20) | 200; bin7 groom: 31×32B names + 63B value forging a zend_string over stale PS(id) slot 62 → PS(id).len=0x1000 → php_url_encode OOB 4096B into Set-Cookie |
| rotate | clean freshly-forked worker (real_size reset), same chunk base per fork (prefork inherit) |
| producer-bigfn | /tmp/sess_r1big 31,457,602B (30MiB filename + a:1 serialization) |
| producer-frame | /tmp/sess_trig2 16,697B (fake zend_execute_data via 0x4000 progress key) |
| arm | BG(unserialize).data=H (emalloc(0x2018) reclaimed from dummy's freed 1MiB-filename buffer page), BG.level=1 |
| R1 | BG.level=2; PS(serializer)=H+0x310 (fake name=0, encode=0, decode=zif_system) via var_push 64-bit-wrap write |
| R2 | zif_system(fake frame) → system(cmd) as www-data; proof to webroot |

## 3. Mechanism notes relevant to later rungs (rung 2-6 preview)

- Chunked POST bypasses post_max_size=8M entirely for multipart (no
  Content-Length → rfc1867 skips the check; REPORT §5.1). Their 120-150MB
  bodies ride on this. [rung 3]
- Pin is rate-hardened: mod_reqtimeout body=10,minrate=500 forced the
  4KiB/s keepalive (pin_adaptive.py:16-21, REPORT §3). Adaptive mode
  discovers the worker count by probing (GET /readme.html) and frees
  exactly one by closing pins tail-first until a probe succeeds
  (pin_adaptive.py:82-94). [rung 3]
- Leak is a single-stage in-band 4096B read: needs NO session-file
  staging, NO second request to resolve (unlike our N-oracle which
  needs precise regrooming and returns qwords one at a time). But it
  needs the bin7 slot-62 groom (31 names) and one prior A request on
  the same worker. [rung 2]
- R1's PS(serializer) write is a wrap-around index into the fake
  var_entries.data: N0 = (psg+0x148-(H+0x200)-0x10)//8, negative →
  wraps; the written value is a *pointer* (H+0x310) — same
  var_push-primitive family as our forged fcall_info chain. [rung 4]
- ASLR gate = 0x7C byte appearing in every H+0x100k candidate
  (choose_str_off, run_ext.py:238-249); fresh container is the fix —
  implies per-process (not fork-uniform) entropy in at least some byte.
  [rung 6]

## 4. Discrepancies/questions to carry forward

- run_ext.py A uses big_a.py with A_ARGS while profiles.build_a()
  duplicates the same groom — profiles.py appears to be the older
  monolithic path (REPORT §4 calls it "profiles.send_a"); poc.py is
  described in REPORT as "legacy" helpers. Consistent, but R1 "r1"
  cmd in stage_rce.py:168-178 vs REPORT §7 table: 38MB big + 64 fake
  fields — matches.
- R2 uses 900 fake fields (stage_rce.py:180-189) vs REPORT §8 "900 fake
  fields" — matches; but r2's fake includes the fake zend_string at
  H+str_off while R1's fake_r1 leaves +0x310..+0x328 = serializer
  struct. In R2 the SAME +0x310 region is re-planted (fake_r2 = fake_r1
  + string) — the serializer must be re-written by R2's own 900 fields
  because R1's are freed/lost? Verify in rung 4 whether PS(serializer)
  persists across R1→R2 or R2 re-establishes it (BG.level=2 after R1
  suggests persistence; R2's re-plant is belt-and-braces).
- Their "chunk" (2MiB ZendMM region) is fork-stable; H=chunk+0x6a000
  is deterministic for the image build (REPORT §4.3 tables).
