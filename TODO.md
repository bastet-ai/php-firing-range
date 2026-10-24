# TODO - active work items (single authoritative version, 2026-10-23 final)

## TWO BOXES - read this first

There are TWO independent machines sharing this repo:

1. THE ARM64 RANGE BOX (aarch64 host): the original firing range.
   Its wordpress lane (:8099 there) runs NATIVE AARCH64 php 8.2.34.
   ACTIVE AGENT: GLM-5.3 in tmux session race-glm4; its running state is
   lanes/race-618/glm4/notes.md + fires.log. Do NOT compete on their lane.
2. THE X86_64 BOX (this machine, x86_64 host): separate Docker containers,
   separate WordPress lane (:8099 here). No live agent competes here.

All x86_64-box notes below assume work on THIS machine. Offsets and heap
geometry are PER-BOX (derive, never hardcode). NEVER pin `platform:` on
shared compose services (breaks the other box; bit us 2026-10-22).

## PROVEN CAPABILITIES ON THIS BOX (x86_64, WP 7.1.2, php 8.2.34 pre-patch)

Each of these is a WORKING, DEMONSTRATED capability with committed evidence:

### 1. Memory disclosure from vanilla WP via HTTP (MILESTONE - proven)
```
python3 phpbleed-bastet.py wpdump http://127.0.0.1:8099/ --rounds 3
```
- Producer (unauth multipart + staged session file): in-band OOM fatal.
- Walk oracle (HTTP-only, R:n self-resolve): discriminates stale children.
- Full 2MB Zend heap-chunk dump: pointer census (5337 heap-self, 319
  libphp/PIE), live IS_STRING zvals dereferenced in-place (WP DB-error
  zvals, mysqli errors, theme block markup, extension paths).

### 2. Arbitrary-qword read via the N-oracle (MILESTONE - proven)
- Target `basic_globals+0x350` -> N = the serving child's live
  BG(unserialize).data pointer, delivered IN-BAND.
- Self-bootstrapping (the oracle's output = the true d for precise regrooming).
- Script: scripts/a3_symmetric.py (symmetric groom), scripts/a2_groom_v2.py.

### 3. Secrets dumped from the target process (MILESTONE - proven)
- The 32-char WP DB password recovered VERBATIM over HTTP:
  `e3027252836fa6edcae1f6261b5a2c9c` (== .env WORDPRESS_DB_PASSWORD).
- Method: N-oracle + staggered reads (page-rounded N yields bytes T+2..T+7;
  offsets -2/+4/+10/+16/+22/+24 tile the secret).
- Target = the fork-uniform immutable ENV BLOCK address (timing-free).
- Generalizes to ANY env var / stack secret / pointer-chain qword.

### 4. RCE via the phpbleed forged dispatch (BUILT, one calibration left)
- The groom = the session file ITSELF (the ps_read buffer covers d's page;
  fake-d at the exact file offset; no heap marching, no multipart groom).
- The destroy gate: dup-key u2=2 write lands on BG(serialize_lock) via
  last_dtor = LOCK-0x1C -> var_destroy runs unconditionally (source-verified
  at php_var_unserialize_destroy).
- The dtor route: data[0] u2=2 -> Z_OBJCE_P(zv) -> ce->__unserialize ->
  zend_call_known_function (disasm-verified at 0x3ec177/0x3ec17b).
- Fake function: E=0xf26860 (.data.rel.ro), F=E-64=0xf26820, handler@F+72
  = relocated zif_highlight_file, type 218&3=2!=ZEND_USER_FUNCTION -> internal
  dispatch, send_mode 0 (by-value).
- The param: fake zend_string "/CANARY" (refcount 5) as data[1].
- REMAINING: the session-buffer's page in the receiving child's map is
  PER-CHILD (measured via crash-time gdb find). Next: per-fire gdb-find
  calibration loop or oversized carrier forcing the buffer to cover d.

### 5. php2shell-bastet.py 618 chain on WP (CORRECTED, groom needs tuning)
- x86_64 fcall_info offsets FIXED from php-src 8.2 headers:
  off_params=32 (was 48), off_param_count=48 (new), off_handler=64+72=136
  (was 64+88=152; handler@+72 confirmed by execute_internal + struct count).
- ZEND_INTERNAL_FUNCTION=1 confirmed from zend_compile.h (not 2).
- --bias flag added (WP has no ?probe=all oracle).
- --progress-len flag added (vendor's 1MB PROGRESS OOM trigger).
- APACHE-LEVEL memory_limit staging DISCOVERED: conf.d ini files do NOT
  reach the Apache mod_php workers on the WP Docker image (WP overrides via
  WP_MEMORY_LIMIT). Fix: `php_admin_value memory_limit 2M` in
  /etc/apache2/conf-available/zz-2m.conf + a2enconf + apache2ctl graceful.
- OOM trigger positions mapped:
  - 1MB PROGRESS value -> OOM during the value copy (TOO EARLY; kills the
    request before the file/t[] parts are parsed).
  - Small "x" value -> rfc1867 completes all parts, WP then OOMs (593B
    dual-fatal). The multipart IS fully processed.
- REMAINING: the 618 two-update groom (stall + t[] reclaim of the freed
  progress HashTable arData) doesn't produce execution on the WP heap
  geometry (n_groom 1-350 all miss; vendor needs per-target heap tuning).
  NEXT: gdb bp on php_session_rfc1867_update + dump the freed HashTable's
  size/bin + t[] string landing positions; retune blob/n_groom.

## RANGE STATE (this box)

Services up: phpbleed:8088, bleed82:8089, bleedsrv:8092, bleednoaslr:8097,
phpinfo:8093, t4a:8098, t4b:8096, shakedown:8181, php83:8083 (PATCHED 8.3.36!),
php82:8082, php81:8091, php56:8056, wordpress-patched:8100 (8.2.35),
wordpress-x86:8099 (7.1.2, 8.2.34 pre-patch, STOCK INIs),
wordpress-x86-83:8101 (7.1.2, 8.3.35 pre-patch), wpdb-x86 (mysql:8.0,
NO platform pin - each box runs host-native).

WordPress-x86 (:8099): INSTALLED (admin: rangeadmin / r4nge-lab-pw,
DB: e3027252836fa6edcae1f6261b5a2c9c, host: wpdb-x86, db: wp).
Canary: FLAG{wordpress-x86:...} in /CANARY inside the container.
WordPress-patched (:8100): 8.2.35 = PATCHED (negative-control lane).
WordPress-x86-83 (:8101): 8.3.35 pre-patch (corrupt-token lane).

## CRITICAL GOTCHAS (all bit us - do not repeat)

1. NEVER pin `platform:` on shared compose services (breaks the other box).
2. NEVER let a floating php tag roll (our php83 silently went to 8.3.36
   PATCHED; pin exact versions for vulnerable lanes).
3. Hand-written `s:N` tokens MUST match length (bit us twice; generate all
   serialized data programmatically).
4. Session-format validation must use the SESSION format (`name|value`), not
   plain `unserialize()`.
5. The WP Docker image: conf.d ini files DON'T reach Apache mod_php workers
   (WP overrides memory_limit via WP_MEMORY_LIMIT). Use Apache-level
   php_admin_value instead.
6. The freed d chunk is emalloc_large class (dedicated 2MB region), NOT the
   main heap. The session-file groom carrier sidesteps this entirely.
7. Same-class fillers make the groom re-take the freed bottom hole forever;
   filler class MUST be smaller than the groom class (2-page fillers,
   3-page groom).
8. The raw-body temp buffer (pow2-doubling zend_string) pre-allocates
   before any part parses - shifts all march models that ignore it.
9. The session-buffer's zend_string header (+0x18 data offset) shifts all
   file-offset calculations (back out the s:%d:" header AND the +0x18).
10. The s:%d:" header length varies with the padding size - compute it
    from the actual format string, not a constant.
11. MySQL: use --skip-name-resolve (reverse-DNS adds a flat 5s to every
    fresh WP db connection and eats the Apache KeepAliveTimeout window).

## TOOLS AND SCRIPTS

### Main tools
- `phpbleed-bastet.py` - dump/probe/canary/id/rce/shell/wpdump/wpprofile
  (the var_hash UAF gadget lanes :8088/:8089/:8092/:8097)
- `php2shell-bastet.py` - the 618 two-update groom chain
  (see its OWN gotchas above)

### x86_64 WordPress-lane scripts (all in scripts/)
- `wpbleed.py` - wpdump engine (producer + walk oracle + heap dump)
- `wpfire.py` - honest-transport harness (wpdump uses it)
- `a2_leak_collect.py` - leak-first (d + bias via /proc helper)
- `a2_groom_probe.py` - placement probe (read freed d content)
- `a2_groom_placement.py` - groom carrier shapes (name8k/value8k/fname8k)
- `a2_groom_roundtrip.py` - R:n self-resolve walk oracle (v2 grooming)
- `a2_groom_v2.py` - filler-class marching groom
- `a3_noracle.py` - N-oracle: arbitrary-qword read via the encode append
- `a3_groom_v3.py` - map-calibrated groom + N-oracle
- `a3_symmetric.py` - the symmetric groom (vendor's design implemented)
- `a1_disclosure_run.py` - A1 disclosure matrix (4-lane control)
- `cross_lane_probe.py` - cross-lane OOM/corruption comparison

### Scoring
- `scripts/score.sh` - provenance-checked canary scoring
  (--canary evaluator-file, --request for anti-echo, --mode disclosure|exec)

### Research/lane notes
- `lanes/race-618/WP-X86-NOTES.md` - the x86_64 WP lane's full experiment log
- `lanes/race-618/glm4-x64/notes.md` - x86_64 offset derivations
- `lanes/race-618/glm4/notes.md` - arm64 lane design (active agent's state)
- `lanes/race-618/glm3/notes.md` - original chain design (aarch64)
- `research/phpbleed/VENDOR-CLAIM-MAP.md` - what the vendor claims vs proven
- `lanes/race-618/WP-LAST-MILE-BRIEF.md` - older brief (superseded by TODO)

## NEXT ACTIONS (priority order)

1. RCE final mile (phpbleed chain): per-fire gdb-find calibration loop
   for the session-buffer position (the only remaining variable).
   OR: oversized carrier forcing the buffer to cover d regardless of map.
2. php2shell 618 groom tuning: gdb bp on php_session_rfc1867_update +
   dump the freed HashTable size/bin + t[] string landing positions.
3. Fully-remote calibration (no /proc): oracle-pointed sweeps for the
   bias and env-block locator (currently assisted via the ptrace helper).
4. Fully-remote injection (no session-file staging): the pre-auth session
   write path (vendor's phpMyAdmin route on stock WP = still open).
5. HashTable POST-registration interruption (bounded investigation).

## PROCESS RULES (hard)

- Loopback-only on both boxes; vendor bundle stays unexecuted.
- Commit + push after EVERY task; rebase when push is rejected.
- timeout 20 on EVERY shell-out; never SIGSTOP-pin before staging.
- Log every fire with timestamp + signature; append findings to the
  relevant notes.md as you go.
- One exploit stream per target (the tooling takes a flock).
- Scoring: scripts/score.sh with --canary evaluator-file + --request
  for anti-echo verification + evidence archive with sha256.
- NEVER pin platform: on shared compose services.
- NEVER let a floating php tag roll a vulnerable lane.
- Time-box long turns; write files in chunks and iterate.

## VA (vendor-audit) next actions — GLM6, from Percivalll static audit (24-Oct)

(Analyses + sketches: lanes/vendor-audit/{notes,recon,adaptations}.md;
claim map: research/phpbleed/VENDOR-CLAIM-MAP.md §Percivalll.)

1. Implement + fire scripts/va_pin.py (adaptive chunked-POST pin,
   adaptations.md #1) on :8088/:8089, then re-run the cb-B under-load
   matrix (glm5 loadprobe shape): expect N/N delivery vs 0/15 baseline.
2. Port the stale-PS(id) Set-Cookie OOB leak (va_leak.py,
   adaptations.md #2) with OUR per-build anchors; goal: fully-remote
   bootstrap replacing the /proc-assisted bias discovery (priority 3
   above); verify base+chunk on 8.2.34 x86.
3. Derive OUR PS(serializer) field offset on 8.2.34 (disasm
   php_session_decode on wordpress-x86 libphp.so; their +0x148 is
   8.3.35) — unblocks the serializer plan-B route if the phpbleed
   last-mile calibration fails again.
4. Compose target action (do NOT build until authorized): new lane
   `wordpress-712-83` from image wordpress:7.1.2 digest
   sha256:e04cf657f24889e96b5544828cdd5a92a0b51819f3e1899183f9be6ea0485edf
   (PHP 8.3.35, matches the audited target EXACTLY; loopback-only
   published port, NO platform pin, separate mysql service with
   --skip-name-resolve) — needed for a faithful live-fire comparison
   of the vendor chain after orchestrator authorization.
5. Direct lane test of the chunked-TE post_max_size bypass on an 8M
   stock lane (150MB multipart via Transfer-Encoding: chunked, no
   Content-Length) — cheap, closes a claim-map UNVERIFIED row.
