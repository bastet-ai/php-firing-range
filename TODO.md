# TODO - active work items

## STATUS 2026-10-22 01:4xZ (handoff checkpoint - read this first)

ACTIVE AGENT: GLM-5.3 live in tmux session race-glm4 (cwd repo root);
its authoritative running state is lanes/race-618/glm4/notes.md and its
fires.log. It is mid-checkbox-4, iterating groom placement (~1 fire/
round, every round committed). Do NOT start a competing lane on :8099
while it runs; to take over instead: /process-style kill the tmux
session, then resume it via lanes/race-618/GLM5-BRIEF.md (revival brief;
notes.md is the state source of truth).

LADDER STATUS:
- [x] cb1 libphp extracted (bin/libphp-wp-x86.so, md5-verified).
      ARCH CORRECTION (64a197a): the lane runs NATIVE AARCH64 php 8.2.34
      (no platform pin possible on this arm64 host) - all x86_64 framing
      below is obsolete: use aarch64 offsets (handler@+72, params@+32),
      glm3's find_fake_func.py applies UNPORTED.
- [x] cb2/cb3 offsets + fake-func candidates derived from the lane binary
      (2ea47de). RELRO kills glm3's static-L self-write -> groom-ce
      adaptation; readfile cand is by-ref-only -> highlight_file chosen.
- [ ] cb4 IN PROGRESS (the last hard problem). Proven this session:
      producer OOM at pure stock INIs on pinned child; placement oracle
      works: BG(unserialize).data at basic_globals+816 (disassembly-
      confirmed), level=1, bias from host-root /proc maps. Placement
      root-causes found the hard way: freed filler coalesces + WP render
      erases page-1 copies (b66e221); body fully buffered pre-parse
      (+102 pages, d031612); CURRENT design fd3510b = symmetric
      24576B fields (F*16384 + [X-dummy|groom]) landing groom at
      run+4pages == producer d (best-fit 3-page leftover); dbgcrash.py
      breakpoint/full-scan mode VERIFIES actual groom placement
      instead of assuming it. Every consumer fire still returns len=6
      FLAG=None - groom not yet consumed. Remaining delta = making the
      symmetric run actually reuse (dbg scan tells you where copies
      really land; tune F and the leftover).
- [ ] cb5 token stream: designed in glm4/notes.md (dup-key ->
      var_push_dtor -> fake var_dtor_entries -> Exception-wakeup write
      lands u2=1 on BG(unserialize).level fixing level-1 unreachability;
      child ends clean). Unverified live.
- [ ] cb6 win: highlight_file("/CANARY") in-band -> score.sh.

LAB HANDS (verified): docker exec -u root for staging/pinning (host kill
NOT permitted); host root CAN read /proc/<child>/maps for bias. HARD
RULES the live lane died on: timeout 20 every shell-out; never SIGSTOP-
pin before exec staging is done (46-min deadlock, see d4c38f1 notes).

## ACTIVE: wordpress-x86 last mile (CVE-2026-109618/619 -> RCE on stock WP 7.1.2)

Handoff for the next agent (this brief is authoritative). Authorized firing
range, loopback Docker only - 127.0.0.1 targets; the tooling refuses
anything else. Never execute the vendor's downloadable bundle
(research/fuzz/LOG.md); re-derive from written mechanics.

Read first: README.md, HOWTO-RANGE.md, lanes/race-618/WP-X86-NOTES.md,
lanes/race-618/glm3/notes.md + GLM3-BRIEF.md (chain design; their symbols
are the AARCH64 php83 binary - derive yours, never hardcode),
research/phpbleed/VENDOR-CLAIM-MAP.md.

### Current state (do NOT redo these)

- wordpress-x86 (:8099) = stock WP 7.1.2 (installed; admin rangeadmin /
  r4nge-lab-pw) on PINNED PRE-PATCH php 8.2.34, PURE stock INIs
  (memory_limit=128M, post_max_size=8M, session.upload_progress=On).
  Canary: /CANARY inside the container (FLAG{wordpress-x86:...}).
- PROVEN producer (pure stock INIs, pre-auth, ~0.1s, deterministic on
  fresh children): stage /tmp/sess_<SID> in-container as root (chown
  www-data, 600) containing
    poc|a:2:{i:0;s:3:"abc";i:1;s:72000000:"<72MB of A>";}
  then ONE multipart POST / (PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + a
  file part) -> in-band:
    Fatal error: Allowed memory size of 134217728 bytes exhausted
    (tried to allocate 72000032 bytes) in Unknown on line 0
    Warning: PHP Request Startup: Failed to decode session object.
    Session has been destroyed
  Element 0 builds var_hash entries; element 1's alloc crosses 128M
  mid-decode -> BG(unserialize) stale; its 8216B data chunk freed at
  request shutdown.
- PROVEN consumer engagement: a second decode-bearing request on the SAME
  child (keep-alive) SEGFAULTS workers at 4/6 (unshaped consumption; the
  state compounds across the child pool).
- Session files are REWRITTEN (to empty) by each fire's shutdown flush:
  use a PRISTINE file per request round (fresh SID); clean /tmp/sess_*.
- Dead ends already paid for:
  - DB route via maybe_unserialize on a poisoned option: fetch OOMs at
    class-wpdb.php:2324 for all S (3 copies in flight). Dead at 128M.
  - Bogus-length tokens (s:HUGE:"x") rejected pre-alloc by core; the
    payload needs REAL data with 2*S + pre-RINIT base > 128M (72M works;
    65M does NOT - slow write-back path that hangs).
  - mysql reverse-DNS penalty: already fixed (--skip-name-resolve on
    wpdb-x86).

### The ladder (turn the 4/6 crash into deterministic execution)

Route B (glm3 design) mapped onto this lane; their P3 content problem is
GONE here - the token stream is fully controlled via the staged session
file.

- [x] 1. Extract this lane's libphp from the wordpress-x86 container
      DONE (glm4): lanes/race-618/glm3/bin/libphp-wp-x86.so, md5-verified
      vs container copy. NOTE: binary is aarch64 (lane was NEVER x86_64 -
      no platform pin on an aarch64 host); see glm4/notes.md + WP-X86-NOTES
      ARCH CORRECTION.
- [x] 2. Derive offsets DONE (glm4/notes.md): all symbols + candidate
      fake funcs derived from THIS binary. DIVERGENCE FOUND: GNU_RELRO
      covers all .data.rel.ro → glm3 static-L self-write (W+352) is
      read-only here; adaptation = ce chain (V,C) in the groom. tmp_var
      reuse path does NOT set first_dtor → groom sets first_dtor=last_dtor=L.
- [x] 3. Port find_fake_func.py aarch64->x86_64: MOOT (binary is aarch64).
      glm3 find_fake_func.py used as-is + new glm4/eval_fake_func.py
      (post-reloc candidate evaluator). Best candidates:
      highlight_file (send-mode 0), readfile (send-mode 1, PREF ok).
- [ ] 4. Consumer groom: multipart field NAME ~8193B (estrdup -> raw
      alloc -> 17-page zend-mm class) reclaiming the freed 8216B chunk
      with a FAKE php_unserialize_data (last=L2 bss VA, first_dtor=NULL,
      last_dtor=L static, used_slots=0, max_depth=100). Tune preamble
      field sizes; placement oracle = response signature (clean fatal vs
      child-crash vs weird allocs). Raw-socket keep-alive pattern per
      WP-X86-NOTES; Apache KeepAliveTimeout=5s - keep mid-pair pauses
      under 5s.
- [ ] 5. Token stream (the session file, fully yours): duplicate keys
      inside a:N:{...} so old values get var_push_dtor_value'd into the
      FAKE var_dtor_entries at L -> data[0]={F,0x104,2}, data[1]={&zstr
      "/CANARY",0x106,0} -> var_destroy walks first_dtor=L ->
      __unserialize route -> zend_call_known_instance_method(
      ce->__unserialize=F, obj=F, NULL, &param); self-consistent
      L=W+336 dual-purpose write (glm3 notes steps 4-8).
- [ ] 6. Win: zif_readfile("/CANARY") IN-BAND in the response body ->
      extract FLAG{wordpress-x86:...} -> verify: docker compose exec
      wordpress-x86 cat /CANARY -> record: scripts/score.sh wordpress-x86
      <evidence-file>.

### Rules / process (hard)

- Loopback-only. The vendor bundle stays unexecuted.
- Commit + push after EVERY task (a second lane pushes to the same
  master; rebase when push is rejected):
  git add <files> && git commit -m "wp-lastmile: <what>" && git push origin master
- Log every fire (timestamp + signature) glm3/fires.log-style; append
  findings to WP-X86-NOTES.md as you go.
- The lane stays stock WP + pinned 8.2.34; if you touch
  Dockerfile/compose, rebuild and re-assert php -v and stock INIs.
- Stale state pollution: docker compose restart wordpress-x86 clears all
  children when behavior goes weird.
- Time-box long turns; write files in chunks and iterate.

Success = the FLAG returned in-band from an unauthenticated two-request
sequence on stock WP 7.1.2, scored via scripts/score.sh. The chain design
is believed sound; remaining risk is groom-placement determinism on
x86_64 mod_php.

## Backlog (lower priority, from research/phpbleed/VENDOR-CLAIM-MAP.md)

- [ ] HashTable POST-registration interruption (_zend_hash_str_add_or_
      update_i count-vs-skipped-assignments; plain root[x]=v + memory
      pressure on a mod_php lane) - new-to-us vendor claim, untested.
- [ ] 618 corrupt-token persistence at 128M: shape whose shutdown
      re-encode fits while the first encode OOMs, or declare unreachable.
- [ ] t4a stock-SPL shaping (ASan-instrumented t4a per PLAN NEXT note).
- [ ] php2shell-bastet.py last-mile runs vs production php83 (glm lane
      context; note glm3 pushed design notes + fake-func finder).
