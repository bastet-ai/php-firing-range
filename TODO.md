# TODO - active work items

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

- [ ] 1. Extract this lane's libphp from the wordpress-x86 container
      (grep -r php_module /etc/apache2 gives the LoadModule path;
      docker cp it out) to lanes/race-618/glm3/bin/libphp-wp-x86.so.
- [ ] 2. Derive x86_64 php 8.2.34 offsets from THAT binary (derive, never
      hardcode): zend_call_function, zif_system/zif_readfile, .data.rel.ro
      zend_function_entry candidates. x86_64 deltas vs the glm3 aarch64
      notes: zend_internal_function handler@+88 (aarch64 +72),
      zend_fcall_info params@+48 (aarch64 +32).
      php_unserialize_data=8216, var_dtor_entries=4096 (arch-independent;
      confirm vs php-src 8.2/DWARF).
- [ ] 3. Port lanes/race-618/glm3/find_fake_func.py (aarch64-only) to
      x86_64: F = E-64 where E=&zend_function_entry with
      handler=bias+zif_readfile; requirements: type!=2, ZEND_ACC_STATIC in
      fn_flags, num_args>=1, by-value arg_info.
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
