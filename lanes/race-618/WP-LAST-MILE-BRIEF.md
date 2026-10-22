# Lane brief: wordpress-x86 last mile (CVE-2026-109618/619 -> RCE on stock WP 7.1.2)

Handoff prompt for the next agent. Repo: php-firing-range (this directory).
Authorized firing range, loopback Docker only - hard rule: 127.0.0.1 targets
only; the tools hard-refuse anything else. Never execute the vendor's
downloadable bundle (research/fuzz/LOG.md); re-derive from written mechanics.

Read first, in order:
1. README.md (rules of engagement, scorecard)
2. HOWTO-RANGE.md (range ops + gotchas)
3. lanes/race-618/WP-X86-NOTES.md (this lane's full findings, all experiments)
4. lanes/race-618/glm3/notes.md + GLM3-BRIEF.md (the chain design; their
   symbols are for the AARCH64 php83 binary - derive yours, never hardcode)
5. research/phpbleed/VENDOR-CLAIM-MAP.md (vendor claims vs what we proved)

## Current state (do NOT redo these)

- Range: scripts/range-up.sh brings everything up; wordpress-x86 (:8099) =
  stock WP 7.1.2 (installed; admin rangeadmin / r4nge-lab-pw) on PINNED
  PRE-PATCH php 8.2.34, PURE stock INIs (memory_limit=128M,
  post_max_size=8M, session.upload_progress=On). Canary: /CANARY inside
  the container (FLAG{wordpress-x86:...}). Sanity after any rebuild:
  docker compose exec wordpress-x86 php -v  (=8.2.34) and php -i limits.
- PROVEN producer (pure stock INIs, pre-auth, ~0.1s, deterministic on
  fresh children): stage a session file in-container as root:
    SID=<32 chars>; F=/tmp/sess_$SID
    printf 'poc|a:2:{i:0;s:3:"abc";i:1;s:72000000:"' > $F
    head -c 72000000 /dev/zero | tr "\0" "A" >> $F
    printf '";}' >> $F; chown www-data:www-data $F; chmod 600 $F
  then ONE multipart POST / with parts: PHPSESSID=<SID>,
  PHP_SESSION_UPLOAD_PROGRESS=poc, and a file part (any filename).
  In-band result:
    Fatal error: Allowed memory size of 134217728 bytes exhausted
    (tried to allocate 72000032 bytes) in Unknown on line 0
    Warning: PHP Request Startup: Failed to decode session object.
    Session has been destroyed
  Mechanics: element 0 builds var_hash entries; element 1's alloc crosses
  128M mid-decode -> PHP_VAR_UNSERIALIZE_DESTROY skipped ->
  BG(unserialize) stale; its 8216B data chunk is freed at request shutdown.
- PROVEN consumer engagement: a second decode-bearing request on the SAME
  child (keep-alive) SEGFAULTS workers at 4/6 (unshaped wild-pointer
  consumption; compounds across the child pool - pairs landing on
  already-poisoned children crash on their first request).
- Session files are REWRITTEN (to empty) by each fire's shutdown flush:
  use a PRISTINE file per request round (fresh SID), and clean
  /tmp/sess_* between rounds.
- Dead ends already paid for: (a) DB route via maybe_unserialize on a
  poisoned option - fetch OOMs at class-wpdb.php:2324 for all S (3 copies
  in flight); (b) bogus-length tokens (s:HUGE:"x") are rejected pre-alloc
  by core - the payload needs REAL data sized to cross; S must satisfy
  2*S + pre-RINIT base > 128M (72M works; 65M does NOT - it takes the
  slow write-back path and hangs); (c) mysql reverse-DNS penalty - already
  fixed with --skip-name-resolve on wpdb-x86.

## Your job: turn the 4/6 crash into deterministic execution

Route B (glm3 design) mapped onto this lane; their P3 content problem is
GONE here - the token stream is fully controlled via the staged session
file. Ladder:

1. Extract this lane's libphp (the mod_php binary in the wordpress-x86
   container): find the LoadModule path via
   grep -r php_module /etc/apache2  then docker cp it out; park it at
   lanes/race-618/glm3/bin/libphp-wp-x86.so next to the aarch64 one.
2. Derive x86_64 php 8.2.34 symbols/offsets from THAT binary (derive,
   never hardcode): zend_call_function, zif_system / zif_readfile (local
   syms), .data.rel.ro zend_function_entry candidates. x86_64 layout
   deltas vs the glm3 aarch64 notes: zend_internal_function handler@+88
   (aarch64 +72), zend_fcall_info params@+48 (aarch64 +32).
   php_unserialize_data / var_entries / var_dtor_entries sizes are
   arch-independent (zval=16B): data=8216, dtor_entries=4096 - confirm
   against php-src 8.2 or DWARF before use.
3. Adapt lanes/race-618/glm3/find_fake_func.py (aarch64-only today) to
   x86_64: F = E-64 where E=&zend_function_entry in .data.rel.ro with
   handler = bias+zif_readfile; requirements: type!=2, ZEND_ACC_STATIC in
   fn_flags, num_args>=1, by-value arg_info bits.
4. Consumer groom: multipart field NAME ~8193B (estrdup -> raw alloc ->
   17-page zend-mm class) reclaiming the freed 8216B chunk with a FAKE
   php_unserialize_data (last=L2 bss VA, first_dtor=NULL, last_dtor=L
   static, entries.used_slots=0, max_depth=100). Placement tuning: tune
   preamble field sizes; your placement oracle is the response signature
   (fresh-child clean fatal vs child-crash vs weird alloc sizes). Use the
   raw-socket keep-alive pattern from WP-X86-NOTES; Apache
   KeepAliveTimeout=5s, so keep mid-pair pauses under 5s.
5. Token stream (the session file, fully yours): duplicate keys inside
   a:N:{...} so old values get var_push_dtor_value'd into the FAKE
   var_dtor_entries at L -> data[0]={F,0x104,2} (u2.next==2 via key-hash
   collisions), data[1]={&zstr "/CANARY",0x106,0} -> var_destroy walks
   first_dtor=L -> __unserialize route ->
   zend_call_known_instance_method(ce->__unserialize=F, obj=F, NULL,
   &param) - the self-consistent L=W+336 dual-purpose write (glm3 notes
   steps 4-8 spell it out).
6. Win: zif_readfile("/CANARY") output IN-BAND in the response body ->
   extract FLAG{wordpress-x86:...} -> independent verify: docker compose
   exec wordpress-x86 cat /CANARY -> record: scripts/score.sh
   wordpress-x86 <evidence-file>.

## Rules / process (hard)

- Loopback-only. The vendor bundle stays unexecuted.
- Commit + push after EVERY task (second active lane pushes to the same
  master; rebase when push is rejected):
    git add <files> && git commit -m "wp-lastmile: <what>" && git push origin master
- Log every fire (timestamps + signatures) to lanes/race-618/glm3/fires.log
  style; append findings to WP-X86-NOTES.md as you go.
- The lane must stay stock WP + pinned 8.2.34; if you must touch the
  Dockerfile/compose, rebuild and re-assert php -v and stock INIs.
- Stale state pollution: if behavior goes weird, docker compose restart
  wordpress-x86 clears all children.
- Time-box long turns; write files in chunks and iterate.

Success = the FLAG returned in-band from an unauthenticated two-request
sequence on stock WP 7.1.2, scored via scripts/score.sh. The chain design
is believed sound; remaining risk is groom-placement determinism on
x86_64 mod_php.
