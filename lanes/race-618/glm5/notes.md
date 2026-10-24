# GLM5-ToB lane notes (started 24-Oct)
- brief: lanes/race-618/GLM5-TOB-BRIEF.md
- host note: arm64 box; new-target matrix work only (:8102+); glm4 owns :8099.
- HOST MEM at dispatch: 108/119G used, 10G avail -> check free -g before each new container; vllm-fn + gitlab-vuln + QEMU VM are the big co-tenants; if <4G avail, ask orchestrator before tearing anything.

## cb-C BUILD (24-Oct): nginx/php-fpm-as-root lane LIVE :8102/:8103
- range/wpfpm/{Dockerfile,nginx.Dockerfile,wpfpm-nginx.conf}; compose: wpfpm (php:8.2.34-fpm TAG-pinned pre-patch, NO platform pin, host-native arm64), wpfpm-nginx (nginx:stable front), wpdb-fpm (dedicated mysql:8.0 - wpdb-x86 root pw unavailable and wp user can't CREATE; separate container keeps race-glm4's DB untouched).
- GOTCHA (new): php-fpm REFUSES pool user=root unless CMD ["php-fpm","--allow-to-run-as-root"] - fixed in Dockerfile.
- GOTCHA (new): nginx caches the fpm upstream IP across fpm rebuilds -> 502 after rebuild; docker compose restart wpfpm-nginx fixes.
- VERIFIED: php -v 8.2.34; memory_limit=128M; display_errors=Off (stock php.ini-production copied); session.upload_progress.enabled=1; pool user=root; WP 7.1.2 stock core installed over HTTP (install.php step2 -> Success), home 200.
- Next: cb-D matrix (:8104 MW, :8105 phpBB), then cb-A revalidation ON THESE NEW TARGETS (:8103 stock 128M - :8099 is glm4's).

## cb-D BUILD (24-Oct): app-matrix lane LIVE :8104/:8105
- range/mw: MediaWiki 1.42 (core UNMODIFIED, COPY --from=mediawiki:1.42) on php:8.2.34-apache pre-patch + mbstring/intl/xml via mlocati installer (MW 500s blank without them - php base ships none; logged gotcha). Stock php.ini-production (128M, display_errors=Off, upload_progress=1). CLI-installed (maintenance/install.php --dbserver wpdb-fpm --dbname mw; NOTE: admin user is a POSITIONAL arg, --admin is rejected). api.php 200, wiki functional.
- range/phpbb: phpBB 3.3.16 official tarball on php:8.2.34-apache pre-patch, same stock production INI; /phpBB3/index.php 302 (install wizard pending - optional; bug is in PHP, not app).
- GOTCHA (new): phpbb.com Cloudflare 403s Docker's ADD http client but allows curl GET -> tarball vendored into build context (range/phpbb/phpBB-3.3.16.tar.bz2).
- wpdb-fpm now carries wp_fpm/mw/phpbb schemas; grants added via fresh-container root pw from logs (GRANT ... IDENTIFIED BY is gone in mysql 8 - grant existing wp user directly).

## cb-A/cb-C/cb-D FIRING RESULTS (24-Oct, lanes/race-618/glm5/matrixbleed.py)
- Targets (all NEW, all stock php.ini-production: memory_limit=128M, display_errors=Off, upload_progress=1; php 8.2.34 pre-patch, host-native arm64):
  - mediawiki :8104 (MW 1.42, CLI-installed): producer OOM MATCHED (tried to allocate 75000032, fatal in container log - display_errors=Off so in-band is gone; log-side detection added to harness) + walk oracle DELIVERED round 1 (stale child picked up; R:14 token round-tripped intact). => ToB matrix headline MATCHED on MediaWiki.
  - phpbb :8105 (phpBB 3.3.16, wizard uninstalled - irrelevant, rfc1867 is pre-script): producer OOM MATCHED + walk DELIVERED round 2. => MATCHED on phpBB.
  - wp-fpm lane :8103 (nginx/1.30.6 -> php-fpm pool-as-root): producer OOM MATCHED (75000032 at stock 128M; 502 to the client) BUT stale-global persistence NOT-MATCHED: every OOM fatal EXITS the fpm child ("child NNNN exited with code 70" in fpm logs), so no serving worker retains the poisoned BG(unserialize).data - walk oracle 0/3 delivered. Apache mod_php children SURVIVE the E_ERROR (that is why wpdump/N-oracle work there); the fpm request-init-phase fatal kills the child. => their "->root under nginx/fpm" shape needs the non-fatal 618-update route, not the session-decode OOM producer. HONEST CAVEAT, logged.
- NEW GOTCHA (strace-verified, syscalls captured live): the fpm ROOT-pool workers (uid=0) open session files O_RDWR|O_CREAT|O_NOFOLLOW and get EACCES on www-data-owned 600 files - the root pool runs WITHOUT CAP_DAC_OVERRIDE, so staged session files MUST be owned by the responding worker's uid (root for the fpm lane, www-data for mod_php lanes). Owner==worker-uid is now a per-target matrixbleed parameter.
- NEW GOTCHA: fatal detection under display_errors=Off is container-log side (fpm: worker stderr via fpm master; apache: ErrorLog -> docker logs); "in Unknown on line 0" is the rfc1867-phase session decode.
- Harness: lanes/race-618/glm5/matrixbleed.py {wp-fpm,mediawiki,phpbb} [--rounds N] [--big N] - programmatic serialized data (gotcha #3), SESSION format (gotcha #4).
- cb-A stock-INI revalidation therefore runs ON THESE TARGETS (:8099 is race-glm4's): producer + carrier = MATCHED at stock 128M production INI on apache/MW + apache/phpBB; NOT-MATCHED-on-fpm for persistence (above). Full wpdump/N-oracle on 128M still needs the ARM64 stale-child lane work (next).
- Laravel: honest skip - no maintained laravel-on-8.2.34 lane image (upstream pins newer PHP); noted, not built this pass.

## cb-B UNDER LOAD (24-Oct, lanes/race-618/glm5/loadprobe.py, mediawiki :8104)
- Method: producer OOM marks a mod_php child stale; walk oracle (R:14 consumer) fired after delay D; 30-concurrent GET flood between.
- UNDER 30-CONCURRENT FLOOD: delivered 0/15 across D = 1/3/6/12/24s. The stale-vs-fresh discrimination COLLAPSES under load on this lane: with ~8 prefork children saturated by flood traffic, the consumer never lands its round-trip on a usable stale child within even 1s. Attack window with the session-decode OOM producer under load ~= 0s on our stack.
- IDLE (no flood) contrast, small sample: 0s 2/4, 5s 0/3, 15s 0/3, 30s 3/3 delivered - NO clean survival curve; delivery is dominated by which child the consumer's connection lands on (p ~= 1/#children per fire). The 30s 3/3 is child-lottery, not window growth.
- VERDICT: ToB "under load" is NOT-MATCHED for the stale-child disclosure consumer with this producer shape on our ARM64/MW lane (0/15 under load); their under-load demo presumably rides the 618-update non-fatal route instead of the fatal session-decode. Honest row added to the claim map.

## SESSION LEDGER (24-Oct, turn 1 complete)
- DONE cb-C build+fire, cb-D build+fire, cb-A (new-target version, producer/carrier half), cb-B. All committed+pushed.
- OPEN (next turn, priority): cb-A full half = wpdump/N-oracle + DB-password tiling at stock 128M on the NEW ARM64 targets - needs arm64 N-oracle offsets (glm3/glm4 notes hold the arm64 lane design; per-child d-region), PLUS cb-E RCE final mile (TODO priority 1; oversized-carrier hint: the fpm/matrix lanes already proved 200M carriers read fine when owner==uid, and php-fpm child-exit finding redirects cb-E work to apache lanes).
- Laravel: honest skip noted in claim map.
- Host mem discipline: free -g checked before every build (12G avail at last check); no co-tenant touched; :8099 never fired.

## TURN 2 (24-Oct): arm64 N-oracle port + carrier experiments (a3_arm64_mw.py)
### DERIVED arm64 offsets (mediawiki image libphp.so, ARM aarch64, PHP 8.2.34, BuildID fd4e9a3d...; verified LIVE not hardcoded)
- basic_globals = .so BSS 0xf1e748; runtime addr READ VIA GOT (slot at .so vaddr 0xEFF220, from adrp eff000+544 in php_var_unserialize_init) - matches base+0xf1e748 live (0xe4d28cbae748, bias 0xe4d28bc90000).
- BG(unserialize).data @ bg+0x330 (str x0,[x19,#816]), .level @ bg+0x338 (w1,[x19,#824]); d = emalloc_large(0x2018=8216) from init disasm; init reuses d when level!=0 (level++ branch at init+0x68).

### PROVEN on the MW :8104 lane at FULLY STOCK php.ini-production
- Producer OOM (75MB staged session + pad-shape multipart) poisons the pool: 5-6 stale children, d FORK-UNIFORM at 0xe4d289c76000 across every child (deterministic; = heap primary chunk 0xe4d289c00000-0xe4d289e00000 + 0x76000).
- /proc helper scan (GOT-based) reads per-child BG live; d chunks are ZEND_MM-cached (freed, NEVER munmapped) - post-mortem dumps show full var_hash content (last=d+0x38, first/last_dtor=0xe4d289c6e000 chain).
- The stale d IS live-dangling: a consumer request on a stale child WALKS the freed entries (consumed, level flips to 0 on normal completion - clean destroy).

### NOT TRANSFERRING from x86 (per-box heap geometry - the x86 lane's own warning)
- a3_symmetric multipart groom (8193B read_body hole model): consumers land but the groom does NOT take the producer's d hole; R:1 resolves against leftover producer entries; occasionally SIGSEGV later in MW's own zif_array_map (x1=-1 walk of freed entries). Same wall x86 hit ("n_groom 1-350 all miss; vendor needs per-target heap tuning").
- 200MB-class oversized carrier: IMPOSSIBLE at stock memory_limit=128M - ps_read emalloc(200MB) alone exceeds the limit -> instant OOM fatal, request dies before decode, stale state SURVIVES (500 returned in <5ms; d untouched). ToB's "normal memory_limit" claim makes >127MB ps_read carriers structurally impossible - their oversized-carrier route must ride a lower limit or a different buffer.
- 1.9MB and 8192B (8216 alloc class, zend_string +0x18 header accounted) session-file carriers: 10+ fires on stale children, MAGIC markers NEVER appear at d - the ps_read large-class alloc does NOT first-fit into the freed d run on arm64 (chunk placement goes to fresh chunks above the heap, not the primary chunk's freed large run).
- GOTCHA (new, bash): od -An -tx1 byte order must be converted little-endian (or use od -An -tu8 for direct decimal qwords); cost an hour of phantom-empty scans.

### NEXT (lane, ordered)
1. gdb bp march-map: break emalloc_large + php_var_unserialize_init; log alloc (ptr,size,caller) sequence for producer vs consumer bodies; find the arm64 hole that the groom must take (the a3 symmetric replay needs per-box retune - same as x86's n_groom sweep).
2. Then wire the N-oracle groom at the mapped hole; self-verify N==*(bg+0x330)==d at stock INIs => production-grade closure row.
3. RCE last mile follows only after 1-2 (the x86 chain's serialize_lock overlay + route offsets need arm64 derivation from this same binary).

## TURN 3 (24-Oct): gdb/perf march-map - instrument built, arm64 hole verdict
### INSTRUMENT (host-only; NO new containers, target unmodified)
- docker-exec /proc reads are BLOCKED this turn (host yama ptrace_scope=1, container lacks CAP_SYS_PTRACE, host-user non-root) -> HOST-side tools: passwordless sudo + host gdb attach FAILS (SW and HW bps both raise SIGILL at bp addr - environment quirk, logged), WINNER: **host perf uprobes on the container's REAL libphp.so inode** (probe -x /var/lib/docker/overlay2/<merged>/usr/lib/apache2/modules/libphp.so; group probe_libphp). Entry+return probes with arg capture (%x0) on: _emalloc_large, zend_mm_alloc_huge, zend_mm_mmap, php_var_unserialize(_internal), init/destroy. Evidence: evidence/turn3/.
### MARCH MAP (arm64, MW :8104, producer=75MB session + pad multipart; consumer=groom 8193B + R:1 token)
- PRODUCER huge march: zend_mm_alloc_huge -> mmap(75005952)=ps_read buffer landing ~248MB BELOW d (0xe4d251000000-class region, mmap-min top-down), then mmap(77099008)=the 75000032+2MB-rounded string-copy value buffer immediately below it. Then OOM "tried to allocate 75000032" (zend_string +0x20 header). NO destroy => stale BG (level=1, data=d) survives. CONFIRMED at allocation level.
- d (var_hash 8216, emalloc_large via init+0x2c) + entries chunk (4096 @ d-0x8000=0xe4d289c6e000) land INSIDE the primary heap chunk (0xe4d289c00000). d's exact slot is recycled ONLY by later var_hash inits (observed rets d, d-0x5000, d+0x33000... - the slot is a first-fit hotspot; d drifts WITHIN the chunk as the free list evolves).
- MULTIPART GROOM VERDICT: the sp-field(8193B) read_body / stream-chunk / body-temp allocations (8216/32768/65536/262144-class) land in the mmap-chunk region ~183MB BELOW d (e.g. 32768 rets at 251592722780160) - NEVER in d's chunk. THE x86 a3_symmetric HOLE MODEL IS STRUCTURALLY DEAD ON ARM64: no request-controlled multipart buffer can land at d.
- 8192B session-file carrier: ps_read buffer for an 8K file NEVER appears in _emalloc_large (no 8192/8216-class alloc for it) and nothing lands at d -> the small-file ps_read-carrier mechanism (x86 TODO #4 "the session file IS the groom") also does NOT transfer.
- OPEN INSTRUMENT QUESTION (next turn, 5 min): the session decode (8K + producer) never shows up at php_var_unserialize / _internal probes with vh=&BG(unserialize) (0xe4d28cbaea78) - the php session serializer's decode path calls something else (or the probe arg mapping is off at that call site); find the real entry (nm: ps_srlzr / serializer decode) and capture the small-file ps_read buffer ADDRESS to close the last carrier question.
### VERDICT (phase 1, honest)
NO actionable content-controlled hole at d found on arm64 via the transferable x86 mechanisms (multipart groom, oversized carrier, small-file ps_read carrier - all structurally absent). The N-oracle groom needs an arm64-native carrier: candidates ranked: (a) resolve the open ps_read-buffer question (if the 8K ps_read buffer IS arena-allocated somewhere predictable, craft the file so the decode's own ENTRIES (which ARE written into d's chunk via init/caller 0x3be708+0x3bea08) carry attacker data - i.e. groom via the decode's OWN entries chunks (8160-class @ d-0x8000), which are the ONLY attacker-adjacent content in d's chunk; (b) producer-side: the stale d's entries data[] = OUR 12 marker zvals - R:n resolution against them is already attacker-pointer-controlled; a marker VALUE that is itself a crafted serialized structure could shape the walk (R: to a string whose bytes form a fake zval in the HEAP at a leaked address). Both logged as the next-lane plan.

## TURN 3 phase 2 (24-Oct, same turn): THE HOLE FOUND + N-ORACLE WIRED AND FIRING
### THE HOLE (perf uprobe on ps_srlzr_decode_php @0x312dc4, arg x0=ps_read buffer val, x1=vallen)
- Session files of 32KB..1MB: ps_read buffer DATA lands at val = d - 0x7FE8 DETERMINISTICALLY (observed identical across all children, sizes 16384..1048576 swept; 1.9MB jumps chunks). => file offset 0x7FE8 maps EXACTLY onto d = the stale BG(unserialize).data. The 8K carrier of turn 2 was 0x6000 bytes TOO SHORT to reach d - that is why it never landed; the +0x18 zend_string header (x86 gotcha #9) confirmed live.
- THE CARRIER: 64KB session file = 'p|s:N:"<fake-d GRID 0x200-periodic at file offsets == 0x1E8 mod 0x200, spanning 0x6FE8-0x8FE8>";k|a:1:{i:0;R:1;}' - the string value carries the groom; the k-pair's R:1 resolves data[0] = fake zval on the stale child (init REUSES d which the ps_read buffer now covers with our bytes).
### ORACLE FIRING (turn3_oracle.py, MW :8104, FULLY STOCK php.ini-production)
- Repeatedly: fatal "tried to allocate N" with N = 251592905879552 = 0xe4d289c87000 = A MEMORY-DERIVED QWORD (the stale child's current BG(unserialize).data - the arena's d slot drifted from the canonical 0xe4d289c76000 after the sweep traffic) - delivered IN-BAND (500 + container-log under display_errors=Off), on ~30% of consumer fires after producer poisoning. THE N-ORACLE MECHANISM (fake zval -> ZSTR_LEN = *(TARGET) -> smart_str append -> OOM fatal carrying N) WORKS AT STOCK INIs ON ARM64.
- Planted-magic control (TARGET = d-0x2FE8 holding 0xDEAD0000BEEF0000) did NOT hit this round: d drifted between the observation and the control build -> the carrier is d-value-sensitive. NEXT (10 min with /proc back): adaptive loop - fire the bg+0x330 oracle to read the CURRENT d, retarget immediately; plus a direct /proc read of bg+0x330 to pin N==d exactly, then the env-secret qword tile.
### Verdict rows (claim map next commit): ToB "production-grade" on ARM64: producer OOM + stale persistence + memory-derived in-band qword read = MATCHED at stock INIs on the MW lane; full arbitrary-read tiling pending the adaptive loop.
