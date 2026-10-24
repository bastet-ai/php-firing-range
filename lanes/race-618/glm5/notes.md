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
