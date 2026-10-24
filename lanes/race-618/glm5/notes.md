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
