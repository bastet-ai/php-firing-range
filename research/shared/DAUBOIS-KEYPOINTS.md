# DAUBOIS KEY POINTS (PHP security team insider, 2026-10-21)
Source: https://daubois.dev/blog/cve-2026-109618-php2shell-rumors/
(alexandre daubois = PHP core/devs; text saved /tmp/daubois.txt)

1. UPLOAD-PROGRESS FLAG IS FOR 619 ONLY. 618 "never mentions sessions" -
   it is the ALLOCATOR OOM bug. Our lab's session.php upload_progress is
   irrelevant to the 618 mile. Kill it from the surface (noise, false gate).
2. VENDOR VALIDATED RCE OVER HTTP ON APACHE MOD_PHP WITH DEFAULT
   memory_limit (128M), BEFORE APP CODE RUNS. => stock 128M is sufficient;
   our 2M .htaccess dir-limit is a LAB SHORTCUT that biases shaping.
   For the real-shape PoC: remove the dir limit, amplify to 128M:
   unbounded per-part HEADERS (GLM S2: 20k tiny headers already fatal
   4096-byte allocs at 2M => scale count ~64x for stock), empty file
   parts, undeclared body length.
3. EXACT pre-fix failure site (verbatim code): zend_mm_safe_error()
   heap->overflow=1; zend_try{ zend_error_noreturn(E_ERROR,...) }zend_catch
   {} zend_end_try(); heap->overflow=0; zend_bailout();  <- longjmp from
   INSIDE emalloc. Publishes-then-jumps. mod_php calls php_request_shutdown
   whether startup finished or not.
4. PATCH internals: soft-limit + delayed error + UnwindExit at next VM
   interrupt point; parser checks pending error BETWEEN parts/fields and
   frees cleanly. NEW: memory_hard_limit_percent = 200% below 1G (256M at
   stock 128M) -> _exit(137). RESIDUAL ON PATCHED: "a real mmap() failure
   still takes the old path" -> patched-target research angle (make mmap
   fail low: RLIMIT_AS / /proc/sys/vm overcommit tricks on OUR range).
5. stopgap #1 advisory: memory_limit=-1 and NEVER RLIMIT_AS (counter-
   intuitive; explains why our "harden to 2M" was the opposite of advice).
6. fix PR 2026-09-25, FINAL COMMIT 01a40e89fbfc (2026-10-18) - use THIS
   sha for patch-revert staging (stage-php-src.sh), not 31c0ea7d7ff alone;
   390 files touched.
7. Embargo broke via HN anon post + Calif.IO PHP2Shell screenshot + video;
   release moved UP a day. Reporters credited: lcfr-hax, sagitzadik-wiz,
   amyb-oai, tomash-areion (lcfr = the php2shell lcfr@pandemonium trace!).
8. PHP-FPM/FrankenPHP/LSAPI believed in scope, NO complete exploit =>
   differentiator target for us (our bleedsrv is php -S cli-server; fpm
   lane cheap to add: php:8.3-fpm + nginx).
9. Old-version claims (5.x-7.x) rumor: mechanism sits in PHP-5.3 allocator
   but no exploit seen on old versions; php56 target = negative-result lab.

## ACTIONS baked in
- surface/lab: drop memory_limit=2M; default 128M (authentic vendor shape)
- race-618 fire recipe: stock-limit header-bloat OOM producer; then same-
  worker consumer-window groom requests (619) OR mod_php shutdown-walks
  half-built state (618).
- patched-target mini-lab: 8.5.12 + RLIMIT_AS to force mmap-fail path
  (does the RESIDUAL jump still corrupt? that's the next CVE).
- fpm/php-fpm + frankenphp targets added to diversity matrix.
