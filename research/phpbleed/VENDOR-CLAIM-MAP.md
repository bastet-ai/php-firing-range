# VENDOR-CLAIM-MAP: calif.io/php2shell (fetched 2026-10-22, page cached /tmp)

Source: https://calif.io/php2shell/ "php2shell by Calif Research - A tale
of two PHP remote vulnerabilities". Text-only read; their downloadable
bundle remains DO NOT EXECUTE (standing rule, research/fuzz/LOG.md).

## What the vendor actually claims (structure)

Two core bugs + THREE interruption points where a memory_limit-based OOM
fatal leaves stale/consumable state in the surviving worker:

1. var_hash decode interruption (shown PHP_VAR_UNSERIALIZE_DESTROY snip):
   any reachable post-startup decode - session_start(), session_decode(),
   unserialize(), "including wrappers such as WordPress's
   maybe_unserialize()" - can be interrupted at a useful point by
   attacker-controlled memory pressure; "the decoded data can be
   legitimate"; a later upload-progress request consumes the stale state.
2. HashTable registration interruption (_zend_hash_str_add_or_update_i):
   count incremented, key/hash/zval assignments skipped on a fatal;
   mod_php request-shutdown teardown "trusts live count" and consumes a
   stale Bucket whose allocation bytes were reclaimed. Reached through
   PLAIN URL-encoded POST variable registration (php_std_post_handler,
   root[x]=v) - no unserialize anywhere. Claimed: RCE against arbitrary
   PHP scripts, Apache mod_php, PHP >= 5.4.0 (one variant 7.3+).
3. PHP-FPM post-startup interruption (startup failure = process exit, so
   their FPM variant uses a different, post-startup fatal window).

App claims: pre-auth RCE confirmed on WordPress 7.1.2, Drupal 11.4.3,
Joomla 6.1.4, MediaWiki 1.46.2, Roundcube 1.7.4, Magento 2.4.9,
phpMyAdmin 5.2.3, Nextcloud 35.0.1, Laravel 13.11, Symfony 8.1, WHMCS.
Demo video claimed (not independently viewable here); one demo stated
as Nginx + PHP-FPM.

## Correction to OUR census framing

The census result stands (verified live on wordpress-x86: 0 classes
implementing Serializable in core; 0 of 32 unserialize call sites fed
from request superglobals) - but it is ORTHOGONAL to the vendor's
WordPress path. Their WP chain needs NO Serializable gadget and NO
request-fed unserialize sink: it interrupts an ordinary
maybe_unserialize() decode of legitimately-stored serialized data
(attacker controls surrounding memory pressure, not the payload), then
consumes the stale state via upload-progress. "phpbleed exploit class =
legacy-app" applies to the C:-gadget var_hash chain only; php2shell's
WP path is the 618/619 + generalized-interruption machinery.

## Verification map (ours vs theirs)

| claim | our status |
|---|---|
| OOM-fatal producer, pre-auth, stock-ish INIs | REPRODUCED (WP lane + php83 lab; stock memory_limit=128M with post_max_size staged; post_max_size=8M pure-stock nuance in WP-X86-NOTES) |
| interrupted-decode stale state; reader-side consumption | PARTIAL (php83 lab: corrupt-token persistence at 2M staging; WP lane: flock-window reader deadlock at 2M; 128M persistence gap documented) |
| HashTable POST-registration interruption (_zend_hash_str_add_or_update_i count/teardown consumption) | NOT IN OUR NOTES - new thread; testable on any mod_php lane with plain root[x]=v + memory pressure |
| full RCE ladder (reclaimed-bin forged zend_fcall_info -> stale FILE_DATA invoke -> system()) | NOT REPRODUCED - the known last mile (php2shell-bastet.py is the ported chain; "GLM lane holds the last mile") |
| app matrix incl. WordPress 7.1.2 pre-auth | NOT REPRODUCED; our WP lane is 6.x |

## Next steps (range-reproducible)

1. Restage wordpress-x86 at 7.1.2 to match the claimed target.
2. WP decode-side test: plant attacker-influenced serialized option
   (we control the DB - pre-auth realism is a separate WP-specific
   question), interrupt its maybe_unserialize decode with controlled
   pressure, consume via upload-progress; verify against canary.
3. POST-registration interruption on php83/8088: plain root[x]=v fatal
   shaping + teardown consumption per their bucket diagram.
4. php2shell-bastet.py last-mile runs against production php83.
Do NOT execute the vendor bundle; re-derive from their written mechanics.

## ToB "production-grade" claim (23-Oct post) - GLM5 verification (24-Oct, ARM64 box, matrix targets :8102-:8105)

| claim element | our status |
|---|---|
| stock php.ini-production knobs (display_errors=off, memory_limit 128M), unauth producer OOM after rfc1867 | MATCHED on mediawiki :8104 and phpbb :8105 (tried-to-allocate 75000032, log-side fatal under display_errors=Off; matrixbleed.py) |
| session carrier / stale child reuse (walk oracle R:14 round-trip) | MATCHED on mediawiki + phpbb (apache mod_php children survive the E_ERROR) |
| nginx/php-fpm -> root lane | MATCHED-with-caveat: producer OOM fires on the fpm lane at stock 128M, BUT the fpm child EXITS (code 70) on the session-decode fatal - per-worker stale-global persistence does NOT hold with this producer; their route must be the non-fatal rfc1867-update shape (618 chain) |
| MediaWiki/phpBB app matrix | MATCHED (MW 1.42 + phpBB 3.3.16 on php 8.2.34 pre-patch, stock core, CLI/log-side staging) |
| Laravel | SKIPPED (no maintained 8.2.34 laravel lane image; honest gap) |
| ARM64 + x86-64 | producer/carrier proven ARM64 here; x86_64 proven on the other box (TODO @ 732775d) |
| under-load stability of stale-child consumption | NOT-MATCHED (0/15 walk deliveries under 30-concurrent flood, delays 1-24s, MW :8104 lane; idle delivery is a child-lottery, no clean window) |
| ARM64 lane at stock INIs: memory-derived in-band qword read (N-oracle) | MATCHED (24-Oct, MW :8104, arm64: ps_read 32KB-1MB carrier covers the stale d at f_d=0x7FE8; fake-zval groom -> N=*(bg+0x330) fired repeatedly in-band under display_errors=Off; adaptive retarget + env-secret tile pending) |

## Percivalll (2026-10-24) — php2shell-wordpress-rce (static audit, GLM6 lane)

Source: github Percivalll/php2shell-wordpress-rce @ 907ceb5 (cloned
READ-ONLY to vendor-audit/, NEVER executed; audit notes in
lanes/vendor-audit/{notes,recon,adaptations}.md). Distinct vendor from
calif.io above: this is a SECOND independent php2shell implementation,
targeting default wordpress:7.1.2 (PHP 8.3.35 NTS, Apache prefork
mod_php, image digest e04cf657…, stock INIs incl. memory_limit=128M,
post_max_size=8M, upload_progress on, strict_mode off).

| claim | our verdict (static code audit; no execution) |
|---|---|
| chunked-POST worker pin: 149 unfinished chunked POSTs free exactly one worker; 4KiB/s survives mod_reqtimeout body=10,minrate=500; adaptive probe frees exactly one | MATCHES-OUR-MECHANICS and SUPERIOR TO OUR PRACTICE — solves our cb-B child-lottery wall by construction (glm5: 0/15 under 30-concurrent flood); pure HTTP, no SIGSTOP/flock hazards; death verified in-band (resp 0 = child died, escalate OOB read 8/12/24MiB) |
| A request leaves stale PS(id) + dirty SAPI header state after FILE_START php_url_encode 4096B OOM; worker survives | matches-our-observed (mod_php children survive E_ERROR — our cb-A/wpdump base fact); the specific stale-PS(id)+send_cookie residue is new-to-us-unverified (plausible; same bailout-skips-cleanup physics as our 618 observations) |
| 4KiB Set-Cookie OOB read: bin7 groom (31×32B names), 63B value forges next-slot zend_string len=0x1000, new session id overlaps it, php_url_encode leaks 4096B heap → base (16-offset vote, min 4) + chunk (2MiB bucket), H=chunk+0x6a000, all in ONE 200 response | new-to-us-unverified; STRONGER than our N-oracle on volume/staging (4KiB contiguous, no session-file staging, base+chunk together) but NOT arbitrary read (fixed groomed window); complementary — see adaptations.md |
| op_array-at-chunk-head requirement: leak must run before index.php executes/opcache caches it; retry in place | new-to-us; consistent with our gotcha #8 (raw-body prealloc shifts march models) physics; no analog tested by us |
| two session-file producers: /tmp/sess_r1big = 30MiB filename (31,457,602B), /tmp/sess_trig2 = 16,697B fake zend_execute_data via 0x4000 progress key; chunked TE bypasses post_max_size=8M for 150MB bodies | new-to-us-unverified; the chunked-TE post_max_size bypass contradicts nothing we observed (we stage at 2M via php_admin_value; theirs rides stock 8M with no Content-Length) — worth a direct lane test |
| arm: dummy 1MiB-filename part's freed page reclaimed by emalloc(0x2018) at FILE_START → BG.data=H chosen deterministically; 500=success oracle, 302=retry | matches-our-observed structurally (BG(unserialize).data = emalloc_large(0x2018), our a3/arm64 init disasm); the H-choosing reclaim is the elegant delta vs our H-discovering N-oracle |
| R1: var_push 64-bit wrap-write PS(serializer)=H+0x310 (fake name/encode/decode=zif_system); R2: ps_read(sess_trig2) → serializer->decode(fake frame) → zif_system(cmd) as www-data | new-to-us-unverified; FEWER primitives than our forged zend_fcall_info chain (no fcall_info/execute_internal/destroy-gate); targets verified writable on OUR 8.2.34 build: ps_globals 0xf0c998 (.bss), zif_system 0x36ff48 (readelf 24-Oct, wordpress-x86 container); serializer field offset +0x148 is their 8.3.35 measurement, needs per-build derivation for 8.2 |
| 9/9 fresh containers, 24-26s, one ASLR gate (0x7c in H pointer bytes), --base/--h reuse within a container | UNVERIFIED (no execution this turn); internally consistent with fork-uniformity we measured (d fork-uniform 8.2/arm64): chunk/base fork-stable within container, byte lottery per boot above it; gate is key-delimiter-specific — our session-file carriers do not inherit it |
| rejected: PG(auto_prepend_file) (var_push writes zval slot, value-shape wall), opcache type confusion (needs ~3700 scripts vs 1513; SMEM persist ≠ request OOM), 8.5 fatal-backtrace (absent 8.3/8.4) | MATCHES our walls (value-shape, carrier-placement coupling = our gotchas #7/#8/#9; symmetric-groom misses); opcache capacity math and the 8.5 gate are NEW-TO-US negative results |
