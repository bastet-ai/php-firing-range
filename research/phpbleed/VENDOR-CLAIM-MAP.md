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
