# wordpress-x86 lane (:8099) - stock-WP 618 findings (2026-10-22)

Target: stock WordPress 6.x (core copied unmodified from the official
wordpress:6-php8.2-apache image) on PINNED PRE-PATCH php 8.2.34
(CVE-2026-109618/619 were fixed in 8.2.35; the floating php:8.2 tag now
ships the patched release - see HOWTO-RANGE.md SS5). x86_64 native,
wpdb-x86 (native mysql:8.0) for the app. WP is functional and unmodified;
the entire attack surface is PHP core's session.upload_progress.

Script: lanes/race-618/glm/poc_wp_stock.py (poc.py's chain, parameterized).

## Findings (all pre-auth, zero app code)

1) PURE-STOCK INIs: post_max_size=8M rejects the oversized POST BEFORE
   multipart parsing ("POST Content-Length ... exceeds the limit of
   8388608 bytes") - upload_progress never runs. The size-based OOM
   vector is capped by post_max_size, not memory_limit, at true stock
   config. New nuance for the P10 scorecard line.

2) STAGED post_max_size=128M (ONE knob; memory_limit untouched at stock
   128M): the 618 OOM fires on stock WP:
   "Allowed memory size of 134217728 bytes exhausted (tried to allocate
   65015808 bytes) in Unknown on line 0"
   with the 70MB-filename shape (FILE_START encode OOM) and the 64MB
   progress-value shape (initialize encode OOM, tried 65016420).
   => P10's "stock-128M trigger (64-100MB field)" is CONFIRMED, with the
   explicit post_max_size caveat.

3) FULL CHAIN at 2M lane staging (same staging as the php83 lab):
   producer = vendor's exact signature ("Allowed memory size of 2097152
   bytes exhausted (tried to allocate 442368) in Unknown on line 0");
   reader on the poisoned SID deadlocks 75s+ on the session fd/flock
   window (the lane's independent per-SID DoS primitive).

## Open gap (128M persistence)

At stock 128M the corrupt-token persistence does NOT land: the session
file stays 0 bytes. Mechanism: the producer OOM leaves BG(serialize)
stale as designed, but the shutdown flush's re-encode hits the same
128M wall a SECOND time (the ~64-70MB request data is still live) and
bails before s_write. At 2M lab staging the numbers leave headroom for
the shutdown pass, which is why the corrupt-token variant is proven
on the 8.3 lab lane only. Closing this needs either a shape whose
shutdown re-encode fits while the first encode OOMs, or is simply not
reachable at 128M - untested further.

## Config knobs on this lane (documented deviation)

- range/wordpress-x86/Dockerfile ships zz-range.ini: post_max_size=128M,
  upload_max_filesize=128M (knob from finding 2). memory_limit stays
  stock 128M in the image; the 2M chain staging is applied at RUNTIME
  (zz-2m-lane.ini + restart) and removed after - image never carries it.
- .env (gitignored) holds WORDPRESS_DB_PASSWORD == MYSQL_PASSWORD.
