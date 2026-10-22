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

## Decode-side producer + consumer crash primitive (2026-10-22 05:2x-05:3xZ)

Lane now: WordPress 7.1.2 (vendor's exact claimed version), pinned pre-patch
php 8.2.34, PURE STOCK INIs (the zz-range.ini post_max_size staging was
REMOVED - the decode-side route needs no upload at all). wpdb-x86 got
--skip-name-resolve (mysqld reverse-DNS was adding a flat 5s to every fresh
WP db connection and eating the Apache KeepAliveTimeout window).

### Route A - WP's own maybe_unserialize on a poisoned option: window CLOSED
Poisoned autoload option blogname with a:1:{i:0;s:<S>:"<S real bytes>";}
and swept S=57.5M..63M at stock 128M. ALL variants OOM in the DB FETCH
(class-wpdb.php:2324, "tried to allocate S+56"), never in the decode:
the fetch holds mysqlnd buffer (S) + row string (S) + base, and the decode
would need a third S. 3 copies in flight close the S window at 128M.
Bogus-length tokens (s:140000000:"A") are REJECTED pre-alloc by core
(@unserialize returns false, verified in-container) - PHP validates the
declared length against the remaining buffer before allocating.

### Route B - session decode (the vendor's phpMyAdmin-style route): WORKS
Stage /tmp/sess_<SID> with poc|a:2:{i:0;s:3:"abc";i:1;s:72000000:"<72MB>"}
(element 0 builds var_hash entries; element 1's allocation crosses 128M:
file buffer 72M + decode alloc 72M + pre-RINIT base > 134217728).
Fire ONE unauthenticated multipart POST (PHPSESSID + upload_progress +
file part; NO memory_limit/post_max_size staging, t=0.1s):
  Fatal error: Allowed memory size of 134217728 bytes exhausted
  (tried to allocate 72000032 bytes) in Unknown on line 0
  Warning: PHP Request Startup: Failed to decode session object.
  Session has been destroyed
- 100% attacker-controlled token structure (element 0 = var_hash builder,
  element 1 = the crossing alloc; glm3's P3 content-control problem does
  NOT exist on this route).
- Each fire REWRITES its session file at request shutdown (empty re-encode
  of an empty $_SESSION) - use a pristine file per request round.
- Controls on fresh children: byte-identical clean fatals (3/3, 6/6).

### Consumer-side engagement on the SAME child: ~2/3 segfault rate
Same-connection pair (req1 = producer on SID_A, req2 = producer on pristine
SID_B, same Apache child): req2 either repeats the clean OOM (2/6) or
SEGFAULTS THE WORKER (4/6, "child pid N exit signal Segmentation fault (11)"
in logs; pair[6]/pair[7] crashed on req1 because those connections landed
on children already poisoned by earlier requests - the primitive compounds
across the child pool). This is a reproducible memory-safety consequence
of consuming the post-OOM state on stock WP 7.1.2, pre-auth, two requests.

### Next mile (glm3 Route B maps 1:1 onto this lane now)
The crash means the stale BG(unserialize) IS consumed but the reclaimed
8216B php_unserialize_data chunk holds wild content. Deterministic version:
8193B multipart field name (estrdup, raw alloc, 17-page zend-mm class)
reclaiming the chunk with a FAKE php_unserialize_data; token stream fully
controlled (the session file!) -> var_push_dtor dup-key gadget -> fake
zend_internal_function from libphp .data.rel.ro -> zif_readfile("/CANARY").
x86_64 offsets for 8.2.34: zend_internal_function handler@+88, fcall_info
params@+48 (vs aarch64 +72/+32 - see GLM3-BRIEF). Extract this lane's
libphp.so and adapt lanes/race-618/glm3/find_fake_func.py (aarch64-only).
