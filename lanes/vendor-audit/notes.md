# notes.md — GLM6 vendor-audit lane (Percivalll/php2shell-wp), durable state

Audit in progress. Repo under audit: /home/user/vendor-audit/php2shell-wp
(READ-ONLY, never executed). Our chain references: phpbleed-bastet.py (forge
dispatch RCE, :8088 proven), scripts/a3_*.py (N-oracle), TODO.md §PROVEN.

## Ladder progress
- [x] rung 1 pipeline reconstruction → recon.md (commit 25fb6db)
- [x] rung 2 leak channel → "set-cookie-oob" below
- [ ] rung 3 worker pinning
- [ ] rung 4 RCE route (serializer vs fcall_info)
- [ ] rung 5 rejected primitives
- [ ] rung 6 ASLR gate
- [ ] rung 7 integration (claim map, adaptations, TODO, compose action)

## set-cookie-oob (rung 2 — their 4KiB leak channel vs ours)

### Their mechanism (code citations)

Stage A — leave stale PS(id):
- big_a.py driven by A_ARGS (run_ext.py:23): ~66MB multipart groom,
  PHPSESSID=\0, progress=k, file part; at FILE_START
  php_session_send_cookie→php_url_encode's 4096B page alloc OOMs
  (REPORT §4.1). Worker survives (E_ERROR is non-fatal to the child),
  leaving PS(id)=stale/controlled zend_string + PS(send_cookie)=1.
- Caveat they note: the first A on a worker also compiles index.php and
  parks its op_array at the ZendMM chunk head — that is what makes the
  OOB window contain libphp handler pointers (run_ext.py:196-204
  comment; REPORT §4.4). opcache-cached index.php zeroes the window.

Stage B — forge + OOB read (b_leak20.py:1-68, profiles.py:88-96):
- b_leak20.py:24-27 forges a 63B value: `struct.pack_into("<Q",
  fake, 0x10, LEAK)` → the value string's zend_string.len field
  (data starts at +0x18 of the zend_string header; a 63B value spans
  header+len of the NEXT slot) = 0x1000; bytes +0x18 = "P2SFAKE1".
- Groom: 31 field names of 32B with empty values fill bin7 slots 0..61
  (b_leak20.py:29-31, REPORT §4.2); the 63B value lands in slot 62;
  php_session_initialize() during cleanup allocates the 32-char session
  id → hits slot 62 → the new PS(id) header overlaps the forged len.
- php_session_send_cookie() calls php_url_encode(PS(id)) with
  PS(id)->len=0x1000 → encodes 4096B of adjacent heap into
  `Set-Cookie: PHPSESSID=...` → 4104B decoded window (REPORT §4.2-4.3).
- Client-side parse (run_ext.py:44-119): libphp base = page-aligned
  vote over 16 known offsets (min 4 votes) + 4 fixed qword anchors;
  chunk = dominant (q & ~0x1FFFFF) 2MiB bucket; H=chunk+0x6a000.

Strength properties:
- ONE request produces base + chunk together, in-band, 200-status
  delivery, no second resolving request.
- No session-file staging required for the leak itself (unlike ours
  where the producer needs a staged session file to OOM).
- But it requires: same-worker discipline (pin or the layout resets),
  a prior A request on that worker (op_array at chunk head), and the
  bin7 slot-62 landing — i.e. a heap groom of similar fragility to
  our symmetric groom, only at 63-byte scale rather than 2MB scale.

### Comparison with our channels

| property | their Set-Cookie OOB | our OOM-fatal in-band + N-oracle |
|---|---|---|
| data per fire | 4096B contiguous window (base+chunk at once) | 2MB dump (wpdump) or ONE qword per fire (N-oracle) |
| transport status | 200 OK, Set-Cookie body | fatal-error message text (593B dual-fatal in-band) |
| needs staged session file | NO | YES (producer = unauth multipart + staged session file) |
| needs same worker | YES (A leaves the layout; rotate kills it) | walk oracle handles stale children (R:n self-resolve) |
| arbitrary-target read | NO — reads heap adjacent to PS(id) only; arbitrary length via LEAK knob but always from that one stale string | YES — N-oracle reads ANY qword (BG(unserialize).data proven; env secrets tiled) |
| primitives needed | forge ONE zend_string len (63B value) + groom bin7 slots | full OOM-fatal producer + precise regroom + fake-zval encode-append |
| failure mode | no cookie / <0x1000 raw → retry in place | oracle silence → regroom |
| which structs leaked | ZendMM chunk head: op_array, handler ptrs, data ptrs | arbitrary, but one qword at a time |

### Verdict (their leak vs ours)

- STRONGER on: volume (4KiB contiguous vs 1 qword/fire), zero staging,
  single-request closure of BOTH unknowns (base + heap chunk), and it
  is per-process-safe (each B is a fresh 200; does not depend on
  fork-uniform d).
- WEAKER on: not arbitrary read — it is a fixed window at a groomed
  location; and it is layout-fragile (slot-62 landing, op_array head
  requirement, opcache zeroing).
- COMPLEMENTARY: their B-forge is essentially a lighter-weight version
  of our a3 fake-zval: where we forge a whole zval to redirect the
  encode append, they forge only len in an existing stale string and
  let the NORMAL cookie path do the read. Adaptation candidate for our
  chain: use a stale-PS(id) len forge to replace the N-oracle's
  bootstrapping step (leak d / bias discovery), keeping the N-oracle
  for arbitrary qwords. See rung 7b.
- Note the asymmetry to remember: our N-oracle target
  basic_globals+0x350 returned BG(unserialize).data — their equivalent
  unknown H (BG.data after arm) is instead derived deterministically
  as chunk+0x6a000 from the leak, because their arm CHOOSES H (emalloc
  0x2018 from the dummy's freed page) rather than discovering it.
