# ADVISORY KEY POINTS (full GHSA text extracted 14:45Z - vendor-blessed roadmap)

## CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) — "OOM strategies", RCE stated by vendor
Mechanism: OOM uses longjmp() to abort; if allocation fails while request
memory is TEMPORARILY REACHABLE PRE-INIT, shutdown READS/BRANCHES on invalid
state. "Multiple OOM strategies can consistently trigger this condition and
lead to remote code execution (RCE)."

Vendor-enumerated OOM strategies (each a body-shape recipe):
 1. multipart WITHOUT usable declared content-length -> passes post_max_size
    gate, keeps supplying decoded body. (We have been sending accurate
    Content-Length! DROP IT or lie small, use chunked/none.)
 2. UNRESTRICTED headers per part; header representation in PHP costs >>
    wire size => exhaust memory_limit inside post_max_size. (Cheap: 10k tiny
    X-Custom headers per part!)
 3. Empty file parts don't count toward max_file_uploads but still build the
    file metadata arrays.
 4. NESTED field names (a[b][c]...) multiply generated array work.
 5. App-specific: attacker input causing large/repeated allocations.

SUSCEPTIBILITY (huge for us): **Apache mod_php unconditionally invokes
request SHUTDOWN even when STARTUP FAILED.** Body parsing during startup
exhausts memory_limit => exit in invalid state => shutdown processes it.
Entirely before any application code. OUR TARGET 8083 IS mod_php. The
vulnerable path is our exact stack; no .htaccess limit trick even needed if
strategy 2 amplification works at stock 128M.

## CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) — producer/consumer UAF, RCE stated
Worker-retained globals (error, session, object, ext state) pointing at
request-owned memory; must be reset before request memory freed.
- State survives via: fatal (incl. OOM) abandoning the matching reset; OR a
  WARNING/nonfatal diagnostic REPOPULATING error state AFTER shutdown cleared
  it.
- Consumer = any op running BEFORE normal next-request init that reads/branches
  on the stale global => UAF. "A strategically crafted heap layout can produce
  full RCE."
=> For prod 8083: producer = our OOM fatal (confirmed at will); then same
   worker must serve the next request; consumer ops pre-init = body parsing,
   session/progress handler, error handling. Craft the heap in request N+1's
   multipart BEFORE the consumer fires (it's in request startup = our POST
   body shapes!). The advisory literally says the attacker's body parses
   before init consumes the stale state.

## Immediate fire-able synthesis for 8083 (stock-ish settings path):
A) OOM WITHOUT dir limit: thousands of tiny headers per part + nested names
   (strategies 2+4) at 128M.
B) On the fatal request + immediately-following requests on same worker:
   interleave crafted bodies so the N+1 startup parser allocates OUR sizes
   into the freed window (619 groom = OUR OWN REQUEST BODY allocations,
   happening in exactly the pre-init consumer window!).
C) Watch for: wrong-content responses, cross-session bleed, segfaults,
   double-fatal, /CANARY leak. uid= = sub-canary win.

## 16:5xZ UPDATE: daubois.dev insider post distilled -> research/shared/DAUBOIS-KEYPOINTS.md
Key: 618 = pure allocator OOM (sessions irrelevant); vendor validated mod_php
RCE at DEFAULT 128M; exact zend_mm_safe_error jump site; patched residual =
real mmap() failure still old path; final fix sha 01a40e89fbfc; FPM/
FrankenPHP in-scope-without-public-exploit = differentiation lane.
