# adaptations.md — VA rung 7b: superior mechanisms adapted to OUR chain

Design + code sketches only. NO changes to live lane scripts this turn.
Target lanes for adaptation: our own x86_64 apache lanes (phpbleed:8088,
bleed82:8089, wordpress-x86:8099 — careful, 8099 lane scheduling), the
ARM64 MW :8104 lane is glm5's; coordination required before firing.

## Adaptation 1 — chunked-POST worker pin (from their pin_adaptive.py)

PRIORITY: HIGH. Solves the cb-B under-load wall (0/15 at 30-concurrent;
glm5 24-Oct) and makes every consumer/producer fire land on ONE known
child. Replaces flood-noise as a variable in ALL our oracle designs.

Design (their pin_adaptive.py, adapted):
- open pins: POST / with `Transfer-Encoding: chunked`, send ONE 4KiB
  chunk, never the terminating 0-chunk; keep-alive headers.
- probe: GET a STATIC file (their choice /readme.html; ours: any
  non-php asset on the lane, e.g. /favicon.ico) with 1s timeout.
- saturate: open pins until probe times out = all workers busy.
- free exactly one: close pins tail-first, probing after each close;
  first successful probe = exactly one free worker.
- maintain: resend 4KiB/s per pin (8x Debian mod_reqtimeout minrate
  500B/s); log "dropped" count; on drop, worker count is no longer
  exact → re-run the free-one procedure.

Sketch (drop-in module for scripts/, integrates with our flock tooling:
take the target's flock as usual, then pin inside it):

```python
# scripts/va_pin.py  (adapted from pin_adaptive.py, static audit only)
def pin_and_free_one(port, max_pins=300, hold=600):
    pins = []
    for _ in range(max_pins):
        pins.append(open_pin(port))          # unfinished chunked POST
        time.sleep(0.02)
        if not probe(port):                 # static-file GET, 1s
            break                           # saturated
    while pins:
        s = pins.pop(); s.close(); time.sleep(0.05)
        if probe(port):
            return pins                     # exactly one free worker
```

Our-stack deltas vs their code:
- KeepAliveTimeout/MaxRequestWorkers differ per lane → always use the
  ADAPTIVE mode (never hardcode 149; our lanes run 5-8 children, so
  the pin cost is 4-7 sockets, trivially cheap — our cb-B "under load"
  problem was 30-concurrent; the pin is ~7 concurrent of a different
  kind).
- fpm lanes: pins still work (busy children not reaped), but our fpm
  children EXIT on the fatal (code 70, glm5) → after each producer the
  free worker is reforked by pm, pin invariant holds; stale-global
  persistence still fails on fpm regardless (their caveat too).
- Interaction with our producer: our OOM producer runs on the free
  worker; pins in other children are untouched by the fatal; rotate
  equivalent = our walk oracle becomes unnecessary on pinned lanes
  (R:n self-resolve was our answer to the lottery; with a pin, consumer
  fires go straight to the marked child).

Verification plan (when firing is authorized): pin :8088, fire producer
+ consumer N times idle and under flood; expect delivery N/N (vs 0/15
baseline). Then repeat on a WP lane with 128M stock INI.

## Adaptation 2 — stale-PS(id) Set-Cookie OOB leak (from their b_leak20.py)

PRIORITY: MEDIUM-HIGH. Use as a BOOTSTRAP leak to replace/augment the
N-oracle's discovery phase (N-oracle stays for arbitrary qwords).

Design: their A (stale PS(id) groom, ~66MB multipart; on our lanes our
existing producer shapes already leave stale state — test whether OUR
producer's stale PS(id) is reclaimable the same way) then B (31×32B
bin7 names + 63B value forging len at value+0x10... careful: their
63B value's +0x10 is the NEXT slot's zend_string.len — rederive per our
8.2 heap geometry; our gotchas #7-#10 apply) → 4096B Set-Cookie window
in one 200. What we get per fire: contiguous window incl. libphp base
anchors AND the chunk → replaces the a2 /proc-assisted bias discovery
(TODO priority 3) with a fully-remote bootstrap.

Sketch: port b_leak20.py's request shape into scripts/va_leak.py using
our wpfire.py transport (honest-transport harness), B_PATH=/ (our
lanes' entry script), parse with their 16-offset vote minus their
build-specific offsets — SUBSITUTE our own anchor offsets derived per
lane (arm64: basic_globals 0xf1e748 etc.; x86 8.2: ps_globals 0xf0c998,
zif_system 0x36ff48 — anchors must be measured per build, never
copied).

Caveats to carry: their window depends on op_array-at-chunk-head (leak
before entry-script execution / opcache zeroing); our lanes' entry
scripts differ (lab.php vs index.php) — the first-B-miss pattern is
expected; retry in place on the PINNED worker (Adaptation 1 makes
"in place" reliable).

## Adaptation 3 (stretch) — fake ps_serializer RCE route as an alternative last mile

PRIORITY: WATCH. Our phpbleed forged-fcall_info dispatch is one
calibration away (per-child session-buffer page); if that wall persists,
their serializer route is a credible plan B with FEWER primitives:
needs ps_globals .bss (verified writable on our 8.2.34), zif_system
(verified 0x36ff48), a 30MB-class session-file producer (their chunked
post_max_size bypass), and the var_push wrap-write. Derive OUR
PS(serializer) field offset from our 8.2.34 php_session_globals layout
(their +0x148 is 8.3.35) before any design commitment. Do NOT fork
effort from TODO priority 1 unless calibration fails twice more.
