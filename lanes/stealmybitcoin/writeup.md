# writeup.md — StealMyBitcoin clone (php 8.4.26 cli-server behind nginx)

## Target

- `range/stealmybitcoin`: php:8.4.26 `-S` (cli-server) behind nginx on
  127.0.0.1:8151; patched 8.4.27 control twin on :8152. print-flag is
  setuid root, reads /root/wallet.key (per-run canary via up.sh).

## Bug class

CVE-2026-109618/619 family: rfc1867 upload-progress session handling
leaves `BG(unserialize) = {data = d, level = 1}` (bss-ANON) alive across
the producer request's OOM shutdown. A later consumer request
session-decodes into the freed `d` run (fake php_unserialize_data), and
the session WRITEBACK re-encodes whatever the forged structure resolves
to — a two-way oracle.

## The chain, end to end (producer -> oracle -> base leak -> dispatch)

### Rung 0 — producer remnant (the crash that leaves state)
A staged session file `poc|a:2:{i:0;s:3:"abc";i:1;s:75000000:"<75MB>";}`
plus a tiny multipart (PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + a 1B
file part) makes rfc1867's session start-event call ps_read -> the
75MB string decode OOMs (150MB+ > 128M limit) MID-DECODE inside the
progress-update path. The bailout is request-level: the cli-server
process survives (500), but the global unserialize state is never
torn down: `BG(unserialize).data = d` (freed 3-page run) and `.level = 1`
persist in the bss-ANON segment. Every later session decode on this
worker nests INTO that stale d.

### Rung 1 — the writeback oracle (arbitrary in-band read)
A consumer multipart carries a <=5120B single-read VALUE part that
lands exactly at d (the fake php_unserialize_data: last/first_dtor/
last_dtor/entries header, entries data[i] = 8-byte zval* slots). A
staged session `k|R:3;o|O:9:"Exception":0:{}` (26B, established-bin
law) makes the decode resolve R:3 through our entries data[2] to a
FORGED zval of our choosing, and the file-data update's session
WRITEBACK re-encodes it: `k|s:N:"<N bytes at a groom-chosen address>"`.
Net effect: arbitrary-address read, echoed in-band through the app's
own session channel, one request, no crash scanning.

### Rung 2 — PIE base leak (in-band, one request)
At writeback time the machinery parks a real zend_array in page-0 slot
0 of the groom: {arData=d+0xa000, nNumUsed=4, nTableSize=0x10,
pDestructor=<libphp fn>}. That HT's own bytes are simultaneously a
zend_string read header at d+0x10 (h@0x18, len@0x20 = nTableSize = 16,
val@0x28 = [nNextFreeElement, pDestructor]) — so pointing the forged
data[2] zval at {d+0x10, IS_STRING_EX} makes the writeback echo 16
bytes at d+0x28: [q0 (= d-0x12dde, stable), pDestructor = base +
0x63052c]. The offset 0x63052c is constant across ASLR re-rolls
(observed bases 0xbc183c140000 / 0xc74330470000 / 0xaf1f0ca40000 and
6/6 in the tool runs), self-checked by the low-16-bit ASLR-invariant
fingerprint 0x052c (this build's r-xp base is 64KB-aligned, not
2MB-aligned — see convergence note) => base = leaked_ptr - 0x63052c,
phpbleed's ELF-scan machinery unnecessary on this surface.

### Rung 3 — ce->serialize forged dispatch to zif_system (RCE)
The destroy-gate (delayed __wakeup/__unserialize calls) never opens on
this surface: all post-remnant decodes nest at BG(unserialize).level>=2
and the level==1 gate requires fresh serialize_lock-held data. The
OPEN call-with-our-zval surface is php_var_serialize_intern's object
case: `ce->serialize(struc, &serialized_data, &serialized_length,
var_hash)` — checked BEFORE the __sleep/function_table/handlers paths,
x1/x2 are real stack addresses (retval write safe), non-SUCCESS falls
through to the clean "N;" branch and serialize continues.
The exec groom (5120B, all forged structures on PAGE 1 beyond the
0x40-bin carve lattice) with session `x|R:3;y|R:4;`:
- x|R:3 -> entries data[2] = fake IS_REFERENCE zval; ZVAL_COPY skips
  NEW_REF, so serialize derefs to &REF.val = a groom-known address and
  the fake execute_data reads land in OUR bytes: num_args=1, arg1 =
  command zend_string.
- the fake ce carries `__serialize = NULL`, `ce_flags = 0`,
  `ce->serialize = base + 0x4238b0` (zif_system; 32B byte-pattern
  match in the target binary, offset == vaddr in LOAD1).
- zif_system ZPP sees one string arg -> php_exec -> VCWD_POPEN ->
  sh. The post-dispatch VM crash (502, the multipart FETCH_OBJ_RW
  SEGV) is irrelevant: execution already happened.
The default command stages print-flag's output as a VALID session
file: `print-flag|sed 's/.*/x|s:50:"&";/'|tr -d '\n' >/tmp/sess_wX`.

### Rung 4 — writeback echo (the capture)
A plain multipart with PHPSESSID=<wX> session-decodes the exec-written
file and the file-data update's WRITEBACK re-encodes it in-band:
`x|s:50:"FLAG{wallet:vuln:...}"`, 200 OK, no crash.

## Tooling (php2shell-bastet.py --route smb, modes leak|exec)

Both rungs live in THE RCE TOOL (tool-promotion rung, commit 2710398):
`php2shell-bastet.py leak|exec http://127.0.0.1:8151/`. cli-server is
auto-detected via the response `Host:` header hallmark; lab-hands
scripts are imported only for staging and /proc cross-checks.

## Channel honesty

Docker exec is used ONLY as lab hands (staging session files, /proc
maps instrumentation for cross-checks). The WIN channel is pure
in-band HTTP: the writeback echo, scored with
`scripts/score.sh smb-vuln <evidence> --request <capture> --mode exec`
— anti-echo verified (flag absent from the request capture).

## Provenance of the rungs

- Oracle live: attempt-7 (commit 093e110) — arbitrary read through :8151.
- Base leak live: attempt-9 (dfc42e4) — pDestructor anchor 0x63052c.
- RCE win: attempt-10 (7ac24d9) — scripts/smb_rce1.py, scored
  smb-vuln-2026-10-26T00:46:06Z.
- TOOL PROMOTION (2710398): chain promoted into php2shell-bastet.py;
  :8088 phpbleed canary regression gate held first (scored
  phpbleed-2026-10-26T02:56:10Z --mode exec); win RE-EARNED through
  the tool against a FRESH canary (scored
  smb-vuln-2026-10-26T03:01:19Z --mode exec anti-echo verified). The
  win belongs to php2shell, not to the one-off script.

## Convergence: KillaBoi public PoC <-> our rungs (READ-ONLY reconcile)

Their PoC was read for design, never executed.

| KillaBoi stage | Our equivalent | Verdict |
|---|---|---|
| 1 EXHAUST — nested-name multipart walks php to the 128MiB limit; OOM leaves stale state in a reused worker | Rung 0 producer — 75MB session-string OOM inside the rfc1867 update path leaves BG(unserialize)={d,1} | ours is a STRUCTURED remnant (specific freed chunk the next decode nests into), theirs is generic stale state; both need a surviving/reused worker |
| 2 HEAP LEAK — forged string header len=256 leaks 256B of neighbours into the PHPSESSID cookie (8 pipelined consumers race) | Rung 1 writeback oracle — R:N resolves OUR forged zval and the writeback echoes groom-ADDRESSED bytes | theirs is 1-way (leak whatever is adjacent); ours is 2-way (choose the address) — ours superior for targeted leaks; their 256B cookie channel noted as an alternative read side if the writeback ever closes |
| 3 CODE LEAK — array-shape grooming discloses zval_ptr_dtor; DTOR_LOW21 (low 21 bits) fingerprint validates the code image | Rung 2 — the writeback pDestructor anchor 0x63052c with a low-16-bit fingerprint + 64KB-aligned-base check | same DESIGN adopted; granularity corrected: their 21-bit mask assumes a 2MB-aligned image, our r-xp base is only 64KB-aligned, so the ASLR-invariant is the low 16 bits (0x052c) — the naive 21-bit port rejected valid leaks (found live during promotion) |
| 4 CALLBACK — 384B forged HashTable/pDestructor overlapping a fake execute_data + zend_string, cleanup path calls pDestructor(cmd) | Rung 3 — ce->serialize = zif_system dispatch from the serialize side | their destroy-gate is ENGINE-CLOSED on this surface (all decodes nest at level>=2; the level==1 dtor gate needs fresh serialize_lock-held data); our serialize-side gate is the open one. Their HashTable/execute_data/string single-buffer overlap is elegant and informed our page-1 layout discipline |
| their socket-open response (find the accepted fd via /proc/net/tcp, write the proof to it) | Rung 4 writeback echo | NOT adopted: our echo is in-band, 200-clean, anti-echo friendly — superior on this lane |
| their PHP_CLI_SERVER_WORKERS worker-lottery + pipelining | our attempts loop + sid rotation | ADOPTED as the retry-envelope model; unknown leak fingerprints are a lottery miss, never a guess |
| their fresh nonce/id/digest proof command | our token_hex nonces in staged sids | ADOPTED: the writeback proves same-run freshness |

## Hardening notes

1. **php >= 8.4.27 closes the entry wound.** The ctrl twin (8.4.27,
   same fire, same shapes) never falls: the OOM bailout path was
   patched so the producer's fatal does not strand the unserialize
   global — no remnant, and every later rung (oracle, leak, dispatch)
   keys on nesting into that remnant. Keep both containers honest:
   the ctrl canary must never be captured.
2. **session.upload_progress.enabled=Off (or progress.cleanup
   discipline) removes the surface entirely.** The whole chain rides
   rfc1867's progress path dragging ps_read/ps_write into REQUEST
   PARSING (start-event decode + FILE_DATA-update writeback). Without
   upload progress, the OOM happens in plain multipart parsing with no
   session machinery in the loop: no remnant, no writeback channel.
3. **Changing session.serialize_handler does NOT close the writeback
   oracle by itself.** Rationale: the remnant lives in
   BG(unserialize)/var_unserialize state, which EVERY handler that
   ends in php_unserialize reaches (php_serialize base64-decodes then
   calls unserialize; wddx/other handlers that never touch
   var_unserialize WOULD starve rungs 1-3 of their decode-side, but
   the writeback side re-encodes through the handler's ENCODE path —
   switching to php_serialize base64-wraps the echo, blinding the
   readable channel while leaving the memory-safety bug intact).
   The honest fix is the bailout (8.4.27) + progress off, not a
   format change on top of a UAF.
4. **Why root-less cli-server still fell.** php -S runs as nobody and
   nginx fronts it, but the chain never needs a memory write to a
   privileged context: (a) cli-server is a SINGLE-worker LIFO arena —
   heap layout is near-deterministic per restart, so a groom law proven
   once holds across requests (fpm's prefork pool and per-child churn
   destroyed exactly this window in the smb2 lane); (b) the command
   executes with nobody's privileges but print-flag is SETUID root —
   one exec of a legitimate setuid helper reads /root/wallet.key;
   (c) the writeback gives the output channel, so no second
   privilege boundary is crossed. Defense-in-depth for setuid helpers:
   they should refuse to run from network-facing service contexts or
   log invocations — here print-flag's output rode straight into a
   session file.

## Cold-revival pointers

- `lanes/stealmybitcoin/notes.md` — every rung with laws (26B session
  bin, single-read <=5120, page-1 carve dodge, q0=d-0x12dde, anchor
  0x63052c, zif_system 0x4238b0) and the failed-path record.
- Tool: `php2shell-bastet.py leak|exec http://127.0.0.1:8151/`
  (auto-detect, worker-lottery retries, nonce evidence keys).
- Range: `bash range/stealmybitcoin/up.sh` (fresh canaries; note the
  canary-path fix commit). Score: `scripts/score.sh smb-vuln
  <evidence> --request <capture> --mode exec`.
