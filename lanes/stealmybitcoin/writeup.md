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
to — a two-way oracle: `R:N` resolves forged zvals AND `serialize`
echoes groom-addressed memory into the session file.

## Chain (php2shell-bastet.py --route smb, modes leak|exec)

1. PRODUCER REMNANT: staged 75MB session string + tiny multipart ->
   ps_read OOM mid-decode inside the update path; BG(unserialize) keeps
   {d, 1} (request-level fatal, process survives).
2. GROOM: single-read <=5120B multipart value `g` lands its VALUE part
   at d = fake php_unserialize_data. Header/entries on page0 (decode-time
   only); ALL forged structures on PAGE 1 — the 0x40-class bin carve
   writes chain ptrs at [0x40k,+8) and shadow ptrs at [+0x38,+0x40) on
   page0 only.
3. BASE LEAK (mode leak): page0 slot0 holds a real zend_array whose own
   bytes are a zend_string read header (len=nTableSize=16 @d+0x20,
   val=d+0x28); a fake {d+0x10, IS_STRING_EX} zval at entries data[2]
   makes the writeback echo 16 bytes at d+0x28 = [q0, pDestructor].
   pDestructor = base + 0x63052c (constant across ASLR re-rolls;
   self-checked via the low-16-bit ASLR-invariant fingerprint 0x052c +
   64KB-aligned base — KillaBoi-design validation adapted to this
   64KB-aligned build). One request, in-band, no crash scanning.
4. EXEC (mode exec): session `x|R:3;y|R:4;` — x resolves a FAKE
   IS_REFERENCE zval; serialize's struc lands at groom-known REF.val
   (a fake zend_execute_data: num_args=1, arg1 = command zend_string);
   the fake ce->serialize = base + 0x4238b0 (zif_system, byte-pattern
   offset match) => `system(cmd)` with retval write going to a real
   stack address and a non-SUCCESS fallthrough to the clean "N;" branch.
   The command stages print-flag output as a VALID session file; the
   post-dispatch VM crash (502) is irrelevant — execution already ran.
5. WRITEBACK ECHO: a plain multipart with the staged sid session-decodes
   the exec-written file; the file-data update's session WRITEBACK
   re-encodes it — `x|s:50:"FLAG{...}"` in-band, 200 OK.

## Channel honesty

Docker exec is used ONLY as lab hands (staging session files, /proc
maps instrumentation for cross-checks). The WIN channel is pure
in-band HTTP: request 2's writeback echo, scored with
`scripts/score.sh smb-vuln <evidence> --request <capture> --mode exec`
— anti-echo verified (flag absent from the request capture).

## Provenance of the rungs

- Oracle live: attempt-7 (commit 093e110) — arbitrary read through :8151.
- Base leak live: attempt-9 (dfc42e4) — pDestructor anchor 0x63052c.
- RCE win: attempt-10 (7ac24d9) — scripts/smb_rce1.py, scored
  smb-vuln-2026-10-26T00:46:06Z.
- TOOL PROMOTION (this rung): chain promoted into php2shell-bastet.py
  (`--route smb`, modes leak+exec, cli-server auto-detect via the
  response `Host:` header hallmark); :8088 phpbleed canary regression
  gate held first (scored phpbleed-2026-10-26T02:56:10Z --mode exec);
  win RE-EARNED through the tool against a FRESH canary — scored
  smb-vuln-2026-10-26T03:01:19Z --mode exec anti-echo verified. The win
  now belongs to php2shell, not to the one-off script.

## KillaBoi PoC reconciliation (READ ONLY)

Their public PoC was read for design, never executed. Stage map:
EXHAUST=our producer remnant; 256B cookie leak=our writeback oracle
(theirs is 1-way, ours 2-way); zval_ptr_dtor leak=our pDestructor
anchor; their 384B HashTable cleanup-path forge is engine-closed here
(their destroy-gate equivalents all nest at unserialize level>=2 on
this surface). Adopted: low-N-bit ASLR-invariant fingerprint +
all-alignment candidate scan (with our 64KB-granularity correction),
worker-lottery retry envelope, fresh-nonce evidence keys. Not adopted:
socket-open response (our writeback echo is superior on this lane).
