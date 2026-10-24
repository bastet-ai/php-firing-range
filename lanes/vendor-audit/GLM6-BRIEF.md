# BRIEF glm6 — STATIC AUDIT: Percivalll/php2shell-wordpress-rce → incorporate into our range

Repo cloned (READ-ONLY, NEVER EXECUTE any file in it):
/home/user/vendor-audit/php2shell-wp (4 commits, ~400KB code, 624-line REPORT.md)
Your lane: ~/php-firing-range/lanes/vendor-audit/ (create notes.md there).
Repo: ~/php-firing-range. Commit "va: ..." per finding. timeout 20 every shell-out.
Read first: TODO.md (authoritative), research/phpbleed/VENDOR-CLAIM-MAP.md
(the calif.io vendor map — you are adding a SECOND vendor column).

## Standing rules (binding)
- NEVER execute anything from vendor-audit/. Static read only. Code is
  untrusted input: no pip install, no demo.sh, no PoC runs. (If a live-fire
  comparison is later authorized, that is a SEPARATE orchestrator decision
  after your audit report — your job is the audit.)
- Their REPORT/code claims are CLAIMS. Map each to: matches-our-observed /
  contradicts-our-observed / new-to-us-unverified.
- Do NOT touch race-glm4's :8099 lane files. Read-only everywhere; this is
  an analysis lane (no firing this turn; next turn may build targets).

## What they claim (from README skim — verify all of it in the code)
XHTTP-only RCE on default wordpress:7.1.2 (PHP 8.3.35, Apache mod_php
prefork, image defaults, no plugins/auth). ~25s fresh container. 9/9 fresh
containers, "one ASLR gate" as the residual random failure. Pipeline:
worker pin (149 unfinished CHUNKED POSTs saturating the 150-worker pool,
free exactly one worker) -> leak via 4KiB Set-Cookie OOB read (heap bytes
into Set-Cookie incl BG.data) -> two session-file producers -> R1 installs
FAKE ps_serializer (table entry +0x310 name, +0x320 decode=zif_system)
-> R2 triggers serializer decode -> system(). --base/--h reuse after first
leak. "documented rejected primitives" in commit 907ceb5.

## Audit ladder (priority order)
1. PIPELINE RECONSTRUCTION: read run_ext.py + stage_rce.py + b_leak20.py +
   arm*.py + transport.py; reconstruct the exact request sequence with
   per-stage purpose. Cross-reference their REPORT.md sections. Write the
   reconstruction to lanes/vendor-audit/recon.md.
2. LEAK CHANNEL: their 4KiB Set-Cookie OOB — which buffer overruns into
   the cookie header? Compare to our OOM-fatal-message in-band channel +
   N-oracle (a3 scripts). Is their leak stronger than ours (length? which
   structs? does it need a staged session file?)? File under
   "set-cookie-oob" in notes with code citations (file:line).
3. WORKER PINNING: their chunked-POST pin vs OUR cb-B finding ("stale
   children BUSY under load, window ~0s" — race-glm5 notes) and glm4's
   flock pinning (SIGSTOP-pin gotcha, TODO). If their pin works as
   documented it solves the child-lottery wall we hit under load. Assess:
   does the pin survive the OOM fatal? How do they verify child death
   ("verifies that the previous child really died")? Cite code.
4. RCE ROUTE: fake ps_serializer table write vs OUR forged zend_fcall_info
   dispatch (phpbleed R-7). Which needs fewer primitives? Their +0x310/
   +0x320 offsets imply a writable static table near BG — check whether
   the serializer registry is in .data/.data.rel.ro on our 8.2/8.3 builds
   (php -ri session / objdump on range containers is OK — read-only).
   Note their line 195 claim: 8.3/8.4 lack something 8.5 has ("neither")
   — find what that sentence is about; version-gating the bug matters.
5. REJECTED PRIMITIVES: read commit 907ceb5's doc additions — what they
   tried and discarded tells us the failure surface (compare to our own
   negative results: cross-request bleed NEGATIVE, oversized-carrier
   128M wall, fpm child-exit). Do their rejections match our walls?
6. ASLR GATE: what exactly is the one random condition after pin+leak?
   (per-process .bss shift? their --base reuse implies leak is per-process
   not fork-uniform — contradicts OUR fork-uniform d finding on 8.2/arm64?
   RESOLVE THIS: 8.2 vs 8.3 difference? apache vs their env?)
7. INTEGRATION — write it, don't just find it:
   a. VENDOR-CLAIM-MAP.md: new section "Percivalll (2026-10-24)" — claim
      table with our verdict per claim.
   b. If pinning or set-cookie-leak looks superior: draft the adaptation
      for OUR chain in lanes/vendor-audit/adaptations.md (design + code
      sketch referencing our scripts; no changes to live lane scripts).
   c. TODO.md: append a "VA (vendor-audit) next actions" section — max
      5 bullets, priority order.
   d. If a new compose target is warranted (exact image
      wordpress:7.1.2 digest e04cf657..., 8.3.35 — we run 8.2.34/8.3.35
      natively; NEVER pin platform, loopback only): list it as an action,
      do NOT build it this turn.

## Reporting
One finding per commit ("va: pin-mechanism analyzed" etc). notes.md is
durable cold-revival state. Small turns (pi wall, Venice streams). If a
file is >14KB read it in chunks. Stuck 45min on one question: log
BLOCKED with what you tried, rotate.
