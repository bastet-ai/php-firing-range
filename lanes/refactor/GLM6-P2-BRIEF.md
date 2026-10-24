# BRIEF glm6-P2 — REFACTOR: php2shell owns RCE, phpbleed just bleeds

Dean's directive (24-Oct, verbatim intent): "move all rce functionality to
the php2shell and simplify the bleed script to just bleed. Borrow what you
must" (the Percivalll audit you just finished is the source of borrowed
designs — designs, not executed vendor code; that rule holds).

You are the right lane for this: you reconstructed their pipeline in
lanes/vendor-audit/recon.md and know our chain's stage proofs.
Repo: ~/php-firing-range. Commit "refac: ..." per step. Never touch
race-glm4's live files (lanes/race-618/glm4/) or fire :8099.

## Target architecture (binding)

phpbleed-bastet.py  = BLEEDER ONLY:
  keep: dump, probe, wpdump, wpprofile, canary-READ via disclosed string?
  NO — canary/id/rce/shell ALL leave. Final modes: dump, probe, wpdump,
  wpprofile (+ helper plumbing those need). The R-1..R-4 leak phases STAY
  (that's the bleed). R-5..R-7 (forged dispatch) LEAVE.
php2shell-bastet.py = THE RCE TOOL (all execution capability):
  modes: probe / rce / shell / canary / id  (plus --dry)
  routes (ordered):
    r1. phpbleed-dispatch (the R-5..R-7 chain moved verbatim from
        phpbleed-bastet.py + phpbleed_chain.py — proven on :8088/:8097;
        MUST re-verify on :8088 after the move: canary + id)
    r2. va-serializer (borrowed design: fake ps_serializer entry,
        decode=zif_system; our 8.2.34 anchors already derived:
        ps_globals f0c998, zif_system 36ff48 — from va rung4)
    r3. 618 two-update groom (existing php2shell groom code path, keep
        working, still needs heap tuning — fine)
  shared leak bootstrap: php2shell may IMPORT phpbleed's leak functions
  (phpbleed stays importable as a module — its bleed IS the leak-first
  bootstrap) OR vendors a thin leak client. Import preferred (no dup).

## Work order
1. Inventory: map every function in phpbleed-bastet.py (778 lines) to
   bleed|exec|shared; same for php2shell-bastet.py (318) +
   phpbleed_chain.py. Write lanes/refactor/map.md. Decisions in the map
   are binding for steps 2-4.
2. Extract: cut R-5/R-6/R-7 + mode_rce/mode_shell/mode_id/mode_canary +
   fcall_info/serializer shaping from phpbleed into php2shell as route r1
   (name it --route dispatch). phpbleed keeps its banner+loopback guard,
   loses exec modes, gains --bleedonly default behavior; module import
   surface documented in its docstring.
3. php2shell absorbs: --route flag (dispatch|serializer|groom), default
   dispatch; banner states RCE ownership; flock kept (same lock key per
   target so the old one-exploit-stream rule holds ACROSS both tools).
4. VERIFIED-BEFORE-COMMIT rule: after extraction, run against :8088:
   python3 php2shell-bastet.py rce http://127.0.0.1:8088/ ... (your
   flags) -> expect uid=33 + canary FLAG{phpbleed:44188d9a...} via
   scripts/score.sh --mode exec; and phpbleed-bastet.py dump on :8088
   still bleeds (ptr census non-empty) + probe on :8104 works.
   A step that regresses the proven :8088 RCE = fix before next commit.
5. va-pin integration (scripts/va_pin.py per adaptations.md #1): fire
   standalone on :8088 under loadprobe-style flood; report delivered-N/N.
   Wire as php2shell --pin option ONLY if it verifies (else leave as
   script + note).
6. Update: README section (tools table), TODO.md priority order (RCE
   final-mile now lives in php2shell --route serializer line), and
   lanes/race-618 notes pointer so glm4 revival finds the new shape.
7. Regression matrix at the end (log all): :8088 dispatch-rce, :8097
   dispatch-rce, :8088 bleed, :8104 bleed/probe, :8121 node-lane NOT
   touched (brotli lane, unrelated).

## Ops
timeout 20 every shell-out; docker exec only on OUR range containers;
small turns (pi wall/Venice streams); git pull --rebase before push;
stuck 45min -> BLOCKED note + rotate to next work-order step.
Your notes: lanes/refactor/notes.md (cold-revival quality).
