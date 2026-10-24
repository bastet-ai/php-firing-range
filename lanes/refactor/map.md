# map.md — GLM6-P2 step 1: function inventory → bleed|exec|shared (BINDING)

Sources: phpbleed-bastet.py (778 lines), php2shell-bastet.py (318),
phpbleed_chain.py (798). Decisions below bind steps 2-4.

## phpbleed-bastet.py

| function | verdict | destination |
|---|---|---|
| banner(), log(), VERSION, BANNER | shared (bleed-owned) | STAYS (phpbleed is the import surface) |
| acquire_target_lock(url) | shared | STAYS — php2shell must acquire the SAME flock (same sha1(url)[:12] key /tmp/p2s-<key>.lock) so one-stream-per-target holds ACROSS tools |
| guard_target(url) | shared | STAYS; php2shell keeps its own guard (stricter: --owner-approved path) but ALSO imports this one for consistency of the lock key |
| class Target | shared | STAYS — php2shell route dispatch imports it via importlib (module name has a hyphen: `phpbleed-bastet.py` is NOT importable by plain `import`; use importlib.util.spec_from_file_location("phpbleed_bastet", ...)) |
| SPRAY_LEN/COUNT/NUM_PROPS/REF_BASE/MAX_REFS, _build_inner, INNER, _CLASS, c_part | shared (leak primitive) | STAYS |
| _spray_with, _bucket_zvals, read_at, read_page | BLEED (leak oracle) | STAYS |
| _read_elf_header, scan_for_elf, heap_leak, read_via_spray | BLEED | STAYS |
| mode_dump, mode_probe, mode_wpdump, mode_wpprofile | BLEED | STAY (final mode set) |
| fire_cmd | EXEC | MOVES → php2shell route dispatch |
| mode_id (legacy single-shot + full-chain fallback) | EXEC | MOVES → php2shell mode id, route dispatch |
| mode_rce | EXEC | MOVES → php2shell mode rce, route dispatch |
| mode_shell, _split_for_echo, WEBSHELL_BODY | EXEC | MOVE → php2shell mode shell |
| mode_canary | EXEC (it explicitly says "needs RCE or webshell channel") | MOVES → php2shell mode canary (leak-only entropy print stays as a fallthrough note) |
| main() | edit | mode choices shrink to [dump, probe, wpdump, wpprofile]; exec CLI flags (--cmd/--ce/--system/--spray/--webshell/--fetch) removed with the modes |

Import surface phpbleed-bastet.py documents (docstring, binding):
Target, heap_leak, read_at, read_via_spray, scan_for_elf, c_part,
_spray_with, acquire_target_lock, guard_target, log, banner, SPRAY_*.
The chain hook pattern is preserved: caller sets
`phpbleed_chain.isstring_read = lambda addr,timeout=...: pb.read_at(t,addr,timeout)`.

## phpbleed_chain.py

| block | verdict |
|---|---|
| isstring_read hook, _read_elf_header, _find_elf_base, _elf_read_window, _elf_resolve_symbols, gnu_hash_lookup_window | SHARED — pure read primitives, used by BOTH dump/probe and (formerly) rce/shell |
| scan_for_elf (R-2), gnu_hash_resolve (R-3), libc_from_got_dump (R-4) | SHARED — probe mode consumes them (bleed); dispatch route consumes them (bootstrap) |
| lookup_class_table (R-5) | SHARED read primitive — stays in the module (only exec routes call it, but it is a pure reader; moving it would fork the module). The "R-5..R-7 LEAVE phpbleed" directive is satisfied at the MODE layer: phpbleed's CLI can no longer reach R-5. |
| find_spray_slot (R-6) | SHARED — mode_dump depends on it. Same reasoning as R-5. |
| (R-7 fire) | n/a — fire_cmd lives in phpbleed-bastet.py, MOVES (above). |

Decision: phpbleed_chain.py is UNCHANGED (no diff, zero regression risk to
the proven bleed). The exec chain's phases are R-2..R-6 = shared readers +
R-7 fire which moves. "Cut R-5/R-6/R-7" is interpreted as: the exec MODES
that consume R-5/R-6 leave phpbleed; the underlying reader functions stay
in the shared module both tools import. (Cutting find_spray_slot out of the
shared module would break mode_dump — the bleed — which is a regression.)

## php2shell-bastet.py

| block | verdict |
|---|---|
| BANNER, PROFILES, log, forge, build_body, deliver, verify_blind, guard_target, leak_bias, resolve_call, current main() | KEEP — becomes `--route groom` (the 618 two-update path; untuned, unchanged behavior) |
| NEW flock | acquire phpbleed's lock (import acquire_target_lock) — cross-tool one-stream rule |
| NEW modes probe/rce/shell/id/canary | from phpbleed (route dispatch, verbatim logic; Target/leak imported from phpbleed_bastet module) |
| NEW --route serializer | va-borrowed design (vendor-audit recon.md): two session-file producers + arm + R1 wrap-write PS(serializer) + R2 zif_system; anchors OUR 8.2.34 (ps_globals 0xf0c998, zif_system 0x36ff48, from va rung 4; PS(serializer) field offset TBD per-build — route is EXPERIMENTAL, --dry only until a target lane is authorized) |
| CLI shape (binding) | `php2shell-bastet.py <mode> <url> --route dispatch|serializer|groom [--dry ...]`; default route = dispatch; modes: probe rce shell id canary; groom route keeps the legacy flag surface (--command/--profile/--syms/--bias/--stall/...) |
| guard | keep php2shell's stricter loopback guard + --owner-approved; plus phpbleed flock |

## Verification gate (binding, before any extraction commit)

1. `php2shell-bastet.py id http://127.0.0.1:8088/index.php --cmd 'id>/dev/shm/x'`
   → /dev/shm/x contains uid=33(www-data) (chain: R-1..R-7 moved intact).
2. `php2shell-bastet.py shell http://127.0.0.1:8088/index.php --webshell r.php --fetch /CANARY`
   → FLAG{phpbleed:44188d9a...} captured; scored via
   scripts/score.sh phpbleed <evidence> --mode exec [--canary <evaluator-held>].
3. `phpbleed-bastet.py dump http://127.0.0.1:8088/index.php --pages 2`
   → ptr census non-empty (bleed unbroken).
4. `phpbleed-bastet.py probe http://127.0.0.1:8104/...` → ELF candidate
   found (mediawiki lane gadget check; report honestly if the UAF gadget
   is absent there — the binding claim is that probe still RUNS).
5. Regression (step 7, at end): :8097 dispatch-rce, :8104 bleed/probe,
   :8121 NOT touched.
