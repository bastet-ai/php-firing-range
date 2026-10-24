# REFACTOR POINTER (2026-10-24, GLM6-P2) — read before reviving any race-618 lane

The tool surface CHANGED. If your lane notes reference the old CLI, apply
this mapping:

| old (pre-2026-10-24) | new |
|---|---|
| `phpbleed-bastet.py id ... --cmd/--ce/--system/--spray` | `php2shell-bastet.py id ... --cmd/--ce/--system/--spray` (route dispatch) |
| `phpbleed-bastet.py rce ...` | `php2shell-bastet.py rce ...` (route dispatch) |
| `phpbleed-bastet.py shell ... --webshell --fetch` | `php2shell-bastet.py shell ... --webshell --fetch` (route dispatch) |
| `phpbleed-bastet.py canary ...` | `php2shell-bastet.py canary ...` (route dispatch → shell) |
| `phpbleed-bastet.py dump/probe/wpdump/wpprofile` | unchanged (phpbleed is bleeder-only now) |
| `php2shell-bastet.py <target> --command ...` (618 groom) | unchanged (legacy invocation = route groom) |

Key facts for revival:
- php2shell-bastet.py = THE RCE TOOL; --route dispatch (moved R-1..R-7
  chain, re-proven :8088 + :8097 at refactor time) | serializer
  (EXPERIMENTAL va-borrowed design, --dry gated, needs 8.2.34
  PS(serializer) offset = TODO VA #3) | groom (the 618 path, unchanged).
- phpbleed-bastet.py = BLEEDER ONLY (dump/probe/wpdump/wpprofile) and is
  the importable leak module php2shell uses for dispatch's bootstrap.
- The per-target flock is SHARED and now keyed by scheme://host:port
  (netloc) — the one-exploit-stream rule holds ACROSS both tools.
- phpbleed_chain.py: UNCHANGED (shared R-2..R-6 read-primitive module).
- Full inventory + bindings: lanes/refactor/map.md; run log + regression
  matrix: lanes/refactor/notes.md.
