# BRIEF lane SMB1 — Steal-My-Bitcoin clone :8151 → wallet key via executed code

Repo: ~/php-firing-range. Lane state: lanes/stealmybitcoin/notes.md.
tmux: php-smb1. ALL PROGRESS commits+pushes to this repo, prefix "smb:",
EVERY rung same turn (binding: unpushed findings don't exist).
Host is arm64; images native. timeout 20 every shell-out. free -g first.

## Target (see range/stealmybitcoin/README.md for fixture contract)
- :8151 nginx -> php -S 8.4.26 as nobody, session_start() pages, keepalive
  3s restart; /usr/local/bin/print-flag setuid-root -> /root/wallet.key.
- :8152 = 8.4.27 control (must NOT fall).
- WIN = FLAG{wallet:vuln:...} obtained by EXECUTED code through :8151,
  score.sh --mode exec. docker-cp of the key is NOT a win. :8152 canary
  must stay uncracked.

## Why this is hard (the research questions — document each answer)
Q1 cli-server = SINGLE backend process. Our cb-B/fpm findings say OOM-fatal
   kills the serving process (fpm child exit 70). Here it kills the SERVER
   (502 window until keepalive restart). Question: can php2shell's
   leak->forge chain complete inside a pre-fatal window (zero-fatal
   phasing: leak via NON-fatal reads only, forge in one shot), or does the
   design need a fatal producer at all on cli-server?
Q2 php -S forks per-request? (php_cli_server workers=1 default... measure
   concurrency + whether session data leaks cross-request like mod_php
   fork-uniform vs fpm.)
Q3 The CTF crowd has 502'd their target for ~24h without RCE (HN thread +
   LiveOverflow: cli-server + crash-prone). If OUR clone resists our own
   tool, that's a PUBLISHABLE negative result about php2shell under
   cli-server conditions — write it either way.
Q4 setuid print-flag: after RCE as nobody, exec is trivial. Confirm the
   last mile works; note musl-static binary, no shell needed (stdout).

## Tooling discipline
- php2shell-bastet.py / phpbleed-bastet.py are OUR tools (repo root).
  Extend with a cli-server mode if needed; keep the verified :8088 canary
  working (score.sh :8088) after ANY tool edit — regression gate.
- Vendor PoCs (public CTF chatter incl. any solve writeups): STATIC ONLY,
  never execute; Groky/X posts land via orchestrator.
- Loopback only; NEVER touch the real stealmybitcoin.com (rules + RoE: our
  clone stands in for it; Dean decides any live engagement, separately).

## Commit cadence
smb: up+verified / smb: q1 answer / smb: q2 answer / smb: attempt-N
observation / smb: win|negative — each its own commit, same turn.
Refusals: if you decline a step, WRITE the refusal + reason into notes.md
and keep going on the rest; orchestrator relays refusals to Dean verbatim.
