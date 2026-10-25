Steal-My-Bitcoin-style clone target (:8151 vuln / :8152 ctrl)

Public CTF stealmybitcoin.com (Show HN 2026-10-24) puts a real BTC wallet
behind exactly our chain: nginx -> php -S (cli-server) on PHP 8.4.26
(pre-PHP2SHELL patch; fixed 8.4.27), flag = wallet key readable ONLY via a
setuid `print-flag` binary as the PHP user. Crowd (~HN-scale) has NOT
solved it in ~24h: segfaults observed, no RCE; LiveOverflow's fingerprint
work says surface = cli-server, and the HN thread shows nginx default
config + crash-prone single-process backend as the friction points.

Our clone = the missing production-realism rung for php2shell-bastet:
nginx (stock default site) -> php -S 127.0.0.1:8080 docroot; app pages
mirror the CTF (index + /ping.php POST message=ping->pong + php-version.php
NOT included so the fingerprint stays honest-lab); print-flag setuid-root
reads /root/wallet.key. vuln 8.4.26 (:8151), ctrl 8.4.27 (:8152).
Win = wallet key string via EXECUTED code (php2shell chain or equivalent),
score.sh --mode exec; NOT via docker cp.

Fixture specifics (grounded, in README-of-repo history too):
- ping.php/index.php call session_start() -> serialized session file written
  per request = the CVE-2026-109618 upload-progress surface (session
  decode at start = our fatal-after-serialize producer). Without a session
  surface there is nothing to exploit; a real CTF app surely has one.
- php -S runs as nobody; /root/wallet.key 600 root; print-flag setuid-root
  4755 (static musl). Chain = RCE as nobody -> exec /usr/local/bin/print-flag
  -> key on stdout.
- entrypoint keepalive restarts php -S 3s after death (crash window real).
- no php-version.php (anti-fingerprint realism); nginx stock-ish all-proxy.

Known friction to characterize (all findings push as "smb: ..."):
1. cli-server is single-process: a 618-class fatal KILLS the backend
   (502s) until OP-restart. Our compose replicates with restart policy +
   keepalive loop in the entrypoint. Question: can php2shell land in the
   window, or does the chain need zero-fatal phasing? (Compare our
   mod_php-survives-fatal finding — this is the fpm/cli-exits-the-child
   class at its extreme: exits the SERVER.)
2. Stock nginx default config passes .php only to fastcgi normally; OP
   proxies everything. Read the shape: our clone proxies all to php -S.
3. Rate: HN crowd DoS-crashes the box; we self-inflict load control
   deliberately (rate-limited) to study crash-window exploitability —
   lab-only, that IS the research question (Dean's RoE: no DoS of real
   third parties; our clone, our rules, loopback only).
4. ASLR + multi-worker claims from ToB "production-grade" post remain
   unverified on cli-server: cli-server forks? php -S does fork per-request
   (php_cli_server worker model) — measure.

Public intel to watch (Groky pinged): HN thread, LiveOverflow posts, any
solve writeup — first solve anywhere = study it statically, replicate.
Rules of the ORIGINAL challenge (binding if we ever probe the live site —
we do NOT without Dean's explicit word): web app + print-flag inside PHP
container only; no host/SSH/nginx/third-party attacks; no DoS/persistence.
