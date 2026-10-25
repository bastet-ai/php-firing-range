# Lane SMB1 notes — stealmybitcoin clone :8151 vuln / :8152 ctrl

Rung log. All commits prefixed `smb:`. Canary replant 2026-10-25 19:0x
(orchestrator-verified containers were recreated afterwards; /root/wallet.key
gone from BOTH php containers + results/canaries/smb-*.flag missing ->
replanted exactly per range/stealmybitcoin/up.sh, print-flag re-verified
as nobody on :8151-equivalent and :8152-equivalent containers).

## Q2 ANSWER — is `php -S` fork-uniform? (measured, benign: scripts/smb_q2_cli_server.py + smb_q2_followups.py, raw log q2-cli-server.log)

NO — and the question dissolves: cli-server does not fork at all.

1. PROCESS MODEL: single process, single thread (Threads: 1), PID stable
   across every request (pid 7 unchanged through the whole series; no
   children during a trickling request; PHP_CLI_SERVER_WORKERS unset =
   no worker pool). NOT mod_php fork-uniform (nothing shares a post-fork
   layout) and NOT fpm (no per-child recycling): ONE long-lived process,
   heap + ASLR set once at exec.
2. CONCURRENCY: requests fully SERIALIZED. 8MB POSTs direct at phpsrv:
   n=1 63ms, n=4 167ms, n=8 327ms (≈41ms/req regardless of parallelism;
   extra connections queue in backlog). No concurrent request pairs are
   possible -> no cross-request races; also producer/consumer "same
   child" pinning is trivial (every request is THE process), but a
   stalled request BLOCKS the whole server.
3. ASLR (assisted /proc reads via SYS_PTRACE helper; in-container root
   lacks CAP_SYS_PTRACE — wpbleed helper precedent): PIE base of
   /usr/local/bin/php CONSTANT across the request series
   (0xb1c553e60000 through 15 benign requests + multiparts); re-rolled
   at every exec: 3 keepalive restarts -> 0xaafea5690000,
   0xb4c08dc30000, 0xb0b85a940000. Recovery after pkill = ~3.2s end-to-end
   (keepalive sleep 3 + spawn).
   Q2->Q1 LINK: a crash-oracle bias brute is STRUCTURALLY IMPOSSIBLE on
   cli-server — every bad forge kills the process and the next exec
   re-rolls the bias; you can never test a base twice against the same
   layout. Any forged-pointer chain must leak the bias non-fatally and
   land before the next crash — or find a channel that survives death.
4. HEAP: single arena lives across requests; RSS stable ~23MB
   (allocator reuse, no per-request reset). Cross-request grooming is
   deterministic (serialized requests on one arena) — unlike fpm's
   which-child uncertainty.
5. SESSION SURFACE: session_start pages create /tmp/sess_* as nobody:600;
   upload_progress.enabled=On, cleanup=On, freq=1%, min_freq=1s, FILLUNIT
   chunking (rfc1867 update callbacks fire per 5120B of file data).
   Benign observability NIL at the file level: progress data never hits
   the session file mid-flight (memory-only until shutdown; cleanup wipes
   the key before write). The 619 decode path is only provable via the
   fatal producer (Q1) or in-memory reads.
6. FIXTURE REALISM — stock nginx defaults measured on :8151, likely the
   real crowd-blockers on the live CTF too:
   a. client_max_body_size = 1m (default): 1.5MB POST -> 413 from nginx,
      php never sees it. 0.9MB passes fine.
   b. proxy_request_buffering = on (default): during a 4s mid-body
      pause there is NO ESTABLISHED connection to phpsrv:8080 (only
      TIME_WAIT) -> nginx swallows the whole body before contacting
      upstream. Attacker-controlled mid-request STALLS DO NOT REACH php
      through :8151. => the groom route's 1.4s two-chunk stall (its
      618 double-update timing primitive, >min_freq gap) is DEAD through
      nginx: php parses the whole multipart in one burst, second
      rfc1867 update is min_freq-throttled, no dtor, no UAF.
   c. => the only live producer through :8151 is the 619 session-decode
      path (staged session file, tiny request, no timing dependence).
      Direct-at-phpsrv attacks (no buffering, no 1MB cap) need a network
      position inside the compose — out of scope for the modeled
      remote attacker.

## Q1 — can php2shell land without killing the server? (in progress)
Next: fatal-window measurement (619 OOM producer -> 502 window, bias
re-roll confirmation, stale-state death), then zero-fatal phasing.
