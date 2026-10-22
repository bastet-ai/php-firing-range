# Lane GLM4: execute TODO.md (the WP last-mile ladder)

You are the sole agent on this lane. The authoritative brief is /home/user/php-firing-range/TODO.md
- read it NOW, plus lanes/race-618/WP-X86-NOTES.md and lanes/race-618/glm3/notes.md.
Everything in "Current state (do NOT redo)" is PROVEN - skip straight to the
ladder checkboxes 1..6.

Target: http://127.0.0.1:8099/ (stock WP 7.1.2, pinned pre-patch php 8.2.34,
PURE stock INIs). Canary /CANARY in container php-firing-range-wordpress-x86-1
(FLAG{wordpress-x86:...}). Docker exec into that container is YOUR LAB HANDS
(staging session files as root, restarts, php -v assertions) - authorized,
this is our own firing range. Never touch any non-127.0.0.1 host.

Work order (from TODO.md):
1. docker cp the lane's libphp out -> lanes/race-618/glm3/bin/libphp-wp-x86.so
2. derive x86_64 8.2.34 offsets from THAT binary (zend_call_function,
   zif_system/zif_readfile, .data.rel.ro candidates; handler@+88, params@+48)
3. port find_fake_func.py aarch64->x86_64 (F=E-64; type!=2, ZEND_ACC_STATIC,
   num_args>=1, by-value arg_info)
4. consumer groom: ~8193B field NAME reclaiming freed 8216B chunk with fake
   php_unserialize_data; keep-alive raw sockets, pauses <5s
5. dup-key token stream -> var_push_dtor into fake var_dtor_entries ->
   zend_call_known_instance_method(ce->__unserialize=F)
6. WIN: readfile("/CANARY") in-band -> scripts/score.sh wordpress-x86 <evidence>

Process rules (hard, from TODO.md): commit+push after EVERY checkbox
(wp-lastmile: <what>); log every fire to lanes/race-618/glm4/fires.log; append
findings to WP-X86-NOTES.md; docker compose restart wordpress-x86 when state
goes weird; pristine session file per round, clean /tmp/sess_*; vendor bundle
stays unexecuted.

Anti-wall-clock rule (pi kills you at 900s per turn): one tool call per turn,
files in <200-line chunks, no giant output turns. You have full bash via your
tools; use short commands. If a push is rejected, git pull --rebase then push.
