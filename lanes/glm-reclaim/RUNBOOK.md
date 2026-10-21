#!/bin/bash
# Post-drop exploit landing runbook (14:00Z+). Read top-to-bottom, execute.
# 1) VERIFY FREE SITE FROM THE PATCH (10 min):
cd /home/user/php-firing-range/research/src/php-src-83
git fetch origin tags 2>/dev/null
# diff 8.3.x -> 8.3.x+1 on ext/session/session.c + main/rfc1867.c:
#   git log --oneline --all -- ext/session/session.c | head
# answers: WHERE does the free fire, and which gate (freq/min_freq/status)
# makes an update free the tree BEFORE the stale store.
#
# 2) GROOM RECIPE (from trace4, findings.md 13:4xZ entries):
#   freed objects at our update: data-array ELEMENTS (32/40B) + Bucket array
#   (272B = 24+8*32; growth 16 buckets = 528B). Zend MM size-cache LIFO:
#   efree(N)->emalloc(N) same slot. t[] packed arrays allocate Bucket arrays;
#   40B-class field VALUES (len 15) allocate 40B strings.
#   Body order (trace-verify each hop on php -S:13999 with P2S_TRACE=1):
#     PHPSESSID field; progress field;
#     file f: fill(5120+64)  [update1 caches ptrs]
#     stall 1.4s (>min_freq)
#     close f; file g data(5120+64) [update2 = the FREEING update (patch
#       confirms gate); g's START/ DATA events fire it]
#     t[] groom AFTER the freeing update: values sized to the freed classes:
#       15B fields -> 40B strings; t[] array sized to realloc a 272B Bucket[]
#     close g; file h data(5120+64): FILE_DATA stale store -> writes through
#       freed, NOW-OWNED zval slots
#   Forge: put the call VA (leaked bias + 0x45bd4c) repeated in field bytes;
#   the store is Z_LVAL_P(ptr)=offset -> if reclaimed slot is a Bucket, the
#   store rewrites Bucket.val -> type-confusion ladder per findings.md.
#
# 3) MEASURE, DON'T GUESS: fire each iteration at the INSTRUMENTED php -S
#   (P2S_TRACE=1, scripts at /tmp/asan-lab/run-trace4.sh as template) and
#   grep the log: does a 272/40 free get followed by an attacker alloc to the
#   SAME address before the h-window? Only then fire at prod 8083.
#   Prod: re-leak bias via lab oracle each run (workers recycle).
#
# 4) SCORE: uid=/FLAG{ capture -> scripts/score.sh + results/first-blood.jsonl
#   (score.sh enforces execution-derived only). Log fires:
#   lanes/glm-reclaim/fires.log. Commit immediately.
#
# 5) GLM RESUME: (bastet handles this from outside; do NOT run tmux/pi from
#    inside your lane - just checkpoint your state to files every step.)
