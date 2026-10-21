# Task: land CVE-2026-109618 chain on OUR php83 target with hardcoded addresses
You are on the firing range box (aarch64). Loopback targets only.

TARGET: http://127.0.0.1:8083/lab/index.php  (php 8.3.35 mod_php apache worker)
- oracle: GET /lab/index.php?probe=all -> arch/version/sapi/module biases/heap
- call target: zend_call_function = libphp.so bias + 0x45bd4c
  (live worker bias 0xe21fde850000 -> call 0xe21fdecabd4c; RE-LEAK per run)
- aarch64 offsets (offsetof-verified): FCI{size@0,fname.val@8,type@16,params@32,
  param_count@48,size64}; zend_internal_function{type@0,handler@72,size136}
- payload visibility: system() output lands in the HTTP response (mod_php)

GROUND TRUTH already measured (read these first):
- research/shared/findings.md  (all corrections incl. the 13:2xZ one)
- /tmp/asan-lab/trace3.log     (alloc/free trace of the stock body on OUR build)
- /tmp/asan-lab/reorder_poc.py (reordered body attempt; failed: forge cannot
  fit an FCI+internal-function into a 15-byte value - needs redesign)

MEASURED FACTS about OUR build (php -S trace, Zend MM on, stock 8.3.35/6):
1. Their stock body fires all events but the stale free happens at the NEXT
   file's FILE_START update - AFTER their 320B groom. Zero attacker allocs
   sit between free and stale store. Their ordering is lsphp-specific.
2. Freed objects at that update: 40B and 32B bins (data-array elements:
   zend_long zval Bucket=32B, plus 40B strings) + two of their 320B blobs.
3. Zend MM size-cache is LIFO: efree(N) then emalloc(N) wins the slot.

YOUR JOB: craft the body where (a) an update frees the tree while the stale
pointers are live, (b) a post-free attacker allocation of EXACTLY the freed
sizes (32/40B, or force a Bucket-array realloc 272B = HT8) reclaims those
slots with bytes that make the subsequent stale Z_LVAL_P store or the
php_session_initialize->...->zend_call_function path yield system(id).
Consider: does the stale store (Z_LVAL_P(post_bytes_processed)=bytes) alone
give control, or must reclaim produce a callable fake function zval? The
trace tells you what the code actually does on our build - trust it over the
writeups. Multi-part bodies: extra parts force updates; file boundaries
control event order; upload_progress.min_freq/freq affect update gating -
you may also test against the instrumented php -S (find it via findings.md,
port 13999 harness scripts in /tmp/asan-lab/run-*.sh) to VERIFY the free->
reclaim->corruption window with P2S_TRACE before firing at 8083.

HARD RULES: write your scripts + notes to lanes/glm-reclaim/ as you go
(frequent checkpoint writes; the provider stream caps at 900s - your work
must survive truncation). Success = `uid=` or FLAG{...} in an 8083 response.
Verify via python3 one-liners; log every fire in lanes/glm-reclaim/fires.log.
