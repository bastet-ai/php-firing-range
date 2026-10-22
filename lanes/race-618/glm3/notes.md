# glm3 notes — CVE-2026-109618/619 final-mile design

## Derived (target binary: lanes/race-618/glm3/bin/libphp.so, PHP 8.3.35 NTS aarch64,
## copied from OUR range's php83 image — symbols derived, never hardcoded)
- libphp: zend_call_function@0x46168c (NOTE: prior lane's 0x45bd4c was from a
  DIFFERENT binary — wrong for this target), zend_eval_string@0x461560,
  zif_system@0x377428 (local sym), php_execute_script@0x4053c0.
- libc (2.41-12+deb13u4): system@0x492c0 (also __libc_system).
- Struct layouts (from our php-src-83-plain DWARF, 8.3.36 — same as target):
  php_unserialize_data: last@0,first_dtor@8,last_dtor@16,allowed_classes@24,
  ref_props@32,cur_depth@40,max_depth@48,entries@56,size 8216 (17 zend-mm pages
  of 512B; reclaim class = allocs 8193..8704).
  var_entries{used_slots@0,next@8,data[1018]@16}; var_dtor_entries{used_slots@0,
  next@8,data[255]@16} size 4096; VAR_WAKEUP_FLAG=1 VAR_UNSERIALIZE_FLAG=2.
  zend_internal_function: type@0,fn_flags@4,function_name@8,scope@16,
  prototype@24,num_args@32,required@36,arg_info@40,handler@72,size 136.
  zend_object: ce@16,handlers@24. zend_class_entry.__unserialize@352.
  zend_function_entry: fname@0,handler@8,arg_info@16,num_args@24,flags@28.
- probe=all oracle (lab index.php): full module bias list (libphp+libc) + arch.

## The chain (Route B — unserialize stale global)
PRODUCER (N): reader request on a poisoned SID whose file contains a bogus
s:<BIG> token → OOM fatal INSIDE php_var_unserialize (proven: prior lane P1
alloc=413696=24+413672 marker; P0 evidence) → bailout between
php_var_unserialize_init/destroy → BG(unserialize)={level:1, data:d} stale,
d freed at N's shutdown (8216B chunk).

CONSUMER (N+1, same worker child, keep-alive):
1. Groom: multipart field with an ~8193B NAME (estrdup → raw alloc, no header,
   attacker bytes at +0, 17-page zend-mm class) reclaims d's page run.
   Placement: after N's shutdown the whole request chunk is one free bitmap
   run; N+1 fills sequentially → page offset of the estrdup = cumulative prior
   allocs → tune with preamble field sizes (deterministic; crash/clean oracle
   + rig P2S traces give exact addresses).
   Fake php_unserialize_data bytes: last=L2(bss VA, valid var_entries area),
   first_dtor=NULL, last_dtor=L (static), rest 0 (entries.used_slots=0,
   max_depth=100).
2. N+1 also reclaims the stale BG(serialize) 64B chunk with a 57-63B field
   name (benign zeros) so its own update's encode survives.
3. First FILE_START update (progress handler, PRE-RINIT) with our SID →
   php_session_initialize → ps_read → php_session_decode →
   php_var_unserialize_init REUSES fake d.
4. Token stream (session file, via poison-machine, see P3): duplicate keys
   inside an a:N: old values get var_push_dtor_value'd → ZVAL_COPY writes into
   the FAKE var_dtor_entries at L (static bss):
   - dup key K1: old LONG value i:<F> with source-slot u2.next==2
     (engineered via key hash collisions) → data[0]={F,0x104,2} at L+16
   - dup key K2: old STRING "/CANARY" → data[1]={&zstr,0x106,0}
5. var_destroy walks first_dtor=L (set by tmp_var since first_dtor==NULL):
   data[0].u2==2 → __unserialize route → ZVAL_COPY(&param,data[1]) →
   zend_call_known_instance_method_with_1_params(ce->__unserialize=F, obj=F,
   NULL, &param). ce = *(F+16) = W; L = W+336 so data[0]@L+16 == W+352 ==
   ce->__unserialize = F (self-consistent, ONE write, dual purpose).
6. F = fake zend_internal_function carved out of a REAL zend_function_entry
   in libphp .data.rel.ro (relocated at load: handler = bias+zif_readfile):
   F = E-64 where E=&entry; handler@F+72 = qword@E+8 ✓; type@F+0, fn_flags@F+4,
   num_args@F+32, arg_info@F+40 = surrounding static bytes — verified offline
   per candidate. Requirements: type!=2, fn_flags has ZEND_ACC_STATIC (avoid
   RELEASE_THIS → obj F is in RELRO), arg_info[0].type by-value bits, num_args>=1.
7. zif_readfile(call, retval) with ZEND_CALL_ARG(call,1)="/CANARY" →
   php_stream_passthru → PHPWRITE → mod_php response. i_zval_ptr_dtor(data[0])
   = LONG → no-op (no deref of RELRO F). data[1] string release ✓.
8. efree_size(L,4096): L is static → fake zend-mm chunk header at L&-2MB is
   KNOWN binary bytes → choose L (and hence W via candidate E) so the page-map
   decode takes a benign path (small-bin free_slot write into writable RW).
   Then efree(d) frees the real estrdup chunk; request completes normally →
   response flushes.

## P3 = content control on the TARGET (the remaining producer engineering)
The dup-key token stream must come from the session file. Progress entries are
structure-fixed (start_time/content_length/... keys). Route: the corruption
machine already observed on target: bogus s:LEN tokens (P1 evidence) → the
reader's decode OOMs *or* desyncs; target oracle = the OOM alloc size in the
fatal message reveals token lengths. Plan: engineer the bogus length via the
encode of DESYNCED session data (multi-generation corruption: stale-unserialize
decode → corrupt zvals (string zval headers groomed by N+1's own allocations →
len field = attacker bytes) → re-encode at next update writes s:<attacker-len>
→ next reader desyncs into our filename bytes = our token structure).

## Win channel
readfile("/CANARY") via zif_readfile → response body. Sub-canary: zif_system.
