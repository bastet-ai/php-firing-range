# glm4-x64 - x86_64 box lane derivations (php 8.2.34, wp lane :8099)

This box's twin of the arm64 glm4 lane. Binary-derived, never hardcoded.

## Binary

- lanes/race-618/glm3/bin/libphp-wp-x86_64.so - extracted from the
  wordpress-x86 container (/usr/lib/apache2/modules/libphp.so),
  ELF64 x86-64, not stripped, php 8.2.34 NTS.

## Symbols (from .symtab, this binary)

- zend_call_function 0x47a710, execute_internal 0x4ec7c0
- zif_highlight_file 0x394760, zif_readfile 0x39f180,
  zif_system 0x39b8a0 (zif_show_source not in symtab - 8.2 alias)

## Struct offsets (disassembly-verified on THIS binary)

- zend_internal_function.handler @ +0x48 (72): execute_internal does
  `mov 0x18(%rdi),%rax; jmp *0x48(%rax)`. The GLM3-BRIEF's "+88 on
  x86_64" is WRONG for 8.2 - same +72 as aarch64, so the F = E-64
  carve geometry is arch-identical here.
- BG(unserialize): basic_globals @ 0xf4c020 (loaded via GOT slot
  0xf2c720); .data @ basic_globals+0x350, .level @ +0x358.
  php_var_unserialize_init disassembly:
    fresh path:  emalloc(0x2018) -> `mov %rax,0x350(%rbx); movl $1,0x358(%rbx)`
    stale path:  level!=0 -> `add $1,%edx; mov 0x350(%rbx),%rax; ret`
  i.e. the 619 reuse primitive is CONFIRMED IN-BINARY: with level!=0 the
  init returns the dangling data pointer with NO realloc. (Also seen:
  a +0x338 guard checked first - likely BG(serialize)-side.)
  NOTE: differs from the arm64 lane's data@+0x330/+816 - per-box offsets
  are mandatory, as TODO.md records.
- php_unserialize_data size 0x2018 = 8216 (arch-independent);
  data->entries @ d+0x38 (lea in init), first fields match the glm3 notes
  layout (last@0, first_dtor@8, last_dtor@16, ... entries@56).

## Fake-function candidates (eval_fake_func ported to x86_64)

Port = accept R_X86_64_RELATIVE (type 8) alongside R_AARCH64_RELATIVE
(1027); everything else unchanged (offsets verified identical above).
Run: lanes/race-618/glm4-x64/eval_fake_func.py

- zif_highlight_file E=0xf26860 F=0xf26820 - PASSES the lane's field
  requirements: type@F=218 (!=2 ok), fn_flags=0 (no ZEND_ACC_CLOSURE
  bit), arg_info[0].type send_mode=0 (by-value), num_args=5800692 (>=1).
  W=*(F+16)=0xeb56e0 in .data.rel.ro (RELRO at load) -> same groom-ce
  adaptation as the arm64 lane; L=W+336=0xeb5830, region NOT zeros ->
  the dtor-walk region must come from the groom design, not the binary.
- zif_readfile E=0xf27cc0: send_mode=3 -> FAILS by-value.
  highlight_file is the win-function candidate on this box too.

## Next rungs (A2)

1. Groom placement: reclaim the freed 8216B d-chunk (multipart field
   name ~8193B, estrdup raw alloc) with the fake php_unserialize_data.
   Placement oracle: response signatures + host-root /proc/<child>/mem
   scans (the glm4 memtool.py pattern works here - container children
   are host processes; we verified root can read their maps/mem).
2. Keep the A1 control-matrix discipline: fresh SID per round, patched
   lane (:8100) A/B, wpfire.py honest transport, per-fire evidence JSON.
3. cb5-style token stream goes in the staged session file (full content
   control - this box's A1 finding), NOT session-progress shaping.

## Assisted leak collection (2026-10-22, the vendor's four values, ours)

The calif php2shell in-band LEAKED block decodes as: main_heap (heap-chunk
base - groom geometry), stale_reference (the freed structure the stale
global points at - the reclaim target), zval_ptr_dtor + zend_call_function
(libphp code ptrs - PIE bias defeat), natural_tables=149 (heap-shaping
calibration constant, leaked not assumed). Their channel = the corrupt-
token round-trip (memory-derived values become token lengths; the reader
OOM fatal prints them) = our A3.

We recorded OUR equivalents (ASSISTED tier - lab reads, not in-band):
scripts/a2_leak_collect.py - producer fire (pure stock, pre-auth) then a
CAP_SYS_PTRACE helper container joins the lane PID namespace and reads
BG(unserialize).level/.data straight from basic_globals of the surviving
child. Note: the lane container's own root CANNOT read children (docker
default caps drop SYS_PTRACE; Yama forbids sibling ptrace) - the helper
(docker run --cap-add SYS_PTRACE --pid=container:...) is the assisted
channel. Results (fresh child, deterministic across fires):
  stale_reference    0x72d17c069000  (BG(unserialize).data, dangling, level=1)
  stale_chunk_base   0x72d17c000000  (dedicated 2MB region of the freed
                     8216B d-chunk - emalloc_large class, NOT the main
                     heap; vendor's 8.5 build keeps their stale ref inside
                     the main heap chunk - allocation class differs)
  zval_ptr_dtor      0x72d17e0f7650  (= bias + 0x487650)
  zend_call_function 0x72d17e0ea710  (= bias + 0x47a710)
Unauthenticated equivalents = A3 (needs the groom first). natural_tables
calibration on this lane: pending groom-placement scan.

## Groom carrier + placement (2026-10-22 late, A2 grind)

### Carrier analysis (SOURCE-VERIFIED, php-src-8.2 fetched to /tmp)
- multipart field NAMES and FILENAMES: php_ap_getword/getword_conf are
  C-string (NUL-terminated) scans - embedded NULs truncate. DEAD as
  binary-pointer carriers (source: while (*pos && *pos != stop)).
- form-field VALUES: multipart_buffer_read_body = safe_ferealloc raw
  buffer, binary-safe, headerless, our bytes at +0; an 8193-byte value
  -> final 8196-byte alloc = 3-page class = the freed d run. THE carrier.
- raw POST body temp: php_stream_temp -> inner MEMORY stream -> ONE
  growing zend_string (24B header at +0, smart-str doubling) - not the
  3-page class and header-misaligned. Not a carrier.
- $_POST registered copies: zend_string (header at +0 kills fake-d.last).
- R: handler semantics (var_unserializer.re): id = R:n - 1 (0-based) ->
  var_access -> if not already a ref: ZVAL_NEW_REF ON THE SOURCE ENTRY
  (in-place mutation!) then ZVAL_COPY. The re-encode emits R:n again ->
  a successful round-trip can produce BYTE-IDENTICAL session files: use
  junk-trailer + mtime oracles, not content equality.
- entries layout on OUR binary: entries@d+0x38 (disasm; the fetched
  branch-HEAD has incomplete_classes_only there = THE 618 FIX FIELD,
  absent in pre-patch 8.2.34). used_slots = zend_long.

### Delivery SOLVED: pool poisoning
N producer fires round-robin-poison the whole child pool (all children
verified stale with IDENTICAL fork-inherited d - 0x72d17c06a000 across
three runs, but page position varies across recycling epochs: 0x69000
once - always leak-read per run). Delivered attempts consume exactly
one stale child each (count decrements 1/attempt) - delivery is now
deterministic at the pool level; keep ~3+ poisoned.

### Placement (the remaining grind = cb4, same frontier as arm64)
- Delivered attempts crash 100% (5/5 and 3/3) - the walk over whatever
  sits at d is fatal; surviving children never show our marker =>
  the groom read_body buffer is NOT landing at d (first-fit takes lower
  free runs; the efree'd remnant walk is the crasher).
- Filler sweep (nfill 0..5, fillers = persistent 8218B $_POST copies
  eating free runs): fillers 0-2 = non-deliveries (round-robin gave
  fresh children), 3-5 = deliveries + crashes; no landing found.
- NEXT: (a) dbgcrash-style PLACEMENT VERIFICATION during the walk
  window (persistent SYS_PTRACE helper polling d at high frequency, or
  a slow-parse trick to widen the alloc->decode gap); (b) symmetric
  producer/consumer shaping per the arm64 cb4 playbook (fd3510b);
  (c) the oracle stack is ready: surviving-child d readback (marker at
  d+0x138) + junk-trailer rewrite + destroyed-warning signatures.
