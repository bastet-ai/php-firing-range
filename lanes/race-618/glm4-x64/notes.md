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
