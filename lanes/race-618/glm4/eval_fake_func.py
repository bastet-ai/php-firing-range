#!/usr/bin/env python3
"""eval_fake_func.py - post-reloc evaluation of fake zend_internal_function
candidates for the wp-x86 lane binary (aarch64 php 8.2.34).

For each zend_function_entry E whose handler relocates to a chosen zif,
F = E-64. Evaluates, from a post-relocation view of the file image:
  type@F+0 (must != 2), fn_flags@F+4 (must NOT have ZEND_ACC_CLOSURE),
  W = *(F+16) (the fake ce; must be in a WRITABLE section, RW data/bss),
  num_args@F+32 (>=1), arg_info@F+40 -> arg_info[0].type send-mode bits
  (must be by-value), L = W+336 (fake var_dtor_entries: report section,
  zeros in [L, L+4096), and the qword at L-16 - the fake zend-mm chunk
  header consumed by efree_size(L,4096)).
Prints geometry for offline verification.
"""
import struct, sys

path, zifs = sys.argv[1], sys.argv[2].split(",")
data = open(path, "rb").read()
e_shoff, = struct.unpack_from("<Q", data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    v = struct.unpack_from("<IIQQQQIIQQ", data, off)
    secs.append(dict(zip("name typ flags addr offset size link info align entsize".split(), v)))
st = secs[e_shstrndx]
strtab = data[st["offset"]:st["offset"] + st["size"]]
def nm(o):
    e = strtab.index(b"\0", o)
    return strtab[o:e].decode()
for s in secs:
    s["secname"] = nm(s["name"])
def sec_of(addr):
    for s in secs:
        if s["typ"] != 8 and s["addr"] <= addr < s["addr"] + s["size"]:
            return s["secname"], s
    return "?", None
def read(addr, n):
    for s in secs:
        if s["addr"] <= addr < s["addr"] + s["size"]:
            o = s["offset"] + addr - s["addr"]
            return data[o:o + n]
    return None
# post-reloc value: R_AARCH64_RELATIVE(1027) => *ptr = base + addend
relocs = {}
for s in secs:
    if s["typ"] != 4:
        continue
    n = s["size"] // 24
    for i in range(n):
        o = s["offset"] + i * 24
        r_off, r_info, r_add = struct.unpack_from("<QQq", data, o)
        relocs[r_off] = (r_info & 0xffffffff, r_add, r_info >> 32)
def q(addr):
    b = read(addr, 8)
    if b is None:
        return None
    v = struct.unpack("<Q", b)[0]
    if addr in relocs and relocs[addr][0] == 1027:
        return relocs[addr][1]
    return v
def dw(addr):
    b = read(addr, 4)
    return None if b is None else struct.unpack("<I", b)[0]
def by(addr):
    b = read(addr, 1)
    return None if b is None else b[0]
# symtab for zif addresses
symtab = {}
for s in secs:
    if s["secname"] == ".symtab":
        strs = [x for x in secs if x["secname"] == ".strtab"][0]
        stb = data[strs["offset"]:strs["offset"] + strs["size"]]
        n = s["size"] // 24
        for i in range(n):
            o = s["offset"] + i * 24
            name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, o)
            if name:
                e = stb.index(b"\0", name)
                symtab[stb[name:e].decode()] = value
SEND_SHIFT = 24  # _ZEND_TYPE_EXTRA_FLAGS_SHIFT (8.2/8.3)
for z in zifs:
    tgt = symtab[z]
    print(f"=== {z} @ 0x{tgt:x} ===")
    for (roff, (rtype, radd, rix)) in sorted(relocs.items()):
        if radd == tgt and rtype == 1027:
            E = roff - 8
            F = E - 64
            tF = by(F)
            ff = dw(F + 4)
            W = q(F + 16)
            na = dw(F + 32)
            ai = q(F + 40)
            Wsec, Ws = sec_of(W) if W is not None else ("?", None)
            Wflags = Ws["flags"] if Ws else 0
            ai_sec, _ = sec_of(ai) if ai is not None else ("?", None)
            ai_type = q(ai + 8)  # zend_internal_arg_info.type (after name ptr)
            send = (ai_type >> SEND_SHIFT) & 3 if ai_type is not None else None
            L = W + 336 if W is not None else None
            Lb = read(L, 4096) if L is not None else None
            zeros = (Lb is not None and Lb == b"\0" * 4096)
            hdr = q(L - 16) if L is not None else None
            print(f"  E=0x{E:x} F=0x{F:x}")
            print(f"    type@F={tF} (!=2 ok)  fn_flags=0x{ff or 0:x} (CLOSURE bit {bool((ff or 0)&(1<<11))})")
            print(f"    W=0x{W:x} sec={Wsec} writable={bool(Wflags & 0x3)}  num_args={na}  arg_info=0x{ai:x} sec={ai_sec}")
            print(f"    arg_info[0].type=0x{ai_type:x} send_mode={send} (0=byval ok)")
            print(f"    L=W+336=0x{L:x} sec={sec_of(L)[0]} zeros4096={zeros}  L-16 hdr=0x{hdr:x}")
