#!/usr/bin/env python3
"""find_fake_func.py — carve a fake zend_internal_function out of a real
zend_function_entry table in a loaded .so/php binary.

Given the binary and a zif_ target symbol (e.g. zif_readfile), find the
zend_function_entry whose handler relocates to it; F = E - 64 makes
F+72 (internal_function.handler) == &entry.handler. Validate every field the
release-build zend_call_function path reads, compute W = *(F+16) (as a runtime
address after relocations), L = W+336, and report geometry.
"""
import struct, sys, subprocess, json

class ELF:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        (self.e_shoff,) = struct.unpack_from("<Q", self.data, 0x28)
        (self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from("<HHH", self.data, 0x3A)
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", self.data, off)
            self.sections.append(dict(name=name, type=typ, flags=flags, addr=addr, offset=offset, size=size, link=link, entsize=entsize))
        strtab = self.sections[self.e_shstrndx]
        self.strtab = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        for s in self.sections:
            s["secname"] = self.cstr(s["name"])

    def cstr(self, off):
        end = self.strtab.index(b"\0", off)
        return self.strtab[off:end].decode()

    def sec_by_name(self, n):
        return next((s for s in self.sections if s["secname"] == n), None)

    def addr_read(self, addr, n):
        for s in self.sections:
            if s["type"] != 8 and s["addr"] <= addr < s["addr"] + s["size"]:
                off = s["offset"] + (addr - s["addr"])
                return self.data[off:off + n]
        return None

    def read_at(self, addr, n):
        """read from file image (any section) with vaddr translation"""
        for s in self.sections:
            if s["addr"] <= addr < s["addr"] + s["size"]:
                off = s["offset"] + (addr - s["addr"])
                return self.data[off:off + n]
        return None

    def dynsyms(self):
        ds = self.sec_by_name(".dynsym")
        st = self.sec_by_name(".dynstr")
        out = []
        n = ds["size"] // 24
        for i in range(n):
            off = ds["offset"] + i * 24
            name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, off)
            end = self.data.index(b"\0", st["offset"] + name)
            nm = self.data[st["offset"] + name:st["offset"] + name + (end - (st["offset"] + name))].decode()
            out.append((nm, value, info))
        return out

    def relocations(self):
        """yield (offset, addend, symname|None, rtype) for RELA relocations"""
        relsecs = [s for s in self.sections if s["type"] == 4]  # SHT_RELA
        dsyms = self.dynsyms()
        for rs in relsecs:
            n = rs["size"] // 24
            for i in range(n):
                off = rs["offset"] + i * 24
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, off)
                rtype = r_info & 0xffffffff
                sym = r_info >> 32
                symname = dsyms[sym][0] if sym else None
                yield (r_offset, r_addend, symname, rtype)

    def syms_full(self):
        """full symtab (incl. local t symbols)"""
        ds = self.sec_by_name(".symtab")
        if not ds:
            return {}
        st = self.sec_by_name(".strtab")
        out = {}
        n = ds["size"] // 24
        for i in range(n):
            off = ds["offset"] + i * 24
            name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, off)
            if not name:
                continue
            end = self.data.index(b"\0", st["offset"] + name)
            nm = self.data[st["offset"] + name:st["offset"] + name + (end - (st["offset"] + name))].decode()
            if value:
                out[nm] = value
        return out


def analyze(path, target_sym, biasname="libphp"):
    e = ELF(path)
    syms = e.syms_full()
    if target_sym not in syms:
        print(f"!! {target_sym} not in symtab; have similar:",
              [k for k in syms if target_sym.split("_")[-1] in k][:5])
        return None
    tgt = syms[target_sym]
    print(f"{target_sym} file off 0x{tgt:x}")

    # candidate relocated qwords: relocations of type R_AARCH64_RELATIVE(1027)
    # with addend == tgt give handler slots.
    cands = []
    for (roff, addend, symname, rtype) in e.relocations():
        if addend == tgt and rtype in (1027, 2, 8) and not symname:
            cands.append(roff)
    print(f"candidate handler qwords ({len(cands)}):",
          [hex(c) for c in cands[:20]])

    # for each candidate E = handler_qword_addr - 8 (entry start),
    # F = E - 64. Check geometry in file image (post-reloc values where the
    # field is itself a relocated pointer).
    rel_by_off = {}
    for (roff, addend, symname, rtype) in e.relocations():
        rel_by_off[roff] = (addend, symname, rtype)

    def qword_at(addr):
        """post-relocation value of qword at vaddr addr (or None)"""
        b = e.read_at(addr, 8)
        if b is None:
            return None
        v = struct.unpack("<Q", b)[0]
        if addr in rel_by_off:
            addend, symname, rtype = rel_by_off[addr]
            if rtype == 1027:  # R_AARCH64_RELATIVE: *ptr = base + addend
                return addend if addend else v
            return addend if addend else v
        return v

    def dword_at(addr):
        b = e.read_at(addr, 4)
        return None if b is None else struct.unpack("<I", b)[0]

    def byte_at(addr):
        b = e.read_at(addr, 1)
        return None if b is None else b[0]

    results = []
    for c in cands:
        E = c - 8
        F = E - 64
        ent = {}
        ent["E"] = E; ent["F"] = F
        ent["type@F"] = byte_at(F)
        ent["fn_flags@F+4"] = dword_at(F + 4)
        ent["scope@F+16(W)"] = qword_at(F + 16)
        ent["num_args@F+32"] = dword_at(F + 32)
        ent["arg_info@F+40"] = qword_at(F + 40)
        ent["handler@F+72"] = qword_at(F + 72)
        ent["fname@E"] = qword_at(E)  # zend_string* (relocated)
        results.append(ent)
        print(f"\ncand E=0x{E:x} F=0x{F:x}")
        for k, v in ent.items():
            print(f"   {k}: {v if isinstance(v,int) else (hex(v) if isinstance(v,int) else v) if v is not None else None}")
    return results, e, syms


if __name__ == "__main__":
    path = sys.argv[1]
    sym = sys.argv[2] if len(sys.argv) > 2 else "zif_readfile"
    analyze(path, sym)
