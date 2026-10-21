#!/usr/bin/env python3
"""Calibrate the ZMM page-map offset + free_slot array offset from the
saved meta window: the correct (map_off, fs_off) pair must make every
nonzero free_slot[bin] entry point into an SRUN page whose map entry
decodes as that bin. Pure offline analysis on window.bin."""
import struct
import importlib.util
import json

data = open('window.bin', 'rb').read()
st = json.load(open(pb.STATE_FILE))
chunk = st['heap_ref'] & ~0x1FFFFF

BIN_SIZES = [8,16,24,32,40,48,56,64,80,96,112,128,160,192,224,256,320,
             384,448,512,640,768,896,1024,1280,1536,1792,2048,2304,2560,2828,3072,3072]

best = None
for fs_off in range(0, 64, 8):          # free_slot[0] candidate offset in data
    for map_off in range(0x100, 0x300, 4):  # map[0] candidate offset in data
        ok = 0
        total = 0
        for i in range(32):
            v = struct.unpack_from('<Q', data, fs_off + i * 8)[0]
            if v == 0 or not (chunk <= v < chunk + 0x200000):
                continue
            total += 1
            pg = (v - chunk) >> 12
            off = (v - chunk) & 0xFFF
            if map_off + pg * 4 + 4 > len(data):
                continue
            info = struct.unpack_from('<I', data, map_off + pg * 4)[0]
            if (info & 0x80000000) and not (info & 0x40000000):
                b = info & 0x1F
                bs = BIN_SIZES[b] if b < 32 else 0
                # slot must sit on the bin's grid inside the page
                if b == i and off % bs == 0:
                    ok += 1
        if total >= 8 and ok >= total - 1 and (best is None or ok > best[0]):
            best = (ok, total, fs_off, map_off)

if best:
    ok, total, fs_off, map_off = best
    print(f"MATCH: free_slot[0] at data+{fs_off:#x}, map[0] at data+{map_off:#x} "
          f"({ok}/{total} entries consistent)")
    print(f"  => map absolute = chunk+{0x58+map_off:#x}")
    # decode bin-320 pages with the calibrated offset
    print("\n  bin-320 (and 0xC) pages with calibrated map:")
    for pn in range(1, 512):
        if map_off + pn * 4 + 4 > len(data):
            break
        info = struct.unpack_from('<I', data, map_off + pn * 4)[0]
        if info == 0:
            continue
        srun = (info & 0x80000000) != 0
        lrun = (info & 0x40000000) != 0
        b = info & 0x1F
        fc = (info >> 16) & 0x1FF
        if b == 16 and (srun or lrun):
            kind = 'SRUN' if srun and not lrun else ('LRUN?!' if lrun and not srun else '0xC')
            print(f"    page {pn}: {info:#010x} {kind} free={fc} -> {chunk + pn*0x1000:#x}")
    # free_slot[16]
    v = struct.unpack_from('<Q', data, fs_off + 16 * 8)[0]
    print(f"\n  free_slot[16] = {v:#x} (page {(v-chunk)>>12 if chunk<=v<chunk+0x200000 else '?'})")
else:
    print("no consistent (fs_off, map_off) found - widen the search")
