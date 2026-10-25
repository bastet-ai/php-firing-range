#!/usr/bin/env python3
"""smb_q2_cli_server.py — Q2 measurement for lane SMB1 (BRIEF).

Is `php -S` (cli-server, default config) fork-uniform like mod_php, recycled
like fpm, or a single long-lived process?  Measurements, ALL benign:

  A. process model      single php -S process? threads? children during a
                        slow request (fork-per-request test)
  B. concurrency        N parallel big POSTs direct to phpsrv: serial vs
                        parallel wall-time
  C. ASLR cross-request PIE base stable across a request series?
  D. ASLR per-exec      base re-rolled after keepalive restart (pkill ->
                        3s keepalive) — repeat 3x
  E. heap continuity    VmRSS/statm across requests incl. one 30MB benign
                        multipart (no OOM)
  F. session surface    benign session roundtrip: sess file created as
                        nobody, rfc1867 upload-progress data lands in it
                        (the CVE-2026-109618 surface is LIVE)
  G. isolation          a second sid's session file never contains the
                        first sid's data (no benign crossbleed)

Assisted lab reads (channel honesty: NOT in-band HTTP leaks):
  /proc/<pid>/maps|statm via a SYS_PTRACE helper container (in-container
  root lacks CAP_SYS_PTRACE; wpbleed helper precedent).

Run:  python3 scripts/smb_q2_cli_server.py | tee lanes/stealmybitcoin/q2-cli-server.log
"""
import re
import socket
import subprocess
import sys
import time
import urllib.request

VULN_NGINX = "127.0.0.1:8151"
PHP_CT = "stealmybitcoin-smb-php-vuln-1"
NGINX_CT = "stealmybitcoin-smb-nginx-vuln-1"
TIMEOUT = 20


def sh(cmd, timeout=TIMEOUT):
    """cmd: argv LIST, no host shell (single-quote/$( ) hell avoided)."""
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + ("|ERR:" + r.stderr if r.stderr else "")).strip()


def docker_exec(ct, cmd, timeout=TIMEOUT):
    return sh(["timeout", "18", "docker", "exec", ct, "sh", "-c", cmd], timeout)


def helper_read(expr, timeout=TIMEOUT):
    """Read /proc of the php process from a SYS_PTRACE helper container.
    expr runs INSIDE the helper; $P = php pid (found by the helper)."""
    inner = 'P=$(pgrep -f "php -S" | head -1); ' + expr
    return sh(["timeout", "18", "docker", "run", "--rm", "--cap-add",
               "SYS_PTRACE", "--pid=container:" + PHP_CT,
               "alpine", "sh", "-c", inner], timeout)


def php_snapshot():
    """(pid, pie_base, threads, vmrss_kb, vmsize_kb) or None."""
    rc, out = helper_read(
        "echo PID=$P; head -1 /proc/$P/maps; "
        "grep Threads /proc/$P/status; grep -E 'VmRSS|VmSize' /proc/$P/status")
    if rc != 0 or "PID=" not in out:
        return None
    pid = int(re.search(r"PID=(\d+)", out).group(1))
    m = re.search(r"^([0-9a-f]+)-[0-9a-f]+ r.xp", out, re.M)
    base = int(m.group(1), 16) if m else None
    thr = int(re.search(r"Threads:\s+(\d+)", out).group(1))
    rss = int(re.search(r"VmRSS:\s+(\d+)", out).group(1))
    vsz = int(re.search(r"VmSize:\s+(\d+)", out).group(1))
    return pid, base, thr, rss, vsz


def http_post(url, data=b"message=ping", sid=None, timeout=15):
    body = data
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if sid:
        headers["Cookie"] = f"PHPSESSID={sid}"
    req = urllib.request.Request(url, data=body, headers=headers)
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(), time.time() - t0


def multipart_progress(host_port, sid, value, filesize=1024):
    """Benign multipart with PHP_SESSION_UPLOAD_PROGRESS (rfc1867 surface)."""
    bnd = b"Q2PROBE"
    body = (b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            + sid.encode() + b"\r\n"
            b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            + value.encode() + b"\r\n"
            b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n" + b"z" * filesize + b"\r\n"
            b"--" + bnd + b"--\r\n")
    host, port = host_port.split(":")
    s = socket.create_connection((host, int(port)), timeout=20)
    s.sendall((f"POST /ping.php HTTP/1.1\r\nHost: {host}\r\n"
               f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
               ).encode() + body)
    buf = b""
    s.settimeout(20)
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        buf += d
    s.close()
    return buf


def stalled_progress_upload(sid, value, total=131072, stall=2.5):
    """Upload with progress field, STALL mid-file, read sess file mid-flight
    (session.upload_progress.cleanup=On wipes the key at upload end, so
    the only benign proof of the rfc1867 surface is a MID-FLIGHT read)."""
    bnd = b"Q2STALL"
    head = (b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            + sid.encode() + b"\r\n"
            b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            + value.encode() + b"\r\n"
            b"--" + bnd + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n")
    tail = b"\r\n--" + bnd + b"--\r\n"
    s = socket.create_connection(("127.0.0.1", 8151), timeout=15)
    s.sendall((f"POST /ping.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
               f"Content-Length: {len(head) + total + len(tail)}\r\n"
               f"Connection: close\r\n\r\n").encode()
               + head + b"z" * 4096)
    time.sleep(stall)                       # mid-flight window
    rc, mid = docker_exec(PHP_CT, f"cat /tmp/sess_{sid} 2>/dev/null")
    try:
        s.sendall(b"z" * (total - 4096) + tail)
        s.settimeout(10)
        while s.recv(65536):
            pass
    except Exception:
        pass
    s.close()
    return mid


def wait_healthy(deadline=30.0):
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            st, _, _ = http_post(f"http://{VULN_NGINX}/ping.php", timeout=3)
            if st == 200:
                return time.time() - t0
        except Exception:
            time.sleep(0.1)
    return None


def main():
    print("== Q2: php -S process model / ASLR / heap — benign session probes ==")
    print("target :8151 (nginx->php -S 8.4.26, single keepalive wrapper)\n")

    # -- F first: session surface roundtrip (benign) --------------------
    print("[F] session surface: benign roundtrip via :8151")
    sid = "q2a" + "0" * 23
    sid2 = "q2b" + "0" * 23
    st, body, dt = http_post(f"http://{VULN_NGINX}/ping.php", sid=sid)
    print(f"    POST message=ping (sid={sid[:6]}..) -> {st} {body!r} ({dt:.2f}s)")
    rc, out = docker_exec(PHP_CT, f"ls -la /tmp/sess_{sid} 2>/dev/null; "
                                  f"cat /tmp/sess_{sid} 2>/dev/null; "
                                  f"stat -c %U /tmp/sess_{sid} 2>/dev/null")
    print(f"    sess file: {'present, ' + out if rc == 0 and out else 'MISSING'}")
    sess_a_present = "q2a" in out or "sess" in out and "nobody" in out

    # rfc1867 upload-progress data: cleanup=On wipes the key at upload END,
    # so prove the surface with a MID-FLIGHT read during a stalled upload
    mid = stalled_progress_upload(sid, "q2probevalue")
    print(f"    sess[{sid[:6]}] MID-FLIGHT during stalled upload: {mid[:160]!r}")
    has_progress = "upload_progress_q2probevalue" in mid
    multipart_progress(VULN_NGINX, sid, "q2probevalue", 1024)
    rc, out = docker_exec(PHP_CT, f"cat /tmp/sess_{sid} 2>/dev/null")
    print(f"    sess[{sid[:6]}] after completed multipart (cleanup=On): "
          f"{out[:60]!r} (key wiped: {not has_progress or not out})")

    # -- G: isolation ----------------------------------------------------
    multipart_progress(VULN_NGINX, sid2, "q2other", 1024)
    rc, out2 = docker_exec(PHP_CT, f"cat /tmp/sess_{sid2} 2>/dev/null")
    bleed = "q2probevalue" in out2
    print(f"    sess[{sid2[:6]}] = {out2[:100]!r} -> cross-sid bleed: {bleed}")
    print(f"[F] 618 upload-progress surface LIVE: {has_progress} "
          f"| [G] cross-sid benign bleed: {bleed}\n")

    # -- A: process model + fork-per-request ------------------------------
    print("[A] process model")
    snap = php_snapshot()
    print(f"    start: pid={snap[0]} pie_base=0x{snap[1]:x} "
          f"threads={snap[2]} VmRSS={snap[3]}kB VmSize={snap[4]}kB")
    base_pid = snap[0]
    # slow request on the wire while we count processes
    slow = socket.create_connection(("127.0.0.1", 8151), timeout=10)
    slow.sendall(b"POST /ping.php HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\n"
                 b"Content-Length: 200000\r\nConnection: close\r\n\r\n")
    time.sleep(0.3)
    for _ in range(3):
        slow.sendall(b"m" * 1000)
        time.sleep(0.2)
    rc, out = docker_exec(PHP_CT, "ps -ef | grep '[p]hp -S'")
    nproc = len(out.splitlines())
    print(f"    php processes DURING a trickling request: {nproc} -> {out}")
    print(f"    => fork-per-request: {'NO' if nproc == 1 else 'YES'}")
    # drain
    try:
        while slow.recv(65536):
            pass
    except Exception:
        pass
    slow.close()
    snap2 = php_snapshot()
    print(f"    after: pid={snap2[0]} (stable: {snap2[0] == base_pid})\n")

    # -- B: concurrency (direct to phpsrv from the nginx container) -------
    print("[B] concurrency: 4 parallel 8MB POSTs direct at phpsrv:8080")
    rc, one = docker_exec(NGINX_CT,
        "dd if=/dev/zero bs=1M count=8 2>/dev/null > /tmp/big.bin; "
        "(time wget -q -O /dev/null --post-file=/tmp/big.bin "
        "--header='Content-Type: application/x-www-form-urlencoded' "
        "--header='Cookie: PHPSESSID=q2conc1' http://phpsrv:8080/ping.php) 2>&1 | tail -3")
    print(f"    single 8MB POST: {one}")
    rc, par = docker_exec(NGINX_CT,
        "t0=$(date +%s%N); for i in 1 2 3 4; do "
        "wget -q -O /dev/null --post-file=/tmp/big.bin "
        "--header='Content-Type: application/x-www-form-urlencoded' "
        "--header=\"Cookie: PHPSESSID=q2conc$i\" http://phpsrv:8080/ping.php & done; "
        "wait; t1=$(date +%s%N); echo total_ms=$(( (t1-t0)/1000000 ))")
    print(f"    4 parallel 8MB POSTs: {par}\n")

    # -- C: ASLR stability across requests -------------------------------
    print("[C] ASLR across requests (same process)")
    bases = [snap[1]]
    for i in range(10):
        http_post(f"http://{VULN_NGINX}/ping.php", sid=sid)
    snap3 = php_snapshot()
    bases.append(snap3[1])
    multipart_progress(VULN_NGINX, sid, "q2probe2", 64 * 1024)
    snap4 = php_snapshot()
    bases.append(snap4[1])
    stable = len(set(bases)) == 1
    print(f"    bases: {[hex(b) for b in bases]} -> stable within process: {stable}")
    print(f"    RSS before/after 64KB multipart: {snap3[3]}kB -> {snap4[3]}kB\n")

    # -- E: heap continuity (30MB benign multipart, well under 128M) ------
    print("[E] heap continuity: 30MB benign multipart (no OOM)")
    snap5 = php_snapshot()
    r = multipart_progress(VULN_NGINX, sid, "q2big30", 30 * 1024 * 1024)
    status = r.split(b"\r\n", 1)[0] if r else b"(no response)"
    snap6 = php_snapshot()
    print(f"    response: {status[:40]!r}")
    print(f"    RSS {snap5[3]}kB -> {snap6[3]}kB (delta {snap6[3]-snap5[3]}kB); "
          f"pid stable: {snap6[0] == base_pid}\n")

    # -- D: ASLR per-exec (keepalive restart) -----------------------------
    print("[D] ASLR per-exec: pkill php -S -> keepalive restart (3s) x3")
    for i in range(3):
        rc, _ = docker_exec(PHP_CT, "pkill -f 'php -S' || true")
        t0 = time.time()
        # poll for 502 window through nginx
        window = None
        codes = []
        while time.time() - t0 < 15:
            try:
                st, _, _ = http_post(f"http://{VULN_NGINX}/ping.php", timeout=2)
                codes.append(st)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
            except Exception:
                codes.append(0)
            time.sleep(0.15)
            if codes and codes[-1] == 200 and any(c in (502, 0) for c in codes):
                window = time.time() - t0
                break
        snapr = php_snapshot()
        print(f"    restart {i+1}: pid {base_pid}->{snapr[0]} "
              f"base 0x{bases[0]:x}->0x{snapr[1]:x} "
              f"(new roll: {snapr[1] != bases[0]}) "
              f"recovery~{window if window else 'n/a'}s")
        bases[0] = snapr[1]
        base_pid = snapr[0]

    print("\n== Q2 VERDICT: see notes.md for the synthesized answer ==")


if __name__ == "__main__":
    main()
