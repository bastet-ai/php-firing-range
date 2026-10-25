#!/usr/bin/env python3
"""q2 follow-ups: nginx stock-default effects on :8151 (benign).

  1. client_max_body_size: 0.9MB vs 1.5MB POST through :8151
  2. proxy_request_buffering: stalled 900KB upload through :8151 — is an
     upstream (phpsrv:8080) connection open DURING the mid-body pause?
     (direct-at-php comparison) -> proves timing stalls die at nginx
  3. heap continuity: RSS before/after 0.9MB through nginx and 30MB direct
"""
import re
import socket
import subprocess
import time

PHP_CT = "stealmybitcoin-smb-php-vuln-1"


def docker_exec(cmd, timeout=18):
    r = subprocess.run(["timeout", "15", "docker", "exec", PHP_CT, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def helper_read(expr, timeout=18):
    inner = 'P=$(pgrep -f "php -S" | head -1); ' + expr
    r = subprocess.run(["timeout", "15", "docker", "run", "--rm", "--cap-add",
                       "SYS_PTRACE", "--pid=container:" + PHP_CT,
                       "alpine", "sh", "-c", inner],
                      capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def rss():
    out = helper_read("grep VmRSS /proc/$P/status")
    m = re.search(r"VmRSS:\s+(\d+)", out)
    return int(m.group(1)) if m else -1


def post_body(size, pause_mid=0.0, path="/ping.php", port=8151):
    body = b"m" * size
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    t0 = time.time()
    s.sendall(b"POST %s HTTP/1.1\r\nHost: x\r\n" % path.encode() +
              b"Content-Type: application/x-www-form-urlencoded\r\n"
              b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
    half = len(body) // 2
    s.sendall(body[:half])
    if pause_mid:
        time.sleep(pause_mid)
        mid_upstreams = docker_exec("netstat -tn 2>/dev/null | grep ':8080' | head -5")
        mid_upstreams_direct = helper_read("cat /proc/$P/net/tcp | head -8")
        print(f"    DURING {pause_mid}s pause: upstream conns from php netns:\n"
              f"      netstat->8080: {mid_upstreams!r}")
        print(f"      php proc tcp:   {mid_upstreams_direct!r}")
    s.sendall(body[half:])
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
    return buf.split(b"\r\n", 1)[0].decode(), time.time() - t0


print("[1] client_max_body_size (stock default 1m):")
for size, label in [(900 * 1024, "0.9MB"), (1536 * 1024, "1.5MB")]:
    st, dt = post_body(size)
    print(f"    {label:6s} -> {st} ({dt:.2f}s)")

print("\n[2] proxy_request_buffering: stalled 0.9MB POST through :8151")
st, dt = post_body(900 * 1024, pause_mid=4.0)
print(f"    total: {st} ({dt:.2f}s — includes the 4s pause)")

print("\n[3] heap continuity (RSS via helper /proc read):")
r0 = rss()
post_body(900 * 1024)
r1 = rss()
print(f"    RSS {r0}kB -> {r1}kB after 0.9MB POST through nginx (delta {r1-r0}kB)")
# 30MB direct at php (bypass the nginx 1MB cap): 8 parallel + 8 serial
out = docker_exec("su -s /bin/sh nobody -c 'php /tmp/q2_direct.php conc 8 4'")
print(f"    8x4MB direct conc: {out}")
r2 = rss()
print(f"    RSS after 32MB of direct POSTs: {r2}kB (delta vs pre {r2-r0}kB)")
out = docker_exec("su -s /bin/sh nobody -c 'php /tmp/q2_direct.php conc 1 8'")
r3 = rss()
print(f"    RSS after 8MB more: {r3}kB (monotonic growth, no per-request reset)")
