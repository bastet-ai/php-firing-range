#!/usr/bin/env python3
"""smb_gdb_triage.py — catch the poisoned-next-decode SEGV under gdb.

Flow:
  1. fresh restart, REAL producer fire (process survives, heap poisoned)
  2. attach gdb (smb-gdb-helper, SYS_PTRACE, shared pid-ns) to the php -S
     process, continue it
  3. fire the trivial consumer (k|i:42; staged session) at :8151
  4. gdb traps the SIGSEGV: bt, registers, faulting address, map of the
     corrupted structure. Saves transcript.
"""
import subprocess
import sys
import time
import threading

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s

GDBI = "smb-gdb-helper"


def gdb_session(kind, on_attached):
    """Run gdb -p PID in a helper; on_attached(pid) fires the consumer."""
    pid_out, err = s.helper(kind, "pid")
    pid = pid_out.strip()
    print(f"[gdb] attaching to php pid {pid}")
    cmd = ["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
           "--pid=container:" + q.CT[kind], "-v",
           "/home/user/php-firing-range/scripts:/sc:ro", GDBI,
           "gdb", "-batch", "-p", pid,
           "-ex", "set pagination off",
           "-ex", "set confirm off",
           "-ex", "handle SIGSEGV stop print nopass",
           "-ex", "continue",
           # after stop:
           "-ex", "printf \"===CRASH===\\n\"",
           "-ex", "info registers x0 x1 x2 x8 x9 x10 x16 x17 x19 x20 x21 x22 pc sp",
           "-ex", "x/4i $pc",
           "-ex", "bt 20",
           "-ex", "info proc mappings"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    time.sleep(6)                      # let gdb attach+continue
    on_attached()
    try:
        out, _ = proc.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return out


def main():
    print("== restart + producer ==")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    t, _ = q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"gt{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")

    def fire_consumer():
        csid = f"gtc{int(time.time())}"
        s.stage_consumer_r("vuln", csid, 14)  # trivial vs R — same crash law
        st2, _ = q.mp_min(q.VULN, csid)
        print(f"consumer fired: {st2}")

    out = gdb_session("vuln", fire_consumer)
    open("lanes/stealmybitcoin/gdb-triage.log", "w").write(out)
    print(out[-4000:])


if __name__ == "__main__":
    main()
