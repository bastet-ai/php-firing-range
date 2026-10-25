#!/usr/bin/env python3
"""smb_gdb_triage.py — catch the poisoned-next-decode SEGV under gdb."""
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s

GDBI = "smb-gdb-helper"


def main():
    print("== restart + producer ==")
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    sid = f"gt{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print(f"producer: {st}")

    pid_out, _ = s.helper("vuln", "pid")
    pid = pid_out.strip()
    print(f"[gdb] attaching to php pid {pid} (gdb loads symbols; wait)")
    cmd = ["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
           "--pid=container:" + q.CT["vuln"], "-v",
           "/home/user/php-firing-range/scripts:/sc:ro", GDBI,
           "gdb", "-batch", "-p", pid, "-x", "/sc/triage.gdb"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    # wait for gdb to attach + continue: poll php /proc for 't' (tracing stop)
    # state, then wait for it to be running again (state R/S) under gdb
    for i in range(60):
        out, _ = s.helper("vuln", "pid")  # cheap no-op keeps helper warm
        time.sleep(1)
        if i >= 28:
            break
    csid = f"gtc{int(time.time())}"
    s.stage_consumer_r("vuln", csid, 14)
    st2, _ = q.mp_min(q.VULN, csid, timeout=60)
    print(f"consumer fired: {st2}")
    try:
        out, _ = proc.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    open("lanes/stealmybitcoin/gdb-triage.log", "w").write(out)
    print("gdb transcript saved; crash section:")
    m = out.find("===CRASH===")
    if m >= 0:
        print(out[m:m + 3000])
    else:
        print("(no crash section — gdb output head:")
        print(out[:1500])


if __name__ == "__main__":
    main()
