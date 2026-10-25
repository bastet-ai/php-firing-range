#!/usr/bin/env python3
"""Atomic BG(unserialize) read of the :8081 debug php via one gdb attach."""
import re
import subprocess
import sys

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q

CT = q.CT["vuln"]


def read_bg():
    r = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        "--pid=container:" + CT, "-v",
                        "/home/user/php-firing-range/scripts:/sc:ro",
                        "smb-gdb-helper", "sh", "-c",
                        "P=$(for p in $(pgrep -f 8081); do "
                        "[ \"$(cat /proc/$p/comm)\" = php ] && echo $p; done | head -1); "
                        "gdb -batch -p $P -x /sc/dbg-bg.gdb 2>/dev/null | grep -E 'PHPBASE|0x'"],
                       capture_output=True, text=True, timeout=120)
    m = re.search(r"0x[0-9a-f]+:\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)", r.stdout)
    if not m:
        return None, r.stdout[-300:]
    return (int(m.group(1), 16), int(m.group(2), 16)), r.stdout


if __name__ == "__main__":
    print(read_bg())
