#!/usr/bin/env python3
"""memtool.py — host-root /proc memory oracle for the wordpress-x86 lane.
Run via sudo. Reads apache children's memory through the container root
(/proc/<container-pid>/root/proc/<child>/mem).

Usage:
  memtool.py children <cpid>            -> list of apache child pids (uid 33)
  memtool.py read <cpid> <pid> <addr> <len>   -> hex bytes to stdout
  memtool.py libphp-bias <cpid> <pid>   -> load bias of libphp.so (hex)
"""
import os, re, sys

def children(cpid):
    out = []
    base = f"/proc/{cpid}/root/proc"
    for p in os.listdir(base):
        try:
            with open(f"{base}/{p}/status") as f:
                st = f.read()
        except OSError:
            continue
        if re.search(r"^Uid:\s+33\s", st, re.M) and "apache2" in open(
                f"{base}/{p}/cmdline", "rb").read().decode("utf8", "replace"):
            out.append(int(p))
    return sorted(out)

def readmem(cpid, pid, addr, n):
    fd = os.open(f"/proc/{cpid}/root/proc/{pid}/mem", os.O_RDONLY)
    try:
        os.lseek(fd, addr, os.SEEK_SET)
        return os.read(fd, n)
    finally:
        os.close(fd)

def libphp_bias(cpid, pid):
    with open(f"/proc/{cpid}/root/proc/{pid}/maps") as f:
        for line in f:
            if "libphp.so" in line and "r-xp" in line:
                return int(line.split("-")[0], 16)
    raise SystemExit("libphp.so not mapped")

if __name__ == "__main__":
    cmd = sys.argv[1]
    cpid = int(sys.argv[2])
    if cmd == "children":
        print(" ".join(map(str, children(cpid))))
    elif cmd == "read":
        pid, addr, n = int(sys.argv[3]), int(sys.argv[4], 0), int(sys.argv[5])
        print(readmem(cpid, pid, addr, n).hex())
    elif cmd == "dump-all":
        # dump-all <cpid> <addr> <len> -> "pid hex" per child line
        addr, n = int(sys.argv[3], 0), int(sys.argv[4])
        for pid in children(cpid):
            print(pid, readmem(cpid, pid, addr, n).hex())
    elif cmd == "libphp-bias":
        print(hex(libphp_bias(cpid, int(sys.argv[3]))))
    else:
        raise SystemExit(__doc__)
