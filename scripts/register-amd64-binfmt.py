#!/usr/bin/env python3
# Register qemu-x86_64 binfmt (F=fix-binary) on aarch64 for the *-x86 lanes.
# Run: sudo python3 scripts/register-amd64-binfmt.sh
import subprocess, sys
Q = "/usr/bin/qemu-x86_64-static"
magic = bytes.fromhex("7f454c4602010100000000000000000002003e00")
mask  = b"\xff"*18
def esc(b): return "".join(f"\\x{c:02x}" for c in b)
entry = f":qemu-x86_64:M::{esc(magic)}:{esc(mask)}:{Q}:F".encode()
open("/proc/sys/fs/binfmt_misc/register","wb").write(entry)
print("registered")
sys.exit(subprocess.run(["docker","run","--rm","--platform","linux/amd64",
      "debian:bookworm-slim","uname","-m"]).returncode)
