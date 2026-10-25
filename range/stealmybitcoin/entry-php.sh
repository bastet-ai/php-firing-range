#!/bin/sh
# keepalive like the CTF OP's restart policy: a 618-class fatal kills
# php -S (single-process server exits); restart after 3s so the crash
# window is REAL and measurable.
cd /var/www/html
# PHP must run UNprivileged (like the CTF): nobody owns nothing readable
# in /root; wallet key ONLY via setuid print-flag.
while true; do
  su -s /bin/sh nobody -c 'php -S 0.0.0.0:8080 -d display_errors=Off -d memory_limit=128M' >>/var/log/phpsrv.log 2>&1
  echo "[$(date -u +%FT%TZ)] php -S exited code=$? — restarting" >>/var/log/phpsrv.log
  sleep 3
done
