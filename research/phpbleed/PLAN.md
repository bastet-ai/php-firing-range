# "phpbleed" task plan (added 15:0xZ) - Calif MADBugs Serializable var_hash UAF
Bug: zend_user_unserialize() missing BG(serialize_lock)++ since PHP 5.1.
Exploit: spray+R: UAF -> heap leak -> uaf_read -> fake closure -> system().
Vendor PoC: 9 phases, ~2000 reqs, needs C: gadget class in app. NO CVE; fix
proposed (2 lines) but NOT shipped: verified 0 serialize_lock hits in
zend_user_unserialize of BOTH php-8.3.36 and php-8.5.12 (today's releases).

## Tasks
T1 (target) [done-ish]: range service phpbleed @ 8088 = php:8.5-apache +
   vendor remote_app.php + /CANARY flag (our scoring oracle, no docroot-w
   webshell mode).
T2 [GLM lane phpbleed-poc]: run vendor php8_remote.py chain against 8088;
   objective FLAG{phpbleed:...} from /CANARY via the serialize channel or
   webshell; log fires; adapt webshell stage to our canary contract.
T3 [bastet]: verify local_exploit.php on our builds (php8.3/8.5 cli incl our
   ASan tree) => confirms vuln surface on OUR stack, cheap.
T4 [research, HIGHER IMPACT]: NO-gadget variants:
   a) app-side: what REAL classes implement Serializable+recursive
      unserialize? scan composer-populated images? (their caveat = weak spot)
   b) CORE-side: session decode (PS_SERIALIZER_DECODE -> php_var_unserialize)
      decodes stored data pre-RINIT; a C: payload in a SESSION FILE would
      dispatch zend_user_unserialize if the class is autoloadable...
      test on our instrumented build: plant session file with C: payload,
      class existence gate. If any stock or common-ext class qualifies ->
      pre-auth, no unserialize-app needed = the bigger impact.
   c) today's 618/619 OOM fatal leaves BG(serialize) at level=1 dangling
      (php2shell leak stage) - same UAF family as 109619; document
      convergence: php2shell authors literally reused var_hash machinery.

## T3 result (15:1xZ): vendor local_exploit.php on php:8.3-cli aarch64
Phase1 heap leak WORKS ([+] zend_reference @ 0xebdb836a4a00), Phase3 object
ptrs found (257-bucket group). Phase4 fails: function_table scan bounds tuned
for 8.5.5 x86_64 (DELTA_MAX=0x600 too small for our aarch64/8.3 EG layout).
=> primitive confirmed live on OUR stack; exploit = per-build param tuning,
   exactly the same landing gap as 109618. Both exploits now need the SAME
   missing skill: per-build/EG offset derivation - candidate for a shared
   derive-offsets tool (extend scripts/derive_offsets.py + phase-3 scan fix).

## T4a/T4b results (17:2xZ, live probes on range)
T4a GADGET CENSUS (wordpress:6-php8.2 arm64, php 8.2.31): ZERO Serializable
implementations in WP core recursive or bundled lib dirs. The vendor's
admitted weak spot CONFIRMED at scale: phpbleed-remote finds no gadget in
stock WordPress core. Plugin-ecosystem scan = next step for a real claim.
T4b SPL QUESTION (the interesting one):
  - stock INTERNAL SPL (ArrayObject, SplObjectStorage) C: payloads REJECTED
    (internal classes don't route through zend_user_unserialize).
  - BUT a trivial USER-defined class extending ArrayObject defining
    unserialize() => C:5:"Probe":3:{abc} FIRES user unserialize with NO
    Serializable declaration on the child.
  => gadget bar LOWER than the writeup suggests: any autoloadable userland
     class with an unserialize() method (even via SPL inheritance) is a
     gateway; composer autoload / phar:// expand it further.
  - range/t4b added (:8096, session_start + Probe only, NO Serializable app)
    -> can SESSION DECODE (pre-auth, zero-gadget) carry the C: UAF? The
    impact mile.

## Status 16:3xZ
- Target LIVE :8088 (php:8.5-apache prefork, vendor gadget app verbatim,
  /CANARY FLAG{phpbleed:...}, loopback-only). Round-trip verified.
- GLM lane phpbleed-glm LIVE (41 msgs) - currently building instrumented
  php-S experiments (stale-BG serialize state = T4c convergence work) plus
  lane dir lanes/phpbleed-glm/.
- race-glm 107 msgs still on 618/619 mile.

## 17:0xZ RCE PROVEN: phpbleed-bastet.py rce => uid=33 on :8088
Full chain end-to-end OUR OWN implementation (leak + vendored R2-R6 via
read_at hook): 2683 requests, R-7 "id>/tmp/x" -> container /tmp/x =
uid=33(www-data). Target survived (200 after). shell mode (staged webshell
readfile channel + /CANARY fetch) added; docroot made 777 in range images.

## Pitfall logged: shared-target thrash
783 segfaults/10min on :8088 while my shell-mode AND GLM lane fired R-7
sprays concurrently. Failed sprays corrupt worker heaps; R-5 class_table
read then lands on stale garbage => false negative ("R-5 ce").
RULE: one exploit stream per container at a time; restart container
(fresh heap + fresh ASLR) between R-7 attempts. Dedicated port per lane.

## Pitfall #2: single-worker + shared lane = starvation
1x1x1 prefork (needed for one heap/ASLR across R-1..R-7) + GLM traffic on
same :8088 => my requests queue behind theirs; shell-mode shot killed by
timeout mid-R-2 while exit code said 0 (tail in pipe swallowed 124).
RULE: one CONTAINER per exploit stream. GLM moved to :8089 (bleed82,
php8.2), mine stays :8088. Watch pipe exit codes; use PIPESTATUS.
