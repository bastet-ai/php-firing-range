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
