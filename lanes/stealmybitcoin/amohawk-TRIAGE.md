# Triage: AndrewMohawk "Picking apart PHP2Shell" (2026-10-26) vs our range

Source: https://andrewmohawk.com/2026-10-26/picking-apart-php2shell/ (site 404s the
bare URL; full HTML lives at .../index.html — retrieved 26-Oct, full text saved in
main-session scratch). Independent analysis by "we" (author+collaborator).
DISPOSITION: link + our own notes only; do not republish their prose.

## Confirms our work (no action beyond citation)
- Stale-state -> reuse -> forged zval/HashTable -> pDestructor dispatch: same chain we built.
- "Per-binary profile required, version string insufficient" == our byte-pattern offset matching.
- Crash != proof; fresh-nonce reverse-connection/webroot-file evidence == our anti-echo score gate.
- 149/150 prefork pin via withheld-body chunked requests == Percivalll/KillaBoi pin we adopted.
- mod_php/Apache survivors vs fpm child-exit: consistent with our cb-B findings.

## NEW to us -> range actions
1. [ADOPT-TEST] Session-less 109618 producer: t=<295B string>, then field t[K][x]
   forces string->array conversion reusing the attacker's freed 320B block; ~4MiB
   field-NAME key crosses memory_limit AFTER nNumUsed=1, BEFORE Bucket0 write.
   No upload-progress needed. Our producers all used the progress path — test this
   shape on :8181/shakedown + :8088 and add to php2shell as producer variant "bracket".
2. [ADOPT] PS(id)+PS(send_cookie) leak channel: forged string length 0xC8000 at stale
   PS(id) -> php_url_encode leaks ~819KB (their run: 4,104B usable cookie) via Set-Cookie.
   Add to --route smb leak modes alongside KillaBoi-style 256B cookie.
3. [ADOPT] Output-after-close solved: forged ZEND_UNSET_OBJ handler-ptr ->
   php_output_activate(), THEN ZEND_DO_ICALL -> zif_system(cmd) => in-band stdout in
   the SAME request. Cleaner than our session-file round-trip. Rework exec route to
   the 2-instruction form; keep writeback echo as fallback.
4. [REPRODUCE-OR-REFUTE - TOP RUNG] Claimed RCE on unmodified official WordPress
   7.1.2 image (PHP 8.3.35, Apache, display_errors=Off, 150 prefork): bracket
   producer + cookie leak + 149-pin + final writes id>/var/www/html/pwn.txt.
   Our stock-WP stance (read-primitives yes, exec last-mile open) must face this:
   run their shape against our :8094-class fixture with fresh canary in webroot.
5. [ADJUST VERDICT] PHP 8.5.11 warning-leak (huge decimal "allocation sizes" =
   module+heap addrs) requires visible warnings: production display_errors=Off
   BLOCKS it on empty endpoints; escapes only via enable_post_data_reading=0 +
   app handler + request_parse_body(). Tightens our fatal_error_backtraces framing.
6. [CITE] Patch semantics: fatals deferred to VM safe-points; emergency limit exits
   worker instead of trusting cleanup. Also: mitigation — reject multipart at FE
   when app doesn't need it; body-size caps <1MiB did NOT stop SMB chain (PHP
   allocates >> wire size). Feed rscmap-style advisory fact sheet.

## Contradictions / scrutiny flags
- Their 8.5.11 chain needs the session-decoder (R:1 reference list) stale-cache —
  our 8.5 probes keyed on BG(unserialize); reconcile: decoder temp list vs
  BG(unserialize).data are likely the same cached list, different naming. Verify.
- Live-internet uid=33 result is self-reported, no raw evidence — cite as such.
- Their producer sizes (4.2MB bracket / 31-33MB measured-layout) differ from our
  ">=64MiB alloc-bailout" recipe on alpine cli-server — arch/build-dependent
  producer families; keep BOTH recipes, label by build class.

## Queued lane rungs (post-quota-pause, GLM-5.3)
- smb: bracket-producer test matrix (session-less) on shakedown + phpbleed pins
- smb: PS(id) cookie-leak mode in php2shell --route smb (leak mode v2)
- smb: 2-instruction output-activate+system exec route, re-earn :8088 + :8151 canaries
- php: stock-WordPress reproduce-or-refute rung (their 7.1.2/8.3.35 profile)
