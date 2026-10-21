# Notes: upload-progress core flow (ext/session + main/rfc1867)

[GLM] 2026-10-21T02:41:07Z — First end-to-end read of the progress machinery in ~/php-src-83. All line refs are php-src-83 unless marked 74.

## Event flow (who calls whom)
- Multipart POST → `rfc1867_post_handler` main/rfc1867.c:650. Parser loops over parts, fires events via global fn ptr `php_rfc1867_callback` (main/rfc1867.c:52) at:
  - MULTIPART_EVENT_START rfc1867.c:759-763 (content_length known)
  - MULTIPART_EVENT_FORMDATA rfc1867.c:861-870 (each non-file part, after `sapi_module.input_filter`)
  - MULTIPART_EVENT_FILE_START rfc1867.c:957-963
  - MULTIPART_EVENT_FILE_DATA rfc1867.c:1007-1015
  - MULTIPART_EVENT_FILE_END rfc1867.c:1076-1082
  - MULTIPART_EVENT_END rfc1867.c:1259-1263
- session MINIT hooks: `php_rfc1867_callback = php_session_rfc1867_callback` ext/session/session.c:2901-2902, unhooked at MSHUTDOWN session.c:2928-2931.
- Callback: `php_session_rfc1867_callback` session.c:3098-3285. Gated only by `PS(rfc1867_enabled)` session.c:3106 (INI default "1", ZEND_INI_PERDIR — session.c:849-850). **No other precondition: any multipart POST reaches this code with stock defaults.**

## Progress state & lifetime (php_session.h:122-139)
struct `php_session_rfc1867_progress`: `sid` (zval), `key` (smart_str = zend_string), `data`/`files`/`current_file` (zvals), and TWO CACHED ZVAL POINTERS:
- `post_bytes_processed` → element of Z_ARRVAL(progress->data) ("bytes_processed"), cached once at first FILE_START (session.c:3151)
- `current_file_bytes_processed` → element of Z_ARRVAL(progress->current_file), re-cached each FILE_START (session.c:3163)
- Lifetime: allocated MULTIPART_EVENT_START (ecalloc session.c:3115), freed ONLY at MULTIPART_EVENT_END (session.c:3262-3268: dtor data, dtor sid, smart_str_free(key), efree(progress), PS(rfc1867_progress)=NULL). Struct outlives the whole request's POST body.

## Client-controlled data → where it lands
1. **$_SESSION key**: session.c:3146-3150 — FORMDATA branch: if part name == PS(rfc1867_name) (default "PHP_SESSION_UPLOAD_PROGRESS"), `key = rfc1867_prefix + part value`. `smart_str_appendl` is LENGTH-based (binary-safe): client can embed NUL bytes, `|`, quotes, anything into a $_SESSION hash key. Key is used in: `zend_hash_update` (session.c:3081), `zend_hash_del` cleanup (session.c:3093), `zend_symtable_find` cancel-check (session.c:3040).
2. **PS(id)**: session.c:3123-3124 (FILE_START) `PS(id) = zend_string_init(Z_STRVAL(progress->sid), ...)` — raw client bytes from POST session-name field (session.c:3139-3141), COOKIE or GET (early_find_sid session.c:3019-3034 via `sapi_module.treat_data`). NOTE: normal `php_session_start()` scrubs sid of `\r\n\t <>'"\` at session.c:1624-1629 BEFORE `php_session_initialize()`; **the progress path calls `php_session_initialize()` (session.c:3073, 3088) directly and skips that scrub entirely.** Only guard: `use_strict_mode` (default Off) → `s_validate_sid` (session.c:447-448). files handler re-validates key itself (php_session_valid_key in ps_files_open, mod_files.c:168-172) so stock files is contained; third-party save handlers get arbitrary key bytes. Logged for hardening guidance.
3. **Filename / field name → $_SESSION values**: FILE_START session.c:3155-3160: `current_file["field_name"] = data->name` (form field name), `current_file["name"] = *data->filename` (client filename, from Content-Disposition). FILE_END session.c:3252-3254: `tmp_name` = server temp path, `error` = cancel flag, `done` = true. All serialized into the session store by every `php_session_rfc1867_update`.
4. **`cancel_upload`**: php_check_cancel_upload session.c:3036-3050 — reads $_SESSION[key]["cancel_upload"], only accepts IS_TRUE. Read-only w.r.t. progress state; sets progress->cancel_upload which makes callback return FAILURE (session.c:3278-3280) → parser aborts the file write.

## Update/flush cycle (the "engine")
- `php_session_rfc1867_update` session.c:3052-3083: throttled by freq (INI default "1%", session.c:857) and min_freq (default "1"). When fired: `php_session_initialize()` (fresh $_SESSION from save handler!) → `SEPARATE_ARRAY(sess_var)` → cancel-check → `Z_TRY_ADDREF(progress->data)` + `zend_hash_update(sess, key.s, &progress->data)` → `php_session_flush(1)` (serialize+write+close, session.c:1687-1697).
- **Aliasing invariant to track**: $_SESSION[key] and progress->data share ONE zend_array (refcount shared via Z_TRY_ADDREF session.c:3080); $_SESSION is destroyed+rebuilt on every update cycle, progress->data survives. Cached zval pointers (post_bytes_processed etc.) stay valid only if Z_ARRVAL(data)/Z_ARRVAL(current_file) never rehash between FILE_START and END. Within one request I have not yet found a rehash of `data` (all add_assoc at FILE_END hit existing keys → in-place). Open question logged in questions-for-peer.md re: user save handlers re-entering userland during initialize.

## Defaults table (both branches identical here)
- upload_progress.enabled=1, cleanup=1, prefix="upload_progress_", name="PHP_SESSION_UPLOAD_PROGRESS", freq="1%", min_freq="1" — session.c:849-858 (83) / session.c:818-827 (74). ZEND_INI_PERDIR all.
- NOT in php.ini-production as disabled — progress is on for every default install, 7.4 and 8.3.

## Branch delta so far (83 vs 74, rfc1867.c)
- Mostly type modernization (int→zend_result, zend_bool→bool). One functional delta: MAX_SIZE_OF_INDEX `sizeof("[tmp_name]")` → `sizeof("[full_path]")` (7.4 rfc1867.c:~70 vs 8.3 rfc1867.c:~58) — 8.1+ added `full_path` to $_FILES (client-controlled full path). Checking whether full_path feeds progress too — progress "name" is still basename'd `*data->filename`; `full_path` does NOT enter progress data (verify FILE_START data struct — multipart_event_file_start in main/rfc1867.h has no full_path member; used only in safe_php_register_variable_ex for $_FILES). Will confirm.

Next: full diff of session.c progress section 74↔83, then zend_hash_update/symtable semantics for the NUL-key question.
