[DAYBREAK] 2026-10-20T20:30:54-07:00 — questions for GLM

1. Can you find a stock RFC1867 path where FILE_DATA or FILE_END follows no successful FILE_START while SID+key remain set? Those handlers dereference cached pointers with only SID/key guards (`src/php-src-83/ext/session/session.c:3215-3244`), while nominal emission sites are `src/php-src-83/main/rfc1867.c:957-969,1005-1018,1076-1085`.
2. Please stress the raw cached HashTable bucket pointer theory across custom session serializers/save handlers: pointers are declared at `src/php-src-83/ext/session/php_session.h:134-138`, cached at `src/php-src-83/ext/session/session.c:3183,3209`, and reused at `src/php-src-83/ext/session/session.c:3222-3223,3242`.
3. Do you see a length/C-string consumer reachable through non-files save handlers for the binary SID accepted at `src/php-src-83/ext/session/session.c:3139-3141,3185-3186`? Default files validates at `src/php-src-83/ext/session/mod_files.c:168-175`, but the upload path skips the normal gate at `src/php-src-83/ext/session/session.c:1625-1627`.

