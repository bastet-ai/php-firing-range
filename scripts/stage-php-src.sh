#!/usr/bin/env bash
# Post-disclosure staging (Wed 2026-10-21+): rebuild affected php branch from
# php-src with the security patch reverted -> "vulnerable-at-commit" core box.
# Usage: stage-php-src.sh <php-branch> <fix-commit-sha>
set -euo pipefail
BRANCH="$1"; FIX="$2"
cd "$(dirname "$0")/.."
mkdir -p build
cd build
[[ -d php-src ]] || git clone --depth=200 https://github.com/php/php-src.git
cd php-src
git fetch origin "$BRANCH" && git checkout -q FETCH_HEAD
# revert the security fix(es) => vulnerable build
git revert --no-edit "$FIX"
docker build -t firing-php:vuln-$BRANCH -f ../range/phpsrc.Dockerfile .
echo "built firing-php:vuln-$BRANCH (patch-reverted). add a compose service to expose it."
