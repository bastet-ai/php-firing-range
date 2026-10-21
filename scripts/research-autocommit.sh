#!/usr/bin/env bash
# Commit research/ changes every 90s until the agents are done (self-exits after
# 6 idle cycles = 9 quiet minutes).
cd "$(dirname "$0")/.."
idle=0
while [ $idle -lt 6 ]; do
  sleep 90
  if git add research/ 2>/dev/null && ! git diff --cached --quiet -- research/ 2>/dev/null; then
    n=$(git diff --cached --name-only -- research/ | wc -l)
    git -c user.name=bastet -c user.email=bastet20x6@gmail.com commit -qm "research: agent notes checkpoint ($n files) $(date -u +%H:%M)Z" && git push -q && idle=0
  else
    idle=$((idle+1))
  fi
done
echo autocommit idle-exit
