# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# T305 items 2 and 6, T291: stalled upload, TCP client that closes without data,
# bare-LF request lines. Stalled-upload part only (VV-9):
#   python3 stall.py BIN PORT TIMEOUT_CLIENT TIMEOUT_SERVER   e.g. 3s 10s
import socket, subprocess, sys, threading, time
BIN, PORT = sys.argv[1], int(sys.argv[2])
BE, BE_TCP = PORT + 50, PORT + 51
seen = {"http": [], "tcp": 0}

def be_http():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", BE)); ls.listen(64)
    while True:
        c, _ = ls.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()

def serve(c):
    c.settimeout(8); b = b""
    try:
        while b"\r\n\r\n" not in b and b"\n\n" not in b:
            d = c.recv(65536)
            if not d: break
            b += d
        seen["http"].append(b)
        if b.startswith(b"POST /stall"):
            while c.recv(65536): pass   # never answer: the upload is stalled
        else:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            time.sleep(0.2)
    except OSError: pass
    c.close()

def be_tcp():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", BE_TCP)); ls.listen(64)
    while True:
        c, _ = ls.accept(); seen["tcp"] += 1; c.close()

threading.Thread(target=be_http, daemon=True).start()
threading.Thread(target=be_tcp, daemon=True).start()
TC, TS = sys.argv[3], sys.argv[4]
cfg = f"""global
    nbthread 1
defaults
    log stdout format raw local0
    timeout connect 1s
    timeout client {TC}
    timeout server {TS}
frontend fe
    mode http
    log global
    log-format "LOG %ST %ts %Tr"
    bind 127.0.0.1:{PORT}
    default_backend b
backend b
    mode http
    server s1 127.0.0.1:{BE}
frontend ft
    mode tcp
    bind 127.0.0.1:{PORT+1}
    default_backend bt
frontend ft_delay
    mode tcp
    bind 127.0.0.1:{PORT+2}
    tcp-request inspect-delay 1s
    tcp-request content accept if {{ req.len gt 0 }}
    default_backend bt
backend bt
    mode tcp
    server s1 127.0.0.1:{BE_TCP}
"""
cf = f"/tmp/vv-stall-{PORT}.cfg"; open(cf, "w").write(cfg)
p = subprocess.Popen([BIN, "-f", cf], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
logs = []
threading.Thread(target=lambda: [logs.append(l.decode(errors="replace").strip()) for l in p.stdout], daemon=True).start()
time.sleep(0.6)

def talk(data, port=PORT, stall=False, wait=7):
    s = socket.create_connection(("127.0.0.1", port)); s.settimeout(wait); t0 = time.time()
    s.sendall(data); o = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            o += d
    except OSError: pass
    s.close()
    st = o[9:12].decode() if o.startswith(b"HTTP/") else ("closed" if not o else repr(o[:20]))
    return st, round(time.time() - t0, 1)

# T305 item 2: stalled uploads (timeout client 2s < timeout server 4s)
for name, req in (("cl_stall", b"POST /stall HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789"),
                  ("chunk_stall", b"POST /stall HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n64\r\n0123456789")):
    n = len(logs); st, t = talk(req); time.sleep(0.3)
    print(f"{name:12s} status={st} after={t}s log={[l for l in logs[n:] if l.startswith('LOG')]}")

import os; sys.stdout.flush(); p.terminate(); p.wait(); os._exit(0)
# T305 item 6: TCP client closes without sending
for name, port in (("tcp_close", PORT + 1), ("tcp_close_delay", PORT + 2)):
    before = seen["tcp"]
    s = socket.create_connection(("127.0.0.1", port)); s.close(); time.sleep(1.8)
    print(f"{name:12s} backend_connects={seen['tcp'] - before}")

# T291: request-line variants
for name, req in (("lf_all", b"GET /a HTTP/1.1\nHost: x\n\n"),
                  ("lf_reqline", b"GET /b HTTP/1.1\nHost: x\r\n\r\n"),
                  ("lf_end", b"GET /c HTTP/1.1\r\nHost: x\r\n\n"),
                  ("cr_only", b"GET /d HTTP/1.1\rHost: x\r\r"),
                  ("tab_sep", b"GET\t/e\tHTTP/1.1\r\nHost: x\r\n\r\n"),
                  ("two_sp", b"GET  /f HTTP/1.1\r\nHost: x\r\n\r\n"),
                  ("trail_sp", b"GET /g HTTP/1.1 \r\nHost: x\r\n\r\n"),
                  ("lead_crlf", b"\r\n\r\nGET /h HTTP/1.1\r\nHost: x\r\n\r\n"),
                  ("lead_lf", b"\nGET /i HTTP/1.1\r\nHost: x\r\n\r\n"),
                  ("http10_lf", b"GET /j HTTP/1.0\n\n"),
                  ("pipe_lf", b"GET /k HTTP/1.1\nHost: x\n\nGET /l HTTP/1.1\nHost: x\nConnection: close\n\n")):
    n = len(seen["http"])
    s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(3); s.sendall(req); o = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            o += d
            if name != "pipe_lf" and b"\r\n\r\n" in o and o.count(b"HTTP/1.1 ") >= 1 and (o.endswith(b"ok") or b"</html>" in o): break
    except OSError: pass
    s.close(); time.sleep(0.2)
    stats = [x[9:12].decode() for x in o.split(b"HTTP/1.")[1:] for x in [b"HTTP/1." + x]]
    fl = [x.split(b"\n")[0] for x in seen["http"][n:]]
    print(f"{name:12s} status={stats} backend_firstlines={fl}")
p.terminate(); p.wait()
