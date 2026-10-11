# SPDX-License-Identifier: GPL-2.0-or-later
# How much CONTINUATION does the proxy swallow, and when does it close? (lab only: 127.0.0.1)
import socket, sys, time
sys.path.insert(0, "/root/battery")
from clients import *
port = int(sys.argv[1]); secs = float(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port)); s.sendall(PREFACE + settings()); time.sleep(0.2)
s.sendall(frame(1, 0, 1, b"\x82\x86\x84\x41" + hpack_lit(b"battery")))
chunk = frame(9, 0, 1, h2_hb_fields(1024)); s.setblocking(False)
sent = 0; t0 = time.time(); closed = None; last_report = 0; rx = b""
while time.time() - t0 < secs:
    try:
        sent += s.send(chunk)
    except BlockingIOError:
        time.sleep(0.01)
    except OSError as e:
        closed = (round(time.time() - t0, 2), str(e)); break
    try:
        d = s.recv(65536)
        if not d: closed = (round(time.time() - t0, 2), "EOF"); break
        rx += d
    except BlockingIOError:
        pass
    except OSError as e:
        closed = (round(time.time() - t0, 2), str(e)); break
    if time.time() - t0 - last_report >= 1:
        last_report = time.time() - t0; print(f"  t={last_report:.0f}s sent={sent//1024} KiB", flush=True)
print(f"  total sent {sent//1024} KiB in {time.time()-t0:.1f}s, closed={closed}, rx={len(rx)} bytes {rx[-40:]!r}")
