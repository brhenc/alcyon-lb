# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""T342d: closer.py PORT [close|short]: accept and close at once (short: send "22" first)."""
import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",int(sys.argv[1])));s.listen(64)
mode=sys.argv[2] if len(sys.argv)>2 else "close"
while True:
    c,_=s.accept()
    if mode=="short": c.sendall(b"22")
    c.close()
