# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
import socket,sys,time
s=socket.socket(socket.AF_UNIX);s.settimeout(float(sys.argv[3]) if len(sys.argv)>3 else 3);s.connect(sys.argv[1]);s.sendall((sys.argv[2]+"\n").encode());b=b"";t=time.time()
try:
    while True:
        d=s.recv(65536)
        if not d:break
        b+=d
    print("(%.2fs) %s"%(time.time()-t,b.decode().strip().replace("\n"," | ")[:300]))
except socket.timeout: print("TIMEOUT after %.1fs, got %r"%(time.time()-t,b[:100]))
