# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
import socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1]);s.sendall(b"show stat\n");b=b""
while True:
    d=s.recv(65536)
    if not d:break
    b+=d
L=b.decode().splitlines(); h=L[0].lstrip("# ").split(",")
for l in L[1:]:
    f=l.split(",")
    if len(f)>1 and f[1]=="s3":
        r=dict(zip(h,f)); print(" ".join("%s=%s"%(k,r.get(k,"?")) for k in ("status","check_status","check_code","check_desc","last_chk")))
