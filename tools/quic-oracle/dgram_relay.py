# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""dgram_relay.py [OUT.json]: relays UDP datagrams to 127.0.0.1:41579, prints its own port, and
rewrites OUT.json (default ./datagrams.json) with each datagram's direction, time, length and
first 64 bytes after every client datagram."""

import socket,threading,json,time,sys
UP=("127.0.0.1",41579)
OUT=sys.argv[1] if len(sys.argv)>1 else "datagrams.json"
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",0))
print(s.getsockname()[1],flush=True)
log=[];t0=time.time();peers={}
def up_reader(us,cli):
    while True:
        try: d,_=us.recvfrom(65535)
        except OSError: return
        log.append({"dir":"s2c","t":round(time.time()-t0,4),"len":len(d),"hex":d[:64].hex()})
        s.sendto(d,cli)
while True:
    d,cli=s.recvfrom(65535)
    if cli not in peers:
        us=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); us.connect(UP)
        peers[cli]=us; threading.Thread(target=up_reader,args=(us,cli),daemon=True).start()
    log.append({"dir":"c2s","t":round(time.time()-t0,4),"len":len(d),"hex":d[:64].hex()})
    peers[cli].send(d)
    json.dump(log,open(OUT,"w"),indent=1)
