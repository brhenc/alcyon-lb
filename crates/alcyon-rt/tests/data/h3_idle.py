#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""T562: one h3 connection that then stays idle. usage: h3_idle.py PORT REQ PING MAXWAIT IDLE
REQ=1 sends one GET first; PING>0 sends a QUIC PING every PING s; prints CLOSED <s> when the
peer closes, STILL OPEN after MAXWAIT s."""
import asyncio, ssl, sys, time
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived
from aioquic.quic.configuration import QuicConfiguration
PORT, REQ, PING, MAXT, IDLE = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
class P(QuicConnectionProtocol):
    def __init__(s,*a,**k):
        super().__init__(*a,**k); s.h3=H3Connection(s._quic); s.fut=None; s.closed=asyncio.Event()
    def quic_event_received(s,e):
        from aioquic.quic.events import ConnectionTerminated
        if isinstance(e,ConnectionTerminated): s.closed.set(); s.why=(e.error_code,e.reason_phrase)
        for ev in s.h3.handle_event(e):
            if isinstance(ev,DataReceived) and ev.stream_ended and s.fut and not s.fut.done(): s.fut.set_result(1)
async def main():
    cfg=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,idle_timeout=IDLE); cfg.verify_mode=ssl.CERT_NONE
    async with connect("127.0.0.1",PORT,configuration=cfg,create_protocol=P) as p:
        t0=time.time()
        if REQ:
            sid=p._quic.get_next_available_stream_id(); p.fut=asyncio.get_event_loop().create_future()
            p.h3.send_headers(sid,[(b":method",b"GET"),(b":scheme",b"https"),(b":authority",b"localhost"),(b":path",b"/")],end_stream=True); p.transmit()
            await asyncio.wait_for(p.fut,5); print("answered",flush=True); t0=time.time()
        async def pinger():
            while PING>0:
                await asyncio.sleep(PING); await p.ping()
        pt=asyncio.create_task(pinger())
        try: await asyncio.wait_for(p.closed.wait(),MAXT)
        except asyncio.TimeoutError: print(f"STILL OPEN after {MAXT}s"); return
        print(f"CLOSED after {time.time()-t0:.2f}s {getattr(p,'why',None)}")
asyncio.run(main())
