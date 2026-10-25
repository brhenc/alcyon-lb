#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""HTTP/3 connections held open, for the connection-counting tests (T504).

usage: h3_hold.py PORT CONNS REQS HOLD WAIT
Opens CONNS connections to 127.0.0.1:PORT at once; on each, sends REQS GET requests one after
the other, waiting at most WAIT seconds for each answer. Prints 'params max_data=<n> bidi_remote=<n>' (the server's flow-control limits) once, 'served' as each connection finishes its requests, 'ready ok=<n> fail=<m>' once every
connection has either finished its requests or given up, holds the survivors open for HOLD more
seconds, closes them and prints 'closed'."""
import asyncio, ssl, sys
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration

PORT, CONNS, REQS, HOLD, WAIT = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
ok = fail = finished = 0
params_printed = []


class P(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.waiters = {}

    def quic_event_received(self, e):
        for ev in self.h3.handle_event(e):
            if isinstance(ev, DataReceived) and ev.stream_ended:
                w = self.waiters.pop(ev.stream_id, None)
                if w and not w.done():
                    w.set_result(True)


async def one(gate):
    global ok, fail, finished
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    good = False
    try:
        async with connect("127.0.0.1", PORT, configuration=cfg, create_protocol=P, wait_connected=False) as p:
            for _ in range(REQS):
                sid = p._quic.get_next_available_stream_id()
                fut = asyncio.get_event_loop().create_future()
                p.waiters[sid] = fut
                p.h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/")], end_stream=True)
                p.transmit()
                await asyncio.wait_for(fut, WAIT)
            good = True
            ok += 1
            if not params_printed:
                params_printed.append(1)
                q = p._quic
                print(f"params max_data={q._remote_max_data} bidi_remote={q._remote_max_stream_data_bidi_remote}", flush=True)
            print("served", flush=True)
            finished += 1
            await gate.wait()
    except BaseException:
        if not good:
            fail += 1
            finished += 1


async def main():
    gate = asyncio.Event()
    tasks = [asyncio.create_task(one(gate)) for _ in range(CONNS)]
    while finished < CONNS:
        await asyncio.sleep(0.05)
    print(f"ready ok={ok} fail={fail}", flush=True)
    await asyncio.sleep(HOLD)
    gate.set()
    await asyncio.gather(*tasks)
    print("closed", flush=True)


asyncio.run(main())
