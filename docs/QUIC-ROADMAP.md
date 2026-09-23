# QUIC and HTTP/3 in Ibex — the plan

Written 2026-09-23. Supersedes the "declined" position in `tradeoff.md` §4.2 and §6.9 for
scaffolding purposes; the reasons those entries give are still the reasons this is hard.

## The number that shapes everything

HAProxy's QUIC and HTTP/3 stack, measured:

```
quic_*.c        ~16,000 lines
mux_quic.c        4,939
h3.c              3,868
qpack-*.c         1,357
xprt_quic.c         283
                 ------
                 32,191 lines of C
```

Ibex in total is 65,579 lines of Rust. **Porting HAProxy's QUIC would be half the project
again**, and most of it is not proxy logic — it is packet protection, loss recovery,
congestion control, ACK ranges, path validation and flow control. Writing that from scratch
is not scaffolding; it is a year.

So the plan does not write it. HAProxy delegates the cryptographic half to OpenSSL; Ibex
delegates the whole transport to a sans-IO state machine and writes only the parts that are
Ibex's own: the datagram path, the connection table, and the HTTP/3-to-HTX conversion.

## The oracle exists, and I built it

The reference binary at `/home/bhenc/reference/haproxy/haproxy` is compiled **`-QUIC`** and
cannot serve HTTP/3 — every QUIC question asked of it so far has been answered by a binary
that does not have the feature.

There is now a second tree, `/home/bhenc/reference/haproxy-quic/`, built with

```
make -j64 TARGET=linux-glibc USE_OPENSSL=1 USE_QUIC=1 USE_ZLIB=1 USE_PCRE2=1 USE_THREAD=1
```

against the system OpenSSL 3.5.8, whose native QUIC API needs neither quictls nor
`USE_QUIC_OPENSSL_COMPAT`. Verified `+QUIC -QUIC_OPENSSL_COMPAT` on HAProxy 3.5-dev7.

```
$ ./tools/quic-oracle/run_oracle.sh
QUIC_PORT=47628 BACKEND=38229 ...
oracle: http_version=3 code=200
```

`curl --http3-only` → HAProxy/QUIC → an HTTP/1 backend → 200. That command is the
definition of done for this whole roadmap, with `ibex` substituted for `haproxy`.

`data/quic_handshake_capture.json` holds every datagram of one such session, captured
through `tools/quic-oracle/dgram_relay.py`, with direction, timing, length and the first 64
bytes of each. Decoded, the shape of a real handshake:

```
0 c2s len=1200 0xc7 Initial   ver=00000001
1 c2s len=1200 0xc0 Initial   ver=00000001
2 s2c len=1252 0xc2 Initial   ver=00000001
3 s2c len=291  0xe2 Handshake ver=00000001
4 c2s len=1200 0xc2 Initial   ver=00000001
5 c2s len=1406 0x44 SHORT(1-RTT)
...  9 client→server, 7 server→client, 6,649 bytes up
```

That capture is the fixture for the datagram path: real Initial packets, real coalescing,
real 1200-byte padding, produced by the client we have to satisfy.

## The transport: `quinn-proto`, not a rewrite, not tokio

```
quinn-proto 0.11.18   "State machine for the QUIC transport protocol"
  tokio in its dependency tree : 0
  license                      : MIT OR Apache-2.0
  rustls                       : 0.23, already Ibex's TLS stack
```

It is sans-IO: you hand it datagrams and a clock, it hands you datagrams and timeouts. Ibex
keeps its own scheduler, its own poller, its own buffers — which is the entire reason tokio
was rejected and the reason quinn itself (the async wrapper) is not what we are using.

**Licensing.** Ibex is GPL-2.0-or-later. `quinn-proto` and `rustls` both offer MIT, which is
GPL-compatible. `ring` is `Apache-2.0 AND ISC`, and Apache-2.0 is incompatible with
GPL-2.0-*only* — but "or later" permits GPL-3.0, with which Apache-2.0 is compatible. Ibex
already depends on `rustls` + `ring` today, so QUIC changes nothing here. Worth stating once
rather than discovering later.

## What is actually ours to write

| layer | HAProxy | Ibex |
|---|---|---|
| UDP datagram path, `recvmmsg`/`sendmmsg`, GSO/GRO | `quic_sock.c` | **ours** (T23) |
| connection table keyed by connection ID | `quic_cid.c` | **ours** (T24) |
| packet protection, loss, congestion, flow control | ~16k lines of C | `quinn-proto` |
| TLS 1.3 inside the transport | `quic_ssl.c`, `quic_tls.c` | `rustls` via `quinn-proto` |
| HTTP/3 framing, control stream, SETTINGS | `h3.c` | **ours** (T25) |
| QPACK | `qpack-*.c` | **ours, static-table only** (T25) |
| HTX conversion | `h3.c` | **ours** (T25) |

Roughly 2,000–3,000 lines of Rust instead of 32,000 lines of C.

## The scaffolding shortcut that makes T25 tractable

QPACK's dynamic table needs two unidirectional streams, an insertion-count state machine and
blocked-stream handling. **It can be skipped entirely and legally**: advertise

```
SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0
SETTINGS_QPACK_BLOCKED_STREAMS    = 0
```

and a compliant client — curl/nghttp3 included — will encode headers using only the 99-entry
static table and literals. Decoding becomes a pure function. The dynamic table is then a
later optimisation with a measurable cost, not a prerequisite for `curl --http3`.

Verify this against the oracle rather than trusting it: the capture shows what nghttp3
actually sends when the server advertises zero capacity.

## The architectural bill, and it is smaller than §6.9 implied

`tradeoff.md` §6.9 records that the constraint is `TcpSession.cli: OwnedFd`, not HTX. That
is still right, but scaffolding does not have to pay it. A QUIC connection is not an fd, so
QUIC gets its **own** session type and its own listener; `TcpSession` is untouched. The two
paths meet at HTX, which is protocol-agnostic — HTX predates QUIC in HAProxy by 28 months and
`mux_quic.c` makes zero `htx_` calls.

Unifying them behind one connection abstraction is worth doing **after** `curl --http3`
works, when there is a second implementation to generalise from. Doing it first is designing
against one example.

## Phases

Each phase is a task with its own oracle. None of them is "write QUIC".

**T23 — the datagram path.** A UDP listener in the engine: bind, non-blocking `recvmmsg`,
`sendmmsg`, peer addresses, integration with the existing poller. `bind quic4@host:port`
parses. No crypto, no QUIC. Oracle: replay `data/quic_handshake_capture.json` and assert
every datagram arrives intact with the right peer and length.

**T24 — connection identity and the transport.** `quinn-proto` `Endpoint` and `Connection`
driven from the datagram path and the timer wheel; a connection table keyed by destination
connection ID; retry and version negotiation. Oracle: `curl --http3` completes the handshake
against Ibex and reports a transport-level error for the missing HTTP layer rather than a
handshake failure.

**T25 — HTTP/3 and QPACK.** Control stream, SETTINGS, the frame layer, QPACK static decode,
HTX conversion, and the response path back. Oracle: `curl --http3-only ... ` against Ibex
returns 200 with the backend's body — byte-identical to what `run_oracle.sh` gets from
HAProxy.

**Later, not now.** Dynamic QPACK, 0-RTT, connection migration, GSO/GRO batching, retry
tokens under load, the unified connection abstraction, `alt-svc` advertisement from an H1/H2
listener.

## The discipline

Every phase compares against `/home/bhenc/reference/haproxy-quic/haproxy`, not against the
RFC. RFC 9000 and RFC 9114 say what is legal; the oracle says what nghttp3 and HAProxy
actually do, and those are the two programs that have to interoperate with Ibex.

This project has already been bitten once by reasoning from an RFC — `GOAWAY
ENHANCE_YOUR_CALM` was inferred from RFC 9113 and stated as HAProxy's behaviour when
HAProxy's real answer was four configuration knobs, all off by default. QUIC has far more
surface for that mistake.

---

## On depending on `quinn-proto` at all

The concern is fair: a third-party transport is one thing in Ibex that is not a faithful
HAProxy port, and it may have to be replaced. Three things make that a manageable bet rather
than a trap.

### 1. Most of what diverges is not quinn-proto's to diverge on

HAProxy exposes **31** `tune.quic.*` knobs. Mapped against `quinn-proto`'s `TransportConfig`:

| HAProxy knob | `quinn-proto` |
|---|---|
| `fe.max-idle-timeout` | `max_idle_timeout` |
| `fe.stream.max-concurrent` | `max_concurrent_bidi_streams` / `_uni_streams` |
| `fe.stream.rxbuf` | `stream_receive_window` |
| `fe.cc.max-win-size` | `send_window` / `receive_window` |
| `fe.cc.max-frame-loss`, `cc.reorder-ratio` | `packet_threshold`, `reordering_threshold` |
| `fe.tx.udp-gso` | `enable_segmentation_offload` |
| congestion controller | `congestion_controller_factory` (Cubic, NewReno, BBR) |

**Not expressible, and mostly not wanted from a library anyway:**

```
fe.sec.retry-threshold      fe.sec.glitches-threshold    sec.stateless-reset-rate
fe.stream.max-total         fe.stream.data-ratio         fe.sock-per-conn
mem.tx-max                  zero-copy-fwd-send
```

Every one of those is a **policy or buffer decision that is Ibex's regardless of which
transport it drives** — the same shape as `tune.h2.fe.glitches-threshold`, which Ibex already
implements itself. Using `quinn-proto` does not take a single DoS control away.

What it *does* own is congestion-control internals — `cc.hystart`, `cc.cubic-min-losses`,
pacing. Those are where a faithful port would be a research project in itself, and where
"different from HAProxy" is least likely to be a security problem and most likely to be a
throughput difference. Which is exactly the thing to measure rather than argue about.

### 2. The seam is designed in, not discovered later

`quinn-proto` is sans-IO, so the boundary is already narrow: datagrams and a clock in,
datagrams and stream events out. T24 is required to put a trait at that boundary so the
transport is one implementation of an interface rather than a dependency woven through the
runtime. If it is ever replaced by a hand-written port, the datagram path (T23), the
connection table, the HTTP/3 layer (T25) and the HTX conversion all survive unchanged.

That is the difference between a bet you can unwind and one you cannot, and it costs one
trait definition now.

### 3. The decision gets made on evidence

T26 answers it: run the same load against Ibex and against
`/home/bhenc/reference/haproxy-quic/haproxy`, and record where they differ under duress.
Until that exists, "quinn-proto is fine" and "quinn-proto must go" are both guesses, and this
project has a rule about those.
