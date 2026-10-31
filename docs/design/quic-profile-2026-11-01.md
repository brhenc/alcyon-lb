# QUIC/h3 profile: Ibex (quinn-proto) against HAProxy 3.5-dev10 (T544, 2026-10-31 night)

Measurement and evidence only. The redesign is T545, which starts from here. All the numbers
are user-space instructions (`instructions:u`). There are no wall-time claims: everything ran in
measuring slot B (`flock -x /tmp/ibex-load-n1.lock`, `IBEX_MEASURE_CPUS=12,13,14`, perf and the
client on 13), governor `performance`, no `wwm.exe`, 21:55-22:16 CET.

**Build measured**: branch `fix/t544` = main d581eae9 (T539: HandleMap hasher, qpack
`static_ref`) + fix/t542 f9ac59ef (vendored quinn-proto 0.11.18 + PADDING-run patch).
`cargo build --profile release-perf --bin ibex` (`~/ibex-targets/t544/release-perf/ibex`). The
profiles come from the same tree built with `RUSTFLAGS="-C force-frame-pointers=yes"`
(`~/ibex-targets/t544/fp/release-perf/ibex`, +5.2 % on h3, +1.5 % on h2), and their shares are
scaled to the plain build's counts. T543's commits (allocations at 0) are **not** in this build.
Oracle: `~/reference/haproxy-quic/haproxy` 3.5-dev10-38e65c-10 (OpenSSL 3.5.9, `-O2 -g`, no
frame pointers, so DWARF unwinding). Scenario: `tools/measure/scenarios/h3.body`, `nbthread 1`,
h2load `-c 1 -m 1`, one connection, a 2000-request warm-up first.

Raw data, folded stacks, logs and scripts: `~/ibex-worktrees/review/t544-2026-11-01/`. The raw
`perf.data` files were deleted after the report; the `*.folded` files were kept.

## 0. Two measurement facts that change how earlier numbers read

**(a) `perf record -e instructions:u` misattributes samples on this host (EPYC 7542, Zen 2).**
A test program (`scripts/s.c`) runs a 1000-iteration add loop (4,007 user instructions), then
`epoll_wait(…, 0)` (53 user instructions in libc). `perf stat` counts it exactly: 4,060
instructions per iteration. But `perf record -e instructions:u -c 100000…1000000` puts **38-48 %
of the samples on a kernel IP** (`entry_SYSCALL_64`). The true share near the syscall is 1.3 %,
and `main` gets 41-53 % of the samples where it should get 98.5 %. The overflow interrupt
arrives late, at the next kernel entry. So every `instructions:u` profile on this host,
**T539's included**, moved cost from the code that runs before a syscall onto the syscall
wrapper (`rustix::…::syscall4` = `epoll_wait`, 15k/req in our h3 profile). The by-function
shares of those profiles are not reliable. The totals from `perf stat` are exact.

AMD IBS gives precise IPs: `perf record -e 'ibs_op/cnt_ctl=1,swfilt=1/u' -c 100000` puts
97.66 % of the samples on `main` in the same test. It counts dispatched ops, not instructions.
This report takes every phase **share** from IBS and scales it to the instructions:u total that
perf stat measured. Samples on the `syscall` instruction itself are dropped (many ops, one
instruction): 22.8 % of Ibex h3's samples, 21.6 % of HAProxy h3's. Ops and instructions differ
by a few percent per phase (AES-NI/AVX, `rep movsb`), so read the table as ±10 % per row.

**(b) h3c1 instructions per request depend on how many ACK-only datagrams h2load sends, and
that changes from one run to the next.** The request packets are always 1.0 per request, and
the proxy always sends 1.078 datagrams per request. But the client sends 1.12 to 1.91 datagrams
per request to Ibex (the extra ones are ACK-only). Over 10 rounds of 10,000 requests
(`rounds/`), a linear fit gives:

`ins/req = 113,222 + 6,041 x (client datagrams/req)`, r = 0.982. **One inbound ACK-only datagram
costs Ibex ~6.0k instructions.**

HAProxy always gets 1.97 datagrams per request from the same client (73.66-73.72k/req). With
the same inbound load, Ibex is at **125.1k = 1.70x HAProxy**. insreq's "min of rounds" picks
the round with the fewest ACKs: 120.2k = 1.63x. h2load prints the datagram counts in each
`<label>.rN.client` (`UDP datagram: N sent, M received`). Read them next to every h3 figure.

(c) strace undercounts h3 datagrams. It slows the proxy enough that the client coalesces its
ACKs: 1.007 rx datagrams per request under strace, 1.91 per request from h2load's counter and
from uprobes on `handle_datagram`. T539's census table (~1008 per 1000 requests) has the same
undercount. The syscall counts below still hold.

## 1. Totals (perf stat, `tools/measure/insreq.sh`, slot B, 3-10 rounds of 10,000)

| | Ibex | HAProxy dev10 | Ibex/HAProxy |
|---|---:|---:|---:|
| h3 mux (h3c1), min of rounds | 120,241 (1.17 client dgrams/req) | 73,684 (1.97) | 1.63x |
| h3 mux at HAProxy's inbound datagram count (fit) | 125,110 | 73,684 | 1.70x |
| h2 over TLS (h2s1) | 79,609 | 53,428 | 1.49x |
| H4 rule: mux <= h2 + 15 % = 91.5k and <= 1.5x HAProxy = 110.5k | misses by 28.7k and 9.7k | | |

## 2. Per-phase table (IBS shares x instructions:u, per request; per packet = / (rx + tx datagrams))

The Ibex h3 profile ran at 1.292 client datagrams per request, scaled to 121.0k (the fit at
1.292). Packets per request: Ibex 1.292 rx + 1.078 tx = 2.37; HAProxy 1.980 + 1.020 = 3.00 (one
QUIC packet per datagram here). HAProxy's IBS DWARF chains unwind for 78 % of the samples. For
HAProxy, each IBS leaf's cost is split over the phases in the proportions that leaf's callers
have in the instructions:u DWARF profile (`scripts/hybrid.py`). Ibex's frame-pointer chains
unwind, with inlined frames expanded by `llvm-symbolizer` (`scripts/fold2.py`).

| phase | Ibex h3 /req | HAProxy h3 /req | Ibex - HAP | Ibex /pkt | HAP /pkt | Ibex h2 /req |
|---|---:|---:|---:|---:|---:|---:|
| UDP recv (recvmmsg glue, rx batch) | 745 | 420 | +325 | 314 | 140 | - |
| packet decode / CID route | 1,795 | 1,203 | +592 | 757 | 401 | - |
| header protection | 851 | 716 | +135 | 359 | 239 | - |
| AEAD open | 2,008 | 12,013 | -10,005 | 847 | 4,004 | (TLS) |
| AEAD seal | 1,057 | 2,368 | -1,311 | 446 | 789 | (TLS) |
| frame parse | 3,816 | 7,050 | -3,234 | 1,610 | 2,350 | - |
| ACK processing (peer's ACKs) | 758 | 326 | +432 | 320 | 109 | - |
| ACK generation (ranges, ACK frames) | 1,848 | 401 | +1,447 | 780 | 134 | - |
| stream bookkeeping | 5,551 | 6,448 | -897 | 2,342 | 2,149 | 219 |
| flow control | 505 | 107 | +398 | 213 | 36 | - |
| loss detection / timers | 4,009 | 766 | +3,243 | 1,692 | 255 | 545 |
| congestion / pacing | 226 | 176 | +50 | 95 | 59 | - |
| packet build (poll_transmit, populate_packet) | 3,504 | 3,189 | +315 | 1,478 | 1,063 | - |
| connection state machine (quinn `Connection` driver / `quic_conn_io_cb`) | 6,967 | 523 | +6,444 | 2,940 | 174 | - |
| UDP send | 412 | 304 | +108 | 174 | 101 | - |
| **QUIC transport subtotal** | **34,052** | **36,010** | **-1,958** | **14,368** | **12,003** | TLS record 3,446 + seal 1,372 |
| of which crypto (HP + AEAD) | 3,916 | 15,097 | -11,181 | | | |
| of which non-crypto | 30,136 | 20,913 | +9,223 | 12,716 | 6,971 | |
| h3 framing + QPACK (`mux_h3`, `qpack`) | 10,066 | 4,610 | +5,456 | | | h2+HPACK 7,469 |
| header codec shared with h2 (Huffman, `check_request_fields`, `DecodedFields`) | 4,827 | 1,540 | +3,287 | | | 2,231 |
| Ibex QUIC glue (listener, owner, endpoint maps, CID SipHash, copies) | 10,996 | 0 | +10,996 | 4,640 | | 714 |
| mux<->stream bridge (`h2_bridge`, child sessions; HAProxy: inside its h3/stream rows) | 11,096 | - | | | | 10,546 |
| HTTP engine + backend h1 | 25,251 | 24,619 | | | | 35,403 |
| scheduler / event loop / poller / `engine::*` | 22,917 | 2,329 | | | | 17,633 |
| **common stream engine subtotal (the three rows above)** | **59,264** | **26,948** | **+32,316** | | | **63,582** |
| malloc/free (HAProxy: `pool_*`) | 671 | 4,166 | -3,495 | | | 0 |
| h2 framing / TLS record residue in the h3 run | 1,150 | 413 | +737 | | | |
| **total** | **121,026** | **73,687** | **+47,339** | **51,066** | **24,562** | **79,609** |

The split between the three "common" rows depends on which inlined frame matches first. Their
sum is the stable figure: 59.3k (h3) against 63.6k (h2) for the same engine.

Where the gaps are:
- **Ibex h3 - HAProxy h3 = +47.3k**: common engine +32.3k (not QUIC: Ibex h2 has the same
  engine, 63.6k); Ibex QUIC glue +11.0k; h3 + QPACK + shared codec +8.7k; quinn non-crypto
  transport +9.2k; crypto **-11.2k** (ring opens 1200 B for 2.0k; OpenSSL opens 1444 B for 12.0k,
  with `evp_cipher_init_internal`/`EVP_CIPHER_CTX_ctrl` on every packet); malloc -3.5k.
- **Ibex h3 - Ibex h2 = +41.4k** (what H4's "h2 + 15 %" measures): transport +29.2k (34.1k
  against h2's TLS record 4.8k), glue +10.3k, h3 framing + codec +5.6k, engine -4.3k.

## 3. Calls, datagrams and syscalls per request

uprobes on the release-perf binary (`scripts/calls.sh`, perf stat `probe_ibex:*`, 5000
requests, 1.91 client datagrams/req in that run):

| per request | Ibex h3 | Ibex h2 |
|---|---:|---:|
| `QuicEndpoint::handle_datagram` = `Connection::handle_event` = `process_payload` = `drive_connection` | 1.911 | - |
| `QuicEndpoint::refresh_timer` (`conn.poll_timeout()` + BTreeSet re-key) | 2.990 | - |
| `QuicListener::send_batch` (each one runs `Connection::poll_transmit` until None) | **8.253** | - |
| `Connection::populate_packet` (a packet actually built) | 1.079 | - |
| `QuicListener::pump` | 1.282 | - |
| `read_stream` / `write_stream` (each a SipHash `ConnectionId` lookup) | 1.001 / 1.000 | - |
| `Engine::step` (loop passes) | 6.975 | 7.152 |
| `Instant::now` (`Timespec::now`) | 44.9 | 37.6 |

Syscalls (strace, 2000 requests; the datagram counts are undercounted, see 0c):

| per request | Ibex h3 | HAProxy h3 | Ibex h2 | HAProxy h2 |
|---|---|---|---|---|
| epoll_wait | 3.01 | 3.01 | 3.07 | 3.00 |
| UDP rx | recvmmsg 1.00 | recvmsg 3.04 (2.02 EAGAIN) | | |
| UDP tx | sendmmsg 1.08 (1 dgram each, no GSO) | sendmsg 1.02 | | |
| TCP to the server | write 1.00, read 1.09 | sendmsg 1.00, recvmsg 1.00 | read 2.00, write 2.00 | recvmsg 4.01 (1 EAGAIN), sendmsg 2.00 |
| other | **getsockname 1.00** | clock_gettime 6.02 (real syscalls) | | clock_gettime 6.0 |
| datagram sizes | rx 1200 B, tx 49 B | rx 1444 B, tx 62-64 B | | |

Ibex makes fewer syscalls than HAProxy. Its `getsockname` per request is
`TcpSession::attach_server_with_xprt` (`crates/ibex-rt/src/proxy.rs:1733`, `bc_src` for
`%bi/%bp`): every h3 stream is a new child session that takes the server connection again from
the idle pool. h2 does not make this call.

## 4. Hypotheses

| # | hypothesis | verdict | the number |
|---|---|---|---|
| 1 | Per datagram: `Endpoint::handle` -> `handle_event` -> drive -> `poll_transmit` round trips | **confirmed** | handle/drive 1.91/req (one full pass per datagram, not batched); `send_batch` 8.25/req for 1.08 packets: ~7 `Connection::poll_transmit` sweeps per request that build nothing; `Connection::poll_transmit` + `QuicEndpoint::poll_transmit` self 2.1k + `send_batch` self 2.0k |
| 2 | An ACK-only datagram is cheap | **refuted** | +6.0k instructions per inbound ACK-only datagram (fit, r = 0.98); HAProxy's whole transport is 7.0k (non-crypto) per packet, Ibex's 12.7k |
| 3 | Does quinn ACK more often than HAProxy? | **refuted** | tx 1.078 against 1.022 datagrams/req; both send one ACK in each response packet. The extra 0.056 is `MAX_STREAMS` (T539) |
| 4 | BTreeMap/BTreeSet/RangeSet costs | **confirmed, moderate** | BTree leaves 2.8k/req; ACK generation 1.85k against 0.40k (`ArrayRangeSet::insert` 565, `RangeSet::pop_min` 226, `PendingAcks` 250) |
| 5 | Timers / loss detection on every packet | **confirmed** | 4.0k against 0.77k: `refresh_timer` 1.7k (2.99 calls/req, each a `poll_timeout` scan of quinn's `TimerTable` and a BTreeSet remove+insert), `TimerTable::next_timeout` 0.6k, `detect_lost_packets` + `pto_time_and_space` + `set_loss_detection_timer` 0.64k, `reset_idle_timeout`/`reset_keep_alive` 0.34k |
| 6 | quinn's connection state machine overhead (spaces, retransmit checks, stats) | **confirmed** | 7.0k against HAProxy's 0.5k: `handle_event` 0.79k, `Retransmits::is_empty` 0.73k, `VarInt::decode` 0.61k, `PacketSpace::take` 0.44k, `process_decrypted_packet` 0.34k, `CidQueue::active` 0.27k, `FrameStats::record` 0.21k |
| 7 | Per-frame `Bytes` refcounting | **confirmed, small** | `bytes::` leaves 1.9k/req |
| 8 | `Instant::now` reads | **confirmed for the engine, not QUIC-specific** | 44.9 reads/req h3, 37.6 h2 (vDSO, ~50 ins each: ~2.2k/req, +0.4k for h3) |
| 9 | `ConnectionHandle`/`ConnectionId` -> map -> `Connection` indirection | **confirmed** | SipHash (`DefaultHasher`) 3.1k/req by leaf, `ConnectionId` hash 1.4k + `ConnectionTable::lookup`/`eq` 0.8k: every `read_stream`/`write_stream`/`finish`/`open_stream` looks up by `ConnectionId` (`get_handle`), on top of the handle maps T539 fixed |
| 10 | Endpoint/Connection split (endpoint events looped back) | **partly** | `drive_connection` self 1.6k/req, including the `poll_endpoint_events` loop and the event queue `push_back` per stream event |
| 11 | `Transmit` / datagram copies | **refuted as h3-specific** | memcpy leaves 3.7k (h3) against 3.5k (h2); rx copies 1200 B into `CopyBlock`/`BytesMut` per datagram, tx copies 49 B twice (`tx_buf` -> `send_raw_bufs`) |
| 12 | Pacing / congestion control | **refuted** | 226 against 176 |
| 13 | More wakeups / loop passes per request than h2 or HAProxy | **refuted** | `Engine::step` 6.98 (h3) against 7.15 (h2); epoll_wait 3.0 for all four |
| 14 | More syscalls than HAProxy | **refuted** | Ibex h3 ~8.2/req against HAProxy ~15/req (HAProxy: 6 clock_gettime, 2 EAGAIN recvmsg); one avoidable `getsockname` per h3 request |
| 15 | HAProxy wins with pools, no per-frame heap | **refuted for this build** | HAProxy `pool_*`/malloc 4.2k/req against Ibex malloc 0.67k (and T543 takes Ibex to 0 allocations) |
| 16 | GSO/GRO, recvmmsg/sendmmsg batching | **refuted at -c1 -m1** | HAProxy does one recvmsg/sendmsg per datagram; Ibex batches but gets 1 datagram per call |
| 17 | PADDING still costs after T542 | **confirmed, fixable** | `frame::Iter::try_next` 1.75k/req: the patch's `position(|&b| b != 0)` scans 1150 B one byte at a time. HAProxy's `quic_parse_padding_frame` does the same, 1.8k/req for 1444 B |
| 18 | Crypto is Ibex's problem | **refuted** | ring HP + AEAD 3.9k/req against OpenSSL 15.1k |
| 19 | h3 framing + QPACK cost more than h2 + HPACK | **confirmed** | 10.1k + 4.8k shared = 14.9k against h2's 7.5k + 2.2k = 9.7k (+5.2k). Largest: `H3MuxContext::put_head` 2.55k (response QPACK encode), `on_headers` 1.06k, `parse_head` 0.85k, `static_ref` binary search 0.74k, Huffman decode 1.72k, `check_request_fields` 1.16k (against h2's 2.2k for the whole shared codec: unknown why h3 pays twice the shared codec) |
| 20 | The gap to HAProxy is mostly QUIC | **refuted** | 32.3k of the 47.3k is the common stream engine (Ibex h2 pays it too: 63.6k against HAProxy's 26.9k). QUIC + glue + h3 is +15.0k net over HAProxy, but +41.4k over Ibex h2 |

## 5. If T543's plans land (from `tasks/T543-progress.md` on fix/t543, 1d2f9114)

T543 part A (done: 0 allocations per h3 request, quinn free lists per connection) is not in
this build. It removes at most the 0.67k of malloc/free here, plus the boxing/unboxing code
around it; T539's "+3.1k quinn malloc" came from a skid-affected instructions:u profile (0a).
Part B's plan (take the largest quinn items in order; BTreeSet timer re-keying; SipHash on CID
maps) covers this report's #5 (refresh_timer + BTree, about 2-2.5k), #9 (SipHash about 2-3k),
and parts of #6. If all of it lands, at 1.29 client datagrams per request: about 121.0k - 0.7k
- 2.3k - 2.5k ≈ **115-116k**. That is still 24k over H4's 91.5k. What is left is the
per-datagram structure (#1, #2: 6k per ACK-only datagram, ~7 empty `poll_transmit` sweeps per
request), quinn's state machine (#6, 7.0k), the glue (11.0k, with send_batch 2.0k and
drive_connection 1.6k as its largest parts), and h3 + QPACK (+5.2k over h2). T543 should use
IBS shares, not instructions:u ones (0a), and should note the client datagram count of each
round it compares (0b). Both were sent to the supervisor at 22:1x.

## 6. Facts for the designer (T545)

Ranked cost centres of the h3 mux, per request at 1.29 client datagrams per request (121.0k in
all), with what each is over HAProxy and over Ibex h2:

1. **Common stream engine** 59.3k (49 %): HAProxy 26.9k, Ibex h2 63.6k. Shared with h2 and not
   QUIC. It accounts for 32k of the HAProxy gap and none of the h2 + 15 % gap.
2. **quinn transport, non-crypto** 30.1k (25 %): HAProxy 20.9k. Structural to quinn: one
   `handle_event` + drive + endpoint-event loop per datagram, a `poll_transmit` that re-checks
   every space, path, CID queue and retransmit queue each time it is asked (~8 times per request
   in our loop, 1 packet built), the `TimerTable` scan on each `poll_timeout`, and its RangeSet
   ACK bookkeeping. Fixable locally: the PADDING scan (1.75k, word-at-a-time),
   `Retransmits::is_empty` and `FrameStats` (~1k), how often Ibex asks for a transmit.
3. **Ibex QUIC glue** 11.0k (9 %): HAProxy 0, h2 0.7k. All Ibex's own: `send_batch` 2.0k (8.25
   calls/req, `take_dirty` set by every `owner_send`), `drive_connection` 1.6k, SipHash
   `ConnectionId` lookups 1.4k + 0.8k (by `get_handle` on each stream call), `owner_recv` 0.84k,
   `pump` 0.5k, wake/news bookkeeping 0.46k, `Bytes` refcounts. Plus 1 `getsockname` per request
   (`proxy.rs:1733`).
4. **mux<->stream bridge** 11.1k: the h2 bridge, reused by h3. Same as h2 (10.5k). Counted in
   item 1.
5. **h3 framing + QPACK + shared header codec** 14.9k (12 %): h2 9.7k, HAProxy 6.15k. Local to
   `ibex_proto::mux_h3`/`qpack`.
6. **Crypto** 3.9k: HAProxy 15.1k. Not a target.
7. **Per inbound ACK-only datagram: 6.0k**. Any design that does a full connection pass per
   datagram pays this. The client decides how many there are (0.1 to 0.9 per request with
   h2load here, 0.97 against HAProxy), so it moves the headline number by up to 5 %.

Structural to quinn-proto (needs a deeper rework or a different layer): items 2's per-datagram
pass and the `poll_transmit` design, the `TimerTable`/`poll_timeout` contract that makes the
caller re-key a global timer after every call, and the RangeSet-based ACK and send-buffer
bookkeeping. Fixable without restructuring quinn: the PADDING scan, the number of
`poll_transmit`/`refresh_timer` calls Ibex makes (item 3), the CID-keyed lookups, the
`getsockname`, and the h3/QPACK encoder.

### Measurement recipe (reuse it)

1. Counts: `IBEX_MEASURE_CPUS=12,13,14 flock -x /tmp/ibex-load-n1.lock tools/measure/insreq.sh
   <label> <bin> tools/measure/scenarios/h3.body h3c1 10000 10 <out>`. Read `grep 'UDP datagram'
   <out>/<label>.r*.client` next to each round, and compare at equal client datagrams per request
   (or fit, as in 0b). HAProxy: the same command with `~/reference/haproxy-quic/haproxy`.
2. Profile: build with `RUSTFLAGS="-C force-frame-pointers=yes" cargo build --profile
   release-perf --bin ibex` (separate `CARGO_TARGET_DIR`), then `EV='ibs_op/cnt_ctl=1,swfilt=1/u'
   scripts/prof.sh <label> <fp-bin> <body> h3c1 20000 fp <out> 100000` (setup as insreq; `sudo -n
   perf record -e $EV --call-graph fp -c 100000 -p <proxy>`). HAProxy: the same with `dwarf` and
   30000 requests, plus an instructions:u DWARF profile for its callers.
3. Fold: `scripts/fold2.py <bin> <perf.data> > x.folded` (frame-pointer chains with inlined frames
   expanded by one `llvm-symbolizer` batch, 15 s; `perf script --inline` takes > 3 min);
   HAProxy `perf script --no-inline -F period,ip,sym,dso | scripts/fold.py`.
4. Phases: `scripts/hybrid.py x.folded <ins/req> [insu.folded]` (rules in `scripts/phase.py`:
   leaf-first, the first frame that names a phase wins; crypto, `core::`/`alloc::`/`hashbrown`
   and mem* frames are skipped up to their caller); `scripts/detail.py x.folded <ins/req>
   '<phase>'` for the functions inside a phase.
5. Calls per request: `scripts/calls.sh` with `perf probe -x <bin> -a 'name=0x<nm addr - 0x1000>'`
   (perf probe reads the address as a file offset; this binary's text is mapped 0x1000 above it).
6. Syscalls: `scripts/census.sh` (strace). Its UDP datagram counts are not valid (0c); use
   h2load's counter.

The scripts are in `~/ibex-worktrees/review/t544-2026-11-01/scripts/`, outside the tree. They
could become a `tools/measure/` helper if T545's slices keep using them (not added: no-code task).
