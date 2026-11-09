<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Multiplexed connections to servers: HTTP/2 (A), then QUIC/HTTP/3 (B) — scope, design, slices (T533, 2026-10-31)

Status: design, no production code. Written on main `348dfcf7` (branch `fix/t533`). Inputs:
`m2-scope-2026-10-25.md` (§2 refuses QUIC to servers), `h3-engine-2026-10-26.md` (owner/child
model, `HtxMux`), `memory-2026-10-24.md`, `rustls-side-by-side-2026-10-24.md`,
`tasks/T341`/`T353` (open item "`server ... ssl alpn h2` loads but Alcyon speaks HTTP/1.1"),
T528's 33-test table (commit `d5afd937`, `tasks/T528-progress.md`).

Scope changed during the task (supervisor, user decision 10-31): **HTTP/2 to servers is scoped
first and in full (section A)**: it is what deployments use (gRPC, h2c to app servers,
`proto h2`, `ssl alpn h2,http/1.1`). **QUIC/h3 to servers (section B) builds on A's backend mux.**

Oracles, both on this host, same minute as the Alcyon runs (host load 15-22, other agents
building: **no timing claim**; the few times shown are context, they come from timeouts and
retries, not from speed):
- HTTP/2: `~/reference/haproxy/haproxy` — `HAProxy version 3.5-dev8-885761-29 2026/10/02`.
- QUIC: `~/reference/haproxy-quic-dev10/haproxy` — `HAProxy version 3.5-dev10-38e65c-10 2026/10/30`,
  `+QUIC -QUIC_OPENSSL_COMPAT`, OpenSSL 3.5.9, `QUIC: connection sock-per-conn mode support : yes`.
- Alcyon: `/home/bhenc/ibex-targets/t528/release/alcyon` (`0.1.0-rc3-484-gc9ce54c3`, main + T528's
  `cond.rs` line; nothing on the server side differs from `348dfcf7`).
- Clients and servers: curl 8.18.0, nghttp/nghttpd (nghttp2 1.68.0), a 20-line Python HTTP/1
  backend that answers after 2 s (`slow.py`) and an echo backend (`echo.py`).

Scripts, configs and every log: `~/ibex-worktrees/review/t533-2026-10-31/{h2,m,ib}/` (copied
from `/tmp/t533`). All on ports 63000-63999, every process stopped by PID at the end.

## 0. Short answers

| Question | Answer |
|---|---|
| How close is HTTP/2 to servers? | **The protocol pieces exist, the engine piece does not.** `alcyon-proto` has frames, HPACK (encoder and decoder, `hpack.rs`), flow control, GOAWAY/RST, and `H2MuxContext` already has an `is_server: false` role: it sends the client preface and SETTINGS (`mux_h2.rs:1208`), applies the server's `MAX_CONCURRENT_STREAMS` (`:1837`) and checks a response's fields (`check_response_fields`, `:1621`, with the comment "no runtime path speaks h2 to a server yet"). Missing: a request HEADERS encoder and client stream ids, the response → HTTP/1 text conversion, and above all **a server leg that is not a file descriptor**: a session's server side is `srv: Option<OwnedFd>` + `srv_xprt` (`proxy.rs:644`), used at ~100 sites (`engine.rs`, `proxy.rs`), and the idle pool holds `IdleConn { fd, xprt }` with cross-worker takeover (`engine.rs:345-560`). **9 slices: 3 S, 5 M, 1 L ≈ 9-11 agent sessions, about two working weeks** (§A.6). |
| How close is QUIC/h3 to servers? | **After A: 7 slices, 1 S, 5 M, 1 L-conditional ≈ 7-8 sessions**, of which B0 is T534 (started). What is there: quinn-proto 0.11 can connect as a client; Alcyon's QUIC server, h3 mux (T509-T520) and static QPACK; rustls 0.24.0-dev.2's QUIC client connection (see the TLS row). What is not: the client half of Alcyon's quinn↔rustls adapter (`crypto.rs` is server-only), a client endpoint and UDP socket per connection, the h3 mux's client role, and A's backend mux to hang it on. |
| Blockers | (1) **The engine's single-fd server leg** (A2, L): every multiplexed backend needs it; nothing in B can be wired before it. (2) **TLS for B**: rustls 0.24.0-dev.2 *has* a QUIC client connection (`ClientConnectionBuilder::build_quic`, `client/connection.rs:89`, driven by `Connection<ClientSide, Quic>::read_hs`, `quic.rs:275-296`, which verifies the server inline in `MessageIterMode::All`); only the typed step-by-step API is unfinished in dev.2 (`FromConn<ClientSide> for ()` is `todo!("nyi")`, `quic.rs:146-152`, reached from `VerifyPeerIdentity::continue_with`) and was finished upstream in `f238d682f` "Support `quic::ClientHandshake`" on 2026-10-14, the day after the dev.2 tag (2026-10-13), unreleased (main is 64 commits past dev.2 today; no milestone or date). T534 writes the client half on the `read_hs` path and proves it with a test; if that path fails, the pin moves to a git rev ≥ `f238d682f` (API churn: `NeedsInput` became generic, so the server half is re-ported too). No rustls 0.23 comes back. (3) **The +0.5 % instructions-per-request budget** on the HTTP/1 path, which A2 touches (§A.5). (4) HAProxy's own QUIC backend is **experimental** (`expose-experimental-directives`; "QUIC is currently incompatible with dynamic backends deletion", `server.c:3842`), so B's oracle moves (the last 8 commits to `mux_quic.c` in the dev10 tree are all bug fixes, two MEDIUM and one MAJOR). |
| Should h2 come first? | **Yes** (and the user decided it). Everything that makes B hard is in A: a backend connection serving several sessions, its owner, the per-worker avail/idle lists, `http-reuse` for a multiplexed connection, `max-reuse`, server GOAWAY/RST handling, per-stream timeouts, checks through a mux. B then adds a transport (UDP, quinn) and a second mux kind behind the same interface. Built QUIC-first, the same engine work would be done against a less stable oracle and harder tooling (no vtest h3). |
| A defect to fix now, independent of A | **`server ... ssl alpn h2` and `alpn h2,http/1.1` are accepted today and every request fails 502** against a server that picks h2 (measured, §A.3 row 1: HAProxy 200 `ver=2.0`, Alcyon `502 Bad Gateway`); `check-alpn h2` with `option httpchk` leaves the server DOWN (`L7TOUT`; HAProxy UP `L7OK`, checks arrive as `HTTP/2.0`). Known since T341/T353 (open boxes), never fixed. AGENTS.md §5: slice A0 (S) makes the parser refuse an `h2` in `alpn`/`check-alpn` until A lands — user decision D1. **Superseded 10-31 (T535, §A.6b): not refused; one stream per server connection, 2 M + 3 S.** |
| What it unlocks | A: 15 dev8 reg-tests whose server line needs h2 (`proto h2` ×13, `alpn h2` ×3, `check-proto h2` ×1; board `f08fe1f3`: 10 OUT_OF_SCOPE, 3 FAIL, 2 SKIP; list in §A.4), gRPC through Alcyon, h2c to app servers. B: T528's 17 OUT_OF_SCOPE QUIC tests (a QUIC bind and a `server quic4@` in one block) and the 12 skipped for `ssllib_name_startswith(OpenSSL)` once forced; Alcyon-to-Alcyon h3 chains (the server half already works with HAProxy as the h3 client, measured §B.2). |

---

# Section A — HTTP/2 to servers

## A.1 Scope (in)

1. **Configuration.** `server ... proto h2` (h2c, prior knowledge), `server ... ssl alpn h2` and
   `alpn h2,http/1.1` (h2 when the server selects it, HTTP/1.1 otherwise — measured: a server
   offering only `http/1.1` gets `ver=1.1`), `default-server` forms, `check-proto h2`,
   `check-alpn h2`, inheritance of the server's `proto h2`/`alpn` by `option httpchk` checks,
   `max-reuse` (enforced on h2), `pool-max-conn`/`pool-low-conn`/`pool-purge-delay` counting a
   multiplexed connection as one connection, `http-reuse never|safe|aggressive|always` with
   HAProxy's measured semantics for a multiplexed connection (A.3 rows 5-8),
   `tune.h2.be.max-concurrent-streams`, `tune.h2.be.initial-window-size`,
   `tune.h2.be.glitches-threshold`, `tune.h2.be.rxbuf`, `tune.h2.be.max-frames-at-once`
   (dev8 doc lines 4512-4563; the generic `tune.h2.*` apply to both sides as in HAProxy).
2. **Semantics.** Any request a frontend accepts (h1, h2, h3) can go to an h2 server: methods,
   bodies with and without length (DATA, END_STREAM), request and response trailers (gRPC:
   `grpc-status`, `grpc-message`, `te: trailers`), 1xx, 204/304 bodyless, `retry-on` replays,
   `option forwardfor`, `http-request set-header`, `%HV`, server-side counters and the log line.
3. **Errors as HAProxy.** Server RST_STREAM → `502 SH--`, connection kept for the others;
   server GOAWAY (graceful, `max-total-streams`, reload) → no request lost, new streams on a new
   connection; connection loss → as the HTTP/1 path today; `timeout server` per stream.
4. **Operations.** `show servers conn` columns (`used_cur used_max need_est idle_sess unsafe_nb
   safe_nb idle_lim idle_cur`) count connections as HAProxy does; `show pools` lists the new
   pools; soft stop drains backend streams.

## A.2 Refused (the parser says so, by keyword)

- `ws h2` (WebSocket over h2 to a server, RFC 8441): stays ignored-with-warning as today
  (`server_keywords.rs:82`: Alcyon upgrades over HTTP/1.1); a WebSocket upgrade always takes an
  HTTP/1.1 connection, as HAProxy's default `ws auto` does.
- `proto fcgi|spop|none` on servers: unchanged (refused, `server.rs:703`).
- **Takeover of a multiplexed connection by another worker**: not built (D3). HAProxy takes over
  *idle* h2 connections (`h2_takeover`, `mux_h2.c:9147`) and never a QUIC one
  (`.takeover = NULL`, `mux_quic.c:5005`). An idle h2 connection stays with its worker until
  purged. Not a keyword: a documented difference (`docs/differences.md`).
- `tune.h2.be.*` keywords not in A.1 (if HAProxy adds more): refused by name.

## A.3 Measured: HAProxy 3.5-dev8 as the h2 client (Alcyon where it differs today)

Rig (`h2/`): client curl → **A** (frontend `:63101` h1, `:63105` `proto h2`; `nbthread 1`
unless said) → **C** (HAProxy dev8 serving `:63102 proto h2`, `:63103 ssl alpn h2,http/1.1`,
`:63106 ssl alpn http/1.1`, answering `ver=%[req.ver] src_port=%[src_port]`, `/slow*` to a 2 s
backend). "per-conn" = requests per distinct source port in C's log.

| # | case | HAProxy 3.5-dev8 | Alcyon today |
|---|---|---|---|
| 1 | `server ... ssl verify none alpn h2` / `alpn h2,http/1.1` to C:63103 | `ver=2.0` `200` / `ver=2.0` `200` | `-c` valid; **`502 Bad Gateway` both** (offers h2, writes HTTP/1.1) |
| 2 | same `alpn h2,http/1.1` to a server offering only `http/1.1` (`:63106`) | `ver=1.1` `200` | (not run: falls in A0) |
| 3 | `ssl verify none` (no alpn) / `proto h2` / plain address to the h2c port | `ver=1.1` / `ver=2.0` / `502` | — / refused `'h2' is not supported` / — |
| 4 | `ssl alpn h3` on a TCP server | needs `expose-experimental-directives` (QMux, `server.c:4276`) | **accepted, speaks HTTP/1.1** (200 against a server offering h2,http/1.1: no ALPN overlap) — refuse, D6 |
| 5 | `http-reuse never`, 5 new client conns + 1 keep-alive conn ×3 + 20 concurrent (2 s) | 26 server conns, 1 request each except the keep-alive one | — |
| 6 | `http-reuse safe` (the default), same | **26 conns: an h2 server connection is private to its client session** (`MX_FL_HOL_RISK` → `session_add_conn`, `backend.c:2248`) | — |
| 7 | `http-reuse aggressive` / `always`, `nbthread 1` | **1 conn for all 26 requests, the 20 concurrent ones as 20 streams** | — |
| 8 | `http-reuse always`, 64 threads (default) | 20 conns for 26 requests (in-use connections are per thread; idle ones are taken over) | — |
| 9 | `tune.h2.be.max-concurrent-streams 5`, warm conn + 20 concurrent | per-conn `5 5 5 5`, 20 × 200 | refused (`global.rs:580`) |
| 10 | server's `SETTINGS_MAX_CONCURRENT_STREAMS 5` (C `tune.h2.fe.max-concurrent-streams 5`) | per-conn `5 5 5 5`, 20 × 200 | — |
| 11 | `max-reuse 2`, 7 sequential, `always` | per-conn `3 3 1` (max-reuse N = N+1 streams) | `max-reuse` ignored with a warning (`server_keywords.rs:91`) |
| 12 | `max-reuse 2` on an **HTTP/1.1** server, 7 sequential, `always` | per-conn `7` (**ignored on h1**, as the doc says: "at least HTTP/2 connections … will respect it") | ignored: **same as HAProxy** |
| 13 | server sends GOAWAY after 3 streams (C `tune.h2.fe.max-total-streams 3`), 7 sequential | 7 × 200, per-conn `3 3 1` | — |
| 14 | same, 10 concurrent with 2 streams left on the warm conn | 10 × 200, per-conn `3 3 4` (no request lost) | — |
| 15 | server `http-request reject` on the h2 stream | `502`, log `SH--`; next request on a **new** conn (C closed it) | — |
| 16 | server `http-request silent-drop` | `502 SH--` | — |
| 17 | server reload (new C started, SIGUSR1 old) with A's idle h2 conn; next request | `200` from the new C | — |
| 18 | server reload during a 2 s request on the shared conn | `200` in 2.0 s, next `200` | — |
| 19 | server SIGKILL 0.5 s into a 2 s request on a **reused** connection | curl `Empty reply from server`, **no log line** (same on an HTTP/1.1 server with dev8 and on h2 with dev10: the reused-connection rule, not an h2 one) | as its HTTP/1 path (not re-measured here) |
| 20 | `option httpchk GET /chk` + `proto h2 check` | UP `L7OK 200`, C sees `HTTP/2.0` | refused (`proto h2`) |
| 21 | `option httpchk` + `check` on an h2c-only port, no `proto` | DOWN `L7TOUT` | — |
| 22 | `option httpchk` + `check check-proto h2` (server line without `proto`) | UP `L7OK`, `HTTP/2.0` | refused: `check-proto h2` |
| 23 | `option httpchk` + `ssl alpn h2 check` (check inherits ALPN) | UP `L7OK`, `HTTP/2.0` | — (falls in A0) |
| 24 | `option httpchk` + `ssl check check-ssl check-alpn h2` | UP `L7OK`, `HTTP/2.0` | **accepted, DOWN `L7TOUT`, 0 checks reach C** |
| 25 | `option httpchk` + `ssl alpn h2 check check-alpn http/1.1` | UP, C sees `HTTP/1.0` | — |
| 26 | gRPC shape: `nghttp` h2c → A `:63105` → `server proto h2` → `nghttpd --trailer 'grpc-status: 0' --trailer 'grpc-message: ok'`, POST `content-type: application/grpc`, `te: trailers`, request trailer `x-req-trailer: one` | client receives `grpc-status: 0`, `grpc-message: ok` in a trailing HEADERS (`flags=0x05`); nghttpd receives `x-req-trailer: one` in a trailing HEADERS | refused (`proto h2`) |
| 27 | Alcyon parser, other keywords | — | `tune.h2.be.initial-window-size`, `.glitches-threshold` unknown → refused; `proto qmux` refused; `ws h2` ignored with warning; `http-reuse always` accepted |

## A.4 Gap table (Alcyon `348dfcf7`)

Size: S ≤ half a session, M = one session with its gate, L = several.

| item | HAProxy | Alcyon | status | slice |
|---|---|---|---|---|
| `alpn h2[,…]` / `check-alpn h2` on a server | h2 when selected | accepted, 502 / DOWN | **defect (§5)** | A0 (S) |
| `alpn h3` on a TCP server | QMux, experimental | accepted, HTTP/1.1 | defect (§5) | A0 |
| frames, HPACK, flow control, GOAWAY/RST, SETTINGS | — | `h2.rs`, `hpack.rs`, `mux_h2.rs` (server role; client preface/SETTINGS/response checks present, unused) | partial | A1 (M) |
| request HEADERS encoder (`:method :scheme :authority :path`, `te` filtering, connection-specific headers dropped, cookie split) | `h2s_bck_make_req_headers` | none (`send_h1_head` writes a response head) | missing | A1 |
| client stream ids (odd, increasing, `max_concurrent_streams` of the peer and of `tune.h2.be.max-concurrent-streams`) | `h2c_bck_new_strm` | none | missing | A1 |
| response HEADERS/DATA/trailers → HTTP/1.1 text in the session's `rep` | `h2c_dec_hdrs` → HTX | `as_text` is server-only (`mux_h2.rs:1628`) | missing | A1 |
| a session's server side as a stream of a shared connection | `struct stream` ↔ `h2s` | `srv: Option<OwnedFd>` + `srv_xprt`, ~100 sites | **missing (the blocker)** | A2 (L) |
| backend connection owner (one per connection, per worker), its pass, wakes | `h2c` + tasklet | none (frontend has `h2_owner_pass`, `engine.rs:10375`) | missing | A2 |
| avail list (connections with free streams) / idle list per server per worker | `srv->per_thr[].avail_conns`, `idle_conns` | `IdlePools` of `IdleConn {fd, xprt}`, cross-worker (`engine.rs:345-560`) | missing for mux | A3 (M) |
| `http-reuse` modes for a multiplexed connection (rows 5-8), `max-reuse` (row 11) | as measured | h1 semantics only; `max-reuse` ignored | missing | A3 |
| `show servers conn` with h2 connections | rows 5-8 | h1 only | missing | A3 |
| `tune.h2.be.*` | accepted | refused | refused (correct) | A4 (S) |
| server GOAWAY / RST_STREAM / REFUSED_STREAM / connection loss (rows 13-19), retries of streams above GOAWAY's last id | as measured | — | missing | A5 (M) |
| `timeout server` per stream, `timeout tunnel` for CONNECT/gRPC long streams | per stream | per session (unchanged) | follows from A2 | A5 |
| checks over h2 (rows 20-25) | `tcpcheck` over `mux_h2` | `check.rs` HTTP/1 only | missing | A6 (M) |
| gRPC / trailers both ways, `te: trailers` (row 26) | works | engine forwards trailers h1↔h2/h3 frontends (T520) | missing for h2 servers | A7 (S) |
| reg-tests needing h2 servers: `checks/http-check`, `connection/reverse_connect_full`, `reverse_server_name`, `tcp_to_http_upgrade`, `http-messaging/connect_tunnels`, `h2_desync_attacks`, `h2_trailers`, `http_1xx_responses`, `http_bodyless_response`, `protocol_upgrade`, `srv_ws`, `truncated_response`, `sample_fetches/h2_stream_state`, `ssl/ssl_alpn` (+ `h3_trailers`, B) | pass | board `f08fe1f3`: 10 OOS, 3 FAIL, 2 SKIP | missing | A8 |

## A.5 Design: types, owners, memory

**The shape is the frontend's, mirrored.** The frontend serves an h2 stream with an ordinary
session (child) under an owner entry that holds the mux (`h2_child_of`, `proxy.rs:1105`;
`h2_owner_pass`, `engine.rs:10375`), and the head goes into the child's `req` as HTTP/1.1 text
once, so the engine's one HTTP/1 parser and every rule run unchanged (`h2_bridge.rs` header).
Towards servers the same trick runs the other way: **the session keeps writing an HTTP/1.1
request into its `req` and reading an HTTP/1.1 response from its `rep`**; what changes is who
moves those bytes. On the h1 path it is the fd; on a mux path it is the backend connection's
owner, which converts them to and from frames. HAProxy converts HTX ↔ h2 (`mux_h2.c`
`h2s_bck_make_req_headers`, `h2c_dec_hdrs`); Alcyon's HTX-equivalent at this boundary is the
HTTP/1 text it already produces, as on the frontend.

```rust
// alcyon-rt/src/proxy.rs — the server leg of a session (replaces `srv` + `srv_xprt` as a pair)
pub enum ServerLeg {
    None,
    Fd { fd: OwnedFd, xprt: ServerXprt },           // today's HTTP/1 path, unchanged
    Stream { conn: BeConnRef, id: u64 },            // a stream of a multiplexed connection
}
pub struct BeConnRef { idx: u32, gen: u32 }        // slot in the worker's `be_conns` arena

// alcyon-rt/src/be_mux.rs (new) — HAProxy's backend h2c / qcc; one per server connection
pub struct BeConn {
    mux: BeMux,                                     // H2(H2MuxContext /* is_server=false */) | H3(B)
    leg: BeLeg,                                     // Tcp { fd, xprt } | Quic (B)
    key: IdleKey,                                   // today's reuse key: addr, backend, server, SNI, PROXY header
    streams: StreamMap<BeStream, u64>,              // id -> attached session (idx, TaskRef), req/rep progress
    private_to: Option<u32>,                        // owner session under `http-reuse never|safe` (HOL risk)
    tot_streams: u32,                               // for `max-reuse` (closed when > max-reuse)
    state: BeConnState,                             // Connecting | Ready | Full | Idle | Draining{goaway_last} | Dead
    exp: Tick,                                      // idle timeout / pool-purge-delay
}
pub struct BeStream { sess: (u32, TaskRef), req_sent: usize, head_sent: bool, rsp_state: RspConv }
```

- **Owner.** The worker that opened the connection owns the `BeConn` and every session attached
  to it is on that worker (a session that wants a stream takes one from *its* worker's avail
  list or opens a connection). Nothing crosses threads (AGENTS.md §8): the avail and idle lists
  of mux connections are per worker and are not in `IdlePools`' shared slots; `may_steal` is
  false for them (D3). The fd is registered as `FdState::BeConn { idx }`; readiness runs
  `be_conn_pass(idx)`.
- **The pass** (`be_conn_pass`, mirror of `h2_owner_pass`): read and demux frames; for each
  stream with response bytes, write HTTP/1.1 text into the session's `rep` (status line,
  headers, then the body with the response's `content-length` or chunked; trailers as chunked
  trailers, which the engine already forwards to h2/h3 frontends since T520) and wake the
  session; for each attached session with new `req` bytes (it wakes the owner, as children do
  on the frontend), parse its HTTP/1 request head once with `alcyon-proto`'s h1 parser into
  HEADERS (HPACK) and its body into DATA under the stream and connection windows; then send.
  A session whose `req` is blocked by flow control stops being read: the client's window, not
  Alcyon memory, holds the body back (the frontend's rule, `h3-engine` §2.3).
- **Attach** (in today's `connect_server` path, `engine.rs:13818-13900`): if the server's mux
  is h2 (`proto h2`, or TLS ALPN selected `h2` — known only after the handshake, so the first
  request on a TLS connection waits for ALPN before choosing h1 or the mux, as HAProxy's
  `conn_install_mux_be` does), look for a `BeConn` on this worker by the reuse rules of A.3
  rows 5-8 (`never`/`safe`: only the session's private one; `aggressive`/`always`: any with a
  free stream), else open one; then `ServerLeg::Stream`. **The h1 branch is untouched**: one
  `match` on `ServerLeg` where `srv` was read. This is where the instruction budget is decided:
  the enum must not cost the h1 path more than +0.5 % (`insreq.sh` ab1, release-perf,
  keepalive and rules scenarios).
- **Detach** (end of transaction, client gone, `release_server`, `engine.rs:8613`): stream
  closed or RST (`CANCEL` when the response is unfinished); `BeConn` → avail if it has room and
  `tot_streams ≤ max-reuse`, → idle if it has no stream (counted against `pool-max-conn`,
  purged by `pool-purge-delay` like an idle h1 connection), → closed if Dead/Draining.
- **Errors.** RST_STREAM from the server → the session sees a server abort (`SH--`, 502, as
  row 15). REFUSED_STREAM, or a stream above a received GOAWAY's last id → the request was not
  processed: replay it on another connection through the existing L7 retry buffer
  (`txn::L7Retry`) whatever `retry-on` says (HAProxy: rows 13-14, 0 lost). Connection lost →
  every attached stream gets what the h1 path gives a lost connection (row 19 same as h1).
- **Checks** (A6): `check.rs` opens its own connection; for `check-proto h2`, an inherited
  `proto h2`, or ALPN `h2` it runs one stream through an `H2MuxContext` (client role) on that
  connection and closes it: same encoder and decoder as A1, no `BeConn`.

**Memory** (`memory-2026-10-24.md`):

| object | design |
|---|---|
| `BeConn` | `Pool<BeConn>` "h2c_be" (`declare_pool!`), per worker, counted in `show pools`, bounded by `tune.memory.hot-size`, drained by `pool_gc` |
| `H2MuxContext` inside it | its `rx_buf`/`tx_buf` (`Vec::with_capacity(8192)` today, `mux_h2.rs:636-637`) become `Buf`s from `buffer`; the HPACK tables live in the pooled object and are cleared, not freed, on reuse |
| `BeStream` / `H2StreamCtx` | `Pool<H2StreamCtx>` "h2s" (one pool for both sides; the frontend's are unpooled today — same change, A1) |
| request/response conversion | written into the session's existing `req`/`rep` `Buf`s; header scratch from `scratch_bytes`; target **0 allocations per request** on a warm connection (`request_allocations.rs` pin duplicated for an h2 server) |
| fds | one TCP fd per server connection, as HTTP/1: the `maxsock = maxconn * 2` arithmetic (`globalconn.rs:274`) is unchanged; multiplexing only lowers it |

## A.6 Slices (task files written when each starts)

| # | slice | scope | size | depends | model |
|---|---|---|---|---|---|
| A0 | **Refuse what does not work** | Test first (row 1: `alpn h2` → 502 today; row 24: `check-alpn h2` DOWN): the parser refuses `h2` in a server's `alpn` and `check-alpn` and `h3` in a TCP server's `alpn`, message names the keyword ("Alcyon speaks HTTP/1.1 to servers until …"), or the D1 alternative. Closes T341/T353's open box. `differences.md` row. | S | — | Sonnet / Muse Glimmer (single file, rows given) |
| A1 | **Client role of `H2MuxContext`** (alcyon-proto only) | Request head (HTTP/1 text) → HEADERS (`h2s_bck_make_req_headers`: pseudo-headers from the request line and `host`, connection-specific headers dropped, `te` kept only as `trailers`, cookies split); client stream ids and the concurrency limit (min of the peer's SETTINGS and `tune.h2.be.max-concurrent-streams`); response HEADERS (incl. 1xx, trailers) → HTTP/1.1 text; GOAWAY received (last id, retryable set); RST_STREAM codes; WINDOW_UPDATE on read; `h2s`/`buffer` pools. Unit tests from frames captured off HAProxy dev8 and nghttpd (`nghttp -v`). | M | — | Sonnet |
| A2 | **The multiplexed server leg** | `ServerLeg` enum in place of `srv`/`srv_xprt` (every site), `BeConn` arena and pool, `be_conn_pass`, attach/detach, `FdState::BeConn`, wakes both ways, `proto h2` (h2c) end to end, then TLS with ALPN `h2` chosen after the handshake. Tests: rows 1, 3, 5, 7 on one worker; the h1 tests unchanged; **`insreq.sh` before/after on the h1 path within +0.5 %**; allocation pin. Two sessions: (a) the enum with the h1 path only (pure refactor, budget measured), (b) the mux leg. | L | A1 | Opus (a: Sonnet) |
| A3 | **Reuse, pools, `max-reuse`** | Per-worker avail/idle lists for `BeConn`; `http-reuse` rows 5-8 (safe/never: private to the session; aggressive/always: shared); `max-reuse` enforced on h2 (row 11), still warned-and-ignored on h1 (row 12, as HAProxy); `pool-max-conn`/`pool-low-conn`/`pool-purge-delay` count a `BeConn` as one; `show servers conn` columns; no cross-worker takeover (D3, documented). | M | A2 | Sonnet |
| A4 | **`tune.h2.be.*`** | `max-concurrent-streams`, `initial-window-size`, `glitches-threshold`, `rxbuf`, `max-frames-at-once` to the data path, each with a test that observes it (row 9 for the first). | S | A2 | Sonnet / Muse Glimmer |
| A5 | **Server-side errors and stop** | Rows 13-19 as tests: GOAWAY (graceful and `max-total-streams`), streams above last-id replayed, REFUSED_STREAM replayed, RST_STREAM → 502 `SH--`, connection loss, server reload with idle and in-flight streams; `timeout server` per stream; soft stop of Alcyon with backend streams in flight. | M | A3 | Sonnet |
| A6 | **Checks over h2** | `option httpchk` over `proto h2` (inherited), `check-proto h2`, `check-alpn h2` (rows 20-25), `http-check expect` on the h2 response, `check_status`/`show stat` as HAProxy. | M | A1 | Sonnet |
| A7 | **gRPC and trailers** | Row 26 as a test (nghttpd fixture or an in-test h2 server), both trailer directions, `te: trailers`, long streaming RPC under `timeout server`/`timeout tunnel`, h2 frontend → h2 backend, h3 frontend → h2 backend. | S | A2 | Sonnet |
| A8 | **Reg-tests, parity, numbers** | The 15 reg-tests of A.4 run (OUT_OF_SCOPE → PASS or a filed reason); a `tools/practical/` topology "node behind h2c" (keep-alive, 100 MB up/down, SSE, gRPC unary + streaming); night measurements: ins/req and allocations per request to an h2 server vs HAProxy, connections per 1k requests under each `http-reuse` mode. | M (+ night) | A3-A7 | Sonnet; V&V night |

**Total A: 3 S + 5 M + 1 L** = about 9-11 agent sessions with their gates, i.e. roughly **two
working weeks** at the project's cadence, plus one night for A8's numbers.

## A.6b Update 2026-10-31 (T535): one stream per server connection first

User decision 10-31: `alpn h2` is **not** refused (A0 / D1 dropped). T535 measured HAProxy dev8
under the default `http-reuse safe` with an h2 client sending 10 concurrent streams: **10 server
connections** (`proto h2` and `ssl alpn h2` alike); sequential streams reuse 1. HAProxy
multiplexes only under `aggressive`/`always` (1 connection). So one stream at a time per server
connection is HAProxy's default behaviour, and it needs no `ServerLeg`/`BeConn` (A2).

A spike (local branch `spike/t535`, not merged) proved it: an h2 codec as a `ServerXprt` variant
under the session (HTTP/1.1 text in and out, frames on the wire), installed when TLS ALPN selects
`h2` and for `proto h2`. It passed `alpn h2`, `alpn h2,http/1.1`, `proto h2`, POST over the flow
control window, HEAD, server GOAWAY after 3 streams (`3 3 1` as HAProxy), server reject (`502
SH--` as HAProxy), `check-alpn h2` (UP `L7OK`, `HTTP/2.0` on the server), and matched HAProxy's
connection count in every `safe` row. Findings, wire captures and the slice list:
`tasks/T535-progress.md`.

**Revised estimate for a working `alpn h2` / `proto h2`:** H1 (codec, M) + H2 (wiring, M), then
H3 checks (S), H4 gRPC/trailers (S), H5 docs/reg-tests (S): **2 M + 3 S ≈ 3-4 sessions**, in
place of A0 and ahead of A1-A8. H1 is A1's codec; A2-A5 remain for multiplexing under
`aggressive`/`always`, `tune.h2.be.*`, and replay of GOAWAY/REFUSED_STREAM streams. The full A
total (9-11 sessions) is unchanged, less A0 and most of A1 (≈ 2 sessions) once H lands.

---

# Section B — QUIC / HTTP/3 to servers (on A's backend mux)

## B.0 Short answers

| Question | Answer |
|---|---|
| What B adds to A | A transport (`BeLeg::Quic`: a quinn-proto client connection and a connected UDP socket) and a second mux kind (`BeMux::H3`: the h3 mux's client role) behind A's `BeConn`, attach/detach, avail/idle lists, error mapping, checks and pools. |
| TLS | rustls 0.24.0-dev.2's `build_quic` + `read_hs` client connection (§0 row 3); Alcyon's adapter gains `qc::ClientConfig` and the client `TlsSession` (T534, started). No rustls 0.23 in the binary (T461's rule; 0.23 + 0.24 together cost +12.6 % binary size, `rustls-side-by-side-2026-10-24.md` §2). Server verification: `verify required`/`ca-file`/`verifyhost`/`sni` as the TCP `srv_tls.rs` path. |
| Endpoint and sockets | **One connected UDP socket per server connection** (HAProxy's `sock-per-conn`: measured, every QUIC server connection has its own source port) and **one client `quinn_proto::Endpoint` per worker** (no server config) that routes datagrams to connections by CID. 1 fd per server connection, so `maxsock` is unchanged. No migration (client never migrates; `disable_active_migration` is the server's to send), no 0-RTT (refused: `allow-0rtt` on a QUIC server, D-row in B.3), no Retry handling beyond what quinn does as a client. |
| What HAProxy does with reuse | **Same rules as h2 but no takeover** (B.2 rows 3-6): with 64 threads, 26 requests open 26 QUIC connections in every mode; at `nbthread 1`, `aggressive`/`always` carry all 30 requests on one connection, `safe` and `never` open one per client session. Alcyon with per-worker lists and no takeover matches this by construction. |
| How close | After A: B0 (T534) M, B1 M, B2 M, B3 M, B4 S/M, B5 S, B6 M; B7 (qmux) refused. ≈ 7-8 sessions, **about 1.5 working weeks after A**; B0 runs now in parallel. |

## B.1 Scope

**In:** `server ... quic4@host:port ssl alpn h3` (and `quic6@`, `default-server`), `verify`,
`ca-file`, `sni`, `verifyhost`; `http-reuse` and `max-reuse` as A; `tune.quic.be.max-idle-timeout`,
`tune.quic.be.stream.max-concurrent` (measured to reach HAProxy's data path, B.2 row 7; `be.max-idle-timeout` from the doc, not measured);
plain `check` = a QUIC handshake (`L6OK`, row 10); errors as B.2 rows 11-16; `show quic` listing
backend connections **only if** HAProxy does (measured: dev10's `show quic` on the client side
lists none, row 2 — so Alcyon lists none either); counters in `show stat`/`show servers conn`.

**Refused, by keyword:**
- `proto qmux` and `ssl alpn h3` on a TCP server (QMux, `draft-ietf-quic-qmux-01`, experimental
  in HAProxy; D6).
- `option httpchk`/`http-check` on a QUIC server: HAProxy accepts it and sends the check **over
  TCP** to the same port ("For explicit tcp-check/http-check rules, always assume TCP, QUIC is
  not supported yet", `tcpcheck.c:1447`), so the server is DOWN with `Layer6 invalid response,
  "Connection refused"` and `-c` says nothing (row 10). Alcyon refuses the combination with a
  message (D5) — an action that parses must work.
- `allow-0rtt` on a QUIC server, `quic-cc-algo` on a server (other than the default cubic), the
  other `tune.quic.be.*` (`cc.*`, `sec.glitches-threshold`, `stream.data-ratio`, `stream.rxbuf`,
  `tx.pacing`, `tx.udp-gso`: dev10 doc lines 1992-2003) until a test needs them.
- `expose-experimental-directives` is **not** required by Alcyon (Alcyon has no experimental tier);
  the HAProxy alert text is recorded in B.2 row 1 for the differences file.

## B.2 Measured: HAProxy 3.5-dev10 as the h3 client

Rig (`m/`): curl → **A** (dev10, frontend `:63001` h1, backend `server q1 quic4@127.0.0.1:63002
ssl verify none alpn h3`) → **B** (dev10, `bind quic4@:63002 ssl crt … alpn h3`, `:63003 proto
qmux`, `:63004 ssl alpn h3`, answering `ver=%[req.ver] src_port=%[src_port]`).

| # | case | HAProxy 3.5-dev10 |
|---|---|---|
| 1 | `-c` without `expose-experimental-directives` | `'server bq/q1' : QUIC is experimental for server 'q1', must be allowed via a global 'expose-experimental-directives'`, exit 1; for `bind … proto qmux`: `'proto' : 'qmux' protocol is experimental, must be allowed via …` |
| 2 | one request | `200`, B sees `ver=3.0`, B logs `fb~ … "GET /x HTTP/3.0"`; A's `show quic` lists **no** connection, B's lists one (`ESTAB`); A's `show servers conn bq` row `safe_nb 1` |
| 3 | 64 threads, `http-reuse never|safe|aggressive|always`: 5 new client conns, 1 keep-alive conn ×5, 20 concurrent 2 s | **every mode: 26 QUIC connections** (25 with 1 request, the keep-alive one with 5); no takeover (`mux_quic.c:5005` `.takeover = NULL`) |
| 4 | `nbthread 1`, `never` / `safe` | 26 connections (as row 3) |
| 5 | `nbthread 1`, `aggressive` / `always` | **1 connection for all 30 requests** |
| 6 | `nbthread 1`, `always`, 20 concurrent on a **cold** server (no warm connection) | 14-20 connections (requests arriving before the first handshake completes each open one) |
| 7 | `nbthread 1`, `always`, warm connection then 20 concurrent: `tune.quic.be.stream.max-concurrent` 100 / 5 | 1 connection (21 requests) / 4 connections (`5 5 5 6`) |
| 8 | `max-reuse 2`, 7 sequential, `always` | per-conn `3 3 1` (as h2) |
| 9 | `server … proto qmux` to `:63003`; `ssl verify none alpn h3` to TCP `:63004` | `ver=3.0` ×3 on one TCP connection, both (QMux clear and over TLS) |
| 10 | checks: `check` / `check check-proto quic` / `check check-alpn h3` **with** `option httpchk` | DOWN, `Layer6 invalid response, info: "Connection refused"` (the check went to TCP) — all three; `check-proto h2` → alert `server 'q1' uses an incompatible MUX protocol for the selected check type`; plain `check` without `httpchk`: **UP `L6OK`**, B counts no session |
| 11 | B not running | `503` after 3.0 s, `SC--`, 3 retries |
| 12 | B SIGKILLed 0.5 s into a 2 s request | nothing until a timeout: client's `-m 12` → `400 CH--` at 12 s; with `timeout server 4s` → `504 sH--` at 4.0 s (no ICMP-driven detection) |
| 13 | B `http-request reject` on the h3 stream | `502 SH--`, B closed the connection: the next request opens a new one (`200`) |
| 14 | B `http-request deny` | `403` forwarded |
| 15 | B `tune.quic.fe.max-idle-timeout 1s`, request, 2.5 s pause, request | `200`, `200` on a new connection (the closed one is not reused, no error) |
| 16 | B soft stop (SIGUSR1) with A's idle connection | B exits at once; A's next request `503 SC--` after 3 s; a request **in flight** during B's soft stop completes `200` in 2.0 s |

### B.2b Alcyon as the h3 server, HAProxy dev10 as the client (the other half of an Alcyon↔Alcyon chain)

`ib/`: A (dev10) → `server q1 quic4@127.0.0.1:63022 ssl verify none alpn h3 http-reuse always`
→ Alcyon (`bind quic4@… alpn h3`, backend echo server), with `tune.alcyon.h3-path relay` and `mux`:
5 sequential `200`, 20 concurrent **20/20 `200`**, POST 1 MiB `200`, Alcyon `show quic` lists 2
connections — **both h3 paths serve HAProxy's QUIC client today**. What is missing for
Alcyon↔Alcyon is only the client side (B).

## B.3 Design (on A)

```rust
// alcyon-quic: client half (B0 = T534) and endpoint (B1)
pub struct QuicClientConfig { /* qc::ClientConfig over rustls24 ClientConfig: alpn h3, verifier, SNI */ }
pub struct QuicClientEndpoint {                // one per worker; quinn Endpoint without server config
    endpoint: quinn_proto::Endpoint,
    conns: Slab<quinn_proto::Connection>,      // by ConnectionHandle; timers: T493's BTreeSet, not a walk
    rx: CopyBlock, tx: CopyBlock,              // as the server endpoint (`endpoint.rs:82-110`)
}
// alcyon-rt be_mux.rs
enum BeLeg { Tcp { fd: OwnedFd, xprt: ServerXprt }, Quic { sock: OwnedFd /* connected UDP */, handle: ConnectionHandle } }
enum BeMux { H2(H2MuxContext), H3(H3ClientCtx) }   // H3ClientCtx: mux_h3.rs client role (B2)
```

- **Connect** (B1): `socket(UDP)`, `connect(server)`, register `FdState::BeConn`; `endpoint.connect(now,
  client_config, addr, sni)` → handshake datagrams sent on that socket; the `BeConn` is `Connecting`
  until `Connected` (cold-burst behaviour of row 6 is HAProxy's too: no queueing on a handshaking
  connection is required for parity). Reads: `recvmmsg` on the socket → `endpoint.handle(…)` →
  `conn.handle_event` → `be_conn_pass`.
- **h3 client mux** (B2): control stream + SETTINGS (QPACK capacity 0, as the server side), request
  streams = client bidi ids 0, 4, 8 …, HEADERS via `qpack::encode_field_section` (static table,
  as today's response encoder), response decode via `decode_qpack_static`, DATA, trailers, GOAWAY
  received (stream id), `H3_REQUEST_REJECTED` → replay as REFUSED_STREAM in A5. Shares A1's
  HTTP/1 text ↔ head conversion.
- **Limits** (B4): available streams = min(peer's `initial_max_streams_bidi`/MAX_STREAMS,
  `tune.quic.be.stream.max-concurrent` (default 100), `max-reuse`); idle close =
  `tune.quic.be.max-idle-timeout` (default 30 s) → the connection leaves the idle list silently
  (row 15).
- **Memory**: `Pool<BeConn>` as A; quinn's per-connection state stays quinn's (tradeoff.md 6.30,
  ~3.9 allocations per request on the server side, the same expected here); datagram buffers per
  worker endpoint, not per connection; target: Alcyon's own allocations 0 per request on a warm
  connection.

## B.4 Slices

| # | slice | scope | size | depends | model |
|---|---|---|---|---|---|
| B0 | **Client half of the quinn↔rustls adapter** = T534 (running) | `qc::ClientConfig` + client `TlsSession` over `build_quic`/`read_hs`; test: Alcyon client ↔ Alcyon server handshake and ↔ quinn's own (dev-dependency) server; ALPN, SNI, verification failure as a TLS alert. Decides D7. | M | — | (T534) |
| B1 | **Client endpoint and socket** | `QuicClientEndpoint` per worker, connected UDP socket per connection, `BeLeg::Quic`, timers, close/drain; test: connect, one stream echo, idle close, server gone (rows 11-12). | M | B0, A2 | Sonnet |
| B2 | **h3 client mux** | `mux_h3.rs` client role (B.3), unit tests against frames from HAProxy dev10's server (aioquic capture) | M | A1 | Sonnet |
| B3 | **Wire into `BeConn`** | parser accepts `server quic4@… ssl alpn h3` (refusal at `server.rs:34` lifted), attach/detach/reuse rows 2-8 on `nbthread 1` and N; errors rows 13-16 | M | A3, A5, B1, B2 | Sonnet |
| B4 | **`tune.quic.be.*` and `max-reuse`** | the two keywords of B.1 with tests (rows 7, 8, 15) | S | B3 | Sonnet / Muse Glimmer |
| B5 | **Checks over QUIC** | plain `check` = handshake `L6OK` (row 10); `httpchk` on a QUIC server refused (D5) | S | B3 | Sonnet |
| B6 | **Reg-tests and chains** | the vtc runner stops sending `server quic+…` blocks to the oracle: T528's 17 OOS run on Alcyon alone; Alcyon→Alcyon h3 practical topology; night numbers (ins/req, allocations, RSS per backend QUIC connection vs HAProxy) | M | B3-B5 | Sonnet; V&V night |
| B7 | **QMux** (`proto qmux`, `alpn h3` over TCP) | **refused** (D6); revisit when HAProxy drops "experimental" | — | — | — |

---

## C. Decisions needed from the user

| # | decision | options | recommendation |
|---|---|---|---|
| D1 | `server ... ssl alpn h2[,http/1.1]` today: accepted, 502 on every request to an h2-capable server | (a) refuse `h2` in `alpn`/`check-alpn` until A2 (A0); (b) silently offer only `http/1.1` with a warning, so `alpn h2,http/1.1` keeps working over HTTP/1.1 | (a): §5, and (b) changes what goes on the wire without the operator asking; `alpn h2,http/1.1` users get a clear message and can drop `h2` |
| D2 | `http-reuse safe` (default) with h2 servers | HAProxy's: an h2 server connection is private to its client session (measured rows 5-6); or share it | HAProxy's (the oracle; head-of-line risk is the reason) — multiplexing across clients needs `aggressive`/`always`, documented |
| D3 | cross-worker takeover of **idle** h2 connections (HAProxy does, row 8; QUIC never) | build it later / never | not in A; per-worker only (AGENTS.md §8); a `differences.md` row; revisit only if night numbers show many more server connections than HAProxy at nbthread > 1 |
| D4 | order | A then B (B0 in parallel, already started) / B first | A then B (user's direction today) |
| D5 | `option httpchk` on a QUIC server (HAProxy checks over TCP, always fails, `-c` silent) | copy / refuse | refuse with a message |
| D6 | QMux (`proto qmux`, `ssl alpn h3` on a TCP server) | build / refuse | refuse (experimental draft-01 in HAProxy; no client asks for it) |
| D7 | rustls pin for B | stay on `=0.24.0-dev.2` if T534's `read_hs` client path works / move to a git rev ≥ `f238d682f` / wait for the next dev tag | stay if T534 proves it; else the next published dev tag (a git rev cannot be vendored for M3's reproducible builds without extra work) |
| D8 | `max-reuse` on HTTP/1 servers | keep warned-and-ignored (HAProxy ignores it there too, row 12) / implement | keep, reword the warning to "applies to HTTP/2 and HTTP/3 server connections" once A3 lands |

## D. What was run (abridged; full configs, scripts and logs in the review dir)

```
~/reference/haproxy-quic-dev10/haproxy -vv | head    # 3.5-dev10-38e65c-10, +QUIC, OpenSSL 3.5.9
~/reference/haproxy/haproxy -v                       # 3.5-dev8-885761-29
# h2 (dir h2/): C serves h2c/h2+TLS/h1+TLS; A is the h2 client
./run.sh <tag> "<server args>" "<backend extra>" "<global extra A>" "<frontend extra C>"
./reuse.sh h2-<mode>-t1 "127.0.0.1:63102 proto h2" "    http-reuse <mode>"     # rows 5-8 (+ nbthread removed for t64)
tune.h2.be.max-concurrent-streams 5 | C tune.h2.fe.max-concurrent-streams 5 | max-reuse 2 | C tune.h2.fe.max-total-streams 3   # rows 9-14
C http-request reject / silent-drop; C reload (new C + SIGUSR1 old); kill -9 C mid-request                                       # rows 15-19
option httpchk GET /chk + proto h2 check | check | check-proto h2 | alpn h2 check | check-ssl check-alpn h2 | check-alpn http/1.1    # rows 20-25
nghttpd --no-tls -d htdocs -v --trailer 'grpc-status: 0' --trailer 'grpc-message: ok' 63104
nghttp -v -H 'content-type: application/grpc' -H 'te: trailers' -d req.bin --trailer 'x-req-trailer: one' http://127.0.0.1:63105/svc  # row 26
# Alcyon parser and runtime (dir ib/): alcyon -c -f k<n>.cfg; alcyon -f k2|k3|k4|k7.cfg against C        # A.3 rows 1, 4, 24, 27
# QUIC (dir m/): B = h3 server, A = h3 client (dev10)
./reuse.sh <mode>       (64 threads, then a.cfg with nbthread 1)                                   # B.2 rows 3-5
tune.quic.be.stream.max-concurrent 100|5 (cold and warm); max-reuse 2                               # rows 6-8
server … proto qmux | ssl alpn h3 over TCP; check variants with/without option httpchk              # rows 9-10
B down; kill -9 B mid-request (timeout server 4s); reject; deny; B tune.quic.fe.max-idle-timeout 1s; SIGUSR1 B   # rows 11-16
A (dev10) → Alcyon quic4@:63022, tune.alcyon.h3-path relay|mux                                          # B.2b
# rustls upstream (read-only GitHub API): commits on rustls/src/quic.rs, compare v/0.24.0-dev.2...main, tags
```
Processes: every haproxy, alcyon, nghttpd, `slow.py`, `echo.py` started here was stopped by PID;
`ss -ltnup` showed no listener on 63000-63999 afterwards. No file in `crates/` was changed;
`tools/checkin.sh` was not run (documentation-only branch).

## Note added 2026-10-31 (supervisor, after T534)

T534's QUIC client (`crates/alcyon-quic/src/crypto/client.rs`) uses `build_quic` + `read_hs` +
`events()` only; the server certificate is verified inside rustls's internal `ClientState`
(`client/hs.rs:73-79`), so the `todo!("nyi")` of rustls 0.24.0-dev.2 (`quic.rs:146-152`, `impl
FromConn<ClientSide> for ()`) is unreachable: it needs a `VerifyPeerIdentity<ClientSide, Quic>`,
which only `ClientNext` builds, and `ClientNext` comes only from a TCP connection. **A future
step-by-step client path** (`start_handshake` / `VerifyPeerIdentity` for QUIC, e.g. asynchronous
certificate verification) would reach it on dev.2 and needs rustls f238d682f or a later dev tag.
