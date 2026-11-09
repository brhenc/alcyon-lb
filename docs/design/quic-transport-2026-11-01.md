# QUIC transport and the h3/h2 engine path: options, recommendation, slices (T545, 2026-11-01)

Design only. Evidence: T544 (`quic-profile-2026-11-01.md`, the IBS per-phase table, trusted
±10 % per row), T543's batch 4 (`tasks/T543-progress.md` on fix/t543, merged to main since),
T550 (`rust-performance-survey-2026-10-31.md`). No new measurement was run for this document:
the two tables cover every number below, and slot B was left to the coding tasks.

## 0. Where the code stands (post-T543 main, slot B, h3c1 10000 x 7, release-perf)

| build | h3 ins/req at 1.30 client dg/req | at 1.50 | at 1.97 (HAProxy's count, fit) | h2s1 |
|---|---:|---:|---:|---:|
| T544's build (pre-T543) | 120.8k | 122.0k | 125.1k | 79.6k |
| main after T543 (T5 30609647) | 109.8k | 111.3k | ~114.8k (slope 7.4k/dg) | 79.7k |
| HAProxy 3.5-dev10 | | | 73.7k | 53.4k |
| H4 rule: h2 + 15 % / 1.5x HAProxy | 91.6k / 110.5k | | | |

Per T544 §2, scaled by what T543 removed (-10.8k, all QUIC-side: PADDING 3.8k, CID hashing
~2k, `Retransmits::is_empty` 0.7k, ~7 empty `poll_transmit` sweeps ~3k), the h3 request now
splits about so: common stream engine **59k** (HAProxy 27k; Alcyon h2 pays 64k), quinn
transport **~24k** (of which crypto 3.9k; HAProxy 36k with crypto 15k, so non-crypto Alcyon ~20k
against HAProxy 21k: level), Alcyon QUIC glue **~9k** (HAProxy 0), h3 framing + QPACK + shared
codec **15k** (h2 9.7k, HAProxy 6.2k), plus one `getsockname` a request.

Two facts shape the design:

1. **The h2 + 15 % leg of H4 is stricter than HAProxy itself meets.** HAProxy h3 is 1.38x its
   h2 (73.7k against 53.4k). Alcyon h3 - h2 is ~31k today, of which transport ~19k over h2's TLS
   record (4.8k), glue ~9k, h3 codec +5.3k over h2's; 15 % of h2 is 12k. Every engine saving
   lowers the bar as much as it lowers h3. So H4's relative leg can only be met by making the
   QUIC side of an h3 request cost at most ~12k more than TLS-over-TCP, which is below where
   HAProxy's QUIC stands (its h3 - h2 = 20.3k). Decision D1.
2. **Each inbound ACK-only datagram costs 6-7k** (T544 0b, T543 batch 4: slope 5-7.4k), and
   the client sends 0.1 to 1.0 of them per request. HAProxy pays its per-packet cost too (it gets
   1.97 dg/req from the same client). The headline must be compared at equal client datagrams
   (D6), and the per-datagram pass is the one QUIC-structural cost worth a deep change (§2 b1).

## 1. Options

Gains are instructions per h3 request from T544's rows after T543, as ranges; "h2 too" marks a
saving the h2 path gets as well (which lowers H4's relative bar by 15 % of it).

| | option | expected gain | size | risk | verdict |
|---|---|---:|---|---|---|
| (a) | **Keep patching quinn incrementally** (T543 style): `FrameStats::record`, `VarInt::decode`, `PacketSpace::take`, `CidQueue::active`, `handle_event` self (T544 #6, ~2.2k of the 7.0k state-machine row), `ArrayRangeSet::insert` fast path for in-order packet numbers (0.4-0.6k of ACK generation 1.85k) | 2-3k | S-M | low; each patch upstreamable | **do**, as the mechanical half of slice Q2 |
| (b) | **Deep rework of quinn's hot paths** in `vendor/quinn-proto`: b1 one drive + one `poll_transmit` per connection per loop pass (not per datagram, not per `owner_send`); b2 `poll_transmit` early-out on a `dirty` flag maintained where frames are queued (`connection/mod.rs:460`, `spaces.rs` `PendingAcks`/`Retransmits`, `streams/state.rs` sends); b3 ACK-only packets skip the keep-alive/idle re-arm and stream wakeups that cannot apply; b4 `SendBuffer.acks` as `ArrayRangeSet` (no BTree node); b5 loss detection only when the largest acked advances, PTO cached (`detect_lost_packets` + `set_loss_detection_timer` + `pto_time_and_space` 0.64k, plus `reset_*` 0.34k) | 6-10k (b1+b3: 2-3k per extra inbound datagram, 2-4k at 1.5 dg/req; b2 1-2k; b4 0.3-0.5k; b5 1-2k) | M-L | medium: fork diverges; quinn's 181 tests + `alcyon-quic` `timers::`/`quic_transport_tests` hold the RFC behaviour | **do**, slices Q2 and Q4 |
| (c) | **Replace parts**: own packet/frame layer feeding quinn's state machine; own stream layer; own ACK/loss handling | packet decode + frame parse are 5.6k against HAProxy's 8.3k and stream bookkeeping 5.6k against 6.4k: ≤ 1k to gain from a rewrite. ACK/loss/timers 6.6k against HAProxy's 1.5k is the only part with room (4-5k), and it is RFC 9002, the riskiest code in QUIC | L-XL | high | **no**: (b5) takes what is cheap inside the existing loss path; a separate layer re-opens correctness for the same 4k |
| (d) | **A different stack**, pure Rust only: quiche (BoringSSL) and neqo (NSS) refused; tquic links its own BoringSSL (`tquic`'s `boring` build) refused; s2n-quic can run on rustls but `s2n-quic-core`/`-transport` carry `unsafe` and are built around their own tokio event loop with no sans-IO server embedding like `quinn-proto`'s; no per-request figure exists for any of them | unknown; the number to beat is quinn's non-crypto ~20k, which is already HAProxy-level | XL (redo T461 crypto, T534, T539, T542, T543, `crates/alcyon-quic` 3.3k lines, the h3 mux's stream API) | high | **no** (D4). The transport is not where the gap is |
| (e1) | **The Alcyon QUIC glue by handle**: every `ConnectionId`-keyed map in `quic_listener.rs` (`h3`, `outq`, `peers`, `pending`, `admitted`, `held`, `streams_done`, `owned`: ~44 SipHash operations a request, T543) and `endpoint.rs`'s `get_handle` on each `read_stream`/`write_stream`/`finish_stream`/`open_stream` become a dense `Vec`/slab indexed by `ConnectionHandle`; the `ConnectionId` is looked up once, at datagram routing, where quinn's own `Endpoint` already does it. `refresh_timer`'s `BTreeSet` re-key (2.99 calls/req, 1.7k) becomes a per-connection `next_timeout` slot and one min over the active connections when the loop asks (T1's lazy re-key fired early and lost 3k: compute exactly, lazily). `send_batch` once per listener per pass (T5's `to_poll` is its input), not per `owner_send` | 4-7k (SipHash ~1.5k after T3, refresh_timer 1.7k, send_batch self 2.0k -> ~0.5k, drive_connection self 1.6k -> ~1.0k, `Instant::now` in the glue ~0.4k) | M | low: Alcyon code, pinned by `alcyon-quic` `it` tests | **do first**, slice Q1 |
| (e2) | **Parse once, request side** (h2 too): the mux keeps the decoded fields; the bridge writes HTX blocks from them straight into `sess.htx_buf` and lets `rebuild_req_buffer` (`engine.rs:15749`, exists for rule edits) produce the HTTP/1.1 wire text once. Gone: `H2ReqHead::write` 1.9k, `H1Parser::parse` 4.7k, UTF-8 and copies ~1k; added: HTX from fields ~1k, one serialisation ~1.5k | 3-5k, h2 too | M-L | medium: every rewrite the bridge does on text today (cookie blanks, canonical `content-length`, chunked, ws key) has a test | **do**, slice E1 |
| (e3) | **Parse once, response side** (h2 too): one parse of the server's head into a `RspHead` index (status, version, field offsets, framing, close, upgrade) that `check_response_head`, `HeadFacts::scan`, `status_of_line`, `websocket::check_response`, `rewrite_header_names_before` and `response_framing` all read; `HtxMux::send_head_fields(id, status, fields)` replaces `send_h1_head`'s `from_utf8_lossy`/`lines`/`split_once`/`trim` and `put_head`'s `lower` copy | 3-5k, h2 too (scan family 4.4k, re-split 1.5k; the HPACK linear scan 1.9k is Track 3 Q3) | M | medium | **do**, slice E2 |
| (e4) | **ACK frequency** (RFC 9000 ext., draft-ietf-quic-ack-frequency; `ack_frequency_config` is unset in `crates/alcyon-quic/src/config.rs`; ngtcp2/h2load implements it): the server asks the client to ACK every N packets or after max_ack_delay, so fewer ACK-only datagrams arrive at 6-7k each | 0-6k on the headline, 0 on the per-datagram cost; changes the client's behaviour, so it is not an A/B of the proxy | S (one config line + a `quic_transport_tests` row) | low | **measure first** (D8): the single cheapest number on the list |
| (e5) | **A stream object per h2/h3 request instead of a `TcpSession` child** (T550 S2) and the `getsockname` (`proxy.rs:1733`, Track 3) | 2-4k + 0.5k, h2 too | L | medium (logs, counters, stick keys the children copy) | later, slice E3 |

What is **not** worth a slice: crypto (3.9k against 15.1k), frame parse, stream bookkeeping,
congestion/pacing, syscall count (Alcyon 8.2 against HAProxy 15 a request), malloc (0 since T543).

## 2. Recommendation

**Keep quinn-proto; do deep surgery on its per-connection driving contract (b1-b5) and on
Alcyon's glue (e1), and run the parse-once engine path (e2, e3) in the same programme, because
the engine is where 32k of the 41k gap to HAProxy is and the H4 bar moves with it.** Order by
instructions per line changed: glue first (all Alcyon code, 4-7k), then the request parse-once
(3-5k on both protocols), then quinn's early-out and ACK/loss fast paths, then the response
parse-once, then the per-datagram batching after a re-profile. The pools slice (Track 1) runs
in parallel from the start: it touches `streams/*.rs`, `send_buffer.rs` and `spaces.rs`'s
`Retransmits`, which no other slice edits before Q2 (Q2 waits for it on `spaces.rs`).

Projected, at 1.5 client dg/req (ranges do not add; read the sum as ±30 %):
111k - Q1 (4-7k) - E1 (3-5k) - Q2 (3-5k) - E2 (3-5k) = **89-98k** (1.21-1.33x HAProxy at
equal datagrams), with h2 at 70-74k. 1.5x HAProxy (110.5k) is met by Q1 alone; 1.3x (95.8k)
needs Q1 + E1 + Q2 + E2; the h2 + 15 % leg (then 80-85k) needs Q4 + E3 as well and is the
subject of D1; 1.1x (81k) is Q1-Q4 + E1-E3 + Track 3 + PGO if the user allows PGO (T550 D1).

### 2.1 Quinn and the engine, one design: where they meet

The datagram enters at `QuicListener::recv_batch` -> `QuicEndpoint::handle_datagram`
(`endpoint.rs:627`) -> `quinn::Endpoint::handle` -> `Connection::handle_event` (one packet
decoded, decrypted, its frames applied) -> `drive_connection` (`endpoint.rs:436`: the endpoint
event loop and the stream events, queued as `TransportEvent`) -> `QuicListener::pump`
(`quic_listener.rs:786`) -> `H3MuxContext` (frames -> HTX, QPACK) -> `dispatch_mux` /
`start_request` (`h2_bridge.rs:94, 154`) -> child `TcpSession` -> engine -> server. The
response comes back as HTTP/1.1 text in `sess.rep` -> `apply_http_response_rules`
(`engine.rs:11324`) -> `forward_response_mux` (`h2_bridge.rs:358`) -> `HtxMux::send_head`
(`mux_h3.rs:1264` -> `put_head`, `mux_h2.rs:935` `send_h1_head`) -> `owner_send` ->
`write_stream` -> `send_batch` (`quic_listener.rs:709`) -> `poll_transmit` -> `sendmmsg`.

After the slices, the contract between the two halves is: **one drive per connection per loop
pass** (Q1, Q4), **a stream head is decoded once** (E1: fields -> HTX, no text in between) and
**encoded once** (E2: `RspHead` -> HEADERS, no text re-split), the connection is addressed by
`ConnectionHandle` everywhere after routing (Q1), and every per-stream object quinn or the mux
holds comes from an `alcyon_alloc` pool visible in `show pools` (P1).

### 2.2 Quinn's memory in `show pools` (Track 1, slice P1)

**Direct dependency, behind a feature.** `vendor/quinn-proto/Cargo.toml` gains
`alcyon-alloc = { path = "../../crates/alcyon-alloc", optional = true }` and a feature
`alcyon-pools`; `crates/alcyon-quic` turns it on. With the feature off the crate is upstream's
shape plus the local patches, and `tools/quinn-proto-tests.sh` keeps running quinn's 181 tests
with no Alcyon code linked. A hook trait would put a type parameter or a `dyn` call on
`Connection` for objects only quinn constructs (T543's finding); the direct dependency costs a
`cfg` per site instead.

| quinn type | today (T543) | pool | `Poolable` | nominal |
|---|---|---|---|---|
| `streams::Send` (`streams/send.rs`) | per-connection free list of `Box<Send>` | `quic_send`: `PoolBox<Send>` | `reset` clears the `SendBuffer` (keeps its `VecDeque` capacity, wipes the unacked segments when `wipe`), `footprint` = `size_of` + buffer capacities | ~200 B + buffers |
| `streams::Recv` + `Assembler` (`recv.rs`, `assembler.rs`) | quinn reuses a freed `Recv` when one is free | `quic_recv`: `PoolBox<Recv>` | `reset` clears the `Assembler` heap (capacity kept, wiped when `wipe`) | ~150 B + heap |
| `spaces::Retransmits` (`spaces.rs:309`) | 8 spare boxes a connection | `quic_retransmits`: `PoolBox<Retransmits>` | `reset` clears its sets | ~300 B |
| `SendBuffer.acks: RangeSet` (BTree) | root kept on `clear` | **no pool**: `ArrayRangeSet` (`range_set/array_range_set.rs`, inline `TinyVec`) | - | - |
| `SendBuffer.unacked_segments: VecDeque` | 16 segments kept | capacity retained inside `Send`'s footprint | - | - |
| `H3MuxContext`, `H3StreamCtx`, `H2ReqHead`/fields, rx datagram `CopyBlock` | Alcyon pools or per-connection spares | already `alcyon_alloc` (h3-engine §6) or counted in `buffer`; the `CopyBlock` (`endpoint.rs:38`) becomes a `PoolBox<Mem>` of the `buffer` pool | | |

Accounting: three `declare_pool!` lines in the vendored crate with `file`/`line` pointing into
`vendor/quinn-proto/src/...` (so `show pools` names where they live), under the one
`tune.memory.hot-size` budget, per-thread caches (a QUIC connection is owned by one thread; a
give from another thread goes to that thread's cache, as the design allows). Budget for the
change: instructions ±0.3k (a pooled take is ≤ 50 against a free-list pop ~10, ~4 takes a
request), allocations stay 0 (`request_allocations_h3.rs`), `show pools` shows the three rows
with `used` after one request. Thread safety: `Poolable: Send` holds for all three (they hold
`Bytes`/`VecDeque`/`BTreeMap`), and nothing crosses threads on the request path.

### 2.3 Upstreamability

Kept where it costs nothing: (a)'s patches, b2 (`dirty` early-out), b4, b5, the ACK fast path
and the `alcyon-pools` feature are each one commit and could go upstream. b1/b3 (the driving
contract) and E1/E2 are Alcyon's. `vendor/README.md` lists each commit with "upstreamable: yes/no".

## 3. Slices

Measuring, all slices: release-perf, slot B (`flock -x /tmp/ibex-load-n1.lock`,
`ALCYON_MEASURE_CPUS=12,13,14`), `tools/measure/insreq.sh <label> <bin>
tools/measure/scenarios/h3.body h3c1 10000 7 <out>` for the change and for its parent commit,
each round's `UDP datagram: N sent` from `<out>/<label>.rN.client`, the figure read from the
linear fit at 1.30, 1.50 and 1.97 client dg/req (T544 0b); `h2s1`, `keepalive ab1`, `rules
ab1` flat (±0.5 %); `request_allocations_h3.rs` 0; `tools/quinn-proto-tests.sh` 181 for any
vendor change; profiles with IBS (`ibs_op/cnt_ctl=1,swfilt=1/u`), never `instructions:u`
(T544 0a). Budget per slice is its own saving: a slice that saves nothing measurable is not
merged (AGENTS.md §8).

| slice | what | files, functions | test that fails first | saving (h3 /req) | size | depends | model |
|---|---|---|---|---|---|---|---|
| **Q0** | ACK frequency on, measured | `crates/alcyon-quic/src/config.rs` (`TransportConfig::ack_frequency_config`, `AckFrequencyConfig::default()` with `max_ack_delay` 25 ms, `ack_eliciting_threshold` 2), one `quic_transport_tests` row | `the_server_asks_the_client_for_fewer_acks`: an established quinn client sees an `ACK_FREQUENCY` frame (red: none) | 0-6k on the headline (client datagrams/req from ~1.5 to ~1.1); the report shows both | S (1 h) | - | Sonnet |
| **Q1** | Glue by handle, one timer slot per connection, one send per pass | `crates/alcyon-quic/src/endpoint.rs`: `get_handle` (428) removed from `open_stream`/`read_stream`/`write_stream`/`finish_stream` (872-973): they take `ConnectionHandle`; `refresh_timer` (402): no `timers: BTreeSet`/`timer_of`, a `next: Option<Instant>` in the connection slot, `poll_timeout` (840) = min over `active_handles`, computed once per pass; `table.rs` lookup only in `handle_datagram` (627). `crates/alcyon-rt/src/quic_listener.rs`: `h3`, `outq`, `peers`, `pending`, `admitted`, `held`, `streams_done`, `owned` keyed by handle (a `Vec<Option<Slot>>` indexed by `handle.0` with a generation, §5 (i); the `ConnectionId` kept in the slot for logs); `owner_recv` (394)/`owner_send` (450) take the handle; `send_batch` (709) called once per pass from `pump` after the owner passes, `to_poll` (T5) as today | `crates/alcyon-quic/tests/it/timers.rs`: `a_request_routes_its_connection_once`: a counter `cid_lookups` on `QuicEndpoint` (as `timeout_polls` is) stays at the datagram count across `read_stream`+`write_stream`+`finish_stream` (red: +3); `a_pass_computes_the_timeout_once`: `timeout_polls` +1 per pass (red: 3 per datagram) | 4-7k | M | - (Track 3's clock slice touches `Instant::now` in `pump`: take the pass clock from it when merged) | Opus |
| **E1** | Parse once, request side | `crates/alcyon-proto/src/htx.rs`: `Htx::put_request_head(fields: &DecodedFields) -> Result<(), &'static str>` doing what `H2ReqHead::write` (`mux_h2.rs:213`) checks, writing `ReqStartLine` + `Header` + `Eoh` blocks (bytes, no `String`); `mux_h2.rs`/`mux_h3.rs` `on_headers`: fields kept, no text; `htx_mux.rs` `HtxStream::take_req_head` -> `take_req_fields`; `h2_bridge.rs` `dispatch_mux` (94): `content-length` canonical check and `add_len` on the fields; `start_request` (154): `put_request_head` into `sess.htx_buf`, `keep_cookie_blanks`, ws key as a `Header` block, chunked/`add_len` as blocks, then `rebuild_req_buffer(sess)` for `sess.req`; `req_method`/`req_uri`/`req_headers` from the HTX; `H2ReqHead` reduced to `%r`/`%U` facts | `crates/alcyon-rt/tests/h2_per_request_work.rs`: `an_h2_request_head_is_parsed_once`: a `#[cfg(debug_assertions)]` counter on `H1Parser::parse` (alcyon-proto) is 0 for one h2 request through the bridge (red: 1); the h2 battery, `h3_mux*.rs`, cookie blanks, `content-length` canonical rows, ws key row stay green | 3-5k, h2 too | M-L | - (Track 3 Q4 `&[u8]` fields: merge first if it lands first, else E1 does it for `DecodedFields`) | Opus |
| **P1** | quinn pools on `alcyon_alloc` (§2.2) | `vendor/quinn-proto/Cargo.toml` (feature), `streams/send.rs`, `streams/recv.rs`, `assembler.rs`, `spaces.rs` (`Retransmits`), `send_buffer.rs` (`acks: ArrayRangeSet`), `streams/state.rs` (the free lists go) | `crates/alcyon-rt/tests/memory_baseline.rs` (or `buf_counters.rs`): `show pools` lists `quic_send`, `quic_recv`, `quic_retransmits` with `used >= 1` after one h3 request (red: no such rows); `request_allocations_h3.rs` stays 0; quinn 181 | 0 (±0.3k budget) | M | - (parallel with Q1/E1; before Q2 on `spaces.rs`) | Sonnet |
| **Q2** | quinn early-out and ACK/loss fast paths (b2, b4 done in P1, b5, (a)) | `vendor/quinn-proto/src/connection/mod.rs` `poll_transmit` (460): `if !self.dirty && !self.timers.is_expired(..) { return None }` with `dirty` set in `spaces.rs` `PendingAcks::packet_received`, `Retransmits` pushes, `streams/state.rs` `write`/`finish`/`reset`, `paths.rs` challenge, `handle_timeout`; `ArrayRangeSet::insert` contiguous fast path; `detect_lost_packets` (1695) only when largest acked advanced; `set_loss_detection_timer` (1886) PTO cached per space; `FrameStats::record`, `VarInt::decode` `#[inline]`, `PacketSpace::take`, `CidQueue::active` | quinn unit test in `connection/mod.rs` tests: `an_idle_connection_answers_poll_transmit_without_a_sweep` (a `#[cfg(test)]` sweep counter, red: 3 spaces); `range_set/tests.rs` row for the fast path | 3-5k | M | P1 (`spaces.rs`), Q1 (so the remaining polls are visible) | Opus (early-out, loss), Sonnet (the (a) list) |
| **E2** | Parse once, response side | `crates/alcyon-proto/src/response_head.rs` `check_response_head` returns `RspHead` (status, version, fields `[(u32,u32,u32,u32)]`, framing facts, `wants_close`, upgrade); `crates/alcyon-rt/src/txn.rs` `HeadFacts::scan` (1644) built from it; `engine.rs` `apply_http_response_rules` (11324-11420) one parse, `rewrite_header_names_before` on the index; `htx_mux.rs` `send_head_fields`, `mux_h2.rs` `send_headers_frame` (908) and `mux_h3.rs` `put_head` (856) take fields; `h2_bridge.rs` `forward_response_mux` (358) | `h2_per_request_work.rs`: `a_response_head_is_scanned_once` (a debug counter on head scans: red 5-6); the response battery (T275, T281, T436 rows) green | 3-5k, h2 too | M | Track 3 Q3 (HPACK static `match`) | Opus |
| **Q4** | Per-datagram batching: all datagrams of a connection in a `recvmmsg` batch applied, then one drive + one `poll_transmit`; ACK-only packets skip keep-alive/idle re-arm and stream wakeups (b1, b3) | `endpoint.rs` `handle_datagram`/`drive_connection`; `connection/mod.rs` `handle_event` (1121), `process_decrypted_packet` (2431), `reset_idle_timeout` (1985) | `timers::a_batch_of_datagrams_drives_the_connection_once` (drive counter; red: one per datagram); RFC rows: idle timeout still resets on an ack-eliciting packet (existing `timers::` rows) | 2-4k at 1.5 dg/req (2-3k per extra datagram); re-profile after Q1/Q2 first | M-L | Q1, Q2 | Opus |
| **E3** | Stream object per child (T550 S2) + `getsockname` | `proxy.rs` `h2_child_of`, `attach_server_with_xprt` (1733); engine `spawn_h2_children` (6168) | ins pin in `h2_per_request_work.rs`; `%bi/%bp` log rows | 2-5k, h2 too | L | E1, E2 | Opus |
| **M1** | `insreq.sh` prints the client datagrams/req and the fit at 1.30/1.50/1.97 for `h3c1`; the PGO training set gains h3, TLS h1 and h2 `-m 10` (§4); the board gains the PGO column | `tools/measure/insreq.sh`, `tools/measure/scenarios/h3.body`, `tools/pgo/train.cfg`, `tools/pgo-build.sh` `train()` | - (tooling) | - | S | - | Sonnet |

The 02:00 cut: Q0, Q1, E1 and P1 are briefable as written (files, functions, red test, saving,
measurement). Q2 and E2 need the re-profile Q1/E1 leave behind to pick their (a)-list order.

## 4. PGO: what ships, and what it changes in the plan (user, 23:35: PGO builds yes)

T435 measured `tools/pgo-build.sh`: -13.4 % instructions, -35 % user cycles on keep-alive h1.
PGO buys code layout, inlining of hot small functions, branch weights and hot/cold splitting.
It removes instructions in call/return, spills and mispredicted-path code; it cannot remove a
pass over the head, a hash lookup, a BTree operation or an extra drive per datagram. So:

| class | slices | under PGO |
|---|---|---|
| **structural, survive PGO** (fewer parses, lookups, passes, datagrams) | Q0, Q1, E1, E2, Q4, E3, P1's `ArrayRangeSet` | the saving carries over nearly in full; the ratio to HAProxy improves by about the same fraction on both builds |
| **partly layout** | Q2's early-out (the sweep's branches become predictable under PGO, but the sweep's loads and `maybe_queue_probe`/`space_can_send` calls stay) | keep; expect 60-80 % of the non-PGO saving |
| **layout only, PGO may make them unnecessary** | the (a) list in Q2: `#[inline]` on `VarInt::decode`, `PacketSpace::take`, `CidQueue::active`, `FrameStats::record`, `handle_event` self | do them last and only after a PGO profile of the h3 path still shows them in the top 40 |

Rules: the +0.5 % budget and the A/B against HAProxy stay on the non-PGO `release-perf` build
(HAProxy is not PGO-built: like for like); every merged slice is also measured on the PGO
build, which is the figure the board reports as "shipped". PGO builds only at slice merge
(a PGO build is two builds plus the training run), not for each A/B round. A profile trained
before a slice landed still applies (rustc warns on mismatch, does not fail): the merge gate
retrains.

**Training workload** (`tools/pgo/train.cfg` + `tools/pgo-build.sh` `train()`; today it covers
h1 plain, TLS with `alpn h2,http/1.1`, h2c, the rules path and a 403 path, and **no QUIC**): add
a `bind quic4@127.0.0.1:@P_H3@ ssl crt @CERT@ alpn h3` frontend to the same backend and, in
`train()`, `h2load --alpn-list=h3 -n 20000 -c 10 -m 1 https://127.0.0.1:$P_H3/` (keep-alive,
the h3c1 shape) plus a `-c 50` round and a POST round (`-d` a 4 KB body) so QPACK, DATA
framing and the ACK path are all hot; TLS h1 (`h2load --h1 https://...`, the `ab1s` shape) and
h2 over TLS with `-m 10` (the mux with concurrent streams). Weight: ~1/4 each for h1, TLS/h2,
h3, rules, so no path's branch weights are starved. This is part of slice M1 (Sonnet).

A cheap confirming measurement, when slot B is free: one PGO build of main (training as above)
against HAProxy on `h3c1`, which gives the first "shipped" h3 ratio (expected ~95-100k from
111k, i.e. ~1.3x at 1.5 dg/req before any slice). It is not needed for the design.

## 5. Connection-ID lookups (user, 23:35: do ebtrees fit?)

Where the lookups are today, per h3 request at 1.5 client dg/req:

1. **quinn's own routing**, inside `vendor/quinn-proto/src/endpoint.rs` `Endpoint::handle`:
   `connection_ids: FxHashMap<ConnectionId, ConnectionHandle>` (unkeyed FxHash) for every
   packet, `connection_ids_initial` for Initial packets. The 1-RTT DCIDs are **server-issued**
   (`RandomConnectionIdGenerator`, 8 random bytes, the quinn default Alcyon uses): the client can
   only choose among the CIDs it was given, so this map's keys are not peer-chosen and FxHash
   is not a flooding surface there. The Initial table's keys are client-chosen and bounded by
   the half-open and Retry thresholds. ~0.15k per packet, 0.4k a request.
2. **Alcyon's `ConnectionTable`** (`crates/alcyon-quic/src/table.rs`, keyed SipHash since T543 T3,
   one write), keyed by the client's original DCID: `get_handle` on every `open_stream`,
   `read_stream`, `write_stream`, `finish_stream` (3-4 a request) and the eight
   `ConnectionId`-keyed maps of `quic_listener.rs` (~44 operations a request). ~1.5-2.5k.

| | option | instructions saved /req | security | verdict |
|---|---|---:|---|---|
| (i) | **Internal maps by our own handle**: `Vec<Option<Slot>>` indexed by `ConnectionHandle.0` (quinn's `Slab` index: dense, reused after close, so the slot carries a generation and the owner session holds `(handle, gen)`); `ConnectionTable` consulted once, at datagram routing, where quinn has already routed (the table can go: quinn's `ConnectionEvent(handle, ..)` names the handle) | 1.5-2.5k | no peer-chosen key anywhere after routing; a stale handle is caught by the generation | **do** (slice Q1) |
| (ii) | **`ebmb` tree** (`crates/ebtree`, pure Rust, allocation-free) for the one client-chosen table (original DCID -> handle), as HAProxy's `quic_cid_tree`: deterministic, no rehash, no growth allocation, O(min(key bits, log n)) node visits | -0.1 to -0.3k against keyed SipHash (an 8-20 B key hashes in ~60-100 instructions and probes once; a descent of ~10 levels at 1000 connections costs 200-400) | no hash-flooding surface by construction; keyed SipHash with `RandomState` already has none in practice, and the residual (rehash growth under a connection flood) is amortised and bounded by `maxconn` | **not now**: after (i) this table is read once per datagram at most (quinn's routing is what answers), so a slower deterministic lookup buys nothing measurable; it is the fallback if the connection-flood battery ever shows a rehash pathology, and the natural structure when QUIC goes multi-thread (a per-thread tree, no lock, as HAProxy shards it) |
| (iii) | **Our CIDs encode the handle** (QUIC-LB style: handle + generation, a random nonce, a tag, the whole 16 B CID encrypted as one block so migrated CIDs stay unlinkable, RFC 9000 §9.5): the per-packet DCID lookup becomes decode + verify, no table; quinn's `ConnectionIdGenerator` (`cid_generator.rs:10`, `generate_cid`/`validate`) is the hook for generation and validation, and routing by the decoded handle is a ~100-line patch to `Endpoint::handle` | 0.3-0.5k (quinn's FxHash lookup per packet, ~0.15k each; (i) already took the Alcyon table) | needs a whole-CID PRP (one AES-128 block, ~40 instructions with AES-NI; ring exposes no raw block cipher, so a pure-Rust AES or `alcyon-crypt`), a per-process key, a generation check so a decoded handle of a closed connection cannot reach a new one, and constant-time tag compare; quinn's `HashedConnectionIdGenerator` (FxHash nonce + tag, `cid_generator.rs:136`) is **not** unlinkable (the tag is a function of the nonce only) and must not be the model. A design error here is a cross-connection confusion, the worst class of bug for a proxy | **defer** to the multi-thread QUIC design: HAProxy encodes the thread id in its CIDs (`quic_get_cid_tid`) to route a datagram to the owning thread without a shared table, and still looks the CID up in that thread's tree; that is where an encoded CID earns its keep. For 0.3-0.5k on one thread it is not worth the crypto |

Recommendation: (i) now; keep keyed SipHash for the single client-chosen table; (ii) is the
fallback, (iii) comes with multi-thread QUIC, designed as a whole-CID PRP, never a tag-only
scheme.

## 6. Decisions

| | decision | recommendation |
|---|---|---|
| **D1** | H4's "h3 mux ≤ h2 + 15 %" leg: HAProxy's own h3 is 1.38x its h2; Alcyon's bar moves down with every engine saving | Restate H4 as absolute ratios to HAProxy h3 at equal client datagrams (1.5x now, 1.3x, 1.1x) plus a relative leg of (Alcyon h3 - Alcyon h2) ≤ 1.5x (HAProxy h3 - HAProxy h2) = 30k, then 1.2x = 24k. Keep "h2 + 15 %" as the long-run aim in the design, not as the accept rule |
| **D2** | quinn depends on `alcyon_alloc` directly | Yes, behind the `alcyon-pools` feature (§2.2); no hook trait |
| **D3** | Fork divergence | Accept; one commit per change in `vendor/README.md` with "upstreamable: yes/no"; nothing goes upstream now |
| **D4** | Another QUIC stack | No. If still wanted: a 1-day Sonnet measurement of s2n-quic-on-rustls per-request instructions in a minimal server, before any port |
| **D5** | The HTX-primary engine (rules on HTX only, HTTP/1.1 text produced at the server send, M2's end state) against E1/E2's staged path that keeps `sess.req`/`sess.rep` as the wire form | E1/E2 first (3-5k each, both protocols, M each); decide the HTX-primary engine after their measurement, together with the rules-path rebuilds (`memory-2026-10-24.md` §1.3 S7: `rules ab1` 77k against 42k) |
| **D6** | The h3 headline figure | The linear fit at 1.97 client dg/req (HAProxy's count), with 1.30 and 1.50 shown; "min of rounds" retired (M1) |
| **D7** | Slice order and models | Q0, Q1, E1, P1 now (Q1/E1 Opus, Q0/P1 Sonnet); Q2, E2, Q4, E3 after re-profiles |
| **D8** | ACK frequency on by default | Measure first (Q0). It is a standard extension and a production gain, but it changes the client's load: report the A/B against HAProxy with it off, and the production figure with it on, until the user decides the default (`fair benchmark defaults`) |
| **D9** | PGO (§4): what the board reports and what gates | Budget and A/B on non-PGO release-perf (decided); every merged slice measured on the PGO build too, reported as "shipped"; the (a)-list layout patches wait for a PGO profile; training gains h3, TLS h1 and h2 `-m 10` (M1) |
| **D10** | Connection-ID lookups (§5): slab by handle, `ebmb`, or encoded CIDs | (i) slab by handle with a generation, now (Q1); keyed SipHash stays for the one client-chosen table; `ebmb` is the fallback; encoded CIDs with the multi-thread QUIC design, as a whole-CID PRP |

**User decisions, 2026-11-01 11:20.**
- **D1 agreed**: H4 is restated as ratios to HAProxy's own h3 at equal client datagrams (1.5x, then 1.3x, then 1.1x), plus the relative leg (Alcyon h3 - Alcyon h2) <= 1.5x (HAProxy h3 - HAProxy h2). Always measured against HAProxy.
- **D5**: a Fable plan for the HTX-primary engine (rules on HTX only, HTTP/1.1 text produced at the server send) comes first; no code before it is reviewed.
- **D8**: ACK_FREQUENCY becomes an operator setting, default off (fair A/B against HAProxy). The operator may turn it on for the production gain; note that it only asks a peer to ACK less, so a hostile client sending ACK floods can ignore it.
- **T560** (+0.49% h3fit for the nbthread-1 burst fix, VV-31): accepted.
- **Kernel instructions count** (Track 3 item 4, no `getsockname()` per request): a kernel-side saving is a saving and is welcome; `insreq.sh` reports kernel instructions beside user-space ones (T568).
