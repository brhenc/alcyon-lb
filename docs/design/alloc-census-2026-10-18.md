# Allocation census, Ibex release binary, 2026-10-18

Tree: ~/ibex-worktrees/alloc-review, detached at batch 36ef460f. Binary: `cargo build --release -p ibex-rt --bin ibex`
with `CARGO_PROFILE_RELEASE_DEBUG=true`, run `nbthread 1` under an LD_PRELOAD counter. Counts = malloc+calloc+realloc
calls (aligned: 0); bytes = requested bytes. Each cell = min of 3 after 3 warm-up operations, one operation at a time,
measured under `flock -s /tmp/ibex-load.lock`. No timing was taken. Counts are deterministic; the idle process
allocates nothing on its own (tcp health check measured 0.0, below).

Tools (scratch, not committed): driver `scratchpad/census.py`, shim `scratchpad/shim_trace.c` (copy of tools/allocshim/shim.c
plus `backtrace()` of every allocation while a flag byte is set), aggregation `agg.py`/`agg2.py`, all in
/tmp/claude-1000/-home-bhenc-project-ibex/2c9bb267-2e19-4881-8a74-ff955698230a/scratchpad/ (raw trace `out/raw.pkl`,
symbolised `out/census.json`). Call sites come from `backtrace()` + `addr2line -i` on the debug-info binary, not gdb: the
first frame inside crates/ibex-* is reported, so `engine.rs:10058` is the line in Ibex that triggered the allocation, and
the type is read off the source line. Ports 47580-47587 were used (47440 was busy: another session uses the 474xx range).

Sanity check: the bare and blog counts reproduce the harness pins (bare/min 2, blog/curl 62 keep-alive, 64 close).

## 1. Allocations per operation

| Path | allocs/op | bytes/op | note |
|---|---:|---:|---|
| h1 GET, bare config, keep-alive | 2 | 4 | proxy.rs:2234,2235 (method, uri `to_string`) |
| h1 GET, bare config, new connection | 2 | 4 | same; connection setup allocates nothing |
| h1 GET, curl-like headers, bare, keep-alive | 2 | 4 | |
| h1 GET, blog config, keep-alive | 62 | 1911 | log + httplog + forwardfor + acl + 1 req set-header + 1 resp set-header |
| h1 GET, blog config, new connection (Connection: close) | 64 | 1926 | +2 for the Connection-header rewrite (txn.rs:1178) |
| h1 GET /static (ACL hit, use_backend) | 64 | 1966 | |
| h1 POST 64 KB, close | 67 | 51159 | body 64 KB: +1 big buffer (buf.rs:850, 32.8 KB x2 on keep-alive) |
| h1 POST 64 KB, keep-alive | 65 | 51144 | |
| log to stdout instead of UDP syslog | 62 | 1911 | identical: sink is not the cost; line build is 2 allocs |
| backend connection NEW (`http-reuse never`, no resp rules, httplog+forwardfor) | 11 | 492 | |
| backend connection reused (blog) | 64 | 1926 | no difference vs new in the blog config: reuse is not allocation-relevant; the 53-alloc gap to the line above is the response-rule path |
| h2c GET, 1 stream, new connection | 175 | 26012 | prior-knowledge, nghttp |
| h2c GET, 3 streams, same connection | 437 | 39762 | marginal stream = 131 allocs, 6.9 KB |
| TLS ALPN h2 GET, 1 stream, full handshake | 313 | 89185 | |
| TLS ALPN h2 GET, 3 streams | 574 | 103026 | marginal stream = 131 allocs |
| TLS h1 GET, full handshake | 198 | 65950 | |
| TLS h1 GET, resumed (session reused: yes) | 187 | 59301 | resumption saves only 11 allocations |
| err: 400 bad request | 3 | 373 | error page copy, log line (2) |
| err: 503, no server (frontend with 3 rules) | 34 | 1539 | |
| err: deny rule (403) | 20 | 1000 | |
| err: redirect (302) | 25 | 765 | |
| err: plain GET on that same frontend | 73 | 2059 | 3 ACL rules evaluated |
| stats HTML page (`stats uri`, 1 fe + 5 fe + 2 be) | 38 | 204443 | 4 big buffers: 65536 + 32768 + 35 KB x3 copies |
| CLI show info | 270 | 15393 | 177 x `format!` per line, stats_typed.rs:381 |
| CLI show stat | 987 | 83812 | 11 rows, ~90 allocs/row (per-field `to_string`) |
| CLI show pools | 24 | 7612 | |
| CLI show sess (1 session) | 56 | 7858 | 35 from `cmd.starts_with(&format!(..))` in applet.rs:148 |
| Health check tick, tcp check | 0.0 | 0.0 | 33 ticks in 6 s |
| Health check tick, http check (`option httpchk GET /`) | 15 | 398 | check.rs:1046 etc. |
| Prometheus scrape | not measured | | `use-service` is refused by the parser on this tree ("not supported in this build") |
| reload (-sf) | not measured | | skipped (time) |

Total stray allocations for one blog request: **62 (keep-alive) / 64 (close)**, 1.9 KB. HAProxy target is 0 (pool chunks).
Causes, from the call-site list: response-rule header mirror 40, request set/del-header mirror 7, ACL/sample 5,
request-line strings 3, connect_http_backend 3, format render 2, access log 2, (+2 Connection rewrite on close).

The trace pass sometimes sees more allocations than the counter pass for h2/TLS operations (TLS h2: 505 traced vs 313
counted). I took the ratios from the trace and the totals from the counter pass; per-site numbers for h2/TLS are
approximate. Blog/err/CLI traces equal the counter totals exactly.

## 2. Sites, ranked by (frequency on a blog request path) x (attacker reachability)

Reachability: R = any client with a well-formed request; H = scales with the number of request/response headers the
attacker sends (inferred from the loops, not re-measured with 100 headers); T = any TCP peer that can send a TLS
hello (pre-authentication); A = admin socket only.

| # | file:line | type | per blog req | reach | fix |
|---|---|---|---:|---|---|
| 1 | engine.rs:13496 `publish` closure: `CURRENT_RES_HEADERS ... clone_from(hdrs)` | Vec<(String,String)> clone, 2 String per header | 7 | R,H | reuse/borrow |
| 2 | engine.rs:10053 `hdrs.push((k.trim().to_string(), v.trim().to_string()))` (response head parsed into owned pairs) | String x2 per header | 5 | R,H | reuse (parse into ranges over the buffer) |
| 3 | engine.rs:10058, 10250 `CURRENT_RES_HEADERS ... = hdrs.clone()` (twice) | Vec<(String,String)> clone | 10 | R,H | reuse (thread-local scratch kept, but strings still allocate; pass `&[...]`) |
| 4 | engine.rs:10068 `entry.sess.req_headers.clone()` | Vec<(String,String)> clone | 5 (+13 per h2 stream) | R,H | reuse (borrow; the clone exists to appease the borrow checker) |
| 5 | engine.rs:12859 `add_req_header` `hdrs.push((name.to_string(), val.to_string()))` + finish_grow 192 B | String x2 + Vec grow | 5 | R,H | reuse |
| 6 | engine.rs:10436/10438 `format!` / `write!` of the rebuilt response head | String grow (3 reallocs) | 5 | R | stack buffer / write into the response buffer |
| 7 | engine.rs:10034-10043 status line split: `to_string`, `collect::<Vec<&str>>`, `join(" ")` | String, Vec | 5 | R | stack buffer (split in place) |
| 8 | ibex-sample registry.rs:1648 + 6351 + 6356 + sample.rs:19 (`path` fetch -> `Sample::Str(String)` -> collect into Vec -> clone) per ACL | String + 2 Vec | 5 per request with an ACL (4 per extra rule on the 503/deny path) | R | needs the pool design (Sample owns its bytes; T364 typed variables is the vehicle) |
| 9 | engine.rs:12976 `del_req_header` `vec![name.to_string()]` -> Box<[String]> | String, Box | 2 | R | stack buffer |
| 10 | proxy.rs:2234,2235,2317 `req.method.to_string()`, `req.uri.to_string()`, `from_utf8_lossy(..).into_owned()` | String x3 | 3 (2 in bare) | R | stack buffer / borrow (this is the whole bare-config cost) |
| 11 | engine.rs:11601, 11614 `xff_excepts` Vec, `ip.to_string()` x2 | Vec, String | 3 | R | stack buffer (`itoa`-style IP write) |
| 12 | engine.rs:12450 `render_sample_format` `String::with_capacity` | String | 2 | R | stack buffer |
| 13 | logfmt.rs:650 `Vec::with_capacity(160)`, logfmt.rs:1233 `format!("{}~")`/`to_string` frontend name | Vec, String | 2 | R | reuse (worker scratch for the log line) |
| 14 | regex bytetext.rs:44 `bytes_to_text` `valid.to_owned()` | String | 1 | R | stack buffer / Cow |
| 15 | txn.rs:1178 `Connection` rewrite `to_string` x2 | String | 2 on close | R | stack buffer |
| 16 | engine.rs:13622 `hdrs.push((act_name.to_string(), val))` | String | 1 | R | reuse |
| 17 | xprt.rs:422 `accepted.into_connection(config)` (rustls ServerConnection) | rustls internals, Vec/Box/Arc | 51 per TLS connection (57 h2) | T | needs the pool design (library allocates; would need an allocator hook or arena) |
| 18 | xprt.rs:488 `process_new_packets` | rustls Vec growth | 34 per TLS conn (36 h2) | T | needs the pool design |
| 19 | xprt.rs:409 `acceptor.accept()` (ClientHello parse) | rustls Vec | 31 (21 h2) | T | needs the pool design |
| 20 | xprt.rs:895 `Gate { Acceptor::default(), config }` Box (1816 B) x2 | Box | 2 per TLS conn | T | reuse (pool) |
| 21 | h2: h2_bridge.rs:85 `rx_htx.headers().map(clone).collect()` | String x2 per header + Vec | 12 per 1-stream (36 over 3) | R,H | reuse |
| 22 | h2: hpack.rs:817-819 `HeaderField{n.to_string(), v.to_string()}`, 836/919/926 dynamic_table.insert clone, 721 Huffman Vec, 570 push_front | String x2 per field, VecDeque | ~17 + 8 per stream | R,H | needs the pool design (HPACK table holds owned Strings; a byte arena) |
| 23 | h2: mux_h2.rs:452 `headers.push((name.trim().to_string(), val.trim().to_string()))`, 404 `to_ascii_lowercase`, 415 clone, 399-413 response HeaderField vec | String, Vec | ~7+12+4 | R,H | reuse / needs the pool design |
| 24 | h2: h2_bridge.rs:66 `format!("{} {}{} HTTP/2.0")`; mux_h2.rs:924 `format!("{s}://{a}")` | String | 3 + 2 per stream | R | stack buffer |
| 25 | h2: htx.rs:2390 `blocks.push(block)` (2016 B per 6) | Vec grow | 2 per stream | R | reuse (pre-sized Vec in the stream) |
| 26 | h2: engine.rs:9570/9171/9576 `wake_queue.push` | Vec grow | 2-6 | R | reuse (Vec capacity kept) |
| 27 | h2: h2.rs:360/361/374/375/420 `out.extend_from_slice` frame serialisation | Vec grow | ~10 | R | stack buffer / reuse |
| 28 | buf.rs:850 `vec![0u8; needed].into_boxed_slice()` (POST body, 32 KB) | big Vec | 2 per 64 KB POST | R,H (body size) | needs the pool design (pool of bufsize chunks; HAProxy takes a buffer from the pool here) |
| 29 | stats_html.rs:70 (32 KB), :770 (64 KB), engine.rs:10681 `format!` (35 KB), engine.rs:13820-13821, proxy.rs:1688 `raw.to_vec()` (35 KB) | String/Vec, 4 large copies | 38 per stats page | R if the stats URI is public | needs the pool design (one 64 KB chunk instead of 4 copies) |
| 30 | check.rs:1046 (5x headers), 923, 1038, 1066, 1070 (http check response parse) | String | 15 per http tick, per server per `inter` | none (own timer; backend-controlled response size via headers) | reuse |
| 31 | CLI: stats_typed.rs:381 `format!("{name}: {value}\n")` (177/show info), stats.rs:225/233 `value.to_string()` (900/show stat), stats.rs:216 `vec![String::new(); N]` per row (3.5 KB), applet.rs:148 `starts_with(&format!(..))` | String | 0 | A | stack buffer (`write!` into the out_buf) |

## 3. What an obvious change removes, vs what needs the pool design

Obvious (stack buffer, borrow or a worker-scratch Vec; no pool needed), blog request path: sites 1-7, 9-16 and 24: about
**55 of the 62** blog allocations (all of the response-rule header mirror, set/del-header mirror, request-line strings,
status-line split, `format!` calls, log line, xff/ip strings). The common cause of 1-5 (about 32 of the 62 by themselves)
is one design choice: request and response headers are mirrored into `Vec<(String, String)>` for the rule engine
(`CURRENT_RES_HEADERS` thread-local, `req_headers`, `hdrs`), cloned 4-5 times per request and re-serialised
(`new_hdr = format!`). A borrowed view over the HTX/buffer (ranges, not Strings) removes it. This also removes the
H-scaling: a request with 100 headers should cost 100x that group today (inferred).
The bare config already is at the floor Ibex can reach without fixing 10 (2 allocs).

Needs the pool design: site 8 (Sample owns a String; the ACL path), 17-20 (rustls: 120+ allocations per TLS
connection, 313 for an h2 TLS request, dominated by library-internal allocation Ibex cannot reach without an allocator
hook or an arena), 22-23 (HPACK dynamic table owns Strings), 28-29 (large buffers: HAProxy takes a bufsize chunk from
the pool). H2 as a whole (131 allocs per extra stream, 175 for the first) is the largest non-TLS remaining consumer and
needs both kinds of change.

Not removable by a local change: nothing found in the h1 path; every h1 site is a local String/Vec.

## 4. What was not done / caveats

- No reload, no Prometheus (parser refuses `use-service`), no compression rules (the harness blog config has none, and I
  did not add one), no QUIC/H3, no `stats`-with-auth, no DNS, no peers.
- Clients: python sockets (h1, TLS), `nghttp -n` (h2c and h2/TLS, certificate warning ignored). One stream per
  connection for the x1 rows; the x3 rows use three requests on one connection.
- The h2/TLS trace counts are not equal to the counter pass (505 vs 313): per-site numbers there are approximate; I did
  not find why (a timer or the second thread racing the flag are the candidates).
- Another session (t371-inv) builds into the same CARGO_TARGET_DIR (/home/bhenc/ibex-targets/alloc-review) and
  was relinking `release/ibex` during this run; I copied my binary to the scratchpad (`ibex-census`) and measured
  that copy. The target directory is therefore not a reliable place for this tree's binary.
- Health-check ticks per second: 33 checks in 6 s on a 200 ms interval; the per-tick figure divides by backend
  accepts, so it includes nothing else.
