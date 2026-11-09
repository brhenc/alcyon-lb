# The HTX-primary engine: rules on HTX only, HTTP/1.1 text at the send (D5, 2026-11-01)

Status: design, no production code. Plans D5 of `quic-transport-2026-11-01.md` §6 (user, 11:20:
"a Fable plan for the HTX-primary engine comes first; no code before it is reviewed"). Numbers
are from the records cited; no measurement was run for this document (the host was in use).
Oracle: `~/reference/haproxy` (`include/haproxy/htx-t.h`, `src/htx.c`, `src/http_htx.c`,
`src/mux_h1.c`, `src/h1_htx.c`, `src/http_ana.c`, `src/http_fetch.c`), line numbers as of
2026-11-01.

## 0. Short answers

- **What changes.** One message representation per direction, the HTX, is what the rules,
  fetches, converters, logs, facts and the h2/h3 muxes read and edit. HTTP/1.1 text exists only
  on the wire: it is parsed once into HTX blocks at the receive and written once at the send
  (request: the server send; response: the h1 client send). `sess.req`/`sess.rep` stop being
  "the message": they are the transport bytes, and the three parallel copies the engine keeps
  today (`req_headers: Vec<(String, String)>`, `req_method`/`req_uri` text, E2's `RspHead` index
  into the raw head, plus the `run_res_rules` head as `Vec<(String, String)>` + status + reason)
  go away.
- **The one design choice (D-A, §2.1): the HTX descriptors live in the transport buffer**, over
  the received head bytes, HAProxy's layout (payload from the front, 8-byte block descriptors
  from the back, `htx-t.h:30-127`) applied to the `Buf` the bytes were read into. The h1 parse
  writes descriptors, not a copy. An unmodified head is sent as the bytes that arrived (zero
  serialisation, as today's keep-alive path); a modified one is written once at the send. This is
  what keeps `keepalive ab1` flat while `rules ab1` and the h2/h3 paths lose their copies.
  HAProxy copies instead (`h1_headers_to_hdr_list` -> `htx_add_all_headers`, h1_htx.c:244/376):
  one head copy each way that Alcyon does not need to pay.
- **Expected gain (§3, reasoning per slice).** `rules ab1` 75.6k -> ~63-66k (-10 to -13k,
  from 1.80x to ~1.5-1.57x HAProxy's 42k); `h2s1` ~70k -> ~64-66k (-4 to -6k); `h3fit` the same
  -4 to -6k; `keepalive ab1` 45.9k flat (±0.5 %, the X2 budget) with -1k possible. After this the
  remaining gap on rules is the engine/scheduler and per-stream session rows (T550 S2, S3), not
  the message representation. The plan does not reach HAProxy's 42k on rules; it removes the
  representation's share of the gap, which §1 bounds at 12-15k.
- **Cost.** Six engineering slices after a profile slice, four of them Opus and L/M; ~2-3 weeks
  of agent time at the current pace. Each is mergeable alone; the ones that retire a
  representation do it with a `#[cfg(debug_assertions)]` counter test that fails first.

## 1. Where the instructions go today

### 1.1 Records that exist

| scenario | Alcyon (release-perf) | HAProxy | ratio | record |
|---|---:|---:|---:|---|
| rules ab1 | 75,630 | ~42,000 | 1.80x | `data/measurements.jsonl` last row (main 59c2f3bb, 2026-11-01 07:50); HAProxy from `memory-2026-10-24.md` §1.3 (42.0k) |
| keepalive ab1 | 45,879 | 33,300 | 1.38x | same row; HAProxy §1.3 (33.3k) |
| h2s1 | ~70k (79.6k at T544, then E1 -1.9 %, E2 -2.7 %, T560/T563 small) | 53.4k | ~1.31x | E1/E2 merge messages (f18dd295, 53902978); `quic-profile-2026-11-01.md` §2 |
| h3fit (1.97 dg/req) | 98.4k | 73.7k (dev10) | 1.34x | the brief for this task; `quic-transport-2026-11-01.md` §0 |

The only per-function profiles in the tree are **pre-E1/E2**: `memory-2026-10-24.md` §1.3 (rules,
`perf record`, before S7's rebuild-once) and `rust-performance-survey-2026-10-31.md` §3.2 (h2s1,
T544 IBS, 79.6k). What they show about the message representation, and what E1/E2/S7 have
already taken:

| bucket (rules ab1, §1.3, pre-S7) | then | after S7/E2 (estimate) | what remains and why |
|---|---:|---:|---|
| request re-serialised after each header action (`memset` 8 KiB stack, `memmove` body, `req_line` re-split, `write_h1_wire`) | ~6.5k | ~2.5k | S7 holds the rebuild for the rule run (`hold_req_rebuild`, engine.rs:15991); one `write_req_head` per request remains: the 8 KiB `memset` (16018), `write_h1_wire`, `replace_prefix` moving the body |
| spare strings and header lists (`req_headers` re-collected as `(String, String)` after every edit, engine.rs:15971; `reuse::with_string`) | ~4.1k | ~3-4k | untouched by S7/E1/E2; the list is what `req.hdr`/`hdr` fetches read (`SampleContext.req_headers`, registry.rs:212) |
| `SampleContext::clone` per response rule | ~1.5k | ~0-1.5k | S7 said "borrow"; verify in X0 |
| `Expr::cached` by text | ~1.5k | ~0.5k | T455 compiled most; tcp rules, `track-sc`, formats remain (memory doc §9 S7 note) |
| UTF-8 re-validation (`from_utf8` per fetch that wants `&str`) | ~1.6k | ~1.6k | untouched |
| response: `check_response_head` + `HeadFacts::scan` + `rewrite_header_names_before` + `run_res_rules` head materialised as `Vec<(String, String)>` + text rewritten | ~4-5k | ~3k | E2 made the scans one index (`RspHead`, response_head.rs:71) but the rules still build the `Vec<(String, String)>` head (`run_res_rules`, engine.rs:16567) and the text is rewritten after |

Sum of the representation's share still standing on rules: **~11-13k** of the 33.6k gap. On
h2s1 (survey §3.2 minus E1/E2): `H2ReqHead`/`put_request_head` into `sess.htx_buf` then
`write_h1_wire` into `sess.req` (one serialisation, ~1.5-2k), `copy_header` building the
`req_headers` list (~1k), the `from_utf8`/`str` boundary checks (~1.5k), `indexed_fields` on the
raw response for the mux (~0.5k): **~4.5-5k**. On h3 the same, plus nothing h3-specific.

### 1.2 Slice X0: the profile this plan needs

No record is post-E2. **X0** (Sonnet, S, slot B, IBS per T544's recipe, `rules ab1`, `h2s1`,
`keepalive ab1` on main, scaled to the `insreq.sh` totals): a per-function table of the buckets
above, so X2-X4's budgets are set against measured numbers and not these estimates. Output:
`docs/design/htx-engine-2026-11-01.md` §1.3 (append), raw folded stacks in `/tmp`, the figures in
the task file. Nothing else in this plan depends on X0 for its design, only for its numbers.

### 1.3 X0 results

Measured on main e83cd302 (2026-11-01), release-perf, IBS with inlines expanded, shares scaled to
`insreq.sh` user totals (45,900 keepalive / 75,719 rules / 71,593 h2s1), +-15 %, as in
`engine-architecture-2026-11-01.md` §2.1 (method, totals, raw data in
`~/ibex-worktrees/review/x0-2026-11-01/`). Inclusive instructions a request; the buckets overlap by
up to ~1k.

**Totals against §1.1's records:** keepalive 45.9k (HAProxy dev8 **36.2k**, not 33.3k), rules 75.7k
(HAProxy **43.8k**, not 42.0k), h2s1 71.6k (HAProxy 53.2k), h3fit 98.9k (dev10 now 64.0k, not 73.7k).

| bucket | then (§1.1) | estimate after S7/E2 | measured now (rules ab1 / keepalive / h2s1) | reading |
|---|---:|---:|---|---|
| request re-serialised: `write_req_head` + its 8 KiB `memset` + `replace_prefix` | ~6.5k | ~2.5k | rules: `write_req_head` **2.97k** (called **2.00 times a request**; keepalive 1.00, h2s1 0), plus `memset` 0.44k (`rewrite_request_connection`) + 0.38k (`flush_req_rebuild`) + `replace_prefix` 0.21k = **~4.0k**; keepalive 3.16k + 1.14k memset + 0.22k = **~4.5k**; h2s1 0 | S7 did not get it to one rebuild per request on rules (two); the estimate was 1.5k low. `write_h1_wire` 1.72k / 2.31k / 2.13k inside it. |
| h2: head built into `htx_buf` then serialised | ~1.5-2k | | h2s1: `put_request_head` **3.87k**, `write_h1_wire` 2.13k (of which the h1 text), `req_htx_init` 0.83k, `start_request` 8.69k in all | two copies of the head (HTX, then h1 text) cost ~6.8k, not 1.5-2k; X4's -2 to -3k is conservative. |
| `req_headers` re-collected as `(String, String)` | ~4.1k with the spares | ~3-4k | `req_headers`/`copy_header` **0.01k (rules) / 0 / 0.20k (h2s1)**: **the list is not built on these scenarios**; spare pool take/give `spare::*` **2.26k** (rules), `reuse::with_string`-family inside it; `VarStore`/`vars::` **1.31k** | the 4.1k bucket is now 2.3k spares + 1.3k vars; the `(String, String)` list is gone from rules ab1 (E2/S7). R4/R2 carry the 3.6k. |
| `SampleContext` per rule | ~1.5k | 0-1.5k | **2.11k incl** (self 0.24k) on rules; `SampleContext` is built for every rule's `eval`; `Expr::eval` **3.75k**, `any_acl` 2.26k, `eval_g` 1.33k for **3 fetch bodies a request** (0.44k a fetch) | S7's "borrow" is not in: the per-rule context is 2.1k. X2/X3's single-context work is worth ~1.5-2k. |
| `Expr::cached` | ~1.5k | ~0.5k | **0** (no `cached` frame in the profile) | compiled (T455); remaining expression cost is `Expr::eval` itself (R1). |
| UTF-8 re-validation | ~1.6k | ~1.6k | `from_utf8` **1.68k incl, 593 self, 39 calls a request** (rules); keepalive 1.45k incl, **22 calls**; h2s1 1.07k | the rules add 17 calls (~0.25k); the other 22 a request are the parse/facts path (`validate_request_head` 0.67k, `HeadFacts`...). D-B's "validated once" saves ~1.2k on rules, ~1.0k on keepalive. |
| response head: `check_response_head`, `HeadFacts::of_response`, `rewrite_header_names_before`, `run_res_rules`/`RspHead` | ~4-5k | ~3k | rules: 0.82k + 1.87k + **2.88k** + 1.74k = **7.3k** (overlap <1k); keepalive: 1.11k + 2.04k + 0.70k + 0.20k = 4.0k (all with no rules); h2s1: 1.87k + 2.35k + 0.34k + 0.21k = 4.8k | E2 left 4.0k standing on a rules-free keepalive; the rules scenario adds 3.3k, mostly `rewrite_header_names_before` (2.2k more than keepalive) and `run_res_rules` (1.5k more). |
| request parse into the HTX (new, for X2/X3) | | | `validate_request_head` **10.06k** keepalive / 9.34k rules (`H1Parser::parse` 7.51k / 6.78k; `parse_headers` 5.86k / 4.89k; `parse_start_line` 1.14k; `finalize_last_header` 0.56k; `req_line`/`req_line_bytes` 2.2k / 1.9k) | HAProxy's `h1_parse_msg_hdrs` + `h1_headers_to_hdr_list` + `htx_*` ~4.9k. Leaves: `memchr` 3.5k self (7.1k on rules: regexes/ACLs), `eq_ignore_ascii_case` 1.1k, `to_ascii_lowercase`/`is_ascii_uppercase` 1.25k, `ascii_word_spans` 1.1k: byte-at-a-time scans X2 should replace. |

**Sum of the representation's share standing on rules:** `write_req_head` family 4.0k + spares and vars
3.6k + `SampleContext` 2.1k + UTF-8 1.7k + response head 7.3k = **~18.7k**, of which ~4k is the
rules-free base (the response head scan, the facts); the rules' own representation cost is
**~14-15k of the 29.8k gap** (§1.1 estimated 11-13k of 33.6k). On h2s1: `put_request_head` 3.87k +
`write_h1_wire` 2.13k + `req_htx_init` 0.83k + `from_utf8` 1.07k + `copy_header` 0.20k +
`indexed_fields` 0.30k = **~8.4k** against §1.1's 4.5-5k estimate.

**Conclusions for the slices:** X1/X5/X2/X3 budgets stand or are low (rules: write 4.0k, context 2.1k,
spares 2.3k, parse 7.5k; the engine doc §4.1 ranges are not too high). Two items of this plan are
not covered by an X slice and are in `engine-architecture` §2.1: the **`Connection`-header path
on HTTP/1.0 keep-alive requests** (8.1k vs ~0.5k on HAProxy, includes `write_req_head` once) and
**`write_req_head` called twice a request on rules**.

## 2. Target design

### 2.1 Layout: HTX descriptors in the transport buffer (D-A)

HAProxy's HTX (`htx-t.h:268-286`): one buffer, payload packed from the front, `struct htx_blk`
(`flags:4, addr:28, info` = type in the top 4 bits, value length, name length; 8 bytes) packed
from the back; `tail_addr`/`head_addr`/`end_addr` for the wrapping payload; holes left by
removals count as free but are reused only by `htx_defrag` (htx.c:52). Alcyon already has this
structure: `HtxSlice`/`HtxSliceRef` (htx.rs:1366/761) are views over any byte slice with the
descriptor table at its end, `HtxBlockType` (htx.rs:79) mirrors `enum htx_blk_type`
(`htx-t.h:204-214`, with `Eom` extra), and the session holds one in `sess.htx_buf` (proxy.rs:688,
a `Buf` from the `buffer` pool: `buf.rs:123`, `THREAD_POOLS`, 64 per class per thread, counted
in `show pools`; `memory-2026-10-24.md` §2.1).

What changes is **where the payload is**. Today the h1 parser copies the head into
`sess.htx_buf` (`req_htx_init`, engine.rs:15657 sizes it as HAProxy would) and keeps the text in
`sess.req`; the design puts the descriptor table in the **reserve** of the transport `Buf`
itself, with `addr` pointing at the received bytes:

```
sess.req (one Buf, 16 KiB):
| head text as received | body bytes (forwarded as today) | ... free ... | appended values -> | <- descriptors |
                                                            |<------------ reserve (maxrewrite) ------------>|
```

- The reserve is `maxrewrite.min(bufsize / 2)` (default 1024), the region `req_htx_init` already
  withholds from the body (engine.rs:15666-15674, "the body is clamped once against the head").
  Descriptors (8 B x blocks: a 30-header head is ~33 blocks, 264 B) grow from the end; values
  appended by `set-header`/`add-header`/`set-path` grow from the reserve's start, exactly
  HAProxy's two-ended growth but confined to the reserve. HAProxy's `tune.maxrewrite` has the
  same meaning: the room a rewrite may take (and the 400/502 when it does not fit,
  `http_replace_req_uri` failing, as `req_set_uri` engine.rs:15688 models today).
- **A removed header is a tombstone** (`Unused`, as T15 and `htx_remove_blk` htx.c:399). The CRLF
  and the colon-space between fields are never addressed: the bytes between blocks are holes
  from the start, which is fine, they are the received text and cost nothing.
- **A head that is not modified is sent as received**: `htx_modified == false` (the field exists,
  proxy.rs:692) means the send writes `sess.req.readable()[..head_len]` as today. This is the
  keep-alive path and it does not change by a byte.
- **A modified head is written once, at the send**, by the h1 encoder (§2.3) into the free space
  after the body when it fits, else by compacting: `write_h1_wire` into the stack array and
  `replace_prefix` (today's `write_req_head` path, engine.rs:16010-16030) is the fallback, not the
  rule. The `memmove` of the body happens at most once per request instead of once per
  rebuild. When the reserve is exhausted mid-rules (five 200-byte `set-header`s) the same
  fallback runs once, as an in-place `defrag` that rewrites the head text from the blocks and
  resets the reserve.
- `sess.rep` is laid out the same way for the response. E2's `RspHead` (status, `http11`,
  `upgrade`, `start`, `len`, `fields: [RspField; N]`, response_head.rs:71) **is already this
  index**, with a fixed-size field array instead of descriptors at the buffer's tail. X3 makes
  `check_response_head` write `ResLine` + `Header` + `Eoh` blocks instead and `RspHead` goes.
- `sess.htx_buf` is then needed only when the message has to be **built** rather than parsed:
  the h2/h3 request (E1's `put_request_head`, htx.rs:1469), a `return`/`redirect`/`deny`
  response, an `errorfile`. In those cases the HTX buffer **is** the transport buffer of the
  outgoing side: the h2/h3 mux writes the request blocks into `sess.req`'s layout directly
  (payload from the front, descriptors from the back, no received text) and the h1 encoder
  writes the text at the server send. One buffer fewer per h2/h3 stream, and `rebuild_req_buffer`
  moves from the bridge (h2_bridge.rs:204-242, text written immediately) to the send.

**Alternative (B): HAProxy's own arrangement**, a separate HTX buffer per direction filled by
copying (`htx_add_all_headers`), the transport buffer freed as soon as it is parsed. Simpler
(one layout, no reserve arithmetic, T15's `HtxBuffer` nearly is it), but it adds one head copy
per direction (~1.0-1.5k each on a 300-500 B head) and makes the unmodified keep-alive head a
serialisation instead of a passthrough: `keepalive ab1` would move +2-3k, outside any budget.
HAProxy affords it because its h1 mux is the only reader; Alcyon's measured keep-alive figure is
45.9k against 33.3k and cannot take more. **Recommendation: A.** B is the fallback if A's
reserve model fails X2's tests on large heads (§4).

### 2.2 What reads the HTX

- **Fetches and converters** (`crates/alcyon-sample`): `SampleContext` keeps `htx_slice` (the
  request) and gains `res_htx: Option<HtxSliceRef>`; `req_headers`, `req_uri`, `req_method`,
  `req_version`, `raw_req`, `raw_res`, `res_headers`, `res_status` (registry.rs:212-240) go.
  `hdr`/`req.hdr`/`res.hdr`/`req.fhdr`/`hdr_cnt`/`hdr_names`/`hdr_val` read blocks as
  HAProxy's `smp_fetch_hdr` does (http_fetch.c:980-1019): a view into the buffer, `SMP_F_CONST`,
  comma-split by `http_find_header(full=0)`'s rule (http_htx.c:130-245: next element in the same
  block first, then the next block of the same name; `full=1` one whole line). Alcyon's
  `header_blocks_where`/`get_header` (htx.rs:874-1126) already walk this way for the request.
- **Samples are bytes** (user decision 2026-11-01, superseding the 2026-10-10 half of tradeoff
  6.12 that kept `str` samples UTF-8): Alcyon keeps data as bytes like HAProxy and neither
  validates nor re-encodes it. A `str`-typed sample is `Cow<'a, [u8]>` (engine doc §4.4 R2);
  matchers and converters work on bytes (HAProxy's `pat_match_*` on `smp->data.u.str`); the
  linear regex is `regex::bytes`, the backtracking one (fancy-regex, `str`) validates at the
  match only and a non-match is the answer on bytes it cannot decode. The ~1.6k "UTF-8
  re-validation" row goes to zero: the parse-path 22 calls with T575 Part 2, the rules-path 17
  with R2, the format/var `String` sites with R4. Bytes that are not UTF-8 are forwarded byte
  for byte (HAProxy treats values as opaque: h1.c:899-909 stops only at NUL, CR, LF; tradeoff
  6.24, E1). Closes 6.24's open item (`:path` with such bytes is a `ReqLine` block of bytes,
  forwarded; `%r` logs it as HAProxy's `#E9` escape), D-B.
- **Rules** (`rule_compiled::http_req`, rule_compiled.rs:354; `req_rule_header` engine.rs:15720;
  `run_res_rules` engine.rs:16567): every action edits blocks through `HtxSlice`
  (`set_header` 1834, `add_header` 1819, `remove_header` 1992, `replace_header` 1866, `set_uri`
  1892, `set_path` 1912, `set_method` 1941; status/reason for the response, new) and **nothing
  else**: no `req_headers` re-collection (15971), no `rebuild_req_buffer` call (eleven sites,
  engine.rs:4866-15972, all go), no `Vec<(String, String)>` head for the response rules. The
  action set is unchanged; `early-hint` stays unparsed (it is not in `HttpReqAction` today,
  rules_http.rs:77, and the parser refuses it; it becomes possible after X3's interim messages).
- **Facts and logs**: `HeadFacts::of_response` (txn.rs:1805) reads the blocks; `%U`/`%B`
  byte counts come from the wire (today: `write_h1_wire_vec` at proxy.rs:2387/2443/2939 to size
  the head, three serialisations for a number; X7 takes it from the encoder's return or the
  received length); `%r`/`%hr`/captures from blocks.
- **Websocket, framing, `option forwardfor`, cookies** (`websocket::check_response`,
  `response_framing`, `keep_cookie_blanks`, cookie.rs `HeaderEdit`): on blocks, as the cookie
  path already is (engine.rs:15960-15968).

### 2.3 The h1 encoder at the send (request to the server, response to an h1 client)

One function per direction, the port of `h1_make_reqline`/`h1_make_stline`/`h1_make_headers`/
`h1_make_eoh` (mux_h1.c:2464-2935), run when the head is modified or built:

- walks blocks from the head in order (order preserved, `h1_make_headers` 2646), skips `Unused`
  and pseudo-headers;
- **names in lower case** on the wire, as HAProxy (`htx_add_header` lowercases at the parse,
  htx.h:557; `h1_format_htx_hdr` h1_htx.c:1122 then applies `h1-case-adjust`/`-file`, which Alcyon
  parses, global.rs:217, and `option h1-case-adjust-bogus-client/-server`, proxy.rs:90). Alcyon's
  `rewrite_header_names_before` (engine.rs:16803) is this rule done late on text; it goes. The
  unmodified passthrough keeps the client's case, which is **not** what HAProxy does (HAProxy
  always rewrites); D-E asks whether to lower-case unmodified heads too (costs the passthrough).
- owns the framing headers: `transfer-encoding` emitted once and only as `chunked` when the
  message is chunked, `content-length` once, `connection`/`upgrade` filtered through the
  mode (`h1_update_req_conn_value` 1675, `h1_update_res_conn_value` 1699: `http-server-close`,
  `httpclose`, keep-alive to a 1.0 peer), `te` reduced to `trailers`, the missing
  `content-length: 0`/`transfer-encoding: chunked`/websocket key added at EOH (`h1_make_eoh`
  2807-2935). Today these are text edits spread over the bridge (`chunked_head`
  h2_bridge.rs, the `add_len` rows), `check_response_head`'s `rewrite`, `websocket::Verdict::
  Rewrite`, and the connection-mode code; X5 moves them into the encoder as **flags on the start
  line** (`HTX_SL_F_CLEN/CHNK/XFER_LEN/CONN_UPG/BODYLESS`, `htx-t.h:128-144`; Alcyon's
  `RequestLineView`/`res_line` grow the same flags).

### 2.4 h2/h3 muxes

- **Request in** (E1, done): fields -> blocks. After X4 the blocks are written straight into the
  child's `sess.req` layout (§2.1 last bullet); the `copy_header` list and the immediate
  `write_h1_wire` (h2_bridge.rs:204-242) go; the server send encodes once.
- **Response out** (E2, done as an index): `send_head_fields(id, status, fields)`
  (htx_mux.rs:70, mux_h2.rs:1028, mux_h3.rs:1265) iterates the response HTX's blocks; the HPACK
  static index lookup (`find_table_entry_octets`, hpack.rs:719, the 1.9k linear scan) becomes a
  `match` on the name length and first bytes, Track 3 Q3 of the transport doc, folded into X3
  because the block iterator is the natural place to carry it.
- **Backend h2** (`srv_h2.rs`, T540): today fed HTTP/1.1 text and parsing it; X8 feeds it blocks
  (`h2_srv.rs:482 start_request` takes an `HtxSliceRef`) and writes the response as blocks.
- h3 is the same code through `HtxMux` (`h3-engine-2026-10-26.md` §2.4).

### 2.5 Body, trailers, 1xx, tunnel, `http-buffer-request`

- **Body**: stays in the transport buffer and is forwarded as today (Alcyon has no DATA blocks on
  the h1 fast path). This is HAProxy with fast-forward always on: once the head is parsed,
  `SE_FL_MAY_FASTFWD_PROD` (mux_h1.c:2369-2375) lets `h1_fastfwd` (5273) move bytes to the
  consumer's `obuf` or a pipe and **the body never becomes HTX blocks**. `htx_xfer` (htx.c:837)
  is a memcpy, not zero-copy, so HAProxy's non-fast-forward path is slower than Alcyon's; nothing
  to port. Chunked input is passed through to an h1 peer, dechunked for h2/h3 (today's
  `forward_response_mux`, h2_bridge.rs:452); the remaining length is the mux's business
  (`h1m->curr_len`, not an HTX field, in HAProxy too).
- **DATA blocks on demand** (X6): `option http-buffer-request` (`defaults.rs:246`,
  `PR_O_WREQ_BODY` -> `http_wait_for_request_body` http_ana.c:843, waits for the body or a full
  buffer), `http-request wait-for-body`, `req.body`/`req.body_len`/`req.body_size`: the body
  bytes already in `sess.req` become one `Data` block addressed in place (zero copy; HAProxy's
  `smp_fetch_body` is a const view for one DATA block, http_fetch.c:685, a trash copy for more).
  Nothing is copied for a request that has no such rule.
- **Trailers**: `Trailer` + `Eot` blocks both ways (`h1_parse_msg_tlrs` h1_htx.c:981;
  `h1_make_trailers` mux_h1.c:3483). Today Alcyon handles them on text in the bridge
  (`late_trailers`, `drop_trailers`, h2_bridge.rs:510/817, T559); X6 parses the trailer section
  into blocks at the end of the transport buffer with the same reserve rule, so
  `option http-drop-response-trailers`, `%U` and the h2/h3 HEADERS frame read one thing.
- **1xx**: each interim response is its own HTX message, parsed, forwarded (`channel_htx_fwd_
  headers`, http_ana.c:1591-1600), and the analyser loops for the final one; 101 is kept for the
  upgrade. X3 does the same on `sess.rep`: an interim head is a complete message in the layout,
  sent (h1: as received; h2/h3: `send_interim`, h3-engine §4), then the layout is reset for the
  next head. The response rules run only on the final one (`http_process_res_common` stops early
  for 1xx, 1894).
- **Tunnel / upgrade**: after 101 (or CONNECT 2xx) both sides are raw (`h1_set_tunnel_mode`
  mux_h1.c:1890 clears XFER_LEN/CLEN/CHNK; `RAW_DATA` blocks): in Alcyon the transport buffers are
  already raw; the descriptor region is released (reserve returns to the body) when the tunnel
  starts. No change to `websocket.rs`'s decision, only to where it reads the fields.

### 2.6 Oracle-compatibility risks, with the HAProxy rule each follows

| item | HAProxy | Alcyon today | design |
|---|---|---|---|
| header case on the h1 wire | names lowercased in HTX (htx.h:557), case-adjust map on output (h1_htx.c:1122) | passthrough keeps the client's case; `rewrite_header_names_before` lowercases some | lowercase at the parse (in place, 0 copies) so every output is HAProxy's; the passthrough is then byte-identical to HAProxy only when the client sent lowercase; **D-E** |
| header order | preserved (blocks walked from head) | preserved | same; `add-header` appends before EOH, `set-header` removes all then appends (`http_replace_header`/`http_add_header` http_htx.c:678/286) |
| obs-fold | unfolded into spaces in the value (h1.c:929-937), leading/trailing LWS trimmed | `append_to_last_header` (htx.rs:1628) | the in-place parse writes the fold's CRLF+SP as part of the addressed value and the encoder emits HAProxy's spaces: a folded head counts as modified (sent through the encoder), never passed through; a differential test row (R1 item 2 corpus) |
| duplicates and comma lists | separate blocks; `http_find_header` element rule | `header_blocks_where` | port the `full` flag semantics exactly; test against `req.hdr(x,-1)`, `req.fhdr`, `hdr_cnt` rows |
| actions that rewrite raw text | none: all through `http_replace_*` on blocks | `chunked_head`, `check_response_head.rewrite`, websocket `Rewrite`, `rewrite_header_names_before`, `replace_prefix` sites | all become block edits or encoder flags (X5); the parser refuses nothing new, nothing is dropped |
| `option http-buffer-request` | waits for the body in HTX up to the buffer | `buffer_request` honoured on `sess.req` | X6 DATA block in place; same wait rule |
| tunnel / upgrade | `H1_MSG_TUNNEL`, RAW_DATA | raw | same |
| 1xx | own message, forwarded, loop | forwarded on h1; dropped on h2/h3 (h3-engine §4) | X3 interim messages; h2/h3 `send_interim` |
| `maxrewrite` | 400/502 when a rewrite does not fit (`tune.maxrewrite`) | `res_htx_resize` models it (engine.rs:15688) | the reserve **is** `maxrewrite`: same limit, now enforced by the layout; large-head rows (16 KiB head, 1 KiB reserve, five `set-header`) in the test plan |
| non-UTF-8 bytes | opaque | values forwarded (E1/E2), `:path`/`:method` refused on h2/h3 | all forwarded as bytes (D-B); samples, matchers and converters on bytes, no validation (user, 2026-11-01; R2) |

## 3. Slices

Measuring, all slices: release-perf, slot A (`flock -x /tmp/ibex-load.lock`), `insreq.sh` for
`rules ab1`, `keepalive ab1`, `h2s1`, `h3fit` against the parent commit; kernel instructions
reported beside user ones and counted (T568); `request_allocations*.rs` stay at their pins;
`./tools/checkin.sh` green. **Budget: +0.5 % on every scenario the slice does not name as its
saving**, including kernel instructions; a slice that names a saving and does not measure one is
not merged (AGENTS.md §8). Every slice keeps the parser refusing what it does not implement
(AGENTS.md §5): nothing in this plan adds a keyword.

| slice | goal | files | test that fails first | expected ins/req, reasoning | size | depends | model |
|---|---|---|---|---|---|---|---|
| **X0** | post-E2 profile of rules ab1, h2s1, keepalive (§1.2) | `tools/measure/insprof.sh`, this doc §1.3 | - (measurement) | - | S (half a day) | - | Sonnet |
| **X1** | the layout: `HtxSlice::over_received(head: &mut [u8], reserve: &mut [u8])` or an offsets form of `with_offsets` (htx.rs:1366) whose payload region is the received text plus the reserve's front and whose descriptors are the reserve's tail; in-place parse `HtxSlice::index_h1_head(&mut self) -> Result<ReqLineFlags>` writing `ReqLine`/`ResLine` + `Header` + `Eoh` descriptors over the bytes (names lowercased in place); `defrag` rewriting the head text from blocks when the reserve is full; `Buf` gains a reserve accessor (buf.rs:938 area). Data structure only, nothing on the path yet | `crates/alcyon-proto/src/htx.rs`, `crates/alcyon-rt/src/buf.rs` | `crates/alcyon-proto/tests/it/htx_differential.rs` (exists; T15's module) gains the rows: for 200 generated heads (T15's generator + the R1 smuggling corpus), `index_h1_head` then every reader (`headers`, `get_header`, `req_line`, `body_len`) equals `H1Parser` + `put_request_head`'s HTX; edit sequences (set/add/del/replace x reserve sizes 64-1024) then `write_h1_wire` equals the copying HTX's output; reserve exhaustion triggers one `defrag` and the result is equal. Red: the constructor does not exist | 0 (not on the path); the file's existing `HtxSlice` tests stay green | M | - | Opus |
| **X5** | the h1 encoder owns the framing (§2.3): `h1_encode_head(htx, mode: ConnMode, dir) -> usize` with the `h1_make_eoh` rules; start-line flags `CLEN/CHNK/XFER_LEN/CONN_UPG/BODYLESS`; the text rewrites it replaces (`chunked_head`, `check_response_head.rewrite`, `websocket::Verdict::Rewrite` text form, `rewrite_header_names_before`) call it | `crates/alcyon-proto/src/htx.rs` (encoder), `h1.rs`, `response_head.rs`, `crates/alcyon-rt/src/h2_bridge.rs`, `websocket.rs`, engine.rs (`rewrite_header_names_before` sites) | `crates/alcyon-proto/tests/it/h1_encode.rs`: a table of (HTX, mode) -> bytes, each row's expected bytes **taken from HAProxy** (`h1_make_*` on the same input: run the oracle with `http-server-close`, `httpclose`, 1.0 client, CL+TE, websocket, 204/304, HEAD) and recorded in the test; red: no encoder. Integration: the response battery (T275, T281, T436) and the h2 battery stay green | neutral (±0.5 % budget): it replaces text edits with the same bytes; a differential row in `h2_per_request_work.rs` asserts the wire is byte-equal to today's for the scenarios' heads | M | X1 | Opus (the `h1_make_eoh` rules) |
| **X2** | request head in place for h1, rules on HTX: the h1 parse writes descriptors into `sess.req`'s reserve (X1); `req_htx_init`/`sess.htx_buf` copy gone for h1; `req_headers`, `req_method`/`req_uri` text, `raw_req` retired from `TcpSession` and `SampleContext` (the fetches read blocks); the eleven `rebuild_req_buffer` sites and S7's hold/flush become one `encode_if_modified` at the server send; `req_set_uri`'s resize model becomes the reserve check | `engine.rs` (rules region 15400-16040, send site, `req_htx_init`), `proxy.rs` (`TcpSession` fields 687-701, `htx_slice` 1476), `crates/alcyon-sample/src/registry.rs` (`SampleContext`), the header fetches in `alcyon-sample`, `txn.rs` | `crates/alcyon-rt/tests/it/htx_primary.rs` (new module): `a_request_head_is_written_at_most_once`: a `#[cfg(debug_assertions)]` counter on the encoder is 0 for keep-alive GET and 1 for the rules scenario's head (red today: `write_req_head` runs once per request on rules **and** the `req_headers` collect runs per edit, counted by `work::Op::ReqRebuild` engine.rs:16012: assert `ReqRebuild == 0` for an unmodified head); `an_unmodified_head_is_the_bytes_that_arrived` (mixed-case client header reaches the server unchanged or lowercased per D-E); `rules_with_a_full_reserve_still_forward` (16 KiB head + five 200 B `set-header`, 1 KiB reserve: 200 and the server sees all five; red: n/a today, pins the fallback); the rules battery, cookie, forwardfor, `set-path`/`set-query` rows green; differential corpus rows (R1 item 2) unchanged against HAProxy | **rules -6 to -8k** (the per-edit `req_headers` collect 3-4k, one `write_req_head` with its 8 KiB memset and body memmove 2.5k, UTF-8 ~0.5-1k, `SampleContext` fields ~0.3k); **keepalive flat** (the parse writes ~12 descriptors where it wrote nothing: +0.2k; `req_htx_init` and the `htx_buf` take/give go: -0.3k; net within ±0.5 %); h2 -1k (`copy_header` list) | L | X1, X5 | Opus |
| **X3** | response head in place, response rules on HTX: `check_response_head` writes `ResLine`/`Header`/`Eoh` descriptors into `sess.rep`'s reserve, `RspHead` and `HeadFacts::scan`'s text path go, `run_res_rules` takes `&mut HtxSlice` (no `Vec<(String, String)>`, status/reason as start-line edits), the h1 client send is passthrough-or-encode, `send_head_fields` iterates blocks with the static-index `match` (Track 3 Q3); interim (1xx) messages as §2.5 | `response_head.rs`, `txn.rs` (`HeadFacts`), engine.rs (`apply_http_response_rules_in` 11500-11600, `run_res_rules` 16567-16700), `h2_bridge.rs` (`indexed_fields` 431, `forward_response_mux` 452), `mux_h2.rs`/`mux_h3.rs` (`send_head_fields`), `hpack.rs` (static `match`) | `htx_primary.rs`: `a_response_head_is_walked_once_and_written_at_most_once` (the E2 counter `scans == N` tightened to: no `Vec<(String, String)>` build, `ReqRebuild`-style `RspEncode == 0` with no response rules, 1 with the scenario's two); `an_interim_response_reaches_an_h2_client` (103 then 200 from an h1 server: HEADERS without END_STREAM then the final; red: dropped today, h3-engine §4; oracle: main HAProxy over h2 works, the h3 oracle's BUG_ON noted); the 23 response probe cases x h1/h2 of E2 stay identical to HAProxy | **rules -3 to -4k** (`Vec<(String, String)>` head + `SampleContext` per-rule copies ~2k, the text rewrite after the rules ~1k, `rewrite_header_names_before` 0.7k); **h2/h3 -2 to -3k** (`indexed_fields` and the HPACK linear scan 1.9k -> ~0.3k); keepalive -0.5 to -1k (`HeadFacts` from blocks, no second walk) | L | X1, X5 | Opus |
| **X4** | h2/h3 request built in the child's transport layout: `put_request_head` writes blocks into `sess.req`'s layout (no `htx_buf`, no text until the server send); `start_request`'s cookie/ws/`content-length` work on blocks; the chunked-without-length head is an encoder flag | `h2_bridge.rs` (95-242), `htx.rs` (`put_request_head` target), `mux_h3.rs`/`mux_h2.rs` (`take_req_fields`), `proxy.rs` (`h2_child_of` buffers) | `h2_per_request_work.rs`: `an_h2_request_head_is_parsed_once` kept and `..._is_written_once` added (encoder counter 1 per request; red: `write_h1_wire` at h2_bridge.rs:242 **and** the send); `h3_request_framing_to_backend.rs`, cookie-blank and canonical `content-length` rows (E1, VV-32) green | **h2/h3 -2 to -3k** (the bridge's immediate `write_h1_wire` 1.5k, one `Buf` take/give 0.3k, `copy_header` remainder 0.5k) | M | X2 | Opus |
| **X7** | retire the rest: `write_h1_wire_vec` sizing sites (proxy.rs:2387/2443/2939) take the encoder's length or the received length; `HtxBlock`/`Htx` (`Vec<HtxBlock>`, htx.rs:314/2470) deleted if no reader remains; `has_htx`/`htx_modified`/`htx_tail`/`htx_blocks` collapse into the layout; tradeoff 6.24's open item closed (`:path` bytes) | htx.rs, proxy.rs, txnlog.rs, engine.rs | `htx_primary.rs`: `a_log_line_does_not_serialise_the_head` (`%U` on a 1 KiB head: encoder counter 0; red: three `write_h1_wire_vec`); `h2_field_validity.rs` `:path` non-UTF-8 forwarded (red: RST_STREAM) | rules -1k, h2 -0.5k, keepalive -0.3k (`%U` sizing) | M | X2, X3, X4 | Sonnet |
| **X6** | DATA on demand (`http-buffer-request`, `wait-for-body`, `req.body*`) as one in-place `Data` block; trailers as `Trailer`/`Eot` blocks both ways (replaces `late_trailers`/`drop_trailers` text handling) | engine.rs (body wait), `alcyon-sample` body fetches, `h2_bridge.rs` (510, 817), htx.rs | `htx_primary.rs`: `req_body_is_a_view_into_the_request_buffer` (debug counter: 0 copies for a 4 KiB POST with `option http-buffer-request`; red: a copy today, verify in X0), T559's trailer rows green, `option http-drop-response-trailers` row | neutral on the four scenarios (none buffers a body); `h3_request_framing_to_backend` body rows measured once, -0.5k expected | M | X3 | Sonnet |
| **X8** | backend h2/h3 from blocks: `srv_h2.rs` takes `HtxSliceRef` (no text parse), writes the response as blocks | `srv_h2.rs`, `h2_srv.rs:482` | `h2backend` scenario pin in `htx_primary.rs` (encoder counter 0 to an h2 server; red: text) | `h2backend` -3 to -4k (one serialisation and one parse gone); the four main scenarios untouched | M | X3, X4 | Sonnet |

Order: X0 -> X1 -> X5 -> X2 -> X3 -> X4 -> X7 -> X6 -> X8. X1 and X5 are parallel (different
functions in the same file: X1 the layout, X5 the encoder; X5's tests use the copying HTX until
X1 lands). X2 and X3 are parallel after X5 (request side against response side; both touch
`engine.rs` in different regions and `SampleContext`, the second to merge rebases). Against the
transport doc's programme: Q1, P1, Q2 do not touch these files; E3 (stream object per child)
waits for X4 (it changes what a child owns); Track 3 Q3 (HPACK static `match`) is inside X3.

Expected total, ranges not added (read ±30 %): **rules 75.6k - 10 to 13k = 63-66k**; **h2s1
~70k - 4.5 to 7k = 63-66k** (1.18-1.24x HAProxy's 53.4k; the survey §6's 1.1x then needs S2/S3);
**h3fit 98.4k - 4.5 to 7k**; **keepalive 45.9k - 0 to 1.3k**.

## 4. Risks, stop rules, open questions

**Risks.**
1. The reserve model (§2.1) on edge heads: a head that nearly fills the buffer leaves a 1 KiB
   reserve; HAProxy's own limit is the same `maxrewrite`, but Alcyon's today is modelled, not
   enforced by layout, and the large-head reg-tests (`h1_large_headers`, the 400/502 rows) may
   change a verdict. X2's `rules_with_a_full_reserve_still_forward` and the reg-test board decide.
2. In-place lowercasing of names changes what an unmodified head looks like (D-E); if the user
   keeps passthrough case, two outputs exist for the same head (passthrough: client's case;
   encoded: lower) and the differential corpus must accept both.
3. `defrag` correctness (T15's warning: a stale `addr` yields plausible bytes). X1's differential
   test and a `cargo fuzz` target over edit sequences (R1 item 1) before X2 merges.
4. Keep-alive regression from the in-place parse. Budget ±0.5 % on 45.9k = 230 instructions; the
   descriptor writes are ~12 x 2 stores plus the lowercase pass over ~150 bytes of names
   (`rewrite_header_names_before` costs 0.7k today on the response: that is the number to beat).
5. `SampleContext` is shared with `tcp-request content`, `use_backend`, logs, stick rules and the
   Lua-less converters: retiring `req_headers` touches every fetch (`alcyon-sample` ~1,200 lines of
   sample code, T272's count) and the 290 test sites tradeoff 6.12 counted. X2 is L for this.

**Stop rules.** Stop and reconsider B (§2.1) if X2 measures keepalive > +0.5 % with the parse in
place and no fix inside the slice; if the X1 differential test cannot be made to pass on the R1
corpus within the slice (the layout is wrong, not the test); if X3's interim-message handling
needs a second buffer per response (then 1xx stays forwarded-without-rules as today and X3 ships
without that row). Do not weaken a `tools/checkin.sha256` test to pass; report it.

**Decisions for the user.**

| | question | recommendation |
|---|---|---|
| **D-A** | Layout: (A) descriptors in the transport buffer's reserve over the received bytes, passthrough for unmodified heads; or (B) HAProxy's separate HTX buffer, copy at the parse | **A.** B costs keepalive +2-3k for simplicity Alcyon does not need; A keeps today's zero-work keep-alive path and is HAProxy's layout in every other respect |
| **D-B** | Header values, `:path`, `:method` as bytes in the HTX; `str` samples validated at the fetch (tradeoff 6.12 kept, 6.24's open item closed) | **Yes.** It is what HAProxy does (opaque bytes) and removes the h2/h3 `:path` reset where HAProxy forwards. **Amended 2026-11-01 (user, §5)**: no validation at the fetch either; samples are bytes (R2) |
| **D-C** | Keepalive budget for X2: strict ±0.5 %, or allow up to +1 % if rules gains ≥ 6k | **Strict.** Keep-alive is the production path for a blog; the design claims it is flat, so measure it flat |
| **D-D** | Body in HTX as DATA blocks always (HAProxy's non-fast-forward path) or on demand only (X6) | **On demand.** HAProxy itself bypasses HTX for the body whenever it can; always-DATA is a copy per body for nothing |
| **D-E** | Lowercase header names on every h1 output (HAProxy's behaviour, costs the unmodified passthrough ~0.2-0.4k on keepalive) or keep the client's case when nothing was modified (today) | **Lowercase everywhere**, inside the keepalive budget, because the oracle does and the differential corpus (R1 item 2) otherwise carries a permanent documented difference; if it does not fit the budget, keep passthrough and document in `tradeoff.md` |
| **D-F** | Order against the transport programme: X-slices before E3/Track 3, parallel to Q1/P1/Q2 | **Yes**; E3 after X4 |
| **D-G** | Spend: four Opus L/M slices (X1, X5, X2, X3) plus X4 Opus M and three Sonnet M; ~2-3 weeks | approve X0, X1, X5 now; X2/X3 after X0's numbers confirm the §1 estimates (if the representation's share measures < 8k on rules, stop after X5 and go to S2/S3 instead) |
| **D-H** | `early-hint` (`http-request early-hint`, missing from the parser): add after X3's interim messages, or leave refused | leave refused until X3 ships; then one Sonnet S slice |

## 5. User decisions (2026-11-01 11:45)

- **D-A, D-B, D-C, D-D, D-F, D-H: as recommended** (layout A; values and `:path` as bytes; strict
  keepalive budget; body on demand; X slices before E3; `early-hint` refused until X3).
- **D-E: a setting, not a fixed rule.** "HAProxy lowercasing everything has been a headache."
  `tune.alcyon.h1-lowercase-headers on|off` (name to be settled in X5): `off` = an unmodified head
  keeps the case it arrived with and the encoder writes names as stored; `on` = every h1 output
  lowercased, as HAProxy (with `h1-case-adjust` still applying on top, as HAProxy). Default
  `off` (today's Alcyon behaviour, and the cheaper path); differential rows against HAProxy run
  with `on`. Built in X5 (encoder) and X2 (passthrough).
- **D-G: both.** The representation work (X0 -> X1, X5 -> X2, X3 ...) and the engine/scheduler
  work (T550 S2 = slice E3, a stream object per h2/h3 child; S3, the loop row: 17.4k on h2 against
  HAProxy's 2.3k, 7.15 loop passes per request) run in parallel. X0's profile covers S3 too, so the
  S3 slices are written from its numbers; X2/X3 go ahead whatever X0's representation share is.

**2026-11-01 (evening), after X0.**

- **D-B amended: bytes like HAProxy.** Alcyon keeps request and response data as bytes and does
  not validate or re-encode it; the "`str` samples stay UTF-8, validated once at the fetch" half
  of tradeoff 6.12 is retired (`tradeoff.md` 6.12 and 6.24 updated at R2's merge). `Sample` Str
  becomes borrowed bytes, matchers and converters on bytes, the linear regex `regex::bytes`,
  fancy-regex (`str`) only where a pattern needs lookaround or backreferences and then
  validating at the match (engine doc §4.4 R2, §2.2 above). The parse path goes to bytes first
  (T575 Part 2, in flight).
- **The "expected" cells of §3 are superseded** by the engine doc §4.1 (X1 is now L and owns
  the parse scan; X2 keepalive -3 to -5k, not flat; X3 keepalive -1.5 to -2.5k and rules -3.5
  to -5k; X4 -3 to -5k) and the landing by its §5; the goals, files and tests of §3 stand.
  The §3 "Expected total" paragraph is pre-X0 and is not the landing.
