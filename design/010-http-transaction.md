# Ibex Design: the HTTP transaction

Status: steps 1-4 implemented on branch `txn/010`, 2026-10-02 (see "As built" at the end).
Step 5 (one transaction per H2 stream) is not done.

## Why now

Most reg-tests still failing need behaviour inside one HTTP transaction: bodies
(`wait-for-body`), error replies (`errorfile`), retries, keep-alive, `http-response`
rules, reuse. Every one of them is being built against the same missing abstraction, and
it shows up as the same class of bug each time:

| Date | Defect | Root |
|---|---|---|
| 09-25 | `http-response` rules ran on the first response of a connection only | server side left `Established`; "rules applied" inferred from `srv_state` |
| 09-25 | a backend close after a complete response closed the client | no notion of "response body complete" |
| 09-25 | a pipelined request forwarded down a closing backend connection | no notion of "this request is finished; the next one waits" |
| 09-25 | `Connection: close` injected into the previous header | header edits made on raw bytes, per call site |
| 09-27 | one request answered with an endless stream of 503s | a request answered locally was never marked consumed; the reset re-ran it |
| 09-27 | `return ... errorfile` closed the connection; `return` inline kept it | two hand-written copies of "end this transaction", which diverged |
| 09-27 | `errorfile 503` ignored for the proxy's own 503s | 23 places write responses into `rep`, each deciding for itself which page |

Each fix was correct and each added another flag: `resp_released`, `resp_length_known`,
`resp_status`, `response_rules_applied`, `resp_headers_processed`,
`srv_connection_close`, ... `TcpSession` has 64 public fields. The cost per feature is
rising because every change must rediscover which combination of them means "where is
this transaction", and the reviewer must too. Sonnet's T57 and T64 each spent most of
~300K tokens there, and T64's `wait-for-body` stopped exactly at "a suspension point that
doesn't exist".

## What Ibex does today

`crates/ibex-rt/src/engine.rs` `step_stream` (:3463) runs numbered steps over a
`TcpSession` (`proxy.rs`) whose byte-level `process()` (:1462) moves data between `req`,
`rep` and the two sockets. HTTP is layered on top by inspecting buffers between steps:

- request rules run when a full head is in `req`;
- Step 2.5 / `process_srv_active` apply response rules when `srv_state == Ready`;
- Step 3.8 (:3616) declares the transaction finished when `response_rules_applied &&
  !has_pending_output()`, then resets ~20 fields by hand and re-wakes the session.

There is no request message state, no response message state, and no single place a
transaction ends. "Finished" is inferred, and the inference is wrong whenever the request
had a body not yet read, the response was generated locally, or the server closed early.

## What HAProxy does

`/home/bhenc/reference/haproxy`:

- One `struct http_txn` per transaction (`http_create_txn`, `src/http_ana.c:5385`), holding
  `req` and `rsp` `http_msg`s, each with an explicit state
  (`include/haproxy/http_ana-t.h:207`): `RQBEFORE/RPBEFORE -> BODY -> DATA -> ENDING -> DONE
  -> CLOSING -> CLOSED`, or `TUNNEL`.
- Analysers advance those states in a fixed order: `http_wait_for_request` (:83),
  `http_process_req_common` (:380, frontend then backend rules),
  `http_wait_for_request_body` (:843, the `wait-for-body` suspension point),
  `http_request_forward_body` (:933); `http_wait_for_response` (:1254),
  `http_process_res_common` (:1786), `http_response_forward_body` (:2160).
- The transaction ends in one place: `http_end_request` (:4539) and `http_end_response`
  (:4671) move each side to `DONE`, and only when **both** are `DONE` is the transaction
  reset for the next request on the connection, or the connection closed.
- Every locally generated response goes through `http_reply_message` (:5048) /
  `http_reply_and_close` (:4873), with the page chosen by `http_error_message` (:4912):
  txn reply, then backend, then frontend, then built-in.

We do not port the analyser bit-mask machinery. We take the three ideas: explicit message
states, one end-of-transaction function, one reply function.

## Proposal

### 1. `HttpTxn`

A struct owned by the session entry, created when a request head is complete, dropped at
end of transaction:

```rust
pub struct HttpTxn {
    pub req: MsgState,   // Head, Body { remaining }, Done, Tunnel
    pub rsp: MsgState,   // Waiting, Head, Body { remaining | Chunked | UntilClose }, Done
    pub status: u16,
    pub reply: Option<Reply>,         // set when the proxy answers itself
    pub close_after: bool,            // the one "close the client when done" decision
    pub rules: RulesProgress,         // req rules done, backend chosen, rsp rules done
    pub vars: HashMap<String, String>,
}
```

It absorbs the per-transaction fields now scattered over `TcpSession` and
`SessionEntry` (`req_method`, `req_uri`, `req_headers`, `req_vars`, `resp_status`,
`resp_length_known`, `resp_released`, `resp_headers_processed`, `response_rules_applied`,
`srv_connection_close`, `connection_close`, `is_first_req`, ...). "Reset for the next
request" becomes `entry.txn = None`.

### 2. Body framing is tracked, not inferred

`MsgState::Body` carries what is left (Content-Length count, chunk parser state, or
until-close). The byte mover reports how many body bytes it forwarded; the txn decides
when the body is `Done`. This is what `wait-for-body`, request-body retries, keep-alive
after a POST, and "a server close after a complete response" all need, and today none of
them has it.

### 3. One way to end a transaction

`fn end_txn(entry, ...)` runs when `req == Done && rsp == Done && output drained`:
keep or pool the backend connection, then either close the client (`close_after`) or drop
the txn and re-wake. Step 3.8's inference and its hand-written reset go.

### 4. One way to reply

`fn reply(entry, status, source)` for every locally generated response (deny, return,
redirect, auth, 400/408/500/502/503/504): picks the page (`http_error_message` order,
including T57's `errorfile`/`http-error`), marks the request consumed, sets `rsp` to its
final state and `close_after` from the page and the request's framing. The 23 direct
writes into `rep` go through it.

## Migration

One PR per step, each on its own branch, each gated by `./tools/checkin.sh` and the full
reg-test board with no newly failing test.

1. **Tests first.** A binary-level transaction suite (pattern: `tests/keepalive_binary.rs`),
   each case measured against HAProxy 3.5 first: pipelined GETs; POST with CL body then
   GET; chunked POST; `deny` / `return` / generated 503 then a second request; server close
   after CL response; close-delimited response; `Expect: 100-continue`; `http-response`
   rules on every response. Most pass today; the point is to hold them while refactoring.
2. **`reply()`**: route the 23 writes through one function. Behaviour change limited to
   picking pages in HAProxy's order (finishes T57).
3. **`HttpTxn` with states, `end_txn()`**: move the fields, replace Step 3.8. No new
   features in this step.
4. **Body tracking**: then `wait-for-body` (T64's remainder) becomes a state that waits.
5. H2 streams get one `HttpTxn` each (today `h2_active_stream_id` is a single slot).

Steps 2-4 are too entangled to delegate; they need one session holding the whole of
`step_stream` in mind. After step 4, reg-test tasks against the transaction become
the kind of self-contained change agents have been good at.

## Not in scope

HTX as HAProxy has it, filters, the analyser bit-mask, HTTP/3.

## As built (2026-10-02)

Where the implementation differs from the proposal above, and what it found.

- **Where the transaction lives.** `TcpSession::txn: Option<HttpTxn>` (`crates/ibex-rt/src/
  txn.rs`), not the session entry: the byte movers in `proxy.rs` need the message states to
  bound what they forward. `req_method`/`req_uri`/`req_headers` stay on the session; they are
  cleared in one place, `TcpSession::reset_for_next_request`.
- **Steps 3 and 4 are one change.** A message state that does not know where the body ends
  cannot say when the message is done, so the explicit states and body tracking went in
  together. `MsgState::window`/`consume` scan Content-Length, chunked (with extensions and
  trailers) and until-close bodies; the forwarders send only the window.
- **The forwarders.** `TcpSession::req_window` / `rep_window`: a request's bytes and nothing
  after them (a pipelined request waits for its turn and is routed on its own); a response is
  held (`MsgState::Waiting`) until the engine has run its head through the response rules --
  this replaces `resp_released`. The byte layer no longer parses response heads or applies
  rules; `process_cli_transitions` does nothing in HTTP mode.
- **One end.** `EngineDispatcher::end_txn`: a server connection that can carry another
  request stays on the session; the next request is routed afresh by its own rules and
  takes it only if it goes to the same server (otherwise it goes to the idle pool). The
  client then either closes or waits for its next request.
- **Reading the server.** Always, except while the proxy writes its own reply: a kept
  connection's close is seen without probing it, and the read interest does not flip per
  transaction. A read that would block is not retried until the poller reports the socket
  readable (`TcpSession::srv_cant_recv`, `HAProxy`'s `fd_cant_recv`).
- **One reply.** `TcpSession::write_reply` (bytes) and `reply_error` (status -> page in
  `http_error_message` order). The request is dropped through its framing; a body still
  arriving is drained as it comes (`drain_request`), as `HAProxy` 3.5 does, bounded by
  `timeout client`. The connection closes after an empty page or one that says
  `Connection: close`. (It also closed after an unread body behind `Expect: 100-continue`;
  `HAProxy` 3.5 keeps that connection, and so does Ibex now --
  `a_reply_to_an_expect_100_continue_request_keeps_the_connection`.)
- **What `HttpTxn` replaced.** `resp_released`, `resp_length_known`, `resp_status`,
  `resp_headers_processed`, `srv_connection_close`, `connection_close`, the session copies of
  the response rules (`http_res_rules`, `http_after_res_rules`, `acls`) and their second
  implementation in `proxy.rs`, `SessionEntry::response_rules_applied`, Steps 2.5, 2.6, 3.7,
  3.8, 3.9, `discard_unforwarded_request`, `send_synthetic_*`.

Defects found on the way, each with a test that failed first (`tests/http_txn.rs` unless
noted):

| Defect | Cause |
|---|---|
| `http-request deny` skipped for a request after the first on a connection with a kept server connection | rules ran only when `srv_state == Init` |
| every response through `http-response` rules carried 4 extra bytes before its body | the rebuilt head was spliced in at the start of the old blank line, not its end |
| a backend's own `timeout server`/`timeout connect` ignored; `defaults` won | legacy `srvtimeout`/`contimeout` fields, filled from `defaults`, read before the section's own |
| a wake without a socket event waited up to 100 ms (50 pipelined requests: 4.9 s; now 0.01 s) | `Engine::step` polled with timeout 0 only for `runnable()`, which excludes tasklets |
| a client that stops reading kept a session requeued every loop | Step 4b requeued on pending output; the poller is level-triggered and already asked for `EPOLLOUT` |
| `send-proxy-v2` request forwarded as 4 bytes | the v2 signature starts with `\r\n\r\n` (counted now as head) |
| no 502 for a server that closes without answering, no 504 on `timeout server` | no "response not started" state |
| a 101 was not a tunnel | no tunnel state |

Not done, recorded: T87 (oversized head: HAProxy says 431, earlier), T88 (client
half-close: HAProxy aborts). HAProxy 3.5-dev7 itself aborts on a 1xx and a final response in
one read (`BUG_ON` at `src/htx.c:391`); that case is decided by RFC 9110 in the suite.

For profiling later: `MsgState::window` rescans a chunked body's buffered bytes on every call
(it is asked by `interests`, `has_pending_output` and the forwarders); caching the window per
buffer state is the obvious fix if it shows.
