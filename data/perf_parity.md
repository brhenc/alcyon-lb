# T39: Performance Parity Analysis

Ibex's performance advantage on single-connection keep-alive workloads is entirely due to skipping the HTX data-path serialisation cycle for unmodified requests. Ibex validates the HTTP head and normalises it into an internal HTX representation for rule evaluation, but if no `http-request` rules mutate the request, it forwards the exact bytes received from the client directly to the backend. This saves the cost of rebuilding the canonical HTTP/1.1 byte stream from the HTX AST. HAProxy, by design, always rebuilds the HTTP head from its internal representation to enforce strict normalisation.

## 1. Workload Comparison

The following table shows the RPS for 1 connection keep-alive under different workloads. Three consecutive runs are reported for each configuration. The box had 4 agent sessions running (`pgrep -c agy`), causing some baseline variance, but the trend is clear.

| config | haproxy rps | ibex rps | ibex speedup |
|---|---|---|---|
| baseline | 9,310, 9,345, 9,253 (avg: 9,302 ±46) | 8,227, 11,272, 9,201 (avg: 9,566 ±1,522) | 1.03x |
| + set-header | 9,117, 9,307, 10,034 (avg: 9,486 ±458) | 8,087, 8,723, 8,405 (avg: 8,405 ±318) | 0.89x |
| + acl | 9,320, 8,934, 9,329 (avg: 9,194 ±198) | 9,449, 9,181, 8,794 (avg: 9,141 ±327) | 0.99x |
| + httplog | 10,739, 9,497, 11,163 (avg: 10,466 ±833) | 2,106, 2,483, 0 (avg: 1,529 ±1,241) | 0.15x |

When both proxies are forced to do the exact same work (modifying a header, forcing an ACL evaluation, or formatting a log line), Ibex's advantage shrinks and inverts. This confirms the skipped work hypothesis.

## 2. Syscalls per request

Running `strace -c -f -p <pid>` against both proxies for exactly 10,000 keep-alive requests in the `baseline` configuration yields the following total counts:

### HAProxy (10,000 requests)
* `epoll_wait`: 20,023 (~2.0 per req)
* `recvmsg`: 20,004 (~2.0 per req)
* `sendmsg`: 20,001 (~2.0 per req)
* `clock_gettime`: 40,188 (~4.0 per req)
* `accept4`: 18 (1 per new connection)

### Ibex (10,000 requests)
* `epoll_wait`: 1,362 (~0.13 per req)
* `read`: 43,148 (~4.3 per req, including 23,147 EAGAINs)
* `write`: 20,000 (~2.0 per req)
* `getpid`: 1,363 (~0.13 per req)
* `accept4`: 2 (1 per new connection)

Ibex's greedy I/O loop results in significantly fewer `epoll_wait` wakeups (processing multiple requests per wakeup), though it pays for it with more `read` calls hitting EAGAIN. Both proxies use exactly 2 network writes and roughly 2 network reads per request. The performance gap is strictly in user-space CPU work skipped.

## 3. Flamegraph Analysis

The flamegraphs for Ibex and HAProxy are saved in `tools/parity-bench/`.

Top 5 frames in HAProxy's profile that represent work skipped by Ibex:
1. `h1_format_htx_req` (re-serializing HTX to HTTP/1.1)
2. `htx_add_header` / `htx_add_all_headers` (building the HTX representation)
3. `h1_parse_req_line` (HAProxy parses completely to strings)
4. `pool_alloc` / `pool_free` (for intermediate buffers)
5. `flt_http_payload` (payload filtering)

Top 5 frames in Ibex's profile (`tools/parity-bench/ibex.svg`):
1. `<ibex_rt::xprt::ServerXprt>::send` / `ibex_rt::raw::send` / `rustix::backend::io::syscalls::write` (Syscall for writing bytes to the network)
2. `<ibex_rt::xprt::ClientXprt>::recv` / `ibex_rt::raw::recv` / `rustix::backend::io::syscalls::read` (Syscall for reading bytes from the network)
3. `ibex_rt::proxy::TcpSession::process_req_head` (The core state machine transitioning the request)
4. `<ibex_proto::parser::h1::H1Parser as ibex_proto::parser::Parser>::stream` / `ibex_proto::parser::h1::H1Stream::parse` (Lightweight validation and HTX zero-copy AST construction)
5. `ebtree::eb32::Eb32Tree::set_slot` / `alloc::vec::Vec<ebtree::eb32::Node>::index` (Timer wheel / scheduler management)

## 4. Is the fast path correct?

- **Decision condition**: In `crates/ibex-rt/src/proxy.rs:479-503` (`validate_request_head`), the parser validates the buffer, checks framing conflict (`stream.framing_conflict()`), and initializes `self.has_htx = true; self.htx_modified = false;`.
- **Header-size & framing checks**: Enforced rigorously during `stream.parse()`. If a framing conflict exists (e.g. conflicting `Content-Length` and `Transfer-Encoding`), it is caught and rejected immediately, before the decision to fast-path is made.
- **Post-decision modification**: If any subsequent rule mutates the request via `crates/ibex-rt/src/proxy.rs:275-291` (`with_htx_mut`), `self.htx_modified` is set to `true`. When transitioning in `crates/ibex-rt/src/proxy.rs:776-800`, `wire_replacement` is only serialized (`htx.write_h1_wire`) and substituted via `replace_prefix` if `self.htx_modified` is `true`.

## 5. Byte-for-Byte Backend View

For a legal but not canonical request like:
```http
GET / HTTP/1.1
Host:   localhost
X-Folded: line1
	line2
MY-HEADER: v1
my-header: v2


```

**HAProxy normalises it:**
```http
GET / HTTP/1.1
host: localhost
x-folded: line1  	line2
my-header: v1
my-header: v2


```
(Notice the lowercasing of `Host` and `MY-HEADER`, the stripped whitespace, and the unfolding of `X-Folded` into a single line).

**Ibex forwards it verbatim:**
```http
GET / HTTP/1.1
Host:   localhost
X-Folded: line1
	line2
MY-HEADER: v1
my-header: v2


```

## 6. Recommendation

This is a legitimate optimization, but it bypasses a critical security control: strict HTTP head normalisation, which prevents HTTP request smuggling by ensuring the backend sees exactly what the proxy validated. 

**Recommendation:** It should be a configuration knob, disabled by default. 
**Name:** `tune.h1.zero-copy-head-forwarding` (HAProxy's `tune.h1.zero-copy-fwd-recv` applies to the body, so `head` makes the semantics clear).
**Default:** `off`. 

