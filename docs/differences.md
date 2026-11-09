# Where Alcyon differs from HAProxy

What an operator can see: HAProxy 3.5-dev8-885761-29 does one thing, Alcyon does another or
refuses. Each entry says what to do instead.

## `userlist`: hashed passwords (`user <u> password <hash>`)

HAProxy hands the hash to glibc `crypt(3)`. Alcyon has no `crypt(3)` (it needs `unsafe` or a C
library) and verifies the formats it can in safe Rust, with the `alcyon-crypt` crate.

| format | prefix | HAProxy (glibc) | Alcyon |
|---|---|---|---|
| MD5-crypt | `$1$` | verifies | verifies |
| SHA-256-crypt | `$5$` (`rounds=1000..999999999`) | verifies | verifies |
| SHA-512-crypt | `$6$` (`rounds=1000..999999999`) | verifies | verifies |
| bcrypt | `$2a$`, `$2b$`, `$2y$` (cost 04..31) | verifies | verifies |
| bcrypt, buggy 2x variant | `$2x$` | verifies | refused at load, names the format |
| yescrypt | `$y$` | verifies (warns it takes ~25 ms) | refused at load, names the format |
| DES, BSDi extended DES | `ab...`, `_...` | verifies | refused at load, names the format |
| SunMD5, sha1crypt, NT-hash | `$md5$`, `$sha1$`, `$3$` | verifies | refused at load, names the format |
| anything glibc refuses (unknown id, malformed salt, rounds out of range, ...) | | alert "not supported by crypt(3)" | the same alert |

Refused at load, the message is
`the encrypted password used for user 'u' is in the yescrypt ($y$) format, which Alcyon cannot verify
(it verifies $1$, $5$, $6$, $2a$, $2b$ and $2y$); rehash it with one of those or use 'insecure-password'.`
Rehash with `mkpasswd -m sha-512` (or `openssl passwd -6`), `mkpasswd -m bcrypt` or
`htpasswd -B`.

Same as HAProxy:

- the hash is recomputed on every request that carries an `Authorization: Basic` header for a
  user of the list; nothing is cached (HAProxy has no `tune.*` setting for it either), so the
  cost of the algorithm is paid per request, on the worker that serves it;
- at load, a hash that takes 10 ms or more to verify is warned about with HAProxy's text;
- a well formed setting whose hash part is cut short loads and never matches;
- the password is read as a C string (it ends at a NUL).

Measured here (release build, `secret`, one core): `$1$` 0.15 ms, `$5$` 0.5 ms, `$6$` default
5000 rounds 1.8 ms, `$6$rounds=100000` 35 ms, bcrypt cost 5 2 ms, cost 10 64 ms, cost 12 256 ms
(glibc `crypt`, process start included: 52 ms, 63 ms, 249 ms for the same three). A cost-12 bcrypt user blocks a
worker for a quarter of a second per request, in both; choose `$6$` with default rounds or
bcrypt at cost 5 to 8 for a hash on the request path.

Known gap against glibc: the characters allowed in a `$1$`/`$5$`/`$6$` salt were measured on a
sample (`:`, space and non-ASCII bytes are refused by glibc, printable ASCII else is accepted);
Alcyon applies that rule and has not been compared on every byte. The 900 verdicts of
`crates/alcyon-crypt/tests/vectors.txt` (salts, rounds, password lengths, malformed settings) agree
with glibc.

## Regular expressions

HAProxy compiles every regular expression with PCRE2 (or the C library's POSIX regex).
Alcyon is memory-safe Rust and links no C regex library, by decision (T154, 2026-10-04):
`pcre2` and its C bindings are out. Alcyon compiles a pattern with the `regex` crate first and,
only when `regex` refuses it, with the pure-Rust `fancy-regex` crate (crate `alcyon-regex`,
type `UserRegex`). An ordinary pattern keeps `regex`'s guarantee of matching in time linear in
the input and costs what it did before; a pattern with a PCRE-only feature is slower and can
backtrack. This covers every place a configuration regex is used: ACL `-m reg` and the `*_reg`
fetches, `replace-header`, `replace-value`, `replace-path`, `replace-pathq`, `replace-uri`,
`map_reg`, `map_regm`, `regsub`, `http-check expect rstring`/`rstatus`, `reqrep`-style rewrites.

### What works (`fancy-regex`)

Look-ahead and look-behind (`(?=..)`, `(?!..)`, `(?<=..)`, `(?<!..)`), back-references (`\1`,
`\k<name>`, `(?P=name)`, `\g1`), atomic groups (`(?>..)`), possessive quantifiers (`a++`,
`a*+`, `a?+`, `a{1,2}+`), named groups (`(?<n>..)`, `(?P<n>..)`), inline flags (`(?i)`,
`(?s)`, `(?m)`, `(?x)`), conditionals (`(?(1)a|b)`), `\K`, `\G`, `\Z`, `\h`, `\R`, `\N`.
Each of the first group was measured on HAProxy and is a test in
`crates/alcyon-rt/tests/it/pcre_regex.rs`, in an ACL, in `replace-header` and in `regsub`.

### What is refused at load

A pattern with a PCRE feature `fancy-regex` lacks is refused when the configuration is read
(`alcyon -c` fails; HAProxy accepts all of these), with a message that names the feature:

```
bad regular expression <(?R)>: PCRE feature not supported by Alcyon: recursion and subroutine calls (see docs/differences.md)
```

- recursion and subroutine calls: `(?R)`, `(?1)`, `(?-1)`, `(?+1)`, `(?&name)`, `(?P>name)`, `\g<n>`, `\g'n'` (and `\gN`, which `fancy-regex` would compile as a call, not a back-reference),
- callouts `(?C)`,
- the conditions `(?(R)..)`, `(?(R1)..)`, `(?(R&name)..)`, `(?(VERSION>=10)..)`, and a condition on a
  bare group name `(?(name)..)` (write `(?(<name>)..)`): `fancy-regex` would read each as "this
  text matches here", not as PCRE2's test (T277),
- branch reset groups `(?|..)`,
- `\X` (extended grapheme cluster),
- `\Q..\E` literal quoting,
- the other escapes `fancy-regex` does not parse, refused with its own "unrecognized escape
  sequence": `\g{n}`, `\cX`, `\o{..}`, an octal `\012`, the `(?J)` flag and `(*VERB)` start-of-pattern
  options such as `(*UTF8)`.

Some Unicode properties (`\p{..}` scripts and categories) are those of the `regex` crate's
tables, not PCRE2's; a name PCRE2 knows and `regex` does not is refused as a syntax error.

An ACL pattern is now checked at load too, in `acl` lines and in inline `{ ... }` terms
(before T154 an inline ACL with a bad regex loaded and never matched).

A conditional on a group the pattern does not have, `(?(2))` with no group 2 or `(?(0)..)`, is
refused as PCRE2 refuses it ("reference to non-existent subpattern"): `fancy-regex` 0.19.2
compiles it and then panics at the first match, which aborted Alcyon before T277. So are the
keys of a `map_reg`/`map_regm` file, at load, and `add map`/`add acl` on the CLI.

### Unnamed groups in ACL, `map_reg` and health-check regexes

HAProxy compiles the regex of an ACL (`-m reg`, `*_reg`, pattern files, `add acl`), of
`map_reg` (file and `add map`) and of `http-check expect rstring`/`rstatus` and `tcp-check
expect rstring` with PCRE2_NO_AUTO_CAPTURE: only a named group captures and has a number. Alcyon
does the same (T274 J2): `(a)\1`, `((a))\2`, `(a)(?<n>b)\2` and `(a)(?(1)b|c)` are refused
with `reference to non-existent subpattern`, `(?<n>a)\1` is a reference to `n`, and
`(a)(?<n>b)\1` refers to `n` too. `map_regm`, `replace-header`, `replace-value`,
`replace-path`, `replace-uri` and `regsub` number every group, as in HAProxy. The refusal
carries PCRE2's `erroffset` on the CLI (`add acl`, `add map`): just past the `\N`, or at the
inner `(` of `(?(N)`.

At load, every regex refusal is worded `bad regular expression <re>: <why>` where HAProxy
says `regex '<re>' is invalid (error=<why>, erroffset=<n>)`, and carries no offset (T287).

### Regexes PCRE2 refuses

Alcyon refuses, with PCRE2's text and `erroffset` (CLI), a quantifier after a quantifier
(`a**`, `a{2}{3}`; `a*+`, `a*?` stay valid) or after an anchor or option setting (`^*`,
`\b+`, `(?i)*`), `{n,m}` out of order or above 65535, an unknown POSIX class
(`[[:foo:]]`), a collating element (`[[.a.]]`) and a group name used twice (T287). Remaining
differences, measured on HAProxy 3.5-dev8-885761-29:

* PCRE2 refuses an unbounded look-behind (`(?<=a*)b`, "length of lookbehind assertion is
  not limited"); Alcyon runs it.
* PCRE2 accepts a quantified look-ahead (`(?=a)+`, `(?!a){2}`) and `(?J)` duplicate names;
  `fancy-regex` refuses both.

### Map value types

A `map_<in>_int` or `map_<in>_ip` converter checks its file's values at load (`unable to
parse '<v>' at line <n> of file '<f>'.`), and `add map`, `set map` and a payload line check
the value (`unable to parse '<v>'.`) as HAProxy does (T287).

### The CLI command line

Every command line is cut into words as `cli_parse_request` does: `\\` is a backslash, a
backslash before another character (a blank included) is dropped and the character kept,
there is no quoting. `set var` needs `experimental-mode on` (T287). Payload lines of `add map
<<` are taken as written.

### The backtrack limit

A `fancy-regex` match runs under a limit of 1,000,000 backtracking steps
(`alcyon_regex::BACKTRACK_LIMIT`). A match that exceeds it is a non-match, silently: nothing is
logged per request. This is HAProxy's outcome, measured with `^/(a+)+(?=$)` against
`/aaaa...ab` (28, 48, 100 and 3000 `a`): PCRE2 gives up and the ACL does not match. Alcyon
answers in about 15 ms in a debug build, whatever the length. The limit bounds the cost of a
hostile request, not the answer a legitimate pattern gets: a pattern that needs more than a
million steps on a real header is a pattern to rewrite.

The plain pattern `^/(a+)+$`, with no PCRE-only feature, is not backtracking at all on Alcyon
(it runs in `regex`, linear time) and gives the answer PCRE2 gives.

## `use_backend` with a log-format name

`use_backend %[req.hdr(x)]` (a backend name built per request) is refused at load with
`'use_backend' with a log-format backend name is not implemented by Alcyon`. HAProxy accepts
it, skips the rule when the built name is no backend, and does not check the name at load.
`use-server` with a log-format server name is refused the same way. Name the backends in
`use_backend ... if` rules instead.

## Out of Milestone 1 scope: refused at load (T164)

These are refused by the parser with `'<keyword>' is not supported by Alcyon (out of scope, see
docs/differences.md)`, so a configuration that relies on one fails to load instead of running
without it. HAProxy accepts them (when built with the feature).

| family | refused keywords |
|---|---|
| Lua | `lua-load`, `lua-load-per-thread`, `lua-prepend-path`, `tune.lua.*`, `http-request` / `http-response` actions `lua.<name>`, `tcp-request ... lua.<name>` ("lua actions require Lua support"), `lua.<name>` fetches and converters in `%[...]`, `use-service` as a section keyword and `tcp-request content use-service` (`http-request use-service prometheus-exporter` works, see below) |
| SPOE and filters | `filter spoe`, `filter compression`, any `filter` line |
| Compression | `compression algo/type/offload/...` |
| Peers | `peers` sections, `stick-table ... peers <name>` |
| Cache | `cache` sections, `http-request cache-use`, `http-response cache-store` |
| FastCGI | `fcgi-app` sections, `use-fcgi-app`; `server ... proto fcgi` is refused too |
| OpenSSL-only | `ssl-engine`, `ssl-mode-async`, `ssl-propquery`, `ssl-provider`, `ssl-provider-path`, `tune.ssl.async` |

Not refused, on purpose:

- QUIC / HTTP/3 (`quic4@`, `quic6@`, `proto quic`, `alpn h3`): Alcyon has a QUIC listener
  (`alcyon-quic`, exercised by `crates/alcyon-config/tests/it/quic_bind.rs`); it is experimental.
  The reference HAProxy binary here is built without QUIC and refuses these.
- `resolvers` sections: parsed and checked as HAProxy does (T483), and a server whose address is a
  name and that has `resolvers` (or inherits it from `default-server`) is re-resolved at run time
  as HAProxy does it (T484): one query every `timeout resolve` whatever the TTL, retries, the
  `hold` timers, `MAINT (resolution)`, the address swaps and their log lines, `resolve-prefer`,
  `resolve-net`, `resolve-opts allow-dup-ip|prevent-dup-ip`, a layer-4 check timeout asking for a
  resolution. Families are HAProxy's default `dns-accept-family auto` (AAAA only while the host
  has an IPv6 route, re-probed every 30 s). Differences: every section runs on worker 0 (with the
  health checks; HAProxy spreads them over threads); a forged or malformed reply never ends a
  resolution early (the honest answer is still taken); only a layer-4 timeout of a check, not a
  refused connect, triggers a resolution. `server-template <prefix> <n|lo-hi> <name>[:port]` expands to servers `<prefix><n>` that share one resolution (T486); `from none` is accepted, `from be:`/`from srv:` are refused, and a parameter error names `server <slot>` where HAProxy says `server-template <px>/<prefix>`. An SRV name (`_...`, T487) is
  queried as SRV: its records fill the slots in HAProxy's key order (target, port, weight
  `(w + 255) / 256` unless `resolve-opts ignore-weight`, the address from an additional record or
  else an A/AAAA resolution per target), `hold obsolete` removes a record that is gone, and
  `show servers state` reports `srv_fqdn`, `srv_port` and `srvrecord`. Not measured against the
  oracle: a truncated SRV answer over UDP (`allow_truncated_srv`). `dns-accept-family ipv4|ipv6|auto[,...]`, `parse-resolv-conf` (the `nameserver` lines of
  `/etc/resolv.conf` where it stands, HAProxy's warnings), `set server <b>/<s> fqdn` and
  `http-request` / `tcp-request content` `do-resolve` are built (T489). `do-resolve`: a hit in
  the worker's cache costs no lock and no allocation; a miss asks worker 0 (which owns the
  sections) through the mailbox and the stream waits; a server resolution of the same name
  younger than `hold valid` answers it, as in HAProxy. The cache is per worker (HAProxy's is the
  resolution itself, shared), bounded by the Alcyon-only `tune.resolvers.cache-size` (default
  1024 entries, about 290 KB a worker, allocated by the first `do-resolve` a worker runs); a
  stream waits at most 30 s for an answer worker 0 never sent. `tcp-request content
  do-resolve` waits only within the `inspect-delay` (as HAProxy, which asks nothing without
  one) and runs the rules before it again while it waits. `set server fqdn` on a server written
  as an address takes the default `resolve-*` options; its `srv_admin_state` shows 64 once the
  section takes the new name (HAProxy: at the next answer). Still refused: the address
  prefixes `mptcp@`, `unix@`, `abns@`, `quic4@`... on a `nameserver`. TCP is done (T488): a
  truncated UDP answer is asked again over TCP to the same nameserver at once (one connection per
  nameserver, opened by the first query, four queries in flight, closed after 5 s idle); `tcp@`,
  `tcp4@`, `tcp6@`, `stream+` send everything over TCP; `udp@`, `udp4@`, `udp6@`, `dgram+` are UDP
  without fallback. The queries of a TCP connection are numbered 1, 2, 3 as in HAProxy (T489). A
  TCP port nobody listens on is not a `snd_error` (measured: the queries count `sent`, the
  resolution times out), as in HAProxy. HAProxy also
  creates an implicit `default` section (from `/etc/resolv.conf`, used by its httpclient); Alcyon has
  no httpclient and does not (user, 2026-10-25). `show resolvers` (T485) therefore lacks the block
  HAProxy 3.5-dev8 ends with, even for a configuration with no `resolvers` section at all:
  `Resolvers section default` / ` nameserver 127.0.0.53:` and the sixteen counters at 0 (the first
  `nameserver` of `/etc/resolv.conf`; `show stat domain resolvers` has the row `127.0.0.53,default,0,...`).
  With no section Alcyon prints `No resolvers found` (HAProxy never does). The counters are the
  sixteen of `show resolvers` per nameserver, bumped where `resolv_process_responses` bumps them,
  also readable as `haproxy_resolver_<counter>{resolver=,nameserver=}` (the name `send_error` for
  `snd_error`; scrape with `scope=resolver`; the reference binary here has no exporter, so the
  names come from `resolvers.c:104`). `cname` and `timeout` stay 0 (HAProxy never bumps them
  either), `tcp_fallback` counts the TCP queries sent after a truncated UDP answer (T488). Not done: `show stat domain resolvers` (typed rows) and
  `show resolvers` in `help`.
- A name on a `server` line is resolved by libc while the configuration loads, as HAProxy does
  (`localhost` is the first answer of `getaddrinfo`, `::1` on most hosts, no longer `127.0.0.1`),
  and `init-addr last|libc|none|<ip>` is applied in order; `last` (and so the default
  `last,libc`) is the `srv_addr` of the server's line in its server-state file (T490), read while
  the configuration loads. When the load then fails on an address, HAProxy has already printed
  the state file's own messages ("Can't open ...") and Alcyon has not; when it does not fail, Alcyon
  prints the `init-addr` notices before them, HAProxy after. A server that starts without an address (`init-addr none`)
  shows `srv_admin_state 32`; after `disable server` HAProxy shows 33 and Alcyon still 32 (Alcyon keeps
  one admin state per server, not HAProxy's flags), and in both it stays in `MAINT (resolution)`.
  `-dr` appends `none`, as in HAProxy.

## Logs and `show stat` (T165)

Same as HAProxy (measured, 3.5-dev8-885761-29): `option httplog`, `httpslog`, `tcplog` and the default format (one `Connect from` line per connection) byte for byte except timings; a datagram or line ends with one line feed that `len` counts; `show stat` frontend, backend and server rows for `status scur stot bin bout dreq ereq econ eresp wretr wredis weight act bck chkfail chkdown lastchg downtime qcur rate rate_max hrsp_* req_tot lbtot cli_abrt srv_abrt lastsess qtime ctime rtime ttime *_max mode`.

Different, and what to do instead:

| what | HAProxy | Alcyon |
|---|---|---|
| `fc_err` (in `option httpslog`) | the connection error code (48 for a client that reset) | always `0` |
| `ssl_c_err`, `ssl_c_ca_err`, `ssl_fc_err` | the verify error and the last TLS error | `0` on a TLS connection, no sample otherwise |
| `show stat` `h1_*`, `h2_*`, `ssl_*`, `connect`, `reuse`, `srv_icur`, `idle_conn_cur`, `req_rate` windows, `agg_*`, `reqbin`.. | filled | empty (not counted) |
| `smax` of a server or backend | the peak when a stream started | the peak seen when a stream ended (the same for a request that overlaps another, never above it) |
| `show info` `CumConns`, `CumReq` | count the CLI connection too | do not |
| `log` to a unix datagram socket | works | works (`unix@/path`, `/path`, `unix@@abstract`); not compared with HAProxy, whose `sendmsg()` to a socket bound in the test failed with ENOENT |
| a client that closes during the TLS handshake | session gone at once | counted in `scur` until its timeout (found, not fixed) |
| `%fi`, `Connect from ... to` on a wildcard bind | the accepted socket's address | the listener's configured address |

## TLS handshake failures: what is not matched (T272B)

Measured on HAProxy 3.5-dev8-885761-29; pinned in `crates/alcyon-rt/tests/tls_handshake_log.rs`.

- Frontend `smax` after probes that fail the handshake: HAProxy reports 1 to 6 for the same
  sequential probes, run after run, so it is not a concurrency maximum there (it looks like a
  sum over threads). Alcyon reports the real maximum of concurrent sessions: 1 at most, since a
  failed handshake never makes a session.
- `strict-sni` is refused at load (HAProxy answers a ClientHello with no or an unknown SNI with
  alert `unrecognized_name` and logs `callback failed`). Implementing it needs the certificate
  resolver to refuse instead of falling back to the default certificate: a feature, not scheduled.
- Whether a client that leaves mid-handshake is `Connection closed during SSL handshake` or a
  bare `SSL handshake failure` depends in HAProxy on whether the FIN came with the bytes or
  alone. Alcyon follows the same rule (a whole handshake record read, then a FIN in a read of its
  own, not queued behind the data at `MSG_PEEK` time) and so can differ from HAProxy on a
  race between the two.

## An IP address as the SNI to a server is not sent (T538)

In `mode http` the automatic SNI of an `ssl` server is the Host header without its port
(`req.hdr(host),field(1,:)`); for Host `127.0.0.1:8080` that is `127.0.0.1`. HAProxy (OpenSSL)
sends it in the ClientHello, which RFC 6066 does not allow; rustls sends no SNI for an address,
so the server sees none (`ssl_fc_sni` empty) and picks its default certificate. The connection
is still keyed by `127.0.0.1` for reuse, as HAProxy keys it (a Host `127.0.0.2` does not share
it). Measured on HAProxy 3.5-dev8-885761-29; pinned in `crates/alcyon-rt/tests/it/server_tls.rs`
(`a_tls_connection_whose_sni_is_an_ip_address_*`).

## HTTP/2 to servers: one stream per connection (T540)

`server ... proto h2` (h2c, and h2 over `ssl` whatever ALPN selects) and `ssl alpn h2` /
`alpn h2,http/1.1` (h2 when the server selects it) speak HTTP/2 through
`alcyon_proto::h2_srv::H2SrvCodec`, one stream at a time per server connection, which is
HAProxy's behaviour under the default `http-reuse safe` (an h2 server connection private to its
client session: 26 connections for 26 client sessions, T533 A.3 row 6). Measured on HAProxy
3.5-dev8-885761-29; pinned in `crates/alcyon-rt/tests/it/server_h2.rs`. Where it differs:

- Under `aggressive` / `always` HAProxy multiplexes concurrent requests as streams of one
  connection (A.3 row 7: 20 concurrent requests on 1 connection); Alcyon opens one connection
  per concurrent request (sequential requests share one, as HAProxy's).
- A refused stream (REFUSED_STREAM, a GOAWAY whose last id is below the stream) under `retry-on
  all-retryable-errors`: HAProxy retries it on the same connection while it lives (measured: 3
  retries on one connection, then 502 `SH--`); Alcyon retries on a new connection each time (its
  L7 retry closes the server connection). With `retry-on empty-response` both retry once on a
  new connection; without, both answer 502 `SH--`. `retry-on refused-stream` does not exist in
  dev8 (refused there too).
- A GOAWAY whose last id is below the stream in progress: HAProxy waits for `timeout server` (504
  `sH--`); Alcyon ends the stream at once (502 `SH--`, retryable as above).
- An HTTP check request without a Host (`option httpchk GET /`) goes without `:authority`, as
  HAProxy's: a server that requires one (nghttpd) refuses it, `SOCKERR` in both.
- `%B` of an h2 response follows HAProxy's HTX count (no reason phrase; the `transfer-encoding:
  chunked` written for a response without a length counts 25 bytes less), measured equal for
  bodies of 2, 19, 1000 and 40000 bytes.
- CONNECT to an h2 server: HAProxy tunnels it; Alcyon's codec refuses it, 502, no stream opened
  (CONNECT and WebSocket to h2 servers: T548).

## `tune.maxaccept`: the default is no limit (T295)

`tune.maxaccept <n>` is accepted and applied: one listener wakeup accepts at most `n`
connections in a row (`-1`: no limit; `0` or a non-number: the default, as `atol` gives
HAProxy). HAProxy's default is `MAX_ACCEPT`, 4, after which its thread goes on to its other
work and the connections left in the backlog wait for the next poll. Alcyon's default is no
limit: its listener is polled level-triggered and an accept loop drains the backlog it finds,
which is what every measurement so far was made with. Set `tune.maxaccept 4` to get
HAProxy's behaviour.

## Chunked bodies: chunks are not merged (T302)

Like HAProxy, Alcyon forwards a chunked body (either way) with each chunk-size line rewritten:
the extension and blanks dropped, the size in upper-case hex without leading zeros (`0005;a=b`
goes out as `5`, `a` as `A`). HAProxy also merges the chunks it holds in its buffer at once
into one (`A` and `3` received in one read go out as `D`); Alcyon keeps the chunks as received.
Which chunks HAProxy merges depends on how the bytes arrive, and the payload is the same.

## Slow clients (slowloris) and timeouts (T349)

Measured live on 2026-10-17 (main e517536b vs HAProxy 3.5-dev8, timeouts of 1-3 s, raw-socket
clients; scripts in T349). Open items are tracked in `tasks/T349-slow-client-defences.md`.

**The same on both:**
- HTTP/1: `timeout http-request` (408 and close, counted from the first byte of each
  request), the fall-back to `timeout client` when it is unset, and `timeout http-keep-alive`.
- `http-request tarpit` with `timeout tarpit` and `deny_status`.
- `tcp-request connection reject`.
- `http-request wait-for-body` and `option http-buffer-request`: same timing.
- Global and frontend `maxconn`.
- Stick-table per-source limits (`track-sc0 src` with `sc_conn_cur`, `sc_conn_rate`,
  `sc_http_req_rate`, `sc_http_err_rate`, `src_conn_cur`).
- `timeout queue`, `tune.h2.fe.max-concurrent-streams`, `option http-ignore-probes` and
  `option dontlognull`.
- A slow reader is cut by `timeout client`.

**A request body sent slowly is not cut by `timeout http-request` on either proxy.** That
timeout ends with the request head. To close a client that trickles its body, use
`http-request wait-for-body time <t>` or `option http-buffer-request` (both work in Alcyon, as
in HAProxy).

| | HAProxy | Alcyon | what to do |
|---|---|---|---|
| `maxconnrate`, `maxsessrate` (global), `rate-limit sessions` (frontend) | accepted | **refused at load** (unknown keyword) | limit per source with a stick table (`sc_conn_rate`) until implemented (T349) |
| `timeout client-fin` | accepted | **refused at load** | remove it; half-closed clients wait for `timeout client` (T349) |
| Idle HTTP/2 connection after a request | GOAWAY after `timeout http-keep-alive` (else `http-request`, else `client`) | GOAWAY after `timeout client` only: an idle h2 connection lives longer (5.7 s vs 1.7 s with client 6s, http-request 4s, keep-alive 2s) | set `timeout client` close to the keep-alive you want for h2 until fixed (T349) |
| `tcp-request inspect-delay` + `tcp-request content accept if { req.proto_http }` (or `req.len`, `req.payload`) when the first segment is short | waits for more data up to the inspect delay | **decides on the partial data and resets at once** | avoid content rules that need the whole head on slow links until fixed (T349) |
| A content `reject` after the inspect delay | FIN after the inspect delay | RST at once | (T349) |
| h2 HEADERS without END_HEADERS at `timeout http-request` | GOAWAY, then close | close without GOAWAY | none needed |
| After a `wait-for-body` 408 | keeps the connection | closes it | none needed |
| Stalled HTTP/1 upload | 400 at 2x `timeout client` | 400 at 1x `timeout client` (stricter) (VV-9) | none needed |
| TLS handshake that stalls | `timeout client` only | also `timeout http-request` (stricter) | none needed |
| h2 connection that never sends a request | GOAWAY at `timeout http-request` | close at `timeout http-request` without GOAWAY | none needed |

## `http-request normalize-uri` (T358, T359)

All eight normalizers give HAProxy's answers on the paths measured (`path-strip-dot` and
`path-strip-dotdot`, with and without `full`, on 1451 paths since T359g, 2026-10-17). Each takes
only its own option, with HAProxy's message for any other word. An unknown normalizer is
refused, as HAProxy does. Alcyon does not yet require `expose-experimental-directives` for
`normalize-uri` (HAProxy 3.5 does).

## `listen()` backlog: the `bind` option `maxconn` is refused (T360)

The backlog of a bind follows HAProxy's `listener_backlog()`: the bind's `backlog`, else the
proxy's `backlog` (frontend, listen or defaults), else the proxy's `maxconn` (the global one
when the proxy sets none), else 1024, capped by `net.core.somaxconn`. The one step Alcyon does
not have is the `bind` option `maxconn` (between the proxy's `backlog` and its `maxconn`
in HAProxy): `bind ... maxconn N` is refused at load, as before. A socket handed over by a
reload keeps the backlog it was bound with, as in HAProxy.

## `tune.alcyon.zero-buffers on|off`: an Alcyon-only global keyword (T437 5b)

When a buffer goes back to its pool (or is freed), Alcyon overwrites the bytes that were written to
it (up to a per-buffer high-water mark, not the whole 16 KB) with zeros, so the plaintext of one
connection is not what the next one is handed, and a core dump or a memory-disclosure bug finds
less. The overwrite is a `zeroize` write the compiler may not remove. Default **off** (since S1,
2026-10-24: Alcyon's per-request safety extras stay off while it is compared with HAProxy; `on`
costs ~840 instructions per request on a rules benchmark). HAProxy has no such setting (its pools
keep stale bytes; `-dM` poisoning is a debug option) and refuses the keyword as unknown. It takes
exactly `on` or `off`; anything else, or a missing argument, is a configuration error. Limits:
bytes written through `Buf::writable()` and never committed are not tracked, and buffers owned by
rustls itself are not Alcyon's to overwrite. The TLS record buffers (plaintext and ciphertext,
`rx_raw`/`tx_raw` included) are not covered by this setting: they have their own
`tune.alcyon.ssl-zero-buffers` (default on, below).

## `tune.alcyon.ssl-zero-buffers on|on-free|off`: an Alcyon-only global keyword (S2)

When a TLS connection ends, Alcyon overwrites the whole capacity of its TLS record buffers (the
ciphertext read from and written to the socket, and the plaintext decrypted from it) with zeros,
so session data does not stay in freed memory. Default **on** (user decision 2026-10-24: TLS keys
and plaintext are a real target); `off` leaves them as HAProxy does. The plain I/O buffers
follow `tune.alcyon.zero-buffers` (default off) instead. HAProxy 3.5-dev8 refuses the keyword as
unknown. It takes exactly `on`, `on-free` or `off`; anything else, or a missing argument, is a
configuration error. Limits: key material inside rustls/ring is not covered (`tradeoff.md` 6.27).

`on-free` (T553) keeps everything above except one wipe: the pooled TLS send buffer (`tls_tx`,
ciphertext already on the wire) is no longer zeroed each time a response has been written and the
buffer goes back to its pool, but when the pool really frees it (trim, memory budget, thread exit,
stop). In between, a thread's idle chunk carries the previous connection's ciphertext until the
next one overwrites it. Only ciphertext, never read past its length by safe Rust; visible in a core
dump or through a memory-disclosure defect. It saves about 1 instruction per 18 bytes of response
(`tradeoff.md` 6.32). The default stays `on`.

## `tune.alcyon.h3-path relay|mux`: an Alcyon-only global keyword (T509, temporary)

Which path an HTTP/3 request stream takes into the stream engine while the h3 mux is being
brought in (`docs/design/h3-engine-2026-10-26.md`, slices H3a to H5): `mux` (the default since
T536) makes each QUIC connection an owner session whose request streams are children served
through the same bridge as HTTP/2 streams; `relay` is the HTTP/1 relay over a socket pair.
Unset, the environment variable `ALCYON_H3_PATH` (`mux` or `relay`) decides, then `mux`, so the
h3 tests run on either path. HAProxy refuses the keyword as unknown. It takes exactly `relay` or `mux`. The keyword is
deleted with the relay (slice H5).

## `tune.alcyon.quic-ack-frequency on|off` and two parameters: Alcyon-only global keywords (Q0)

`on` (default `off`) makes the server send an ACK_FREQUENCY frame (draft-ietf-quic-ack-frequency) to
a QUIC peer that advertises `min_ack_delay`, asking it to acknowledge less often so fewer ACK-only
datagrams arrive. `tune.alcyon.quic-ack-frequency-threshold <n>` (0 to 255, default 2) is how many
ack-eliciting packets the peer may receive before it acknowledges at once;
`tune.alcyon.quic-ack-frequency-max-delay <time>` (1ms to 16383ms, default 25ms) is how long it may
delay an acknowledgement. A value out of range is refused at parse time. It only asks the peer: a
hostile client can ignore it, so it is not ACK-flood protection by itself. Off, nothing is sent,
as HAProxy 3.5-dev10, which does not send ACK_FREQUENCY; HAProxy refuses all three keywords as unknown.

## QUIC peers that ignore ACK_FREQUENCY: `alcyon_fc_quic_ack_*`, `show quic alcyon-acks`, `QuicAck*` (T569)

Alcyon extensions; HAProxy 3.5-dev10 has no equivalent (it sends no ACK_FREQUENCY, and neither its
`quic_*` stats nor its fetches count a peer's ACK-only packets). Per QUIC connection, the vendored
quinn-proto counts (`AckStats`, vendor change 8) the ack-eliciting 1-RTT packets sent, the 1-RTT
packets received with an ACK frame and nothing ack-eliciting ("ACK-only"), and, once the peer has
acknowledged an ACK_FREQUENCY frame (`tune.alcyon.quic-ack-frequency on` and a peer that advertises
`min_ack_delay`), the "excess": ACK-only packets that acknowledge at most the threshold's number of
new ack-eliciting packets, all sent after that frame, sooner than the requested `max_ack_delay`
(less 1 ms) after the first of them was sent, with no gap (a packet missing or acknowledged late,
which draft-ietf-quic-ack-frequency 6.2 lets the peer acknowledge at once) and none of them an
IMMEDIATE_ACK packet. Each of those would have let a compliant peer acknowledge; an ACK-only packet
none explains is one it should not have sent. The bar is lenient: ECN-CE marks (which also allow an
immediate ACK) are not seen, and are not needed as Alcyon sends no ECN. A peer that never acknowledged
an ACK_FREQUENCY frame is never judged: its excess has no value.

- Fetches, on an HTTP/3 stream (mux path; no sample elsewhere, the relay path included), as the
  stream's request head found them: `alcyon_fc_quic_ack_eliciting_sent`, `alcyon_fc_quic_ack_only_rcvd`,
  `alcyon_fc_quic_ack_ratio` (ACK-only received per 1000 ack-eliciting sent; no sample before one is
  sent), `alcyon_fc_quic_ack_excess` (no sample for a peer that is not judged). For example
  `http-request deny if { alcyon_fc_quic_ack_excess gt 100 }`, or `track-sc0` and a `gpc` on it.
- `show quic alcyon-acks [all|clo]`: the one-line head, then `ack_elic_sent ack_only_rcvd ratio_pm
  ackf_thr ackf_excess` per connection (`-` for a peer that is not judged).
- `show info`, with `tune.alcyon.quic-ack-frequency on` only (as the zero-on-free lines, not in
  `typed`/`json`): `QuicAckElicitingSent`, `QuicAckOnlyRcvd`, `QuicAckFreqExcess`, summed over
  the connections that ended (a live one's are in `show quic alcyon-acks`).

No setting closes a connection on these counts: a rule does it (`http-request deny`/`reject`).

## A QUIC connection a rule rejects is closed with `H3_NO_ERROR`, not transport `NO_ERROR` (T511)

`tcp-request connection reject` and `tcp-request session reject` on a QUIC bind (mux path)
close the connection with an application CONNECTION_CLOSE, code `H3_NO_ERROR` (0x100).
HAProxy 3.5-dev7 sends a transport CONNECTION_CLOSE with `NO_ERROR` (0x0). quinn-proto gives an
application no transport-level close; both tell the client the connection ended without an
error, and nothing is served either way. (With `tune.alcyon.h3-path relay` a session rule resets
the request stream with `H3_REQUEST_CANCELLED`, a 502 before T523: gone with the relay, slice H5.)

## HTTP/3 under the mux: interim responses, trailers and CONNECT (T520)

Measured on HAProxy 3.5-dev7 with QUIC (aioquic client) and, for h2, 3.5-dev8 (curl):

- **Interim responses (`100`, `103`) to an h3 client.** HAProxy 3.5-dev7 sends the interim
  HEADERS **with the FIN**, which ends the stream: the final response never arrives (`103`
  from the server, then `200`; `expect: 100-continue`). When the server's `103` and `200` come
  in one segment it aborts (`BUG_ON htx.c:391`, SIGILL). Both are an HAProxy 3.5-dev regression
  fixed upstream by 76454cbbf (in 3.5-dev8; 3.0/3.2 unaffected): a QUIC oracle from current master
  forwards `103` then `200` as Alcyon does. Alcyon (mux path) follows RFC 9114 4.1:
  an interim HEADERS without FIN, then the final response; both in one segment are forwarded.
  The relay path (the default until slice H5) drops interim responses and response trailers.
  `%B` of such a request: HAProxy counts the interim head (`B=119` for a 103 with one `link`
  field and a 2-byte `200`), Alcyon does not (`B=51`), on h2 and h3.
- **Interim responses to an h2 client** are forwarded as HAProxy does (they were dropped before).
- **Response trailers to an h3 client** (mux path): a chunked response's trailer section is one
  HEADERS frame after the DATA, with the FIN, as HAProxy; `%B` counts the trailer names and
  values as HAProxy. With `option http-drop-response-trailers` the data ends with the FIN as on
  HAProxy, but `%B` is smaller by the dropped fields (HAProxy counts them: they are in its HTX
  message when dropped; Alcyon cuts them from the buffer first). **Response trailers to an h2
  client are still not sent** (HAProxy sends them; known since T381).
- **CONNECT** under the mux is reset with `H3_REQUEST_REJECTED` (0x10b), extended CONNECT and a
  `te` other than `trailers` with `H3_MESSAGE_ERROR` (0x10e), the connection staying usable, as
  HAProxy. The relay answers a CONNECT with a 400 and no reset.

## The HTTP/3 relay has no connection timers (T521, until H5)

HAProxy 3.5-dev7 ends an HTTP/3 connection with a GOAWAY and `CONNECTION_CLOSE H3_NO_ERROR` at
`timeout http-request` from its start (no request yet) or from a partial head's stream start, and
at `timeout http-keep-alive` (else `http-request`) from the end of its last stream
(`qcc_refresh_timeout`). The mux path does the same (`h3_mux_drain.rs`). On the relay path (the
default) only quinn's 30 s transport idle timeout ends a connection that sends nothing or a
partial head (RV-16). Gone with the relay, slice H5.

## `tune.alcyon.zero-spares on|off`: an Alcyon-only global keyword (S1)

The header rules, samples and formats reuse per-thread spare strings and header lists (`show
pools` `spare_str`, `spare_list`, `scratch_str`, `scratch_bytes`). With `on`, a string's used
bytes (each string's, for a list) are overwritten with zeros when it is given back to its pool,
whether the pool keeps it or frees it, so an earlier request's cookie or `Authorization` value is
not left in memory. Default **off**: the wipe costs ~1k instructions per request on a rules
benchmark, and HAProxy wipes nothing either. HAProxy refuses the keyword as unknown. It takes
exactly `on` or `off`; anything else, or a missing argument, is a configuration error.

## `tune.alcyon.counters shared|per-thread`: an Alcyon-only global keyword (T582)

Who writes the counters a stream adds to when it ends (`hrsp_*`, `req_tot`, `stot`, `lbtot`,
`connect`, `reuse`, `bin`, `bout`, the aborts and errors, the timing sums, `lastsess`, the
session rate), for every frontend, backend and server. `shared` (default) is one set of relaxed
atomics written by every thread, as HAProxy's with one thread group. `per-thread` gives each
thread its own row per object, written without a locked instruction, and `show stat`, `show
info`, the stats page and the Prometheus exporter sum the rows: the totals read the same as
with `shared`. Two figures are not computed the same way when several threads serve one
object: `rate_max` of a backend or server is the sum of the threads' peaks (an upper bound
when the peaks were not simultaneous, exact with one thread, as `MaxConnRate`), and
`qtime`/`ctime`/`rtime`/`ttime` are the mean of the threads' running averages (each over the
thread's own requests, HAProxy's per-thread-group rule; exact with one thread). The rows are
made when each thread starts, (2 x proxies + servers + 2) x 208 bytes per thread (10,000
servers at 64 threads: ~128 MB); the start prints the size (`[NOTICE] tune.alcyon.counters
per-thread: ...`), `show pools` lists them as pool `counters`, and a thread that cannot have
them stops the start. `clear counters` works as with `shared`. `per-tgroup` is refused: Alcyon
runs one thread group, so it would be `shared` under another name. Read at start: a reload
applies a change. HAProxy refuses the keyword as unknown. Design:
`docs/design/per-thread-counters-2026-11-02.md`.

## `tune.alcyon.zero-on-free off|soft|hard`: an Alcyon-only global keyword (T459)

What the process's allocator does with every heap block that is freed (rustls and ring state,
Alcyon's own objects, std's): `off` (default) frees it as it is; `hard` overwrites it with zeros,
then frees it (the old block of a reallocation too); `soft` puts it on the freeing thread's
quarantine and wipes and frees it when the thread is idle, within bounds (at most 4 x
`tune.memory.hot-size` bytes per thread, at most ~100 ms, emptied by `pool_gc` and a refused
allocation; `tradeoff.md` 6.29). With `soft` or `hard`, `show info` ends with Alcyon-only lines
`ZeroOnFree`, `ZeroOnFreeBytes`, `ZeroOnFreeBlocks`, `ZeroOnFreeOldest_ms`, `ZeroOnFreeQueued`,
`ZeroOnFreeWiped`, `ZeroOnFreeForced`, `ZeroOnFreeExpired` (`typed` and `json` leave them out);
with `off` it is HAProxy's list. Pooled objects are not freed and follow their pools' settings
(`zero-buffers`, `zero-spares`, `ssl-zero-buffers`); the stack is not covered.

HAProxy 3.5-dev8 has no such setting and refuses the keyword as unknown. Its nearest options are
the `-dM` debugging forms (measured with `-dMhelp`): `-dM[<byte>]` fills objects with a byte on
*allocation* (`poison`, default byte `0x50`), `-dMintegrity` fills an object put in a thread cache
with a changing pattern and checks it on reuse, `-dMuaf` gives every pool object its own pages and
unmaps them on free, and `fail`, `no-merge`, `cold-first`, `no-global`, `no-cache`, `caller`,
`tag`, `backup` (and their `no-`/opposite forms) change caching and checks. They are debugging
aids for pool objects, not a wipe of freed memory, and `malloc`'d memory outside the pools is not
touched by any of them; OpenSSL wipes its own key material (`OPENSSL_cleanse`). Alcyon accepts
`-dMfail` and `-dMno-fail` only (S5) and refuses the other `-dM` forms. The keyword takes exactly
`off`, `soft` or `hard`; anything else, or a missing argument, is a configuration error.

## `tune.alcyon.crypto-provider ring|ring-alcyon`, `set ssl crypto-provider` and `show ssl crypto-provider`: Alcyon-only (T460)

The rustls crypto provider every TCP TLS configuration is built on: binds, server lines and
their health checks, TLS 1.2 and 1.3; and since T461 every QUIC bind, log-forward TLS bind and
ring TLS server, which are on rustls 0.24 too. `ring` (the default) is upstream ring through
`rustls-ring`; `ring-alcyon` is the vendored ring fork that wipes key material when it is freed
(`vendor/ringalcyon`, built with its `zeroize` feature on; what it wipes: `vendor/ringalcyon/ZEROIZE.md`,
`tradeoff.md` 6.27). Exactly one argument, `ring` or `ring-alcyon`; anything else is a configuration
error. HAProxy refuses the keyword as unknown.

The TLS binds of a `log-forward` section and the TLS servers of a `ring` section run on it too
since T461 (they were on rustls 0.23, and T460 refused `ring-alcyon` with them): every TLS user of
the process is on rustls 0.24 and the chosen provider, and nothing refuses `ring-alcyon`. Their
handshakes count in `show ssl crypto-provider`, and a swap reaches their new connections.

QUIC (T461): the handshake, the packet and header protection keys, and what quinn-proto took from
vanilla ring directly (the stateless reset tokens' HMAC, the address validation tokens' HKDF and
AES-256-GCM, the Retry integrity tag) all run on the chosen provider. A QUIC bind's TLS is the
same configuration as a TCP bind's of the same line, TLS 1.3 only, with its session tickets.

`show ssl crypto-provider` (CLI, admin level) prints the provider new handshakes use and the
handshakes completed on each provider since start, front and back, QUIC included:

    current ring
    provider ring handshakes 12
    provider ring-alcyon handshakes 0

`set ssl crypto-provider ring|ring-alcyon` (CLI, admin level) changes the provider at run time, for
the handshakes that start after it. Every TLS configuration (each `bind ... ssl`, each `server ...
ssl` and its checks) is built again on the new provider, reading its certificate, CA and CRL files
again; only once all of them are built is the new provider published, so a file that no longer
loads leaves everything as it was and the answer says `Crypto provider unchanged ('ring'): <the
error>`. A connection already open keeps the session and the provider it started with, and so does
the server connection of its session. A configuration keeps both builds once it has them: swapping
back reuses the configurations of startup. Session tickets and session IDs belong to one build (the
ticket keys come from the provider), so a client resuming a session from before the swap gets a
full handshake, not a failure. A QUIC connection takes its bind's build for the provider current
when its first Initial packet arrives, and keeps it. The endpoint's stateless reset and token keys
are its own random bytes, computed on the current provider: HMAC, HKDF and AES-GCM give the same
bytes on either, so a token or reset issued before a swap still verifies after it. The swap
lasts as long as the process: a reload starts the new process on the configured provider, and so
does a restart. HAProxy has no such command (switching
SSL libraries there means a new binary).

HAProxy's `ssl-provider`, `ssl-provider-path` and `ssl-propquery` load OpenSSL 3 providers
(additively, `configuration.txt` "ssl-provider"), which is not this: they stay refused as
OpenSSL-only (table above).

## `alcyon.watchdog-warn-only`: an Alcyon-only global keyword (T361)

HAProxy's watchdog warns about a thread that has stopped processing traffic and, once it has been stuck for a
second, aborts the process (exit status 134); no HAProxy keyword turns the abort off. Alcyon does the same by
default. `alcyon.watchdog-warn-only` (global, no argument; HAProxy refuses it as an unknown keyword) keeps the
warnings and `BlockedTrafficWarnings` and never aborts, for an operator who prefers a slow process to a restart.
The `alcyon.` prefix keeps it from clashing with a future HAProxy keyword.

## `tune.memory.hot-size`: the buffer floor is an Alcyon extension (S1, S2)

`tune.memory.hot-size <bytes>` (default 524288) parses as HAProxy parses it (`mem_parse_global_hot_size`:
one argument, `atol`, strictly positive) and bounds what each thread keeps in its pools together,
with HAProxy's rule: past 3/4 of it a pool evicts down while it holds more than its share, past
the whole of it the largest pools are evicted across (`pool_put_to_cache`,
`pool_evict_from_local_caches`). Two differences. **Floors**: each Alcyon pool declares a per-thread
floor that eviction never goes under, and floor objects do not count against `hot-size`; the three
buffer pools (`buffer`, `small_buffer`, `large_buffer`) have a floor of 64 per thread
(`crates/alcyon-rt/src/buf.rs`), where HAProxy's `minavail` is 2. The reason is measured:
at HAProxy's default, with 50 keep-alive connections of 16 KiB buffers on a thread, the budget
holds fewer buffers than the connections need and HAProxy mallocs about 0.5 buffer per request;
Alcyon with the floor makes none (`docs/design/memory-2026-10-24.md` 1.3, 3.3). Only `pool_gc`
(SIGQUIT, SIGTTOU, SIGUSR1, the stop path, a refused allocation) goes below a floor. **Eviction
order**: one object at a time, newest first, largest pool first across pools; HAProxy evicts
clusters of 8 oldest first from a per-thread LRU (`tradeoff.md` 6.28). `show pools` counts can lag
a busy thread by up to 10 ms (`tradeoff.md` 6.28).

## `tune.buffers.limit`, `tune.fail-alloc` and `-dMfail` / `-dMno-fail` (S5)

`tune.buffers.limit <n>` (parsed as HAProxy: one argument, `atoi`, not negative; 1 and 2 become 3,
0 is no limit) caps the standard buffers the process holds at once, cached ones included. A
stream refused its request buffer or the buffer for its server's response waits for one, as on
HAProxy (S6, `docs/design/memory-q3-2026-10-25.md`), in a per-thread queue by class (responses
under way before new connections, each queue first come first served) and is woken when a
buffer is given back on its thread; `timeout client` while waiting answers `408`, logged `cR--`,
as HAProxy. Differences that remain:

- `tune.buffers.reserve <n>` (S6b) makes `n` emergency buffers per thread at start and raises
  the limit by `nbthread` x `n`, as HAProxy; a take the pool refuses may have one by its class
  (`left * 3 >= q * n`: a local reply down to the last, a client's first buffer only while the
  reserve is full), and a buffer given back refills the reserve first. The default is HAProxy's
  4, but Alcyon makes the reserve only when `tune.buffers.limit` is set (without a limit its pool
  refuses only when memory is short, where the stream fails as in S5; HAProxy makes the 4 per
  thread always). At start HAProxy also fills the pool to its `minavail` (3): `limit 3` shows 7
  allocated from the start on HAProxy, 4 on Alcyon; both reach 7. Alcyon gates only the emergency take on the
  reserve; HAProxy also refuses a pool take of queues 1-3 while its reserve is not full enough.
- A thread's cache does not keep free buffers while another thread's streams wait: they go to
  the pool's shelf and the waiting thread is woken (S6b; HAProxy wakes waiters on the freeing
  thread only, and its caches keep theirs).
- The local reply and the TLS receive buffer wait like the others (S6b; HAProxy's TLS reads into
  OpenSSL's own memory, so its handshake needs no buffer at all). An HTTP/2 connection's and
  stream's buffers still fail as before the queue: 500 `IR--`/`IH--`, or a close.
- Each queue is served in order; HAProxy's own order was not (fast GETs answered 5, 4, 2, 1,
  0, 3 in one run), an artefact of retrying every woken waiter in one pass.
- Alcyon's CLI does not wait for a buffer; HAProxy's answers nothing while they are exhausted.
- HAProxy 3.5-dev8 hit `BUG_ON` `stconn.c:1027` (`tick_is_expired(task->expire, now_ms)`, in
  `sc_notify`) in 2 of 3 runs of a waiter that left with the CLI polling; Alcyon has no such path.

`tune.fail-alloc <0..100>` refuses that percentage of pool allocations at random, and, as on
HAProxy, counts only under `-dMfail` (`-dMfail` alone is a rate of 1). Alcyon honours exactly the
`-dM` forms `fail` and `no-fail` (comma-separated lists of only these are accepted); every other
form (`-dM`, `-dM<byte>`, `integrity`, `uaf`, `no-merge`, `cold-first`, ...) is refused at start
with `... -dM (memory pool debugging) is not supported, except -dMfail and -dMno-fail` and exit 1,
because Alcyon's pools are not malloc-per-object chunks to poison, tag or unmap
(`crates/alcyon-rt/src/bin/alcyon.rs`). Measured on 3.5-dev8 (400 requests, rate 5): a request gets
`200`, `500` with `IR--` or `IC--`, or a closed connection; Alcyon gives the same three (`IH--`
where HAProxy's refusal is of its server connection, `IC--`).

## `-m <megs>`: a connection budget and an rlimit, as on HAProxy

HAProxy's `-m` sets `RLIMIT_DATA` to `<megs>` MiB (soft and hard, `/proc/<pid>/limits`;
measured on 3.5-dev8, T453), shows the value as `Memmax_MB` / `Memmax_bytes` and sizes
`maxconn` from it (`STREAM_MAX_COST + 2 * tune.bufsize` per connection, 97% of the budget,
TLS costs when a `bind` or `server` uses `ssl`; a configured `maxconn` that leaves no room for
TLS is refused, exit 1). Past the limit its pools fail allocations and the streams that needed
them, and the process goes on. Alcyon does the same sizing and reporting and, since T465b, sets `RLIMIT_DATA` the same way.
Past the limit its buffers, sessions, timers and idle lists fail one stream or connection;
an allocation that is still infallible (rustls, h2, std) aborts the process (tradeoff.md 6.23,
6.25). Under `-m` the session arenas are presized for the budget rather than 65536 slots.
Differences left: Alcyon's per-connection cost is a constant calibrated on
HAProxy's results (`sizeof(struct stream)` has no Alcyon counterpart), `maxsslconn` and
`tune.ssl.cachesize` are not configurable, so `MaxSslConns` stays 0 and the
`Automatically setting global.maxconn ...` notice is not printed.

A budget too small for the threads themselves (T508) differs: HAProxy serves at every `-m` from 1
to 8 (its `VmData` is already 43 MB), but Alcyon's worker and watchdog threads each need a stack
under `RLIMIT_DATA`. When one cannot be created, Alcyon refuses the start with an
`[ALERT] ... Failed to create thread N` or `Failed to start the watchdog thread` line and exit 1,
instead of a panic or running without lockup detection. Measured here: `-m 1` and `-m 2`
refuse (worker), `-m 3` refuses (watchdog), `-m 4` and up serve (`nbthread 1`).

## `tune.memory.prealloc on|off`: an Alcyon-only global keyword (T468)

HAProxy 3.5-dev8 refuses it as unknown (`did you mean 'prealloc-fd' maybe ?`), and nothing in
HAProxy pre-fills a pool: pools grow on demand and keep what `tune.memory.hot-size` allows
(`-dM` options are debugging aids; `prealloc-fd` pre-touches the fd table). Alcyon grows and keeps
too (design Q1); `tune.memory.prealloc on` (default off) instead sizes, at start, from `maxconn`:

- the standard `buffer` pool: `2 * maxconn` buffers in the process (a request and a response
  buffer per connection, as `-m` counts one), the smaller `tune.buffers.limit` when one is set.
  Each worker thread makes its share, `ceil(total / nbthread)`, at start; they are floor objects
  (no `hot-size` eviction, kept by `pool_gc`). The total is the pool's limit: after start it
  never grows, and a stream that needs a buffer past it fails as under `tune.buffers.limit`;
- the `session` arena: `ceil(maxconn / nbthread)` slots per worker, made at start and never
  compacted. Past them it still grows (fallibly): HTTP/2 streams take session slots and `maxconn`
  does not bound them.

`show pools` shows the pre-sized `allocated` right after start. It is refused at load (exit 1,
under `-c` too) without an explicit global `maxconn` or `-m` (`'tune.memory.prealloc' needs an
explicit global 'maxconn' or '-m' to size the pools.`), and when the configured `maxconn` needs
more than `-m` (`maxconn * (2 * tune.bufsize + one session slot)`). Not sized by it: small and
large buffers, spare strings and lists, variables, log lines, check runs, stats rows, the applet
and task arenas. The share is per thread and the limit per process: a thread that has used its
share takes no buffer while the others hold theirs, so with `nbthread` above 1 a stream can fail
before `maxconn` connections when the connections are unevenly spread.

## `ssl_fc_ja4`: an Alcyon-only fetch (T344)

`ssl_fc_ja4` returns the JA4 TLS client fingerprint (`t13d1516h2_8daaf6152771_e5627efa2ab1`),
built from the whole captured ClientHello: GREASE-free sorted cipher and extension lists,
the offered ALPN, and a truncated SHA-256. **HAProxy has no such fetch**: `haproxy -c` refuses
a configuration that uses it (`unknown fetch method 'ssl_fc_ja4'`), so such a configuration
does not run on HAProxy. It gives a sample only when the ClientHello capture exists, that is
`tune.ssl.capture-buffer-size` is above 0 (its value does not matter; 0 or unset gives no
sample, as for the other capture fetches). Only JA4 is implemented, not JA4S/JA4H/JA4X/JA4T or
QUIC (`q`) fingerprints. The JA4 specification is by FoxIO; JA4 (TLS client fingerprinting only)
is under the BSD 3-Clause licence in `LICENSE-JA4` of <https://github.com/FoxIO-LLC/ja4>:
"Copyright (c) 2026 FoxIO. All rights reserved", redistribution with the notice permitted, the
name of FoxIO not to be used to endorse. Alcyon implements the specification text and uses FoxIO's
published test vectors (`crates/alcyon-sample/testdata/ja4_vectors.txt`); no FoxIO code is copied.
Where FoxIO's tools and the specification text differ, the default is the tools; see
`alcyon.ja4-compat` below.

### `alcyon.ja4-compat foxio|spec` (Alcyon-only global keyword; HAProxy refuses it as unknown)

Where FoxIO's published tools and the JA4 specification text disagree, `ssl_fc_ja4` follows the
tools by default (`foxio`), because the fingerprint databases operators compare against are
produced by those tools. `alcyon.ja4-compat spec` follows the specification text. Any other value
is refused at load. The two differences:

* A non-alphanumeric end of the first ALPN value. `foxio`: the character itself, or `9` for a
  byte of 0x80 or more (`0xBA 0xAD` gives `99`; FoxIO's published vector for
  `tls-non-ascii-alpn.pcapng`). `spec`: the first and last hex digit of the value (`bd`; `/x`
  gives `28`).
* No extension to list but signature algorithms present (no real ClientHello: the algorithms
  come in an extension). `foxio`: the third part hashes `_` and the algorithms. `spec`: twelve
  zeros. Only a unit test reaches it.

Of the 72 published vectors in `crates/alcyon-sample/testdata/ja4_vectors.txt` (all FoxIO's values,
all given by `foxio`), only `tls-non-ascii-alpn.pcapng` gives a different string under `spec`.

## `http-request use-service prometheus-exporter` (T368)

Served: `http-request use-service prometheus-exporter [if|unless <cond>]` in a frontend, listen or
backend, as HAProxy's PROMEX does (the shipped reference binary is built without PROMEX; the
oracle here was the same source built with `USE_PROMEX=1`). Any other service name is refused
with HAProxy's message (`'<name>' unknown service name.`). The reply, the families, their types
and label keys, and the query parameters `scope=` (`global`, `frontend`, `backend`, `server`,
`listener`, `resolvers`, `*`, empty), `no-maint`, `desc-labels` and `metrics=a,-b` follow
`addons/promex/service-prometheus.c`; a bad query is its 400.

The numbers come from the CLI's sources: the `haproxy_process_*` families are `show info`
(pools, `Memmax`, connections, `PoolFailed`), the frontend, backend and server families are
`show stat` rows, so a value here is the value there. `Tasks` and `Run_queue` are those of the last
pass of the engine loop (a request rule cannot reach the scheduler).

Left out, because Alcyon does not count them (printing 0 would pass a default for a measurement):

| families | why |
|---|---|
| `haproxy_{frontend,backend,server}_{req,res}_bytes_{in,out}_total` | bytes by direction are not tracked |
| `haproxy_server_{idle,private_idle,unsafe_idle,safe_idle,used,need}_connections_current` | no per-server connection pool gauges |
| `haproxy_{backend,server}_last_session_seconds` | `lastsess` is not tracked |
| `haproxy_resolver_*` | present once a `resolvers` section is configured (T485); HAProxy always has the implicit `default` section, Alcyon does not build it |
| `haproxy_frontend_intercepted_requests_total`, `haproxy_{frontend,backend}_http_cache_hint_hits_total` | not tracked |
| `haproxy_backend_agg_server_status`, `_agg_server_check_status`, `_agg_check_status`, `haproxy_server_check_status`, `haproxy_server_agent_*` | per-state check/agent aggregates; Alcyon has no agent checks |

Not done: `extra-counters` is accepted and adds nothing (Alcyon has no stats-module counters: `h1`,
`h2`, `ssl`, ...), and `tcp-request content use-service` stays refused (HAProxy refuses it too,
with another message). With several workers, check columns are those of the worker that answers
the scrape (the same as `show stat`).

A scrape allocates nothing (T369, `tasks/T369-prometheus-scrape-without-allocations.md`): it is
produced a chunk at a time into the session's response buffer, resuming from a cursor, as HAProxy's
applet does, so memory is one buffer whatever the number of servers; `crates/alcyon-rt/tests/promex.rs`
pins 0 allocations including the first scrape. Differences: `http-after-response` rules do not
apply to the reply; a `metrics=` value over 512 bytes decoded, or more than 8 of them, is a 400;
every sample of a family costs a regeneration of the object's `show stat` row, so a scrape of
thousands of servers takes CPU (a few ms per 16 KiB chunk, release build). `scope=global` alone is
the cheap memory-only scrape.

## `abns@` stats sockets across a `-sf` reload (T354, T370)

An abstract name cannot be shared, so a `-sf` successor whose bind finds one in use sends
`SIGTTOU` and the old process lets go of it (`Paused frontend GLOBAL.`); if the successor then
fails to start it sends `SIGTTIN` and the old process binds the name back once (`Resumed frontend
GLOBAL.`). A name something else holds at that moment is reported with HAProxy's two lines
(`Resuming listener: protocol abns_stream: cannot bind UNIX socket (already in use) [abns@NAME].`,
`Some proxies refused to resume, ...`) and tried again on the next `SIGTTIN`, as on HAProxy; neither
polls for it. Two differences:

* HAProxy sends `SIGTTIN` and only then closes its sockets (`src/haproxy.c:2115-2116`), so the old
  process's one bind can race the successor's exit (0 losses in 30 on an idle host; the Alcyon
  equivalent lost 1 in 3 under the gate's load). Alcyon joins its workers, so every socket it bound
  is closed, before it signals.
* `SIGTTOU` pauses every listener on both since T456 (`Paused frontend fe.` for each proxy,
  once a process; TCP frontends and TCP stats sockets refuse connections until `SIGTTIN`). Two
  gaps: QUIC listeners are not paused (HAProxy connects the UDP socket to itself, and its
  connections have sockets of their own; an Alcyon QUIC connection lives on the listening socket,
  which that would cut off), and a listener whose sockets `_getsocks` has handed to a successor
  is only no longer polled, as HAProxy does for an inherited socket.
  A unix socket file is renamed over by the successor on both and is lost to the old process if
  the successor then fails (`Connection refused`, measured on both).

## `dump_all_vars`: variables are listed sorted by name (T364 S4)

`dump_all_vars` prints each variable by its stored type, as HAProxy does (string quoted and escaped, `bin`
as upper-case hex, integer bare, `true`/`false`, address as text, method quoted), and CLI `get var`
prints the stored type name. Within one scope Alcyon lists the variables sorted by name; HAProxy walks its
hash tree, so its order differs between processes (it is seeded per process). A rule must not depend on
the order in either.

## `show quic`: the one-line form, with `-` where quinn-proto has no value (T524)

`show quic [oneline] [all|clo|be]` prints HAProxy's header and one line per connection with its
column widths (measured on 3.5-dev7 with QUIC; `show quic help` is byte for byte HAProxy's, as are the
messages for a bad argument, a bad level and a bad pointer). Differences:

* `in_flight`, `infl_p` and both CIDs print `-`: quinn-proto keeps the bytes and packets in flight and
  the connection IDs private, and a made-up number is worse than none. `lost_p`, the state
  (`HDSHK`, `ESTAB`, `CLOSE`; quinn-proto cannot tell `CLOSE` from `DRAIN`) and both addresses are real.
* The first column is the first eight bytes of the first Initial's destination CID, not a pointer; the
  `[NN]` is the worker (HAProxy's thread), the order is per worker.
* `stream`, `full`, a level list (`tp,sock,pktns,cc,mux`) and a `0x...` connection filter are refused
  with a message naming them. `be` lists nothing (Alcyon has no QUIC to servers). `clo` and `all` show the
  connections quinn-proto still holds closing, which are removed sooner than HAProxy's.
* `show info` has no QUIC field on HAProxy 3.5-dev7 (the field list is identical with and without a
  `quic4@` bind), so Alcyon has none either; the connection counters QUIC feeds are T504's.

## `tune.quic.*` and the QUIC bind keywords (T525)

Implemented, each measured on the QUIC oracle (HAProxy 3.5-dev7-e6f616-55) and tested in
`crates/alcyon-rt/tests/it/quic_knobs.rs` (both h3 paths) and `crates/alcyon-config/tests/it/quic_tune.rs`:
`tune.quic.fe.sec.retry-threshold` (T492), `tune.quic.fe.max-idle-timeout` (transport parameter and
idle close), `tune.quic.fe.stream.max-concurrent` (`initial_max_streams_bidi`),
`tune.quic.fe.stream.max-total` (credit is the smaller of the two; the connection is closed with
`H3_NO_ERROR` once that many request streams are done), `tune.quic.listen` (`off`: no UDP socket for
a `quic4@`/`quic6@` bind, its frontend's other binds are served, no message as on HAProxy), and the
bind keyword `quic-force-retry`.

Gaps in what is implemented: a client that opens stream `max-total + 1` while earlier ones are
still in flight gets the credit quinn-proto extends as streams end (HAProxy stops extending at the
total); the connection is closed when the last allowed stream is done either way.
`max-concurrent` above 100 still queues at 100 on the `mux` path (`mux_h3::MAX_CONCURRENT`).
The `quic_enabled` fetch still answers `false` whatever `tune.quic.listen` says.

Refused at load, the message `'<keyword>' is not supported by Alcyon.` (global) or the bind keyword
refusal (bind): Alcyon has nothing for them to tune (quinn-proto's congestion controller, pacing, GSO
and socket-per-connection are not exposed).

| keyword | HAProxy | why refused |
|---|---|---|
| `tune.quic.fe.cc.cubic-min-losses`, `.cc.hystart`, `.cc.max-frame-loss`, `.cc.max-win-size`, `.cc.reorder-ratio` | congestion-control tuning | quinn-proto's controllers take none of these |
| `tune.quic.fe.sec.glitches-threshold` | close a connection that glitches too much | no QUIC glitch counter |
| `tune.quic.fe.sock-per-conn` | a UDP socket per connection | one socket per bind and worker |
| `tune.quic.fe.stream.data-ratio`, `tune.quic.fe.stream.rxbuf` | stream window sizing | the windows come from `tune.bufsize` (T504) |
| `tune.quic.fe.tx.pacing`, `tune.quic.fe.tx.udp-gso` | pacing, GSO | not switchable |
| `tune.quic.mem.tx-max`, `tune.quic.sec.stateless-reset-rate`, `tune.quic.zero-copy-fwd-send` | memory cap, reset rate limit, zero copy | not implemented |
| `tune.quic.be.*` (`cc.*`, `max-idle-timeout`, `sec.glitches-threshold`, `stream.data-ratio`, `stream.max-concurrent`, `stream.rxbuf`, `tx.pacing`, `tx.udp-gso`) | QUIC to servers | no QUIC backend (T461) |
| bind `quic-cc-algo`, `quic-socket`, `allow-0rtt` | congestion algorithm, socket mode, 0-RTT | refused as before |
