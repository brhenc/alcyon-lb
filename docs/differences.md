# Where Ibex differs from HAProxy

What an operator can see: HAProxy 3.5-dev8-885761-29 does one thing, Ibex does another or
refuses. Each entry says what to do instead.

## `userlist`: hashed passwords (`user <u> password <hash>`)

HAProxy hands the hash to glibc `crypt(3)`. Ibex has no `crypt(3)` (it needs `unsafe` or a C
library) and verifies the formats it can in safe Rust, with the `ibex-crypt` crate.

| format | prefix | HAProxy (glibc) | Ibex |
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
`the encrypted password used for user 'u' is in the yescrypt ($y$) format, which Ibex cannot verify
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
Ibex applies that rule and has not been compared on every byte. The 900 verdicts of
`crates/ibex-crypt/tests/vectors.txt` (salts, rounds, password lengths, malformed settings) agree
with glibc.

## Regular expressions

HAProxy compiles every regular expression with PCRE2 (or the C library's POSIX regex).
Ibex is memory-safe Rust and links no C regex library, by decision (T154, 2026-10-04):
`pcre2` and its C bindings are out. Ibex compiles a pattern with the `regex` crate first and,
only when `regex` refuses it, with the pure-Rust `fancy-regex` crate (crate `ibex-regex`,
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
`crates/ibex-rt/tests/it/pcre_regex.rs`, in an ACL, in `replace-header` and in `regsub`.

### What is refused at load

A pattern with a PCRE feature `fancy-regex` lacks is refused when the configuration is read
(`ibex -c` fails; HAProxy accepts all of these), with a message that names the feature:

```
bad regular expression <(?R)>: PCRE feature not supported by Ibex: recursion and subroutine calls (see docs/differences.md)
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
compiles it and then panics at the first match, which aborted Ibex before T277. So are the
keys of a `map_reg`/`map_regm` file, at load, and `add map`/`add acl` on the CLI.

### Unnamed groups in ACL, `map_reg` and health-check regexes

HAProxy compiles the regex of an ACL (`-m reg`, `*_reg`, pattern files, `add acl`), of
`map_reg` (file and `add map`) and of `http-check expect rstring`/`rstatus` and `tcp-check
expect rstring` with PCRE2_NO_AUTO_CAPTURE: only a named group captures and has a number. Ibex
does the same (T274 J2): `(a)\1`, `((a))\2`, `(a)(?<n>b)\2` and `(a)(?(1)b|c)` are refused
with `reference to non-existent subpattern`, `(?<n>a)\1` is a reference to `n`, and
`(a)(?<n>b)\1` refers to `n` too. `map_regm`, `replace-header`, `replace-value`,
`replace-path`, `replace-uri` and `regsub` number every group, as in HAProxy. The refusal
carries PCRE2's `erroffset` on the CLI (`add acl`, `add map`): just past the `\N`, or at the
inner `(` of `(?(N)`.

At load, every regex refusal is worded `bad regular expression <re>: <why>` where HAProxy
says `regex '<re>' is invalid (error=<why>, erroffset=<n>)`, and carries no offset (T287).

### Regexes PCRE2 refuses

Ibex refuses, with PCRE2's text and `erroffset` (CLI), a quantifier after a quantifier
(`a**`, `a{2}{3}`; `a*+`, `a*?` stay valid) or after an anchor or option setting (`^*`,
`\b+`, `(?i)*`), `{n,m}` out of order or above 65535, an unknown POSIX class
(`[[:foo:]]`), a collating element (`[[.a.]]`) and a group name used twice (T287). Remaining
differences, measured on HAProxy 3.5-dev8-885761-29:

* PCRE2 refuses an unbounded look-behind (`(?<=a*)b`, "length of lookbehind assertion is
  not limited"); Ibex runs it.
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
(`ibex_regex::BACKTRACK_LIMIT`). A match that exceeds it is a non-match, silently: nothing is
logged per request. This is HAProxy's outcome, measured with `^/(a+)+(?=$)` against
`/aaaa...ab` (28, 48, 100 and 3000 `a`): PCRE2 gives up and the ACL does not match. Ibex
answers in about 15 ms in a debug build, whatever the length. The limit bounds the cost of a
hostile request, not the answer a legitimate pattern gets: a pattern that needs more than a
million steps on a real header is a pattern to rewrite.

The plain pattern `^/(a+)+$`, with no PCRE-only feature, is not backtracking at all on Ibex
(it runs in `regex`, linear time) and gives the answer PCRE2 gives.

## `use_backend` with a log-format name

`use_backend %[req.hdr(x)]` (a backend name built per request) is refused at load with
`'use_backend' with a log-format backend name is not implemented by Ibex`. HAProxy accepts
it, skips the rule when the built name is no backend, and does not check the name at load.
`use-server` with a log-format server name is refused the same way. Name the backends in
`use_backend ... if` rules instead.

## Out of Milestone 1 scope: refused at load (T164)

These are refused by the parser with `'<keyword>' is not supported by Ibex (out of scope, see
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

- QUIC / HTTP/3 (`quic4@`, `quic6@`, `proto quic`, `alpn h3`): Ibex has a QUIC listener
  (`ibex-quic`, exercised by `crates/ibex-config/tests/it/quic_bind.rs`); it is experimental.
  The reference HAProxy binary here is built without QUIC and refuses these.
- `resolvers` sections (and `resolvers` in `defaults`): refused with a message naming the keyword, as
  are a server's `resolvers` keyword and `server-template` (see `server_keywords.rs`): Ibex does no
  DNS resolution at run time (out of M1 scope, docs/milestones.md). HAProxy accepts them (T358 #4).

## Logs and `show stat` (T165)

Same as HAProxy (measured, 3.5-dev8-885761-29): `option httplog`, `httpslog`, `tcplog` and the default format (one `Connect from` line per connection) byte for byte except timings; a datagram or line ends with one line feed that `len` counts; `show stat` frontend, backend and server rows for `status scur stot bin bout dreq ereq econ eresp wretr wredis weight act bck chkfail chkdown lastchg downtime qcur rate rate_max hrsp_* req_tot lbtot cli_abrt srv_abrt lastsess qtime ctime rtime ttime *_max mode`.

Different, and what to do instead:

| what | HAProxy | Ibex |
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

Measured on HAProxy 3.5-dev8-885761-29; pinned in `crates/ibex-rt/tests/tls_handshake_log.rs`.

- Frontend `smax` after probes that fail the handshake: HAProxy reports 1 to 6 for the same
  sequential probes, run after run, so it is not a concurrency maximum there (it looks like a
  sum over threads). Ibex reports the real maximum of concurrent sessions: 1 at most, since a
  failed handshake never makes a session.
- `strict-sni` is refused at load (HAProxy answers a ClientHello with no or an unknown SNI with
  alert `unrecognized_name` and logs `callback failed`). Implementing it needs the certificate
  resolver to refuse instead of falling back to the default certificate: a feature, not scheduled.
- Whether a client that leaves mid-handshake is `Connection closed during SSL handshake` or a
  bare `SSL handshake failure` depends in HAProxy on whether the FIN came with the bytes or
  alone. Ibex follows the same rule (a whole handshake record read, then a FIN in a read of its
  own, not queued behind the data at `MSG_PEEK` time) and so can differ from HAProxy on a
  race between the two.

## `tune.maxaccept`: the default is no limit (T295)

`tune.maxaccept <n>` is accepted and applied: one listener wakeup accepts at most `n`
connections in a row (`-1`: no limit; `0` or a non-number: the default, as `atol` gives
HAProxy). HAProxy's default is `MAX_ACCEPT`, 4, after which its thread goes on to its other
work and the connections left in the backlog wait for the next poll. Ibex's default is no
limit: its listener is polled level-triggered and an accept loop drains the backlog it finds,
which is what every measurement so far was made with. Set `tune.maxaccept 4` to get
HAProxy's behaviour.

## Chunked bodies: chunks are not merged (T302)

Like HAProxy, Ibex forwards a chunked body (either way) with each chunk-size line rewritten:
the extension and blanks dropped, the size in upper-case hex without leading zeros (`0005;a=b`
goes out as `5`, `a` as `A`). HAProxy also merges the chunks it holds in its buffer at once
into one (`A` and `3` received in one read go out as `D`); Ibex keeps the chunks as received.
Which chunks HAProxy merges depends on how the bytes arrive, and the payload is the same.

## Slow clients (slowloris) and timeouts (T349)

Measured live on 2026-10-17 (main 603c48a2 vs HAProxy 3.5-dev8, timeouts of 1-3 s, raw-socket
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
`http-request wait-for-body time <t>` or `option http-buffer-request` (both work in Ibex, as
in HAProxy).

| | HAProxy | Ibex | what to do |
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
refused, as HAProxy does. Ibex does not yet require `expose-experimental-directives` for
`normalize-uri` (HAProxy 3.5 does).

## `listen()` backlog: the `bind` option `maxconn` is refused (T360)

The backlog of a bind follows HAProxy's `listener_backlog()`: the bind's `backlog`, else the
proxy's `backlog` (frontend, listen or defaults), else the proxy's `maxconn` (the global one
when the proxy sets none), else 1024, capped by `net.core.somaxconn`. The one step Ibex does
not have is the `bind` option `maxconn` (between the proxy's `backlog` and its `maxconn`
in HAProxy): `bind ... maxconn N` is refused at load, as before. A socket handed over by a
reload keeps the backlog it was bound with, as in HAProxy.

## `tune.ibex.zero-buffers on|off`: an Ibex-only global keyword (T437 5b)

When a buffer goes back to its pool (or is freed), Ibex overwrites the bytes that were written to
it (up to a per-buffer high-water mark, not the whole 16 KB) with zeros, so the plaintext of one
connection is not what the next one is handed, and a core dump or a memory-disclosure bug finds
less. The overwrite is a `zeroize` write the compiler may not remove. Default **off** (since S1,
2026-10-24: Ibex's per-request safety extras stay off while it is compared with HAProxy; `on`
costs ~840 instructions per request on a rules benchmark). HAProxy has no such setting (its pools
keep stale bytes; `-dM` poisoning is a debug option) and refuses the keyword as unknown. It takes
exactly `on` or `off`; anything else, or a missing argument, is a configuration error. Limits:
bytes written through `Buf::writable()` and never committed are not tracked, and buffers owned by
rustls itself are not Ibex's to overwrite. The TLS record buffers (plaintext and ciphertext,
`rx_raw`/`tx_raw` included) are not covered by this setting: they have their own
`tune.ibex.ssl-zero-buffers` (default on, below).

## `tune.ibex.ssl-zero-buffers on|off`: an Ibex-only global keyword (S2)

When a TLS connection ends, Ibex overwrites the whole capacity of its TLS record buffers (the
ciphertext read from and written to the socket, and the plaintext decrypted from it) with zeros,
so session data does not stay in freed memory. Default **on** (user decision 2026-10-24: TLS keys
and plaintext are a real target); `off` leaves them as HAProxy does. The plain I/O buffers
follow `tune.ibex.zero-buffers` (default off) instead. HAProxy 3.5-dev8 refuses the keyword as
unknown. It takes exactly `on` or `off`; anything else, or a missing argument, is a
configuration error. Limits: key material inside rustls/ring is not covered (`tradeoff.md` 6.27).

## `tune.ibex.zero-spares on|off`: an Ibex-only global keyword (S1)

The header rules, samples and formats reuse per-thread spare strings and header lists (`show
pools` `spare_str`, `spare_list`, `scratch_str`, `scratch_bytes`). With `on`, a string's used
bytes (each string's, for a list) are overwritten with zeros when it is given back to its pool,
whether the pool keeps it or frees it, so an earlier request's cookie or `Authorization` value is
not left in memory. Default **off**: the wipe costs ~1k instructions per request on a rules
benchmark, and HAProxy wipes nothing either. HAProxy refuses the keyword as unknown. It takes
exactly `on` or `off`; anything else, or a missing argument, is a configuration error.

## `tune.ibex.zero-on-free off|soft|hard`: an Ibex-only global keyword (T459)

What the process's allocator does with every heap block that is freed (rustls and ring state,
Ibex's own objects, std's): `off` (default) frees it as it is; `hard` overwrites it with zeros,
then frees it (the old block of a reallocation too); `soft` puts it on the freeing thread's
quarantine and wipes and frees it when the thread is idle, within bounds (at most 4 x
`tune.memory.hot-size` bytes per thread, at most ~100 ms, emptied by `pool_gc` and a refused
allocation; `tradeoff.md` 6.29). With `soft` or `hard`, `show info` ends with Ibex-only lines
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
touched by any of them; OpenSSL wipes its own key material (`OPENSSL_cleanse`). Ibex accepts
`-dMfail` and `-dMno-fail` only (S5) and refuses the other `-dM` forms. The keyword takes exactly
`off`, `soft` or `hard`; anything else, or a missing argument, is a configuration error.

## `tune.ibex.crypto-provider ring|ring-ibex`, `set ssl crypto-provider` and `show ssl crypto-provider`: Ibex-only (T460)

The rustls crypto provider every TCP TLS configuration is built on: binds, server lines and
their health checks, TLS 1.2 and 1.3; and since T461 every QUIC bind, log-forward TLS bind and
ring TLS server, which are on rustls 0.24 too. `ring` (the default) is upstream ring through
`rustls-ring`; `ring-ibex` is the vendored ring fork that wipes key material when it is freed
(`vendor/ringibex`, built with its `zeroize` feature on; what it wipes: `vendor/ringibex/ZEROIZE.md`,
`tradeoff.md` 6.27). Exactly one argument, `ring` or `ring-ibex`; anything else is a configuration
error. HAProxy refuses the keyword as unknown.

The TLS binds of a `log-forward` section and the TLS servers of a `ring` section run on it too
since T461 (they were on rustls 0.23, and T460 refused `ring-ibex` with them): every TLS user of
the process is on rustls 0.24 and the chosen provider, and nothing refuses `ring-ibex`. Their
handshakes count in `show ssl crypto-provider`, and a swap reaches their new connections.

QUIC (T461): the handshake, the packet and header protection keys, and what quinn-proto took from
vanilla ring directly (the stateless reset tokens' HMAC, the address validation tokens' HKDF and
AES-256-GCM, the Retry integrity tag) all run on the chosen provider. A QUIC bind's TLS is the
same configuration as a TCP bind's of the same line, TLS 1.3 only, with its session tickets.

`show ssl crypto-provider` (CLI, admin level) prints the provider new handshakes use and the
handshakes completed on each provider since start, front and back, QUIC included:

    current ring
    provider ring handshakes 12
    provider ring-ibex handshakes 0

`set ssl crypto-provider ring|ring-ibex` (CLI, admin level) changes the provider at run time, for
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

## `ibex.watchdog-warn-only`: an Ibex-only global keyword (T361)

HAProxy's watchdog warns about a thread that has stopped processing traffic and, once it has been stuck for a
second, aborts the process (exit status 134); no HAProxy keyword turns the abort off. Ibex does the same by
default. `ibex.watchdog-warn-only` (global, no argument; HAProxy refuses it as an unknown keyword) keeps the
warnings and `BlockedTrafficWarnings` and never aborts, for an operator who prefers a slow process to a restart.
The `ibex.` prefix keeps it from clashing with a future HAProxy keyword.

## `tune.memory.hot-size`: the buffer floor is an Ibex extension (S1, S2)

`tune.memory.hot-size <bytes>` (default 524288) parses as HAProxy parses it (`mem_parse_global_hot_size`:
one argument, `atol`, strictly positive) and bounds what each thread keeps in its pools together,
with HAProxy's rule: past 3/4 of it a pool evicts down while it holds more than its share, past
the whole of it the largest pools are evicted across (`pool_put_to_cache`,
`pool_evict_from_local_caches`). Two differences. **Floors**: each Ibex pool declares a per-thread
floor that eviction never goes under, and floor objects do not count against `hot-size`; the three
buffer pools (`buffer`, `small_buffer`, `large_buffer`) have a floor of 64 per thread
(`crates/ibex-rt/src/buf.rs`), where HAProxy's `minavail` is 2. The reason is measured:
at HAProxy's default, with 50 keep-alive connections of 16 KiB buffers on a thread, the budget
holds fewer buffers than the connections need and HAProxy mallocs about 0.5 buffer per request;
Ibex with the floor makes none (`docs/design/memory-2026-10-24.md` 1.3, 3.3). Only `pool_gc`
(SIGQUIT, SIGTTOU, SIGUSR1, the stop path, a refused allocation) goes below a floor. **Eviction
order**: one object at a time, newest first, largest pool first across pools; HAProxy evicts
clusters of 8 oldest first from a per-thread LRU (`tradeoff.md` 6.28). `show pools` counts can lag
a busy thread by up to 10 ms (`tradeoff.md` 6.28).

## `tune.buffers.limit`, `tune.fail-alloc` and `-dMfail` / `-dMno-fail` (S5)

`tune.buffers.limit <n>` (parsed as HAProxy: one argument, `atoi`, not negative; 1 and 2 become 3,
0 is no limit) caps the standard buffers the process holds at once, cached ones included. A
stream that would pass it fails: 500 with termination state `IR--` (request buffer) or `IH--`
(response buffer), or a close once its response began; where HAProxy puts it on its buffer wait
queue until one frees (that queue is open work, S6, `tradeoff.md` 6.13). An HTTP/2 stream whose
buffer cannot be had closes its connection. **`tune.buffers.reserve` is refused at load** (it
reserves buffers for that wait queue; accepting it would promise what is not there, AGENTS.md 5).

`tune.fail-alloc <0..100>` refuses that percentage of pool allocations at random, and, as on
HAProxy, counts only under `-dMfail` (`-dMfail` alone is a rate of 1). Ibex honours exactly the
`-dM` forms `fail` and `no-fail` (comma-separated lists of only these are accepted); every other
form (`-dM`, `-dM<byte>`, `integrity`, `uaf`, `no-merge`, `cold-first`, ...) is refused at start
with `... -dM (memory pool debugging) is not supported, except -dMfail and -dMno-fail` and exit 1,
because Ibex's pools are not malloc-per-object chunks to poison, tag or unmap
(`crates/ibex-rt/src/bin/ibex.rs`). Measured on 3.5-dev8 (400 requests, rate 5): a request gets
`200`, `500` with `IR--` or `IC--`, or a closed connection; Ibex gives the same three (`IH--`
where HAProxy's refusal is of its server connection, `IC--`).

## `-m <megs>`: a connection budget and an rlimit, as on HAProxy

HAProxy's `-m` sets `RLIMIT_DATA` to `<megs>` MiB (soft and hard, `/proc/<pid>/limits`;
measured on 3.5-dev8, T453), shows the value as `Memmax_MB` / `Memmax_bytes` and sizes
`maxconn` from it (`STREAM_MAX_COST + 2 * tune.bufsize` per connection, 97% of the budget,
TLS costs when a `bind` or `server` uses `ssl`; a configured `maxconn` that leaves no room for
TLS is refused, exit 1). Past the limit its pools fail allocations and the streams that needed
them, and the process goes on. Ibex does the same sizing and reporting and, since T465b, sets `RLIMIT_DATA` the same way.
Past the limit its buffers, sessions, timers and idle lists fail one stream or connection;
an allocation that is still infallible (rustls, h2, std) aborts the process (tradeoff.md 6.23,
6.25). Under `-m` the session arenas are presized for the budget rather than 65536 slots.
Differences left: Ibex's per-connection cost is a constant calibrated on
HAProxy's results (`sizeof(struct stream)` has no Ibex counterpart), `maxsslconn` and
`tune.ssl.cachesize` are not configurable, so `MaxSslConns` stays 0 and the
`Automatically setting global.maxconn ...` notice is not printed.

## `ssl_fc_ja4`: an Ibex-only fetch (T344)

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
name of FoxIO not to be used to endorse. Ibex implements the specification text and uses FoxIO's
published test vectors (`crates/ibex-sample/testdata/ja4_vectors.txt`); no FoxIO code is copied.
Where FoxIO's tools and the specification text differ, the default is the tools; see
`ibex.ja4-compat` below.

### `ibex.ja4-compat foxio|spec` (Ibex-only global keyword; HAProxy refuses it as unknown)

Where FoxIO's published tools and the JA4 specification text disagree, `ssl_fc_ja4` follows the
tools by default (`foxio`), because the fingerprint databases operators compare against are
produced by those tools. `ibex.ja4-compat spec` follows the specification text. Any other value
is refused at load. The two differences:

* A non-alphanumeric end of the first ALPN value. `foxio`: the character itself, or `9` for a
  byte of 0x80 or more (`0xBA 0xAD` gives `99`; FoxIO's published vector for
  `tls-non-ascii-alpn.pcapng`). `spec`: the first and last hex digit of the value (`bd`; `/x`
  gives `28`).
* No extension to list but signature algorithms present (no real ClientHello: the algorithms
  come in an extension). `foxio`: the third part hashes `_` and the algorithms. `spec`: twelve
  zeros. Only a unit test reaches it.

Of the 72 published vectors in `crates/ibex-sample/testdata/ja4_vectors.txt` (all FoxIO's values,
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

Left out, because Ibex does not count them (printing 0 would pass a default for a measurement):

| families | why |
|---|---|
| `haproxy_{frontend,backend,server}_{req,res}_bytes_{in,out}_total` | bytes by direction are not tracked |
| `haproxy_server_{idle,private_idle,unsafe_idle,safe_idle,used,need}_connections_current` | no per-server connection pool gauges |
| `haproxy_{backend,server}_last_session_seconds` | `lastsess` is not tracked |
| `haproxy_frontend_intercepted_requests_total`, `haproxy_{frontend,backend}_http_cache_hint_hits_total` | not tracked |
| `haproxy_backend_agg_server_status`, `_agg_server_check_status`, `_agg_check_status`, `haproxy_server_check_status`, `haproxy_server_agent_*` | per-state check/agent aggregates; Ibex has no agent checks |
| `haproxy_resolver_*` | no resolvers |

Not done: `extra-counters` is accepted and adds nothing (Ibex has no stats-module counters: `h1`,
`h2`, `ssl`, ...), and `tcp-request content use-service` stays refused (HAProxy refuses it too,
with another message). With several workers, check columns are those of the worker that answers
the scrape (the same as `show stat`).

A scrape allocates nothing (T369, `tasks/T369-prometheus-scrape-without-allocations.md`): it is
produced a chunk at a time into the session's response buffer, resuming from a cursor, as HAProxy's
applet does, so memory is one buffer whatever the number of servers; `crates/ibex-rt/tests/promex.rs`
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
  process's one bind can race the successor's exit (0 losses in 30 on an idle host; the Ibex
  equivalent lost 1 in 3 under the gate's load). Ibex joins its workers, so every socket it bound
  is closed, before it signals.
* `SIGTTOU` pauses every listener on both since T456 (`Paused frontend fe.` for each proxy,
  once a process; TCP frontends and TCP stats sockets refuse connections until `SIGTTIN`). Two
  gaps: QUIC listeners are not paused (HAProxy connects the UDP socket to itself, and its
  connections have sockets of their own; an Ibex QUIC connection lives on the listening socket,
  which that would cut off), and a listener whose sockets `_getsocks` has handed to a successor
  is only no longer polled, as HAProxy does for an inherited socket.
  A unix socket file is renamed over by the successor on both and is lost to the old process if
  the successor then fails (`Connection refused`, measured on both).

## `dump_all_vars`: variables are listed sorted by name (T364 S4)

`dump_all_vars` prints each variable by its stored type, as HAProxy does (string quoted and escaped, `bin`
as upper-case hex, integer bare, `true`/`false`, address as text, method quoted), and CLI `get var`
prints the stored type name. Within one scope Ibex lists the variables sorted by name; HAProxy walks its
hash tree, so its order differs between processes (it is seeded per process). A rule must not depend on
the order in either.
