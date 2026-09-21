# 001 — The Layer Model

Reference: `/home/bhenc/reference/haproxy` @ `e6f616af` (3.5-dev7).

HAProxy has five layers, and the discipline that makes it extensible is that
**each layer is a vtable, and the layers above and below never learn each other's
concrete types.** Ibex keeps this exactly; in Rust each vtable becomes a trait, and each
`void *` context becomes an associated type, which removes an entire class of
"wrong context for this vtable" bug that C cannot express away.

```
  protocol (ctrl)   L4   accept/connect/bind/listen       proto_tcp, proto_uxst, proto_quic
       |
  xprt_ops          L5/6 byte transport, stackable        raw_sock, ssl_sock, xprt_handshake
       |
  mux_ops           L7   framing: wire <-> HTX            mux_h1, mux_h2, mux_pt, mux_fcgi
       |
  sedesc / stconn   --   the pivot: decouples the two     "stream endpoint descriptor"
       |
  stream            L7   the transaction: rules, ACLs, channels, analysers
       |
  session           --   the *connection-level* context (1 session : N streams)
```

## 1. `struct connection` (`include/haproxy/connection-t.h`)

Holds three vtable pointers and three opaque contexts:

```c
const struct protocol *ctrl;   /* socket layer  */
const struct xprt_ops *xprt;   /* transport     */
const struct mux_ops  *mux;    /* mux layer     */
void *xprt_ctx;                /* xprt's private state  */
void *ctx;                     /* mux's private state   */
void *owner;                   /* the session           */
```

This is the whole trick. `connection` is a *coordination struct*; it owns no protocol
logic. In Rust this is three trait objects plus three type-erased contexts — except Rust
lets each context be an associated type instead of `void *`, which removes the entire
class of "wrong ctx for this vtable" bugs.

## 2. `session` vs `stream` — the split that H2 forced

- `session` = one client connection's context. Owns `fe` (frontend), `listener`, `origin`
  (the originating conn/applet), `accept_ts`, the **tcp-connection-scope stick counters**,
  the session-scope variables, the handshake timeout task, and the private/idle backend
  conn lists.
- `stream` = one transaction. Owns `req`/`res` channels, `scf`/`scb` (the two stream
  connectors), the HTTP txn, the rule-execution cursor (`current_rule_list`,
  `current_rule`), the content-scope stick counters, logs, and per-stream timeout
  overrides.

**`session : stream` is 1:N.** With H1 it looks 1:1 and you can get away with conflating
them; with H2 one session spawns many streams. HAProxy split these in 1.8 precisely for
this reason. Any design that conflates them has to be torn up when H2 arrives.

## 3. `stconn` / `sedesc` — why muxes are swappable at all

`struct stream` never points at a `connection`. It points at two `stconn`s, each of which
points at a `sedesc`:

```c
struct sedesc {
    void *se;                /* the mux stream OR the appctx -- opaque */
    struct connection *conn; /* NULL for applets */
    struct stconn *sc;
    struct iobuf iobuf;
    ...
};
```

`sedesc.se` is a *stream endpoint*: either a mux's per-stream state or an applet context.
The stream cannot tell the difference and does not try. This is what makes the following
all work through one code path: H1, H2, FCGI, the stats page, the CLI, the cache, the
peers protocol, and DNS.

**Consequence for Ibex:** implement `sedesc` early and the runtime socket + stats page
cost almost nothing extra — they become applets behind the same interface as a real
backend, and they inherit ACLs, timeouts, logging, and TLS for free. Verified: every one
of these is a `struct applet` in mainline —

| Applet | File |
|---|---|
| `cli_applet` | `src/cli.c:4434` |
| `http_stats_applet` | `src/stats-html.c:2166` |
| `http_cache_applet` | `src/cache.c:3784` |
| `peer_applet` | `src/peers.c:3392` |
| `dns_session_applet` | `src/dns.c:1021` |

---

---

## 4. Translation notes for Ibex

| HAProxy | Ibex |
|---|---|
| `const struct protocol *ctrl` + `void *ctx` | `Box<dyn Protocol>` |
| `const struct xprt_ops *xprt` + `void *xprt_ctx` | `trait Transport { type Ctx; }` |
| `const struct mux_ops *mux` + `void *ctx` | `trait Mux { type Stream; }` |
| `void *se` in `sedesc` (mux stream **or** appctx) | `enum Endpoint { Mux(..), Applet(..) }` |
| `enum obj_type` discriminators everywhere | the enum's own discriminant |

The `void *se` case is the interesting one. HAProxy needs `enum obj_type` as the first
field of every such struct so it can recover the type at runtime — that is a hand-rolled
tagged union, checked by convention. In Rust it is a real enum, checked by the compiler,
and `obj_type` disappears from every struct that carried it.

### 4.1 Order of construction

`sedesc`/`stconn` must exist before the CLI or stats work is started. In HAProxy the
runtime socket, the stats page, the cache, peers, and DNS are all `struct applet` behind
this one indirection. Build the indirection first and they are ordinary endpoints; build
it later and each becomes a special case wired around the stream engine.
