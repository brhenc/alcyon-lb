# 008 — TCP First: HAProxy 1.0 as the Scope Anchor

Reference: `/home/bhenc/reference/haproxy` @ tag `v1.0.2` (2005-12-17), the oldest
released HAProxy. The full history is in the clone — 28,223 commits back to
`0f7af912 * initial commit of version 1.0.0`.

---

## 1. Why 1.0 is the right target

**3,047 lines. One file.** That is the entire proxy:

```
Makefile
doc/haproxy.txt
examples/cfg
haproxy.c        <- 3047 lines
tests/test.c
```

Against mainline's 338,000 lines across 572 files. And it is not a toy — it was run in
production. That combination, a complete working proxy small enough to hold in your
head, is rare and worth exploiting.

The decisive detail: **`struct task` and `fdtab` exist in 1.0.0.** The task scheduler is
not a later refinement bolted onto a simpler design; it is the oldest load-bearing part
of HAProxy, present in the first public release. Building [003](003-scheduler.md) first
was right, and 1.0 is the evidence.

## 2. What 1.0 actually does

From `examples/cfg` and the config parser, the complete vocabulary:

| Directive | Meaning |
|---|---|
| `listen <name> <addr>:<port>` | one section is frontend and backend together |
| `mode tcp \| http \| health` | `PR_MODE_TCP`, `PR_MODE_HTTP`, `PR_MODE_HEALTH` |
| `server <id> <addr>:<port>` | a backend server |
| `dispatch <addr>:<port>` | fallback target when no server matches |
| `cookie <name>` | cookie-based persistence |
| `retries <n>` / `redisp` | connect retries, and redispatch on failure |
| `contimeout` / `clitimeout` / `srvtimeout` | connect, client and server timeouts |
| `maxconn` / `grace` | admission control, graceful shutdown window |
| `log <addr> <facility>` | syslog |
| `cliexp` / `srvexp` | regex rewriting of request/response lines |
| `daemon` / `debug` / `disabled` | process control |

**Mode `tcp` is there from the first release**, and it is the simpler path: no header
parsing, no rewriting, just two file descriptors and a state machine.

## 3. The state machine, and how it became today's design

1.0's `struct task` is simultaneously the task, the session, the stream, both
connections and both channels:

```c
struct task {
    struct timeval crexpire, cwexpire, srexpire, swexpire, cnexpire;
    int cli_fd, srv_fd;            /* the two connections          */
    int cli_state, srv_state;      /* the two state machines       */
    struct buffer *req, *rep;      /* the two channels             */
    int conn_retries, conn_redisp;
    char cookie_val[SERVERID_LEN+1];
};
```

Everything in [001](001-layering.md) is a later factoring of exactly this. The mapping
is direct:

| 1.0 | Today |
|---|---|
| `cli_state` (`CL_ST*`) | `scf.state` |
| `srv_state` (`SV_ST*`) | `scb.state` |
| `cli_fd` / `srv_fd` | two `Connection`s behind two `SeDesc`s |
| `req` / `rep` | the two channels |
| `crexpire`… | `StConn::ioto` and `Stream::conn_exp` |
| `process_cli()` / `process_srv()` | the per-side analyser loops |
| `process_task()` | the task's `Dispatch::run` |
| `select_loop()` | the poller feeding the scheduler |

The server-side states are nearly one-to-one with `ScState` as already defined:

```
SV_STIDLE -> Init        SV_STCONN  -> Connecting   SV_STDATA  -> Established
SV_STHEADERS -> Ready    SV_STSHUTR/SHUTW -> Closed SV_STCLOSE -> Closed
```

So the skeleton already built is the right shape, and 1.0 tells us the minimum content
needed to make it move.

## 4. Alcyon Milestone 0: "mode tcp"

**Goal: a working TCP proxy with 1.0's feature set, on the modern layering.**

In scope:

- `listen` / `frontend` / `backend` sections, `mode tcp`
- `bind`, `server`, `balance roundrobin`, `dispatch`
- connect retries and `redispatch`
- `timeout client` / `server` / `connect`
- `maxconn` admission control
- TCP health checks
- the runtime socket, enough for hatop read-only
- graceful shutdown

Explicitly out, and deferred to Milestone 1:

- all HTTP: H1 mux, HTX, header rewriting, cookie persistence
- TLS — `mode tcp` proves the data path without it
- stick tables, ACLs beyond `src`, logging beyond basic

The reason to separate them: **a TCP proxy exercises every layer** — protocol,
transport, mux (`mux_pt`), sedesc, stconn, stream, session, scheduler, poller — without
needing a single line of HTTP parsing. If the architecture is wrong, this is where it
shows, and it shows cheaply.

## 5. Build order

1. **Poller + accept.** `epoll` via `rustix`, thread-per-core with `SO_REUSEPORT`,
   power-of-two-choices admission ([002](002-threading-and-affinity.md) §3). Readiness
   wakes a scheduler task; nothing async.
2. **`raw_sock` transport**, implementing the [`Transport`](001-layering.md) trait.
3. **`mux_pt`** — the passthrough mux. Near-trivial, and it proves the mux seam without
   framing.
4. **Stream engine.** `process_cli`/`process_srv` as one task driving both `StConn`s
   through `ScState`. This is the heart, and 1.0's two functions are the specification.
5. **Backend selection**: round-robin, `dispatch` fallback, retries, redispatch.
6. **Timeouts**, through the scheduler's wait queue — the lazy-requeue path
   ([003](003-scheduler.md) §4) gets its first real workload here.
7. **Health checks** as tasks.
8. **Config parser** for the subset above, over a real lexer.
9. **CLI applet**, `show stat` emitting the 146-column CSV from
   [`data/stats_csv_header.txt`](../data/stats_csv_header.txt).

## 6. Validation, with 1.0 as a live oracle

The scope anchor is also a test oracle, which is the main reason to prefer it over a
scope we invent ourselves.

- **Build `v1.0.2` and run it.** 3,000 lines of 2005 C may need minor fixes to compile
  on a modern toolchain; that is a contained cost for a behavioural reference.
- **Differential proxying.** Drive Alcyon and 1.0 with identical config and traffic;
  compare bytes forwarded, connection lifecycle, and timeout behaviour.
- **The 1.0 config file parses.** `examples/cfg` from the v1.0.2 tree is a real config;
  accepting it is a concrete, checkable milestone.
- **reg-tests.** From [`data/regtests.json`](../data/regtests.json), 312 tests triaged;
  the `REACHABLE_NOW` set sorted by directive count is the roadmap, simplest first.
- **hatop** against the runtime socket, read-only.

## 7. What this buys

A finishable milestone that is demonstrably a proxy, exercising every architectural
decision made so far, with a 3,000-line reference implementation to check against.

It also reframes the project honestly. "Alcyon reaches feature parity with HAProxy 1.0 in
mode tcp, on a memory-safe modern architecture, and passes N of HAProxy's own
reg-tests" is a claim that is true, verifiable, and complete. It is a far better thing
to have built than an incomplete attempt at all of mainline.
