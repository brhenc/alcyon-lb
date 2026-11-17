<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Design: adding and removing servers and backends at run time (T637, 2026-11-16)

Status: **design, no production code; the user decides before any slice starts.** Base: main
588abb16. Oracle: `/var/tmp/qwen-next-eval/oracle/haproxy`, 3.5-dev8-885761-29. HAProxy source
read: `~/reference/haproxy-3.5-latest` (VERSION 3.5-dev10, head 38e65c812); every `file:line`
below for HAProxy is in that tree. *(probed)* = I ran the oracle today, transcript in appendix A.
*(read)* = read in the source, not run. *(estimate)* = reasoned from the code named, not measured.
No Alcyon build or test was run for this document, and nothing was measured.

## 0. Short answers

1. **Recommendation: mechanism A, "published table, stable slots"** (§3.1, §4). The worker's one
   pointer to the proxies becomes a pointer to an immutable `Table`. A change builds a new table
   on the CLI worker and posts it to every worker through the existing mailbox; each worker swaps
   its pointer between two events. Server and backend numbers ("slots") never move. The counters
   that several threads write stay in storage that is shared by every table and only ever grows.
2. **The DELBE class of bug goes away by absence, not by a flag.** A deleted server is not in the
   new table's name index and its slot holds nothing. The server arrays become private to one
   module with one lookup, so no command can reach a deleted server by forgetting a check: there is
   no check to forget (§4.2).
3. **HAProxy never deletes a server that a stream holds.** `del server` is refused while the server
   has a stream, a queued request or a connection *(probed, read)*. The task file's summary is wrong
   on this point (§6). So in-flight streams need no reference count in Alcyon either: they need the
   refusal to be race-free, which a two-phase delete over the mailbox gives without stopping the
   threads (§4.3).
4. **T633 is settled as "published snapshot, cached per worker by generation"**: the map or ring is
   built once per change and shared, each worker keeps one pointer to it and re-fetches it when a
   generation it loads per pick has moved. No lock per pick, no copy per worker (§3.5).
5. **Cost** *(estimate)*: 0 to +30 instructions per request (under 0.1% of the 36.8k keep-alive
   figure), no new shared write, no allocation per request; memory at 60,000 backends about
   +1.5 MB for the table plus 2-3 MB for the name index, once per process, and the consolidation
   of the per-server arrays is expected to give more than that back. Build: 9 slices (§4.6).
6. **`qwen/delbe`**: keep its tests and its `publish`/`unpublish` behaviour; replace its three
   flags and its `del server`/`del backend` handlers (§5).
7. **Found on the way, existing on main:** every request of a frontend with `use_backend` or
   `default_backend` finds its backend by comparing names down the whole proxy list
   (`engine.rs:10418`, `:10428`). With 60,000 backends that is up to 60,000 string comparisons a
   request *(read, not measured)*. Slice S2 removes it.

## 1. What HAProxy does

### 1.1 Per command

`isolate` = `thread_isolate()` (other threads stopped at a safe point), `isolate_full` =
`thread_isolate_full()` (stopped with no temporary reference held either).

| command | code | stops threads | checks, in order | unlinks / builds | frees |
|---|---|---|---|---|---|
| `add server <be>/<srv> ...` | `cli_parse_add_server` server.c:6636 | isolate, 6688 to 6877 | admin level; `be/srv` form; backend exists; `be_supports_dynamic_srv` (backend.c:3096: the algorithm has `BE_LB_PROP_DYN`, the mode is not `log`); name free (6693); the server keywords, each of which must be `dynamic_ok` (4163); no resolution ever (6725); check and agent set up but **disabled** (6797, 6804); id taken from `first_unused_id` (6817) | `srv_alloc_lb` (6433, the algorithm's `server_init`: only chash allocates, lb_chash.c:584); into the id, name and address trees (6847-6854); `rid` from `srv_id_reuse_cnt` (6865); event (6875); the check tasks start after the release (6884-6891); **starts in forced maintenance, stopped** (3664-3669) so it is in no LB tree | on error, `srv_detach` + `srv_drop` (6914-6924) |
| `del server <be>/<srv>` | `cli_parse_delete_server` 7104 | isolate_full, 7122 to 7137 | `srv_check_for_deletion` 6960: backend, server, `SRV_F_NON_PURGEABLE \| SRV_F_NAME_REFD` (6981), in maintenance (6990), `srv_in_use` (7004; defined 6932: used connections, queue length, `srv_has_streams` (2097, a per-thread-group stream count), idle connections) | `srv_unregister` 7035: event, `release_server_track`, `check_purge` of check and agent (check.c:1605: a flag and a wake-up; the check's own task frees it and drops its reference on its thread, check.c:1276, 1482), the algorithm's `server_deinit`, CLI watchers moved to the next server, `srv_detach`, `SRV_F_DELETED`, `proxy_take`, out of the id/name/address trees, out of the GUID tree, out of each thread's idle tree, `srv_id_reuse_cnt \|= 1` | `srv_drop` 3275 after release: freed when the count reaches zero |
| `purge server <be>/<srv>` | `cli_parse_purge_server` 7151 | isolate_full | the same check in `PR_DEL_MODE_ASYNC`: a server not in maintenance is put there (6997) instead of refused | free now if unused; else `SRV_F_TO_PURGE`, on `be->servers_purge`, the backend's purge task in 50 ms (7177-7184) | `proxy_process_purge` proxy.c:557 with `proxy_purge_servers` 523, every 1 s, at most 50 servers a run, under isolate_full; it stops at the first server still in use (541) |
| `purge all servers <be>` | 7216, handler 7247 | isolate_full per run of 50 | per server as `purge server`; servers that cannot go are counted as skipped | as above | as above |
| `add backend <name> from <defproxy> [mode ..] [guid ..]` | `cli_parse_add_backend` proxy.c:5183 | isolate, 5259 to 5350 | name, `from`, known default proxy, a mode (explicit in the defaults or given), tcp or http only; name unused by any proxy or defaults | `alloc_new_proxy`, copy of the defaults, filters, `proxy_finalize`, **`PR_FL_BE_UNPUBLISHED` set** (5319), id from `dynpx_next_id`, into the id and name trees | `proxy_drop` on error |
| `del backend <name>` | `cli_parse_delete_backend` 5511 | isolate_full | `be_check_for_deletion` 5392: exists; not a `listen`; no stick-table; not `PR_FL_NON_PURGEABLE` (set on the target of a static `use_backend`/`default_backend`, 2182, 2260, and for QUIC servers, server.c:4267); tcp or http; unpublished; no server; `beconn == 0` | `be_unregister` 5474: watchers moved on, out of the id and name trees and the proxy list, `PR_FL_DELETED`, filters stopped, event | `proxy_drop` 499 after release |
| `purge backend <name>` | 5642 | isolate_full | as `del backend`, ASYNC: servers must all be flagged for purge | `PR_FL_TO_PURGE`, the purge task | the purge task, when `beconn == 0` (584-592) |
| `publish backend` / `unpublish backend` | 5610 / 5689 | isolate | backend exists (a frontend is "No such backend."); not disabled | clears / sets `PR_FL_BE_UNPUBLISHED`, cancels a pending purge, event | nothing |

What `PR_FL_BE_UNPUBLISHED` does: `be_is_eligible` (backend.h:93) is false, and the switching rules
skip the backend, a static rule as well as a dynamic one, and go on to the next rule, then to
`default_backend` if that is eligible, else the stream stays on the frontend (stream.c:1244-1280).
`force-be-switch` overrides it. `show stat` prints `UP (UNPUB)` (stats-proxy.c:1258).

### 1.2 Who holds a reference to a server

`srv_take` has four callers: `new_server` (server.c:3177, the proxy's list), the check and the
agent when they are set up (check.c:1981, 2044) and Lua (hlua_fcn.c:1802). **Streams and
connections take none.** They are covered by the refusal in `srv_in_use`, and `isolate_full`
makes that test and the unlink one atomic step. The reference count exists so that a check task or
a Lua object that still points at the server after the unlink does not point at freed memory.

Things that point at a server by name and block its deletion for good (`SRV_F_NAME_REFD`): a
static `use-server` (proxy.c:2313), a `track` target (server.c:7490), a server named in a sample
fetch argument (sample.c:1541). A server with DNS resolution is `SRV_F_NON_PURGEABLE`
(resolvers.c:2962), and a dynamic server cannot have one (server.c:6720; "'resolvers' option is
not accepted for dynamic server" *(probed)*).

### 1.3 The load-balancing algorithms

- A dynamic server is accepted only by the algorithms with `BE_LB_PROP_DYN`: roundrobin
  (lb_fwrr.c:677), leastconn (lb_fwlc.c:887), first (lb_fas.c:343), consistent hash
  (lb_chash.c:653), sticky (lb_ss.c:188), and `random` *(probed)*. The map-based ones refuse:
  `static-rr`, `balance uri` and `balance source` without `hash-type consistent` answer "Backend
  does not support dynamic servers : backend '<be>' uses a non dynamic load balancing method."
  *(probed)*. So a map (`lb_map.c`) never has to grow.
- A new server joins no tree at `add`: it is in maintenance. It enters through the ordinary
  `set_server_status_up` when the operator enables it. `server_init` only prepares per-server
  memory, and only chash has one.
- A server leaves the trees when it enters maintenance, which `del` requires. `server_deinit`
  frees per-server memory (chash's nodes lb_chash.c:601, leastconn's spare element lb_fwlc.c:87).
- `del server` is not restricted by algorithm: a server of a `static-rr` or map backend can be
  deleted.

### 1.4 What an operator sees *(probed, appendix A)*

- After `del server be/s1`: `del`, `enable`, `disable`, `set server ... state ready` and
  `set server ... weight` all answer "No such server."; the server is gone from
  `show servers state` and `show stat`.
- `add server be/s1 ...` under the deleted name: "New server registered."; the server gets id 1
  again (the lowest free id) but is listed **last**, after s2 and s3, in maintenance
  (`srv_op_state 0`, `srv_admin_state 1`).
- A deleted backend's name: `del backend`, `publish backend`, `add server` answer "No such
  backend."; `show servers state nb` answers "Can't find backend."; `add backend nb from dflt`
  works again and the new one is listed last.
- A request whose dynamic `use_backend` names an unpublished or unknown backend is served by
  `default_backend`.
- **The oracle (dev8) has no `purge` command at all** ("Unknown command: 'purge'"). The dev10
  reference binary has them (appendix A.4).
- `del backend` on the oracle prints leftover notices of earlier commands before its own answer
  ("Server nb/a is going DOWN for maintenance. ..." then "Backend deleted."). `cli_parse_delete_backend`
  answers with `cli_umsg` and never calls `usermsgs_clr` (proxy.c:5511-5545, still so in dev10).
  This looks like an upstream defect, not behaviour to copy (decision D3).
- On the oracle, `del server` succeeded on a server in maintenance that `show servers conn` still
  listed with one idle connection (A.3). On dev10 the idle connection was already gone after
  `disable server`. The dev10 source refuses while `curr_idle_conns` is non-zero.

## 2. What holds a server or backend number in Alcyon

A server is a position in about 25 parallel arrays on `Proxy`, each a `pub` field, fixed in length
at load. `Proxies` is `Arc<Vec<Proxy>>` (`engine.rs:1904`), one clone of the pointer per worker,
and a backend is a position in it. Counted today: **about 190 places** outside `lb.rs` read a
server array's length or walk one, and **10 places** find a server by name with their own
`server_ids.iter().position(..)`. Those 10 are why a flag cannot work: each needs the check.

"Hold" = what must be true while a stream is attached to the server.

### 2.1 Servers

| holder | where | on add | on delete | while a stream holds the server |
|---|---|---|---|---|
| Name lookups, each its own scan | `applet.rs:1750`, `:1986-1998` (`find_server`), `engine.rs:5468`, `:9185`, `:9209`, `:13626`, `proxy_state.rs:118` (the `srv_*` fetches), `track.rs:147`, `rule_compiled.rs:521`, `server_state.rs:386-413` | the name must resolve on every worker once the command has answered | the name must stop resolving everywhere at once | nothing |
| Shared hot state, fixed-size: `server_statuses` `Arc<Vec<AtomicU8>>` (`engine.rs:1978`), `server_weights` (`:1984`, `srv_rt.rs:131`), `server_maxconn` (`:2024`), `server_actconn` (`:2025`), `server_sess_rates` (`:2030`), `servers` addresses (`:1973`, `srv_rt.rs:267`), `server_ids` names (`:1974`, `srv_rt.rs:436`) | need a slot; all are `Arc<[..]>` or `Arc<Vec<..>>` that cannot grow | the slot must read as "not a server" | the stream's slot must keep meaning the same server: `server_actconn` is decremented by number at the end (`engine.rs:4000`) |
| Cold per-server config, plain `Vec` on `Proxy`: `server_cookies` (`:1977`), `server_backups` (`:2017`), `server_send_proxy`, `server_tfo`, `server_send_proxy_v2`, `server_pp_unique_id` (`:2011-2016`), `server_name_refd` (`:2021`), `server_check_configs` (`:2033`), `server_tls` (`:2035`), `server_check_tls` (`:2038`), `server_track` (`:1980`), `ids.server_puids` and `server_forced_ids` (`:1820`, `:1823`), `ids.server_cmaint` (`:1829`), `ids.server_restored` (`:1869`); and one more shared array, `ids.server_rmaint` `Arc<Vec<AtomicU8>>` (`:1835`) | `Proxy` is immutable inside the `Arc`: there is no way to add an element today | must stop being read | read by number during connect (`engine.rs:13212`, `:17021` for the cookie) |
| **A server found by its address** | `engine.rs:8630` and `:10048`: `servers.iter().position(\|s\| s == addr)`, and `ServerAddrs::position` (`srv_rt.rs:305`, "the first server at `a`") | two servers may share an address (every probe config in appendix A does): the stream is booked on the first one. Existing on main; an added server makes it likelier | the reverse lookup must go: the pick already knows the number | a stream booked on the wrong server blocks the wrong delete |
| `server_retr` | `engine.rs:2028`, a `Mutex<HashMap<usize, ..>>` by number | nothing | the entry must go, or a re-used number inherits the counts | nothing |
| The stream | `target_server_idx` + `srv_backend_idx` (`engine.rs:2420-2424`), read at `:3574`, `:3813`, `:4000` | nothing | must be impossible (HAProxy refuses) | the number is the reference. A server without `maxconn` is **not** counted in `server_actconn` between the pick and the connection's first use (`engine.rs:15063-15065`), so the shared count cannot say whether a stream holds it; each worker's own streams can (`engine.rs:5985` matches them for `shutdown sessions server`) |
| The queue | `QueueWait.srv` + `be_idx` (`proxy.rs:195-199`) | nothing | a queued request counts as "in use" | the same |
| Idle connections | `IdlePools` (`engine.rs:441`): `dense` sized at start through `DenseIdx` (`:156`, `[backend][server]` offsets), and an `RwLock<HashMap<(usize, usize), ..>>` for servers it does not cover (`:449`) | a new server would fall into the `RwLock` map: a lock per request on a path that has none | idle connections must be closed and counted as "in use" until then | a kept connection carries `(backend, server)` in `IdleKey` (`engine.rs:76-79`); another worker may take it (`engine.rs:741`, `:841` `may_steal`), only for a stream already assigned to that server (`:15187`) |
| Round robin | `Fwrr` (`lb.rs:132`): one `Mutex` per backend, `built_from` by number, rebuilt when the length differs (`lb.rs:413`) | grows on the length check | the server is already at weight 0 | picks are checked with `is_server_available` (`lb.rs:49`) |
| Hash map and ring | `WeightMap` (`lb.rs:685`), `Ring` (`:881`), `ChashRing` (`:903`): two `RwLock`s, checked per pick (T633) | the ring gains points when the server comes up; the map never (HAProxy refuses the add) | already out | the same check |
| static-rr, random, leastconn, first | `next_server_idx` (`engine.rs:1985`, `:2362`), `lb.rs:436-592`: scans over `0..servers.len()` | the scan length grows | the scan must skip the slot | nothing |
| The retry's "avoid" | `AVOID` thread-local `(proxy.id, idx)` (`lb.rs:12-30`) | nothing | cleared within the request | nothing |
| `use-server` | `Rule.server` resolved at load (`rule_compiled.rs:325`, T632) | nothing | HAProxy refuses the delete (`SRV_F_NAME_REFD`): the server needs that mark | nothing |
| `srv_*` fetches | by name per evaluation (`proxy_state.rs:113-124`); `server_name_refd` marks the named servers | nothing | HAProxy refuses the delete for a named server | nothing |
| Server tracking | `server_track` (`engine.rs:1980`), `track.rs:46-147` | a dynamic server may track (probed: "New server registered."); a dynamic server cannot be tracked (server.c:7450) | a tracked server is refused; a tracker leaves its target's list | nothing |
| Health checks and agents | `ServerCheckState { proxy_idx, server_idx }` (`check.rs:209-212`), built at `engine.rs:5206-5223`, owned by worker 0 (`engine.rs:5674`) | worker 0 creates one, disabled | worker 0 removes it; HAProxy `check_purge` | nothing |
| Resolvers | `resolvers.rs:596-900`, by `(proxy, server)`, worker 0 | never: a dynamic server has no resolver | never: such a server is not purgeable | nothing |
| Stick tables | `server_id: Option<u32>` in the entry (`alcyon-stick-table/src/entry.rs:106`), stored at `engine.rs:16341` | an entry holding the id of a deleted server points at whichever server has that id now (HAProxy too: ids are re-used, probed) | the id stops resolving: no persistence | nothing |
| Persistence cookie | value to server by scan (`cookie.rs:314`), `server_cookies` | the new value must match | the old value must stop matching | nothing |
| Counters | `CounterTable` (`statcnt.rs:433`): `2 + servers` rows per proxy, spans fixed at `new` (`:450-458`), one slab per worker; `:534` says "Alcyon has no `add server`" | rows for the new server on every worker | the rows must read zero when the number is used again | written by number |
| The log line | the server's name is read by number when the stream ends (`engine.rs:3574-3576`) | nothing | nothing | the name must still be the server's |
| Listings | `show stat` cursor (`stats.rs:1236-1284`), HTML and JSON (`stats_html.rs:1211`, `:1251`), Prometheus (`promex.rs:344`), `show servers state` (`server_state.rs:195`, `:209`), state file load (`:382-413`), server logs (`srvlog.rs:112`, `:206`) | listed, last | not listed; a cursor that yielded mid-backend must not skip or repeat others | nothing |
| Messages between workers | `SessFilter::Server { be, srv }` (`mailbox.rs:57`), `SessSnap.srv` (`:82`) | nothing | a number in a message in flight must not be re-used before it is handled | nothing |

### 2.2 Backends

| holder | where | on add | on delete |
|---|---|---|---|
| The array | `Proxies(Arc<Vec<Proxy>>)` (`engine.rs:1904`); `Proxy.id` is the position | cannot grow | cannot shrink; every other number would move |
| Routing by name, per request | `resolve_backend` (`engine.rs:10398-10432`): `proxies.iter().position(\|p\| p.name == ..)` for each matching `use_backend` and for `default_backend`; also `:10490`, `:13024`, `:13624` | must find the new one once published | must stop finding it |
| Other lookups by name | `ProxiesView::backend` (`proxy_state.rs:69`), `applet.rs:1054`, `:1401`, `:1468`, `engine.rs:9179`, `:14018`, `server_state.rs:348`, `:386`; table names at `engine.rs:7728-8111`, `:14685` | as above | as above; a backend with a stick-table is refused by HAProxy |
| The stream | `backend_idx`, `srv_backend_idx` (`engine.rs:2419-2423`), `be_streams` (`:9780`) | nothing | refused while `beconn` is non-zero |
| Per-worker tables sized at start | `CounterTable.spans` and `epochs` (`statcnt.rs:435-440`), `DenseIdx.offs` (`engine.rs:157`), `ProxyStats` | rows and offsets for the new backend | rows zeroed before re-use |
| `disabled_backends` | `engine.rs:2004` | a new name must not collide | nothing |
| The existing CLI stub | `applet.rs:619`, `:881`: `del backend` prints HAProxy's refusals and deletes nothing | | replaced in S6 |
| Memory test | `tests/backend_memory.rs`: 10,000 backends (`:21`), bound 10 KB of heap per backend (`:62`) | | |

## 3. Mechanisms

### 3.1 A: published table, stable slots (recommended)

**Shape.**

```
Proxies(Arc<Table>)                       one pointer per worker, as today
Table   { epoch: u64,
          chunks: Vec<Arc<[Arc<Proxy>; 1024]>>,   slot -> proxy; a slot never moves
          by_name: HashMap<Arc<str>, u32>,        live backends only
          live: Vec<u32> }                        listing order
Proxy   { ..as today.., set: Arc<ServerSet> }
ServerSet { conf: Box<[Option<ServerConf>]>,      by slot; None = no server here
            by_name, by_puid, live: Box<[u32]>,   live servers only; listing order
            cells: Arc<ServerCells> }             the SAME object in every table
ServerCells { base: Box<[Cell]>,                  the servers of the configuration
              more: [OnceLock<Box<[Cell]>>; 16] } added later; doubling sizes; never freed while the backend lives
Cell    { status: AtomicU8, weight, maxconn, actconn, rate, addr (the seqlock), idle count }
```

- **Immutable and republished:** what exists, what it is called, its cold configuration.
- **Shared and stable:** what several threads write. A worker still on the previous table and a
  worker on the new one write the same `Cell`, so no count is lost in between.
- **A change** (CLI worker, cold): take the one `change` mutex (CLI only, never on the request
  path), build the new `ServerSet`, clone the one `Proxy` (its mutable state is behind `Arc`s
  already: `engine.rs:1898-1902`), copy the chunk it sits in (1,024 pointers) and the chunk list,
  post `Msg::Table(Arc<Table>)` to every worker, swap its own. A worker swaps at the top of its
  loop, where it handles the mailbox today (`engine.rs:5911`), and replies with the epoch.
- `OnceLock` is std and safe; reading it is one load. No new crate.

**Memory at 60,000 backends** *(estimate)*: 8 B of chunk pointer and 16 B of `Arc` header per
backend, 1.4 MB; `by_name` about 40 B per backend, 2.4 MB; the `ServerSet` header about 100 B per
backend, 6 MB, against roughly 15 separate per-server allocations per backend that it replaces
(each a 16-24 B header plus allocator overhead), so the net is expected to be negative. All of it
once per process, nothing per worker. During a change: one chunk (8 KB), the chunk list (59
pointers), one `Proxy` clone and one `ServerSet`, freed when the last worker has swapped.
`backend_memory` (10,000 backends, bound 10 KB each) is the test that decides.

**Instructions per request** *(estimate)*: `proxies[be]` goes from an index into `Vec<Proxy>` to
chunk pointer plus `Arc` pointer: +2 loads at each of the 5 to 15 places a request does it. A
per-server read goes `proxy -> set -> cells.base[i]` where today it goes `proxy -> Arc<Vec> ->
data`: the same number of loads, and the test `i < base.len()` is the bounds check
`server_statuses.get(i)` already makes (`lb.rs:54`). A server added at run time costs one more
branch and a `OnceLock` load. Total: 0 to +30 instructions on 36.8k (keep-alive), under 0.1%,
budget +0.5%. No shared write, no lock, no allocation. With `use_backend` or `default_backend`
the figure should fall, by the cost of the name scan (§0 item 7).

**A worker mid-request when the set changes:** it does not notice. It swaps between two events,
so one event sees one table. A stream that spans the swap keeps its numbers, which mean the same
server and backend in both tables.

**In-flight streams and a deleted server:** there are none, as in HAProxy; §4.3 makes the refusal
race-free. A number is given to a new server only after every worker has replied to the table
that removed the old one, so a number in a message, a cursor or an LB structure cannot name the
wrong server.

**T633:** the table is the "published immutable snapshot read with a plain load" T633 was missing.
See §3.5.

### 3.2 B: a copy per worker, rebuilt on a generation bump

Each worker owns its proxies and rebuilds what changed when a shared generation moves.

- **Memory:** the heap bound is 10 KB per backend; 60,000 backends is 600 MB per copy, 38 GB at 64
  workers. Copying only the server arrays (about 1 KB per backend) is still 3.8 GB.
- **Instructions:** one generation load per request, +2 to +3.
- **Mid-request:** the worker rebuilds at its next generation check; the counts that must be
  shared (`actconn`, `maxconn`, status) cannot be copied at all, so it needs A's shared cells
  anyway.
- **In-flight streams:** as A.
- **T633:** this is T633's option 1 applied to everything.
- **Verdict: no**, on memory. The idea is right for one small thing: a worker's pointer to the
  current LB snapshot (§3.5).

### 3.3 C: stable slots with a tombstone, nothing republished

The arrays become append-only segments (`ServerCells` above for every array); a deleted server's
status byte says "gone"; one lookup function skips gone slots.

- **Memory:** as A without the table, about 4 MB less at 60,000 backends. But a slot cannot be
  given back: its cold configuration (name, cookie, TLS) is write-once, because replacing a value
  that other threads read needs a lock per read, an `Arc` swap primitive that std does not have,
  or `unsafe`. Every add/delete cycle keeps roughly 200 to 300 B for the life of the process. An
  ingress controller doing 100,000 cycles a day leaks about 25 MB a day.
- **Instructions:** the lowest: +0 for configured servers, +1 branch for added ones.
- **Mid-request:** nothing to do; there is only one copy.
- **In-flight streams:** as A.
- **T633:** gives it nothing; T633 must take per-worker copies (its option 1).
- **Verdict: no** as the end state: an unbounded leak under the one workload this feature exists
  for, and the "gone" byte is still a flag that every new reader of an array must remember. A's
  slots, cells and status gate are exactly C's; A adds the republished part so that a slot can be
  re-used and so that a deleted server is absent instead of flagged.

### 3.4 A stream's hold on a server, state by state

The states are the same for A, B and C, because all three keep the number as the reference and
refuse the delete while one exists; they differ in what a wrong step would cost.

| the stream is | what records it | counted by `Retire` as | A | B | C |
|---|---|---|---|---|---|
| picked, slot taken, not connected | `target_server_idx`; `server_actconn` only if the server has a `maxconn` | a stream | number valid in old and new table | valid in each worker's copy only until that worker rebuilds: a rebuild that compacts would break it, so B needs stable numbers too | valid |
| queued for the server | `QueueWait.srv` (`proxy.rs:199`) | a queued request | valid | as above | valid |
| connecting, connected, response in progress | `target_server_idx`, `srv_backend_idx` | a stream | valid | as above | valid |
| between two requests with the server connection kept on the stream | `srv_backend_idx` outlives the routing (`engine.rs:2420-2422`) | a stream | valid | as above | valid |
| gone, its connection idle in a pool | `IdleKey.srv` | an idle connection; the worker closes it in the handler | valid; closed before the commit | as above | valid |
| retrying or redispatching away | gives the slot back, takes another through `take` | not on this server any more | `take` refuses `Retiring` | the same, if every copy sees the status: it must be shared | the same |
| ending, writing its log line | reads the name by number | a stream until it is released | the name is in the worker's table | in its copy | in the write-once slot |
| a health check in flight | worker 0's `ServerCheckState` | not counted; worker 0 is the CLI worker and cancels it in the command | cancelled | the same | the same |

If the protocol had a hole and a stream kept a number past the delete: under A the number reads
`None` in the new table until the slot is re-used, then another server **of the same backend**;
under C it reads the dead server's frozen data for ever; under B it reads whatever the worker's
copy holds. None of the three can read freed memory or index out of bounds: every access is
bounds-checked safe Rust. HAProxy, in the same situation, would use a freed `struct server`,
which is why it needs `isolate_full` and the reference count and Alcyon needs neither.

### 3.5 T633, settled

- Keep T633's generation counter, bumped where a weight or state is written and where the set
  changes (`Fwrr::changed`, `lb.rs:137`).
- The map or ring is immutable once built and lives in an `Arc`. The current one sits behind a
  mutex that is taken **only when the generation has moved**.
- Each worker keeps `(generation, Arc<LbSnap>)` for the hash-balanced backends it has picked on.
  Per pick: one `Acquire` load of the generation, one compare, one read through the worker's own
  pointer. On a miss: lock, rebuild if nobody has yet, clone the `Arc`, unlock.
- So: no lock and no server scan per pick (T633's "done when"), one copy of the map per backend
  instead of one per worker, and no reference-count write per pick. The clone happens once per
  worker per change.
- The worker's cache is an index arena under rule 8 (`alcyon_alloc::Arena`, memory design §3.7):
  16 B per hash-balanced backend per worker, listed in `show pools`.
- Mass events (a thousand servers going down in a second) cost one rebuild per pick-after-change
  on the first worker to notice, not one message per event: the generation coalesces them.
- A server added at run time changes nothing at `add` (it is in maintenance); the ring gains its
  points when it is enabled, through the same generation bump.

## 4. Recommendation: A

### 4.1 What it commits to

- A server is `(backend slot, server slot)`, two `u32`, for its whole life. Streams, the queue,
  idle connections, checks, messages and the LB structures keep holding numbers. Nothing on the
  request path counts references.
- A change of the set is serialised, built off the request path, and visible to a worker from the
  top of its next loop pass. The command answers after every worker has replied.
- Nothing is freed under a reader: old tables go when the last worker drops its pointer.

### 4.2 Why the DELBE bug cannot be written

- `ServerSet`'s fields are private to one module (`srv_set.rs`). There are four ways to a server:
  `find(name)`, `by_puid(id)`, `live()`, `at(slot)`. Each returns `Option<Srv<'_>>` or an iterator
  of `Srv`, and `Srv` cannot be built anywhere else. Every per-server read and write is a method
  of `Srv`.
- A deleted server is not in `by_name`, `by_puid` or `live`, and `conf[slot]` is `None`. `enable
  server be/s1` calls `find`, gets `None`, and answers "No such server." with no code written for
  the case. The same holds for the stats rows, `show servers state`, the cookie match, the
  `srv_*` fetches.
- The same for backends: `Table::backend(name)`, `Table::live()`, `Table::at(slot)`. A deleted
  backend's slot points at one shared empty `Proxy` (no backend, no servers, empty name), so a
  stale number reads nothing instead of panicking or reading freed memory, and the real one's
  memory is released.
- `unpublished` is a state, not an absence, and it is read in exactly one function,
  `Table::route`, which `resolve_backend` calls for every rule and for the default.
- A harness check keeps it so: `harness/server_set_census.py` fails on any access to a per-server
  array outside `srv_set.rs` (slice S1 writes it first and watches it report today's ~190).

### 4.3 Delete without stopping the threads

Safe Rust has no `thread_isolate_full`: Alcyon cannot stop the other workers and inspect their
streams. The mailbox (`mailbox.rs`, T218) gives the same result in two phases.

1. **Close the door.** Under the `change` mutex the CLI worker validates (exists, not referenced,
   in maintenance) and sets the server's status byte to `Retiring`. Every assignment of a stream
   to a server must go through one function, `Srv::take`. Today it does not quite:
   `take_server_slot` (`engine.rs:2311`) has four callers (`:9017`, `:10053`, `:15067-15070`,
   `:15408`), `target_server_idx` is written at five places (`:10065`, `:10070`, `:15170`,
   `:15424`, and `:8630`, which takes no slot and finds the server by address). S1b makes `take`
   the only way to get the value a stream stores. The LB picks already require status `Up`
   (`lb.rs:54`), and `take` refuses `Retiring` for the paths that may choose a server in
   maintenance (persistence, `use-server`). An idle connection is taken, from this worker or
   stolen from another, only for a stream that has passed `take`, so none moves between workers
   once the door is closed. No instruction is added to a pick: it is the load of the status byte
   that is there now.
2. **Count.** The CLI worker posts `Msg::Retire { be, srv }`; each worker answers, from the top of
   its loop, how many streams, queued requests and idle connections it has on that server, and
   closes its idle ones. An assignment that began before step 1 has finished by the time its
   worker answers, so it is counted.
3. **Commit or roll back.** Sum zero: set the status to `Gone`, publish the table without the
   server, wait for every worker's reply to the table, answer "Server deleted." Otherwise set the
   status back to maintenance and answer "Server still has connections attached to it, cannot
   remove it."

Between the commit and a worker's swap, that worker's table still has the name. It cannot use
it: the status byte lives in the shared `Cell`, reads `Gone`, and `take` refuses. A stats page
served by that worker in that interval may still list the server; none does once the command has
answered. The next change starts only after these replies, so a freed slot is always safe to
re-use by then.

`del backend` is the same with the backend's state and `be_streams`: `Table::route` refuses a
`Retiring` backend, and entry is "increment `be_streams`, then check the state".

### 4.4 Each holder of §2 under A

| holder | becomes |
|---|---|
| 10 name scans | `ServerSet::find`. Small sets scan `live`; above 8 servers a hash map |
| hot shared state | fields of `Cell` in `ServerCells`; includes the idle count, so `DenseIdx` and the `RwLock` map of `IdlePools` go |
| cold config | `ServerConf`, one array per `ServerSet` |
| stream, queue, messages | unchanged: numbers |
| `Fwrr` | resizes on the generation, as it does on the length today |
| map, ring | §3.5 |
| scans (first, leastconn, random, static-rr) | iterate `live` |
| `use-server`, `srv_*` fetch arguments, `track` targets | mark the server referenced at load; `del` answers HAProxy's refusal |
| checks | worker 0 is the CLI worker and owns them: it adds or removes the `ServerCheckState` in the command |
| resolvers | untouched; `add server` refuses `resolvers`, and a server with one is not deletable |
| stick `server_id`, cookie | resolve through `by_puid` / `live`; a miss means no persistence |
| counters | rows for an added server come from a second span per proxy in segments each worker creates for itself; a re-used slot starts from a bumped per-slot epoch, as `clear counters` does per proxy (`statcnt.rs:436-442`) |
| listings | iterate `live`; a cursor remembers the last slot it printed and continues after it in whichever table is current |
| backend routing | static rules and `default_backend` resolved to a slot at load (HAProxy refuses to delete their target); dynamic names through `by_name` |

### 4.5 Where Alcyon will differ from HAProxy

- **No isolation.** `del server`, `del backend` and `add` answer after one mailbox round, normally
  well under a millisecond, bounded by the busiest worker's current event. HAProxy answers inside
  the isolation. Both wait for every thread. Commands that change the set run one at a time.
- **Memory is released later.** A deleted server's memory goes when the last worker has swapped,
  not when a count reaches zero. The `Cell` of a deleted server stays allocated until its slot is
  re-used; a deleted backend's cells go with its `Proxy`.
- **`add server` keywords.** Alcyon accepts a keyword only if it implements it for configured
  servers and HAProxy marks it `dynamic_ok`; anything else is refused with HAProxy's "'<kw>'
  option is not accepted for dynamic server" (rule 5: no keyword parsed and dropped). The list is
  slice S5's first deliverable, taken from `add server help` on the oracle.
- **Events, Lua, GUID.** HAProxy publishes `EVENT_HDL_SUB_SERVER_ADD/DEL` and
  `PROXY_ADD/DEL/PUB/UNPUB`; Alcyon has no subscriber. `add backend ... guid` is refused unless
  S6 finds a GUID tree to put it in.
- **`rid`.** HAProxy gives a re-created server a re-use count (server.c:6853-6861). Alcyon's
  per-slot epoch plays that part; whether it must be printed anywhere is checked in S5.
- **`del backend` answer.** One line, "Backend deleted.", without the leftover notices (D3:
  HAProxy's output is treated as a defect; `docs/differences.md`).

### 4.6 Slices

Each is sized under about 250k agent tokens, writes its tests first and watches them fail (rule
1), names the line where the command reaches the data path (rule 5), and reports
instructions per request before and after where it touches the request path (rule 8). Oracle rows
are the lines of appendix A, re-run on the oracle by the slice.

| | what | red first | oracle rows |
|---|---|---|---|
| S1a | `srv_set.rs`: `ServerSet`, `Srv`, `find`/`live`/`at`. Move the cold readers onto it: `applet.rs`, `stats*.rs`, `promex.rs`, `server_state.rs`, `track.rs`, `proxy_state.rs`, `srvlog.rs`, `check.rs`, `resolvers.rs`, `cookie.rs`. No behaviour change | `harness/server_set_census.py` (counts direct array access; ratchet) | none: the existing suite is the spec |
| S1b | The same for `engine.rs` and `lb.rs`; the arrays become private; `ServerCells` with `base` only. ins/req and `backend_memory` before and after | census at zero outside `srv_set.rs` | none |
| S2 | `Table`: chunks, `by_name`, `live`, `route`; static `use_backend`/`default_backend` resolved at load; `Msg::Table` and the epoch reply | a debug counter of backend-name comparisons per request, 0 expected, as T632 did for servers (`rule_compiled.rs:520`); a test that swaps a table under running workers | none |
| S3 | `publish backend`, `unpublish backend`, `(UNPUB)` in the stats | qwen/delbe's tests for these | A.3: publish, unpublish, the dynamic rule falling to the default, `publish backend fe` |
| S4 | `del server`: §4.3, the referenced-server refusals | "after `del`, `enable`/`disable`/`set server` answer No such server."; the in-flight refusal | A.1 del rows; A.3 slow-server rows |
| S5 | `add server`: keyword table, slot and id allocation, re-use after the epoch reply, cells and counter segments, the check created disabled | re-add under a deleted name; traffic reaches an added, enabled server; allocation test: 1,100 requests to an added server allocate what 100 do | A.1 re-add rows; A.2 algorithm rows |
| S6 | `add backend`, `del backend`; named `defaults` kept after load (verify first whether they are) | add, route by dynamic rule, delete, add again | A.2 `add backend` rows; A.3 `del backend` rows |
| S7 | T633 as §3.5. Independent of S2-S6, needs S1b | T633's counter test | T633's rows |
| S8 | `purge server`, `purge all servers`, `purge backend`: maintenance, a flag on the server, a 1 s task on worker 0 that re-runs §4.3 | scheduled purge completes when the stream ends | A.4, **dev10, not the oracle** (D1) |
| S9 | V&V: add/enable/disable/delete churn under load on d13-test; RSS and `show pools` flat; no pick of a deleted server; ins/req on the release-perf build | the leak check | none |

Order: S1a, S1b, S2, then S3 to S6 in order; S7 any time after S1b. At the measured 2.5 h a slice
that is about 25 h of agent time.

## 5. `qwen/delbe` (65bf7708, held)

**Keep**

- `tests/it/cli_unpublish_del_backend.rs` (380 lines): the oracle rows for `publish`,
  `unpublish`, the `del backend` refusals and `del server`'s basic answers. It becomes the spec of
  S3, S4 and S6, with the rows it lacks added first (below).
- `handle_be_publish` and the `(UNPUB)` status: correct against the probe. In S3 the flag moves
  into the backend's shared state and its only reader becomes `Table::route`.
- The order of `del backend`'s refusals, which matches `be_check_for_deletion` and the probe.

**Replace**

- `BackendCliState.deleted` and `server_gone`, `Proxy::is_deleted`, `srv_gone`,
  `attached_srv_count`, `server_gone_slot`, and the `is_deleted()`/`srv_gone()` tests added to
  the stats cursor and the CLI. They do not fit: they are per-reader flags, the thing this design
  removes. Under A the server or backend is absent from the table.
- `handle_del_server`: it has no "This server cannot be removed at runtime due to other
  configuration elements pointing to it." (a `use-server` target, a tracked server, a server named
  in a fetch) and no "Server still has connections attached to it, cannot remove it." Both are in
  the oracle (A.1, A.3).
- `handle_del_backend`'s comment that "Backend still has attached streams on it." cannot be
  reached: a dynamic `use_backend %[..]` sends streams to a backend no rule names (A.3 does it).

**Rows its tests lack** (each failed in review or is missing): `enable server`, `disable server`,
`set server ... state`, `set server ... weight` after `del server`; re-add under the same name;
the two refusals above; `del backend` with a stream in flight.

**How to land it** (rule 9): leave the branch held until S3. Then merge 65bf7708 unmodified, with
the replacements above as separate commits on top in the same merge, each saying what it changed
in the model's code, and regenerate `LOCAL-MODELS.md`. Its tombstones are not kept in any form.

## 6. Where the task file is wrong or out of date

1. "The server's memory lives on, with `SRV_F_DELETED` set, while streams still hold a reference":
   streams never do. `srv_check_for_deletion` refuses while `srv_in_use` (server.c:6932, 7001),
   and the oracle answers "Server still has connections attached to it, cannot remove it." (A.3).
   The count is held by the check, the agent and Lua (§1.2).
2. `purge server` and `purge backend` are not in the oracle binary (dev8). They are in the dev10
   source and reference binary.
3. "The 60,000-backend memory configuration (`backend_memory`)": the test builds 10,000 backends
   (`tests/backend_memory.rs:21`). 60,000 is T304's servers-of-one-backend figure.
4. T633's line numbers have moved: `map_pick` is `lb.rs:917`, `ring` is `:941`.
5. Not checked: that `enable server be/s1` revives the server on `qwen/delbe`. I read the diff
   (nothing in `find_server` tests `srv_gone`, so it follows) but built and ran nothing.
6. Missing from the inventory: a server is also identified by its **address** at two places on the
   request path (§2.1), and the idle-connection index and the counter table are sized per worker
   at start.

## 7. Decisions for the user

- **D1. Oracle for `purge`.** The dev8 oracle does not have it. Either S8 is written against the
  dev10 reference binary (`~/reference/haproxy-quic`, rows in A.4), or `purge` waits for an oracle
  bump and the parser answers "Unknown command" as dev8 does. I would defer S8: nothing else in
  the plan depends on it.
- **D2. Go or no-go, and when.** Nine slices, about 25 h of agent time, and S1 touches about 190
  places in the request path's files. It is a refactor before any visible feature. The
  alternative that ships sooner is S1 to S3 only (publish/unpublish plus the routing fix) and the
  rest after M-level stability work.
- **D3. `del backend`'s answer.** HAProxy prints leftover notices before "Backend deleted." (§1.4).
  Copy it byte for byte, or print the one line and treat HAProxy's as a defect. If the second,
  whether to send it upstream is yours to route.
- **D4. The release gap.** Memory of a deleted server or backend is held until every worker has
  swapped, and a deleted server's `Cell` (about 64 B) until its slot is re-used. Accept, or ask
  for a design that frees cells too (it needs a second published level and costs one more load per
  server read).
- **D5. No cap.** HAProxy has no limit on servers added at run time and I propose none. If you
  want one as a guard for the 10 KB-per-backend bound, it would be a `tune.alcyon.*` setting and
  a divergence.
- **D6. T633's text.** §3.5 replaces its "option 1 or option 2" with a third: update the task
  before it starts.
- No new crate is needed. `arc-swap` would shorten S2, but it is a dependency with `unsafe`
  inside, and the mailbox does the job.

**Answers (user, 2026-11-17 ~06:30):**
- **D1:** `purge` is deferred until the oracle moves to dev11. Until then the parser answers
  "Unknown command", as dev8 does.
  Revised 2026-11-17 (user): `purge` is new in 3.5-dev, so it stays deferred until the 3.6 LTS
  oracle (tradeoff 6.36), even though the oracle is now dev11. S8 waits for that.
- **D2:** go. Claude Sonnet agents build the structural core, S1a, S1b and S2. S3 to S6 and S7
  are local-model (Qwen) cases on top of it. S9 is V&V.
- **D3:** HAProxy's leftover notices are a defect. `del backend` answers the one line, recorded
  in `docs/differences.md`.
- **D4:** the release gap is accepted.
- **D5:** no cap.
- **D6:** T633 is updated to §3.5.

## Appendix A. Oracle probes (2026-11-16)

All on `/var/tmp/qwen-next-eval/oracle/haproxy` (3.5-dev8-885761-29) except A.4. Started with
`haproxy -f <cfg> -D`, commands sent one per connection to `/tmp/t637.sock`. Backends were Python
listeners on 127.0.0.1: 18638 and 18642 answer at once with their port as the body and close;
18643 answers after 3 s; 18644 keeps the connection alive. Long `show` lines are cut.

### A.1 Servers: delete, re-add (config p1)

```
global
    stats socket /tmp/t637.sock mode 600 level admin
    nbthread 2
defaults dnomode
    timeout connect 1s
    timeout client 5s
    timeout server 5s
defaults dflt
    mode http
    timeout connect 1s
    timeout client 5s
    timeout server 5s
frontend fe
    bind 127.0.0.1:18637
    use_backend %[req.hdr(x-be)] if { req.hdr(x-be) -m found }
    use_backend be_ref if { path /ref }
    default_backend be
backend be
    server s1 127.0.0.1:18638
    server s2 127.0.0.1:18639 check
    server s3 127.0.0.1:18640
    use-server s3 if { path /s3 }
backend be_ref
    server r1 127.0.0.1:18638
backend be_static
    balance static-rr
    server x1 127.0.0.1:18638
backend be_chash
    balance uri
    hash-type consistent
    server c1 127.0.0.1:18638
backend be_trk
    server t1 127.0.0.1:18638 track be/s2
backend be_tbl
    stick-table type ip size 10
    server q1 127.0.0.1:18638
listen li
    bind 127.0.0.1:18641
    server l1 127.0.0.1:18638
```

(The run also had a `be_uri` backend; both hash backends were first placed under the wrong
defaults and fell back to round robin, so their rows are taken from A.2 instead.)

```
$ del server be                      Require 'backend/server'.
$ del server nope/s1                 No such backend.
$ del server be/nope                 No such server.
$ del server be/s1                   Only servers in maintenance mode can be deleted.
$ del server be/s3                   This server cannot be removed at runtime due to other configuration elements pointing to it.
$ del server be/s2                   This server cannot be removed at runtime due to other configuration elements pointing to it.
$ disable server be/s1               (empty)
$ del server be/s1                   Server deleted.
$ del server be/s1                   No such server.
$ enable server be/s1                No such server.
$ disable server be/s1               No such server.
$ set server be/s1 state ready       No such server.
$ set server be/s1 weight 10         No such server.
$ show servers state be              3 be 2 s2 127.0.0.1 2 0 1 1 ...
                                     3 be 3 s3 127.0.0.1 2 0 1 1 ...
$ show stat 3 4 -1                   rows be,s2 and be,s3 only
$ add server be/s1 127.0.0.1:18642   New server registered.
$ add server be/s1 127.0.0.1:18642   Already exists a server with the same name in backend.
$ show servers state be              3 be 2 s2 ... / 3 be 3 s3 ... / 3 be 1 s1 127.0.0.1 0 1 1 1 0 ... 18642
$ enable server be/s1                (empty)
$ show servers state be              ... / 3 be 1 s1 127.0.0.1 2 0 1 1 0 ...
$ add server be/s4 127.0.0.1:18642 check             New server registered.
$ add server be/s5 127.0.0.1:18642 track be/s2       New server registered.
$ add server be/s6 127.0.0.1:18642 resolvers r init-addr none
                                     'resolvers' option is not accepted for dynamic server
$ add server be/s7                   'server' expects <name> and <addr>[:<port>] as arguments.
$ add server be_static/x2 127.0.0.1:18642
                                     Backend does not support dynamic servers : backend 'be_static' uses a non dynamic load balancing method.
$ add server li/l2 127.0.0.1:18642   New server registered.
$ add server be/id9 127.0.0.1:18642 id 2    'id' : custom id 2 already used at p1.cfg:20 ('server s2').
$ add server be/id10 127.0.0.1:18642 id 1   'id' : custom id 1 already used at (null):0 ('server s1').
$ show servers state be              ids in order 2 3 1 4 5; s4: op 0 admin 1 check_state 2; s5: op 0 admin 1
$ purge server be/s2                 Unknown command: 'purge', but maybe one of the following ones is a better match: ...
$ purge all servers be_chash         Unknown command: 'purge', ...
```

### A.2 Algorithms, `add backend` (config p2)

```
global
    stats socket /tmp/t637.sock mode 600 level admin
    nbthread 2
defaults dnomode
    timeout connect 1s
    timeout client 9s
    timeout server 9s
defaults dtcp
    mode tcp
    timeout connect 1s
    timeout client 9s
    timeout server 9s
defaults dflt
    mode http
    timeout connect 1s
    timeout client 9s
    timeout server 9s
frontend fe
    bind 127.0.0.1:18637
    use_backend %[req.hdr(x-be)] if { req.hdr(x-be) -m found }
    use_backend be_ref if { path /ref }
    default_backend be
backend be
    server s1 127.0.0.1:18638
backend be_ref
    server r1 127.0.0.1:18638
backend be_empty
backend be_slow
    server w1 127.0.0.1:18643
    server w2 127.0.0.1:18638
backend be_ka
    http-reuse always
    server k1 127.0.0.1:18644
    server k2 127.0.0.1:18638
backend be_uri
    balance uri
    server u1 127.0.0.1:18638
backend be_chash
    balance uri
    hash-type consistent
    server c1 127.0.0.1:18638
backend be_lc
    balance leastconn
    server c1 127.0.0.1:18638
backend be_rnd
    balance random
    server c1 127.0.0.1:18638
backend be_first
    balance first
    server c1 127.0.0.1:18638
backend be_src
    balance source
    server c1 127.0.0.1:18638
backend be_tbl
    stick-table type ip size 10
    server q1 127.0.0.1:18638
listen li
    bind 127.0.0.1:18641
    server l1 127.0.0.1:18638
```

```
$ add server be_uri/n 127.0.0.1:18642     Backend does not support dynamic servers : backend 'be_uri' uses a non dynamic load balancing method.
$ add server be_chash/n 127.0.0.1:18642   New server registered.
$ add server be_lc/n 127.0.0.1:18642      New server registered.
$ add server be_rnd/n 127.0.0.1:18642     New server registered.
$ add server be_first/n 127.0.0.1:18642   New server registered.
$ add server be_src/n 127.0.0.1:18642     Backend does not support dynamic servers : backend 'be_src' uses a non dynamic load balancing method.
$ add server be_tbl/n 127.0.0.1:18642     New server registered.
$ add server be_empty/n 127.0.0.1:18642   New server registered.
$ add backend                             Require backend name.
$ add backend nb                          Usage: add backend <name> from <defproxy>.
$ add backend nb from nope                Cannot find default proxy 'nope'.
$ add backend nb from dnomode             Mode is required as 'dnomode' default proxy does not explicitly defines it.
$ add backend nb from dnomode mode log    Dynamic backends are compatible with only TCP or HTTP mode.
$ add backend be from dflt                Error during backend creation : name is already used by other proxy 'backend be'.
$ add backend fe from dflt                Error during backend creation : name is already used by other proxy 'frontend fe'.
$ add backend dflt from dflt              Error during backend creation : name is already used by other proxy 'defaults dflt'.
$ add backend nb from dflt                New backend registered.
$ add backend nb from dflt                Error during backend creation : name is already used by other proxy 'backend nb'.
$ add backend nt from dtcp                New backend registered.
$ add backend nh from dnomode mode http   New backend registered.
$ show stat -1 2 -1                       configured backends iid 3..15, then nb 16, nt 17 (tcp), nh 18, each "UP (UNPUB)"
```

### A.3 Publish, `del backend`, streams and connections in flight (same process as A.2)

```
GET / x-be: nb                       200, body 18638   (nb unpublished, no server: served by default_backend be)
$ add server nb/a 127.0.0.1:18642    New server registered.
$ enable server nb/a                 (empty)
GET / x-be: nb                       200, body 18638   (still unpublished)
$ publish backend nb                 Backend published.
$ publish backend nb                 Backend published.
$ publish backend nope               No such backend.
$ publish backend fe                 No such backend.
GET / x-be: nb                       200, body 18642
$ unpublish backend nb               Backend unpublished.
GET / x-be: nb                       200, body 18638
$ unpublish backend be_ref           Backend unpublished.
$ unpublish backend li               Backend unpublished.
$ publish backend be_ref             Backend published.
$ del backend                        No such backend.
$ del backend nope                   No such backend.
$ del backend fe                     No such backend.
$ del backend li                     Cannot delete a listen section.
$ del backend be_tbl                 Cannot remove a backend with stick-table.
$ del backend be_ref                 This proxy cannot be removed at runtime due to other configuration elements pointing to it.
$ del backend be                     This proxy cannot be removed at runtime due to other configuration elements pointing to it.
$ del backend be_empty               Backend must be unpublished prior to its deletion.
$ del backend nb                     Only a backend without server can be deleted.
$ del backend nb extra               Usage: del backend <name>.
$ purge backend nb                   Unknown command: 'purge', ...
$ del server nb/a                    Only servers in maintenance mode can be deleted.
$ disable server nb/a                (empty)
$ del server nb/a                    Server deleted.
$ del backend nb                     Server nb/a is going DOWN for maintenance. 0 active and
                                     backend 'nb' has no server available!
                                     Backend deleted.
$ del backend nb                     No such backend.
$ publish backend nb                 No such backend.
$ add server nb/a 127.0.0.1:18642    No such backend.
$ show servers state nb              Can't find backend.
$ add backend nb from dflt           New backend registered.
$ show stat -1 2 -1                  ... li "UP (UNPUB)", nt, nh, then nb last, "UP (UNPUB)"
GET / x-be: nb                       200, body 18638

$ disable server be_slow/w2          (empty)
GET / x-be: be_slow                  (started; w1 answers after 3 s)
$ disable server be_slow/w1          (empty)
$ del server be_slow/w1              Server still has connections attached to it, cannot remove it.
$ unpublish backend be_slow          Backend unpublished.
$ del server be_slow/w2              Server deleted.
$ del backend be_slow                Only a backend without server can be deleted.
$ show servers conn be_slow          be_slow/w1 6/1 127.0.0.1 18643 - 5000 1 1 1 1 0 0 0 -1 0 0 0
                                     200, body 18643   (the request completes)
$ del server be_slow/w1              Server deleted.
$ del backend be_slow                Server be_slow/w2 is going DOWN for maintenance. 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.
                                     Server deleted.
                                     Backend deleted.
$ show servers state be_slow         Can't find backend.

$ disable server be_ka/k2            (empty)
GET / x-be: be_ka                    200, body 18644
$ show servers conn be_ka            be_ka/k1 7/1 127.0.0.1 18644 - 5000 0 0 1 1 0 1 0 -1 1 0 1
$ disable server be_ka/k1            (empty)
$ show servers conn be_ka            be_ka/k1 7/1 127.0.0.1 18644 - 5000 0 0 1 1 0 1 0 -1 1 0 1
$ del server be_ka/k1                Server deleted.
```

Not shown by this run: what a *static* `use_backend` does when its target is unpublished. The
`/ref` request was answered by port 18638, which both `be_ref` and `be` use. §1.1 gives the
behaviour from stream.c:1244-1280 *(read)*; S3 must probe it with distinct ports.

### A.4 `purge`, on the dev10 reference binary (not the oracle)

`~/reference/haproxy-quic/haproxy`, 3.5-dev10-38e65c-10, config p2, fresh process.

```
$ purge server be/nope               No such server.
$ purge server be_ka/k2              Server deleted.                (was not in maintenance: put there, unused, deleted)
GET / x-be: be_slow                  (started)
$ purge server be_slow/w1            Server scheduled for purge.
$ purge server be_slow/w1            Server scheduled for purge.
$ enable server be_slow/w1           (empty)
$ show servers state be_slow         w1 op 2 admin 0; w2 op 2 admin 0
$ purge all servers be_slow          Servers backend iteration performed: 1 removed, 1 scheduled, 0 skipped.
$ purge backend be_slow              Backend must be unpublished prior to its deletion.
$ unpublish backend be_slow          Backend unpublished.
$ purge backend be_slow              Backend scheduled for purge.
$ publish backend be_slow            Backend 'be_slow' purge cancelled.
                                     Backend published.
                                     200, body 18643   (the request completes)
$ show servers state be_slow         (no server: w1 was purged once the stream ended)
$ unpublish backend be_slow          Backend unpublished.
$ purge backend be_slow              Backend deleted.
$ purge backend be_ref               This proxy cannot be removed at runtime due to other configuration elements pointing to it.
$ purge all servers be               Servers backend iteration performed: 1 removed, 0 scheduled, 0 skipped.
$ purge all servers                  A backend name is expected.
$ purge all servers nope             No such backend.
GET / x-be: be_ka                    200, body 18644
$ disable server be_ka/k1            (empty)
$ show servers conn be_ka            be_ka/k1 7/1 127.0.0.1 18644 - 5000 0 0 1 1 0 0 0 -1 0 0 0
$ del server be_ka/k1                Server deleted.
```
