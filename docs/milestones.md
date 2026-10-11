# Milestones

Written 2026-10-04. Two tracks, measured independently:

- **M1 — small-scale usable** (features + practical testing). Progress is tracked against
  this list, not against the whole reg-test board.
- **R1 — robustness** (orthogonal to features). It applies to whatever M1 has shipped,
  and is re-run as M1 grows.

Resource and operations parameters (below) are exit criteria for both.

Every target "against HAProxy" means measured on the same machine, same config, with the
oracle `/home/bhenc/reference/haproxy/haproxy`, and recorded with the command that
produced it.

## M1 — small-scale usable

### Scope (in)

- HTTP/1.1 and HTTP/2 (h2 over TLS and h2c) to clients; HTTP/1.1 and h2 to servers.
- TLS termination with rustls: certificates, SNI, ALPN, TLS 1.2/1.3, `ssl-min-ver`.
  TLS to servers with `verify`.
- `frontend` / `backend` / `listen` / `defaults`, `mode http` and `mode tcp`.
- Load balancing: roundrobin, static-rr, leastconn, source, uri, hdr, random; weights;
  `backup`; `maxconn` and queues; `redispatch` and `retries`; `retry-on`.
- Health checks: TCP, HTTP (`option httpchk`, `http-check expect`), `inter/rise/fall`,
  `slowstart`, agent checks if cheap.
- Persistence: `cookie` (insert/rewrite/prefix), stick tables with `stick on` / `track-sc`.
- ACLs, `http-request` / `http-response` / `tcp-request` rules, redirects, header and path
  rewrites, `use_backend`, maps, `errorfile` / `http-error`.
- Timeouts (client, server, connect, http-request, http-keep-alive, queue, tunnel),
  WebSocket and `Upgrade` tunnelling, Server-Sent Events / long responses.
- `option forwardfor`, `option forwarded`, PROXY protocol v1/v2 (send and receive).
- Idle server connection pools (T159 A+B).
- Logging (`log`, `log-format`, `option httplog`, syslog over UDP/unix and stdout),
  `unique-id`.
- Runtime API: `show stat`, `show info`, `show servers state`, `set server`, `set weight`,
  `disable/enable server`, map and ACL updates, `show table`.
- Stats page (HTML + CSV).
- Master-worker, seamless reload (SIGUSR2), graceful stop (SIGUSR1), `-c` config check.

### Scope (out, refused clearly by the parser)

Lua, SPOE, peers sync,
compression (unless T162 shows it is nearly done), cache, FastCGI, DNS-resolved servers
beyond what already works, OpenSSL-specific engines/keywords. Each refusal names the
keyword and says it is unsupported (AGENTS.md §5); listed in `docs/differences.md`.

HTTP/3 and QUIC are **not** in M1 and not refused either: Ibex has an experimental QUIC
listener with tests (`ibex-quic`). They are the next milestone, **M2**, planned for the
weekend of 2026-10-10 (user, 2026-10-05).

### Practical testing (the point of the milestone)

Run real software in front of and behind Ibex, the way a small deployment would. Each
topology is a script under `tools/practical/` that starts everything, drives traffic,
checks results and tears down; each runs against HAProxy too, and the results are
compared.

Topologies:

1. `client → ibex → node.js` (express): keep-alive, chunked uploads (100 MB), large
   downloads, SSE (10 min stream), WebSocket echo (socket.io and raw `ws`), slow
   responses, backend returning 5xx, gzip done by the backend.
2. `client → ibex (TLS, h2) → nginx → node.js`: h2 to the client, h1 to nginx; nginx as
   a static-file server on the side (`use_backend` by path).
3. `client → ibex → apache2 (httpd, mod_proxy) → node.js`, and apache2 serving static files
   and a PHP or CGI app if available.
4. `nginx → ibex → node.js`: Ibex as the inner balancer behind nginx (PROXY protocol on,
   `X-Forwarded-For` chain correct).
5. Three node.js instances, roundrobin + health checks: restart one (`kill`, then start
   again) under load, then all three one after another (a rolling deploy); deploy with
   cookie persistence and check sessions stay put.
6. Real browsers: Firefox and Chromium through Ibex to a node.js single-page app
   (h2, WebSocket, SSE); look at the developer tools for errors.

Load tools: `curl`, `wrk2` (h1, constant rate, latency histogram; built from source
into `~/.local/bin/wrk2`, rebuild steps with `~/src/wrk2-local.patch`), `h2load`
(nghttp2, h2), node.js scripts for WebSocket (no `websocat`: the node scripts and the
browsers in topology 6 cover it). Not installed yet: `nginx`, `httpd`, `nghttp2`
(`sudo dnf install nginx httpd nghttp2` — the user runs it; `wrk` and `websocat` are not
in Fedora's repositories, which made the first `dnf install` fail as a whole).

### M1 exit criteria

- All six topologies pass their scripts against Ibex, with the same observable results
  as HAProxy (status codes, headers that matter, bodies, logs fields), for 3 runs.
- Every config used in `tools/practical/` passes `ibex -c` and runs; no keyword in it is
  warned-and-ignored.
- Resource and operations parameters below met.
- One week of the practical setup running (topology 5, light constant load) with no
  restart, no error not also produced by HAProxy, and RSS flat.
- **Convergence rule (proposed, not yet accepted by the user).** Each verification method
  (V&V battery + soak, red-team scorecard, differential fuzz, libFuzzer) has run one full
  cycle on the release candidate with no new finding of severity medium or above. The
  record is `data/findings.csv` and `data/verification_runs.csv`; `python3 tools/findings.py`
  prints the clean hours per method since its last new finding on the main lineage.

## Resource parameters (exit criteria for M1)

Measure each on Ibex (release build) and HAProxy, same config; record in `tradeoff.md` §6.5
and as a script under `tools/measure/`.

| parameter | how | target |
|---|---|---|
| RSS at startup, 10 / 1k / 10k backends, nbthread 1 and 16 | `/proc/<pid>/status` VmRSS | ≤ 1.5× HAProxy; nbthread 16 ≤ nbthread 1 + 20 MB (T160) |
| RSS per idle keep-alive client connection | 10k idle conns, RSS delta / 10k | ≤ 2× HAProxy |
| RSS per active connection with a 1 MB body in flight | 1k conns | ≤ 2× HAProxy |
| CPU per request, h1 keep-alive, 50 conns | `tools/measure/run.sh` | ≤ 1.3× HAProxy |
| CPU per request, h2 and TLS handshakes/s | h2load, `openssl s_time` or rustls client | ≤ 1.5× HAProxy |
| Throughput, 1 conn and 50 conns, small and 64 KB bodies | wrk | ≥ 0.8× HAProxy |
| Added latency p50 / p99 at 50% of max throughput | wrk2-style constant rate | p99 ≤ 1.5× HAProxy |
| Backend connections opened per second under uneven load | T159 B's test | within 10% of HAProxy |
| Allocations per request (steady state) | `tools/allocprofile` | ≤ 4 (today) |
| File descriptors per connection | `/proc/<pid>/fd` | equal to HAProxy |
| Startup time, 10k backends | wall time to first accepted conn | ≤ 2× HAProxy |
| Reload time and memory during reload (old + new process) | SIGUSR2 under load | ≤ 2× HAProxy |

## Operations parameters (exit criteria for M1)

- **Reload** (SIGUSR2) under constant load: zero failed requests, zero reset connections,
  old worker drains within `hard-stop-after`; repeated 100 times, RSS and fds flat.
- **Graceful stop** (SIGUSR1): in-flight requests complete; SIGTERM fast stop as HAProxy.
- **Config check** `ibex -c`: same exit codes as HAProxy; errors name file and line.
- **Logs**: `option httplog` and the default `log-format` lines byte-identical to HAProxy
  for the practical topologies (except timings); syslog UDP, unix socket, stdout.
- **Stats**: `show stat` CSV fields that a monitoring tool reads (status, scur, smax, stot,
  bin, bout, hrsp_xxx, chkfail, lastchg, qcur, rate) equal to HAProxy's after the same
  traffic.
- **Runtime changes** from the CLI visible to every worker immediately (`set server`,
  `set weight`, `add map`), and they survive nothing (as HAProxy) unless a state file is
  configured (`server-state-file`).
- **systemd**: an example unit (`Type=notify` if Ibex supports `sd_notify`, else
  `Type=forking`/master-worker), `ExecReload` with SIGUSR2; documented in `docs/`.
- **Failure behaviour**: a backend down is detected within `inter × fall`, traffic moves
  away, comes back after `rise`; all servers down gives HAProxy's 503 page.

## M2 — HTTP/3 and QUIC (next; M3 peers follows, see below)

Planned for the weekend of 2026-10-10. Scope to be written then: QUIC listener parity with
HAProxy built with QUIC (`quic4@`/`quic6@`, `alpn h3`, `proto quic`), HTTP/3 to clients,
the QUIC part of T162 (reg-tests hidden by feature flags), and the practical topologies
over h3 (curl `--http3`, browsers). The reference binary here is built without QUIC, so the
oracle for M2 needs a QUIC-enabled HAProxy build first.

## R1 — robustness (orthogonal)

Division of work: the user (devops background) runs most of R1 — test rigs, soak, load,
hostile traffic, practical topologies — and files what breaks. Agents write the Rust:
fixes, fuzz harnesses, and the test that reproduces each finding first.

Runs against whatever is in scope at the time. Each item is a tool or test under `tools/`
or `fuzz/`, kept outside the workspace if it needs `unsafe` or a non-Rust dependency
(as `tools/allocprofile` does), and runs in CI or nightly, not in every gate.

1. **Fuzzing** with cargo-fuzz (libFuzzer; allowed by the user 2026-10-04: it links only
   into the fuzz binaries under `fuzz/`, never into Ibex):
   HTTP/1 request and response parser, HTTP/2 frame decoder, HPACK, PROXY protocol v1/v2,
   config parser, log-format parser, CLI command parser, sample-fetch/converter
   expressions, regex translation (T154). Target: 24 h per target with no crash, no
   panic, no hang, and no memory growth.
2. **Differential testing against HAProxy**: the same byte stream to both, compare what
   reaches the server and what reaches the client. Corpus: request smuggling (CL/TE,
   duplicate CL, obs-fold, bare LF, chunk extensions), header case and whitespace, very
   long/large heads, invalid methods/URIs. Any difference is a bug in Ibex or a
   documented decision.
3. **Hostile clients**: slowloris (slow headers), slow body, slow read (tiny window),
   HTTP/2 rapid reset (CVE-2023-44487), CONTINUATION flood (2024), HPACK bomb, SETTINGS
   and PING floods, zero-window stalls, many streams. Target: CPU and memory bounded,
   same limits/counters as HAProxy (`glitch` counters, `tune.h2.*`).
4. **Hostile backends**: reset mid-response, wrong Content-Length, slow trickle, never
   answers, answers before the request ends, closes keep-alive without warning (the
   idle-pool race), sends 1xx floods, invalid chunking.
5. **Resource exhaustion**: fd limit reached, `maxconn` reached, memory pressure
   (`ulimit -v`), queue full, disk full for logs. No panic, no crash; HAProxy's
   behaviour (refuse, queue, 503) reproduced.
6. **Soak**: 72 h mixed traffic (topology 5 plus hostile-client mix at 1%), with reloads
   every 10 min. RSS growth ≤ 5% after warm-up, fd count flat, no error rate above
   HAProxy's on the same run.
7. **Panic audit**: every `unwrap`, `expect`, indexing and arithmetic overflow reachable
   from network input or the CLI is listed and either proven unreachable or replaced;
   a panic in a worker is contained (one connection, not the process) — decide and
   document the policy.
8. **Concurrency**: the race tests already in the tree (T152) extended to reload, CLI
   updates under load and idle-pool takeover (T159 B); `loom` where a structure is small
   enough.

R1 exit criteria: all eight run, documented in `docs/robustness.md` with the last run's
date, command and result; every finding fixed or filed as a task.

## Sequence after M1, M2 and R1 (user, 2026-10-05)

R1 runs alongside all of these. Dates are targets, not promises; each milestone gets its
detailed scope and exit criteria written when it starts, as M1's were.

### M3 — peers and reproducible builds (week after M2, target weekend of 2026-10-17)

Stick-table synchronisation between nodes, moved forward from M4 by the user.

- **Wire-compatible with HAProxy's peers protocol**: an Ibex node and an HAProxy node in
  one `peers` section exchange table updates both ways. That is what makes a mixed
  cluster (and a migration one node at a time) possible, and it lets HAProxy serve as the
  oracle peer in tests.
- **Config**: the `peers` section (`peer`, `server`, `bind`, `table`, `shards`,
  `disabled`), `localpeer` / `-L`, `stick-table … peers <name>`; the M1 refusal of these
  keywords is removed only as each one reaches the data path (AGENTS.md §5).
- **Reload**: the old process hands its tables to the new one through the local peer, as
  HAProxy does, so counters and stickiness survive SIGUSR2.
- **Multi-threaded sync — the reason to do it early.** In HAProxy a peer session runs on
  one thread, so a busy cluster's table sync is bounded by one core (the user's
  observation; measure it on the reference binary first and record the numbers). Ibex
  spreads sync across worker threads (per table shard, or per peer) while keeping the
  wire protocol unchanged. Exit: under the same update rate, Ibex peers keep up where
  HAProxy's sync lags, measured with both on the same machine, and no update is lost.
- Practical topology: two Ibex nodes plus one HAProxy node behind a client that alternates
  between them; stickiness and `sc_*` counters agree on all three.

**Reproducible builds (added by the user, 2026-10-05).** This is a must-have for a
modern proxy, and it is cheapest to start early, before M4 packaging depends on it.
Anyone who builds a given commit with the pinned toolchain gets a bit-identical `ibex`
binary, and can check that a released binary came from the published source.

- **Pinned inputs.**
  - `Cargo.lock` is already committed.
  - Add a `rust-toolchain.toml` that names an exact version, not a channel.
  - Vendor the dependencies (`cargo vendor`, or check them by hash) so a build needs no
    network.
- **No build-environment leakage.**
  - Paths: `--remap-path-prefix` for the source tree, `~/.cargo/registry` and the target
    dir.
  - No timestamps, hostnames or usernames in the binary. The `-vv` / `show info` build
    date comes from `SOURCE_DATE_EPOCH` (the commit time), as HAProxy's `BUILD_DATE`
    could.
  - `codegen-units` and LTO settings fixed in the release profile.
  - sccache must not change the output.
- **The release binary contains no C.** The only build script, `crates/ibex-h1-sys` (the
  test-only `haproxy-ffi` feature, which compiles HAProxy's `h1.c` from
  `/home/bhenc/reference/haproxy`), stays out of release builds. A check in the script
  proves it.
- **Verification.** A script, `tools/repro-check.sh`:
  - builds the same commit twice, in two different directories with different
    `CARGO_TARGET_DIR`s, users or containers, and at different times;
  - compares the binaries' sha256;
  - on a mismatch, runs `diffoscope` (if installed) and names the cause.
- **Exit:** two builds from different paths on different days are identical, from a
  clean checkout without network. The check runs in the gate (or in CI once M4 has CI).
  The RPM and container image of M4 are built the same way and record the sha256 and
  the toolchain version. Later: an SBOM (CycloneDX) and signed release checksums.

### M4 — deployable

The step from "works here" to "someone else can run it": RPM and container image,
versioned releases with a changelog, a migration guide for HAProxy users (what is
refused, what differs — from `docs/differences.md`), a security policy, and CI running
the gate and the reg-test board on every push. Also what a presentation needs.

### M5 — feature breadth

Turn M1's remaining refusals into support, in order of how often real configs use them
(the smoke corpus of 529 configs shows which): compression, cache, SPOE, FastCGI. Lua last
or never: an embedded Lua means a C library or a pure-Rust Lua engine, and that is a
memory-safety decision for the user to make.

### M6 — scale

Large deployments: 100k+ concurrent connections, 32–64 threads and thread groups,
splice / zero-copy forwarding, kTLS, CPU per request at or below HAProxy's. Only once
M1–M5 are stable.

## M1 work plan and budget rules

Order (Opus for structural work, Sonnet for the rest; at most 4 agents at once):

| order | task | model | depends on |
|---|---|---|---|
| 1 | T160 per-worker proxy memory | Opus | — |
| 1 | T159 A idle pools per server | Opus | T149b merged |
| 2 | T164 out-of-scope keywords refused | Sonnet | — |
| 2 | T165 log lines and `show stat` parity | Sonnet | — |
| 3 | T159 B shared idle pool | Opus | T159 A merged |
| 3 | T166 reload under load | Sonnet/Opus | T160 merged (touches worker setup) |
| 4 | T167 practical topology 1 (node.js) | Sonnet | — |
| 4 | T168 systemd unit, operator's page | Sonnet | — |
| 4 | T161 `set-status reason`; T87 431 | Sonnet | — |
| 5 | Bugs from the user's practical testing | either | — |

Not in M1 (deferred unless a practical topology needs them): T131 rest, T144/T146/T149
leftover lists, T158, T162 QUIC part, T163.

Budget rules (the user pays; target: M1 code for about two months of subscription):
- At most 4 agents at once; the merge gate is serial anyway.
- Sonnet for small and leftover tasks; Opus for structural ones.
- Agents run the full gate at most twice, then stop and hand back (agent brief).
- No new leftover sweeps outside M1.
- Fewer, larger tasks with tight briefs; the supervisor stages two branches in one gate
  when they don't overlap.
