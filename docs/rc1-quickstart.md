<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE. -->

# Release candidate 1: quickstart

Running Ibex in front of a personal website. HAProxy 3.5 configuration syntax; the details of
the process layout are in [operating.md](operating.md).

## 1. Install

```
cargo build --release -p ibex-rt --bin ibex
install -m 0755 target/release/ibex /usr/local/sbin/ibex
install -d /etc/ibex/certs
install -m 0644 examples/personal-website.cfg /etc/ibex/ibex.cfg
cat fullchain.pem privkey.pem > /etc/ibex/certs/site.pem && chmod 600 /etc/ibex/certs/site.pem
$EDITOR /etc/ibex/ibex.cfg          # the crt path, the backend address
ibex -f /etc/ibex/ibex.cfg -c       # "Configuration file is valid."
install -m 0644 tools/systemd/ibex.service /etc/systemd/system/ibex.service
systemctl daemon-reload && systemctl enable --now ibex
```

A faster binary (measured 2026-10-19, T435: about 13% fewer user instructions per proxied request than
`release-perf`, which is itself about 4% below `release`) comes from a profile-guided build:
`tools/pgo-build.sh --target-dir /var/tmp/ibex-pgo --out ./ibex-pgo` builds an instrumented ibex, drives a
mixed training load against it (HTTP/1 keep-alive and close, TLS, h2, h2c, rules, logging, error
paths; the config is `tools/pgo/train.cfg`), merges the profile and builds the final binary, whose path it
prints. It needs `llvm-profdata` of the same LLVM version as `rustc -vV`, plus `h2load`, `socat`, `openssl`,
`curl` and `nc`, and takes two fat-LTO builds (about 5 minutes each on 48 cores, 11 minutes in all). The profile is not
checked in: regenerate it for each release. `--bolt` adds a reorder-only BOLT pass (needs `llvm-bolt`).

`examples/personal-website.cfg`: HTTPS on :443 with h2 (ALPN), :80 redirecting to https (301),
HSTS, `option httplog` to stdout (the journal), a stats socket, the Prometheus exporter on
`/metrics` from localhost only, timeouts, `maxconn`, `nbthread 2`. It also loads with HAProxy
3.5-dev8 (`haproxy -c`) except the `use-service prometheus-exporter` line: the reference binary
is built without PROMEX. Not in it, because Ibex refuses it at load: `compression` (use your
backend's, or precompressed files). The unit is described in
[../tools/systemd/README.md](../tools/systemd/README.md).

## 2. Reload and stop

```
systemctl reload ibex                                   # ibex -c, then SIGUSR2 to the master
echo reload | socat - /run/ibex/master.sock             # the same, answers Success=1/0 and the new worker's startup log
echo "show proc" | socat - /run/ibex/master.sock        # master, worker, old workers
systemctl stop ibex                                     # fast stop
systemctl kill -s USR1 ibex                             # graceful: finish requests in flight, then exit
```

A reload starts a new worker that takes the listening sockets over; connections open on the
old worker finish there. A bad configuration fails `systemctl reload` before any signal and the
old worker keeps serving. Add `hard-stop-after 30s` to `global` if old workers must not linger.

## 3. Watch memory

The first user reports will be leaks, so look at these after a day and after a week. The numbers
should be flat once traffic is steady, and fall back after a burst.

```
echo "show info"  | socat - /run/ibex/admin.sock | grep -E 'Memmax|PoolAlloc|PoolUsed|PoolFailed|CurrConns|Tasks|Run_queue|BlockedTraffic'
echo "show pools" | socat - /run/ibex/admin.sock       # per pool: allocated, used, failures
ps -o pid,rss,vsz,nlwp -C ibex ; ls /proc/$(pgrep -n -x ibex)/fd | wc -l   # RSS, threads, open fds
```

- `PoolFailed` / `haproxy_process_pool_failures_total` must stay 0. `PoolAlloc_bytes` and
  `PoolUsed_bytes` must not grow with the uptime at constant load.
- `Memmax_MB` is 0 unless you start with `-m <megs>` (a connection budget, not a limit).
- Prometheus (from the host itself, port and scheme of your frontend; the example allows only
  127.0.0.1 and ::1): `curl -sk https://localhost/metrics`. Families to graph:
  `haproxy_process_pool_allocated_bytes`, `haproxy_process_pool_used_bytes`,
  `haproxy_process_pool_failures_total`, `haproxy_process_max_memory_bytes`,
  `haproxy_process_current_connections`, `haproxy_process_max_fds`,
  `haproxy_frontend_current_sessions`. Use `?scope=global` for a cheap scrape.
- Leak signs: RSS or the fd count rising with constant traffic; `CurrConns` / current sessions
  not returning to the baseline when the site is idle; pool "used" above "allocated" minus the
  thread caches growing between two idle observations; many old workers in `show proc` after
  reloads (a worker lingers while a connection is open on it).
- Record `show info` and `show pools` with a timestamp when you see something odd, before
  restarting.

## 4. Logs

`log stdout format raw local0` puts the HAProxy-format access log (and the `[NOTICE]`,
`[WARNING]`, `[ALERT]` lines on stderr) into the journal: `journalctl -u ibex -f`. Use
`log 127.0.0.1:514 local0` for a UDP syslog daemon. Unix-socket syslog (`log /dev/log`) is
not verified.

## 5. What to report

- A crash or restart: `systemctl status ibex`, and `journalctl -u ibex --since ... | grep -B30 -E 'PANIC|WARNING! thread|panicked'`.
  The watchdog aborts the worker with **exit status 134** after a thread has been stuck for
  about a second; stderr then has `WARNING! thread N has stopped processing traffic for M
  milliseconds ...` lines (from ~200 ms) and `PANIC! Thread N is about to kill the process
  (pid P).` The master restarts it per `Restart=always`. A Rust panic or out-of-memory abort
  is also 134 (`thread ... panicked at ...` or `memory allocation of N bytes failed`).
  `ibex.watchdog-warn-only` in `global` keeps the warnings and never aborts.
- Include: the exact config (without the key), `ibex -v`, `show info`, `show pools`, `show proc`,
  what traffic was on, how long it ran.
- A response that differs from what your backend sends directly, or from what HAProxy sends for
  the same config: HAProxy is the reference.

## 6. Known gaps

User-visible ones; the full list is [differences.md](differences.md) and [../tradeoff.md](../tradeoff.md).

- Refused at load (the config fails, it does not run without it): `compression` (planned for M5),
  `cache`, `peers`, Lua, SPOE/`filter`, FastCGI, `resolvers` and `server-template` (no run-time
  DNS: use IP addresses or names resolved at start), OpenSSL-only keywords.
- **Stats page:** `stats auth <user>:<password>` (repeatable), `stats realm`, `stats http-request
  allow | deny [deny_status <n>] | auth [realm <r>] [if|unless <cond>]` and `stats show-version` /
  `hide-version` work as in HAProxy (401 with `WWW-Authenticate`, also for the admin POST). Like
  HAProxy, `stats auth`/`realm` and `stats http-request` cannot be mixed in one proxy. **Stats in
  `defaults`:** a proxy with no `stats` line of its own uses the defaults' whole stats setup, auth
  included; a proxy with any `stats` line (even `stats enable`) starts from an empty one, so it
  needs its own `stats auth`. The stats page runs after the proxy's `http-request` rules, so an
  `http-request deny` in front of it protects it. `stats scope`, `stats show-modules` and other
  `stats http-request` actions are refused at load. Passwords in `stats auth` are plain text in the
  config file: bind the page to a private address or use TLS on the bind.
- TLS: ECDHE only, no finite-field DHE (`DHE-*` ciphers, `ssl-dh-param-file`; `tradeoff.md` 6.18).
  Every current browser does ECDHE. The `ssl_c_*` fetches (the client's certificate) are missing.
- **Check your ACL names by hand** (T430 #1): a rule naming an ACL that does not exist
  (`use_backend b if nosuchacl`) loads, where HAProxy refuses it; a typo then silently never matches.
- **Environment variables inside double quotes** are not expanded (T430 #11): with `P` in the
  environment, `hdr x "${P}"` sends `${P}` where HAProxy sends the value. `bind ${P}` works.
  `setenv`/`presetenv`/`unsetenv`/`resetenv` in `global` are refused at load (T430 #21). Of the
  `HAPROXY_*` variables HAProxy exports, only `HAPROXY_LOCALPEER` (the host name) is set.
- Variables keep their sample type and a keep-alive `set-var` allocates nothing (T364); the
  `tune.vars.*` accounting differs from HAProxy's in four small ways (`tradeoff.md` 6.17).
- Memory: Ibex has one pool type since 2026-10-25 (`tradeoff.md` 6.13, 6.28); `show pools` lists them. A keep-alive
  request allocates nothing; like HAProxy, Ibex keeps the peak of a burst until `pool_gc` (SIGQUIT,
  soft stop) or `tune.memory.hot-size` eviction. Waiting for a buffer (S6) is not built: a stream past
  `tune.buffers.limit` fails instead of queueing. An
  HTTP/1 request gives its head buffer back once the head is forwarded (T371); an HTTP/2 or
  HTTP/3 one keeps it to the end of the transaction.
- A chunked HTTP/1 server's trailers do not reach an HTTP/2 client (T430 #4; matters for gRPC
  through an HTTP/1 backend).
- Known small differences being fixed: IPv4-mapped addresses in `-m ip` matching (T377), quotes and
  `$` in the config lexer (T378), `-c` errors do not name the file and some messages are worded
  differently (T430 #9), a Prometheus scrape omits a few families (`differences.md`,
  "prometheus-exporter"), `monitor` in a backend is accepted without HAProxy's warning.
- A thread blocked off-CPU (a deadlock) is not caught by the watchdog, as in HAProxy.
- QUIC/HTTP-3 is experimental; do not enable it on the production site.
