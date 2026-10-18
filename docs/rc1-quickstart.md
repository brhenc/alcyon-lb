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

- Refused at load (the config fails, it does not run without it): `compression`, `cache`,
  `peers`, Lua, SPOE/`filter`, FastCGI, `resolvers` and `server-template` (no run-time DNS: use
  IP addresses or names resolved at start), OpenSSL-only keywords.
- Variables hold text, not typed values (T364 in progress; `tradeoff.md` 6.12): binary samples
  stored in variables are handled as bytes since T363a, other typed behaviour of `set-var` and
  converters may differ from HAProxy.
- `http-response return` is in progress.
- Memory: object pools are not implemented yet (T372; `tradeoff.md` 6.13): the request path
  still allocates, so RSS follows the traffic and is given back later than HAProxy would. An
  in-flight request keeps a 16 KiB buffer after its head is forwarded (T371: 18 KB per slow
  connection against HAProxy's 4.5 KB), so many slow uploads cost more memory than with HAProxy.
- Known small differences being fixed: IPv4-mapped addresses in `-m ip` matching (T377), quotes and
  `$` in the config lexer (T378), `-c` errors do not name the file, a Prometheus scrape omits a
  few families (`differences.md`, "prometheus-exporter").
- A thread blocked off-CPU (a deadlock) is not caught by the watchdog, as in HAProxy.
- QUIC/HTTP-3 is experimental; do not enable it on the production site.
