<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE. -->

# Operating Ibex

For someone who runs HAProxy under systemd today. Every statement here was run against the
release binary (`ibex -v`: 0.1.0) unless it is under "Does not work yet". Where Ibex differs from
HAProxy it says so. What Ibex refuses to load is in [differences.md](differences.md).

## How the process is laid out

Ibex is one process with worker threads, not HAProxy's master plus worker processes. Consequences
you will see:

- `-W` / `-Ws` do not create a master process. The main thread supervises the worker threads, and
  a reload starts a **new Ibex process**, which takes the listening sockets over from the old one
  and then tells the old one to soft-stop.
- The PID in `-p <pidfile>` is that one process (one line). After a reload the file holds the new
  PID. HAProxy lists master and workers.
- The master CLI (`-S`) and `show proc` / `reload` on it do not exist (see the end).

## Install

```
install -m 0755 target/release/ibex /usr/local/sbin/ibex
install -d /etc/ibex
install -m 0644 contrib/systemd/ibex.service /etc/systemd/system/ibex.service
$EDITOR /etc/ibex/ibex.cfg
systemctl daemon-reload
systemctl enable --now ibex
```

`contrib/systemd/ibex.service` is HAProxy's unit with the names changed: `Type=notify`,
`ExecStart=ibex -Ws -f $CONFIG -p $PIDFILE $EXTRAOPTS`, `KillMode=mixed`,
the same commented sandboxing options. Differences from HAProxy's:

- No `-S /run/haproxy-master.sock` in `EXTRAOPTS` and no `conf.d` directory by default (`-S` is
  accepted but serves nothing useful, see below). `-f` accepts a directory, as in HAProxy
  (`*.cfg` files, lexical order, dot-files skipped); add `-f /etc/ibex/conf.d` to `ExecStart` if
  you use one.
- Put overrides in `/etc/default/ibex` or `/etc/sysconfig/ibex`: `CONFIG=`, `PIDFILE=`,
  `EXTRAOPTS=`.
- Check it with `contrib/systemd/test-unit.sh` (runs `systemd-analyze verify` on a copy; skips
  if `systemd-analyze` is missing).

### What `-Ws` sends to systemd (read from `crates/ibex-rt/src/systemd.rs`, observed on a `NOTIFY_SOCKET`)

| moment | message |
|---|---|
| all listeners up | `READY=1`, `MAINPID=<pid>`, `STATUS=Ready.` |
| SIGUSR2 received | `RELOADING=1`, `STATUS=Reloading Configuration.`, `MONOTONIC_USEC=` |
| new process listening | from the old one, `MAINPID=<new pid>`, `READY=1`, `STATUS=Ready.` |
| reload failed (new process exited) -- from the code, not run by me | the old one logs `[ALERT] reload failed...`, reports the failure to systemd and goes on serving |
| soft stop (SIGUSR1) | `STOPPING=1` |

Without `-Ws` (plain `-W`) the reload works but nothing is sent. Without either, SIGUSR2 is
ignored with `[NOTICE] SIGUSR2 ignored: reloading on SIGUSR2 needs -W or -Ws`.

## Check a configuration

```
ibex -f /etc/ibex/ibex.cfg -c
```

Prints `Configuration file is valid.` and exits 0; on a parse error prints one line and exits 1.
Measured against HAProxy 3.5-dev8 on the same bad file: both exit 1. The messages differ:

```
Ibex:    Configuration parsing error: line 3, col 3: unknown keyword 'foo' in 'frontend' section
HAProxy: [ALERT] (n) : config : parsing [/tmp/t168/bad.cfg:3] : unknown keyword 'foo' in 'frontend' section
```

**Ibex's message names the line but not the file.** With several `-f` files, find the file
yourself. A missing file: `Cannot open configuration file/directory '<path>': No such file or
directory`, exit 1. `ExecReload` runs `-c` first, so a bad configuration fails `systemctl reload`
before any signal is sent.

## Reload

```
systemctl reload ibex          # ExecReload: ibex -c, then kill -USR2 $MAINPID
```

Needs `-W` or `-Ws`. Verified on one reload with the `-Ws` command line: the new process took the
listening socket over (`[NOTICE] took over 1 listening socket(s) from ...`), systemd got
`MAINPID=` of the new PID, the old process exited 0 and the pidfile changed, with a request served
by each. Connections already open finish on the old process. `hard-stop-after <t>` in `global`
bounds how long the old one lingers (measured on a plain soft stop: a request in flight with `hard-stop-after 2s` was cut
about 2 s after SIGUSR1).

Under load (T166): `tools/measure/reload_under_load.py`, 8 keep-alive clients, 2 long
downloads, one WebSocket, `hard-stop-after 4s`, SIGUSR2 every second, 100 reloads, nbthread 1,
release build, same machine:

| | HAProxy 3.5-dev8 | Ibex |
|---|---|---|
| failed requests / resets | 0 / 0 | 0 / 0 |
| requests that met a closed keep-alive connection (client retried) | 23 | 0 |
| responses with `Connection: close` from the old process | 777 | 800 |
| long downloads cut | 0 | 0 |
| WebSocket on the old process closed after its reload | 3.2-4.3 s (FIN) | 4.0-4.1 s (FIN or RST) |
| old process gone after its reload, max / median | 4.35 s / 1.85 s | 4.15 s / 1.70 s |
| reload time (SIGUSR2 to new process) max | 0.04 s | 0.05 s |
| RSS master (HAProxy) / serving process (Ibex), reload 10 -> 100 | 20984 -> 20844 kB | 8184 -> 8148 kB |
| all processes' RSS, peak during reloads | 377 MB | 33 MB |
| fds, net of TCP connections, reload 10 -> 100 | 10 -> 12 (one per live worker) | 6 -> 6 |
| SIGUSR1 with a download in flight | completes, exit | completes, exit |

As in HAProxy, a stopping process answers every request it reads with `Connection: close` and
closes idle connections only when it has nothing else to run, so a client under constant load is
told to reconnect rather than having its connection closed between two requests. A client that is
idle when the stop comes is closed; a request it sends at that instant can meet the close (the
retried case above), as with HAProxy. `crates/ibex-rt/tests/reload_under_load.rs` runs 10 reloads
in the gate and 100 with `--ignored`.

The handover socket lives in a private (0700) directory under `$TMPDIR` (default `/tmp`), so
no `expose-fd listeners` is needed. The new process is started from the same binary path (a
binary replaced on disk is picked up).

## Stop

| signal | effect (measured) |
|---|---|
| `SIGUSR1` | soft stop. The listeners close at once (a new connection is refused), a request in flight completes (a 3 s one did), then the process exits 0. Sends `STOPPING=1`. |
| `SIGTERM` | fast stop. Under `-W`/`-Ws` the process exits 0 at once, as HAProxy's master does (connections are dropped, not drained); the unit needs no `SuccessExitStatus`. Without `-W` the signal is left at its default and the process dies of it (143), as HAProxy standalone does. |
| `SIGINT` | left at the default: terminates. |

`systemctl stop ibex` sends SIGTERM (fast). For a graceful stop use
`systemctl kill -s USR1 ibex` and wait for the service to leave `active`.

## Logs

- Ibex uses HAProxy's `log` directive and writes in the HAProxy syslog format
  (`<134>Oct  5 00:36:14 haproxy[PID]: 127.0.0.1:53002 [...] f b/s1 0/0/-1/-1/3001 503 ...`).
  Note the tag is `haproxy`, as in the oracle.
- Verified here: `log stdout format raw local0` (goes to the journal under systemd) and
  `log 127.0.0.1:<port> local0` (UDP syslog; one datagram per request). I did not get a unix
  datagram socket (`log /dev/log`) to deliver in my test, and HAProxy did not either in the same
  harness, so **treat unix-socket logging as unverified**.
- Process messages (`[NOTICE]`, `[ALERT]`, `[WARNING]`) go to stderr, hence the journal.
- `option httplog` and the default format are made equal to HAProxy's (T165, see
  [differences.md](differences.md) "Logs and `show stat`").

## Stats page and CSV

`stats enable` + `stats uri /stats` in a frontend gives the HTML page; append `;csv` for CSV
(`curl 'http://127.0.0.1:18080/stats;csv'`). Verified: CSV header and a FRONTEND and a server
row come back, `show info` is `Name: Ibex`. The CSV fields monitoring reads are made equal to
HAProxy's after the same traffic in T165.

## Runtime API

Declare `stats socket /run/ibex/admin.sock mode 600 level admin` in `global` (needs
`/run/ibex` to exist and be writable: add `RuntimeDirectory=ibex` to the unit; the shipped unit
does not). Talk to it as with HAProxy, e.g. `echo "show stat" | socat - /run/ibex/admin.sock`.

Commands that exist (from `help` and run): `help`, `prompt`, `quit`, `set timeout cli`,
`show info`, `show pools`, `show stat`, `show table`, `show servers state`, `show errors`,
`show backend`, `show version`, `clear counters`, `enable|disable health`,
`enable|disable server`, `set server <b>/<s> state|maxconn|weight`, `set maxconn
server|global|frontend|backend`, `set weight`, `shutdown sessions server|backend`.
Run: `set server b/s1 weight 5` then `disable server b/s1` and `show servers state` showed
weight 5 and admin state 1.

Runtime changes are not persisted. `server-state-file` is **not** claimed to work here; I did
not test it.

## Does not work yet

- Runtime map and ACL commands (`add map`, `show map`, `show acl`, ...): "Unknown command". The
  milestone lists them.
- `show sess`, `show servers conn`: "Unknown command".
- The master CLI: `-S <path>` creates the socket but it answers `show proc` and `reload`
  with "Unknown command". Reload through systemd (SIGUSR2) is the way.
- Error messages from `-c` do not name the file.
- A connection refused by a server is reported only after the connect timeout (3 s in my test
  where HAProxy answers 503 at once): T170.
- Unix-socket syslog target and `server-state-file`: not verified (above).
- Reload under load repeated 100 times, RSS and fd stability: not measured.
- Everything the parser refuses (HTTP/3, Lua, SPOE, peers, cache, FastCGI, compression, ...):
  [differences.md](differences.md).
