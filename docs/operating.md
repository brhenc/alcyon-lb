<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE. -->

# Operating Alcyon

For someone who runs HAProxy under systemd today. Every statement here was run against the
release binary (`alcyon -v`: 0.1.0) unless it is under "Does not work yet". Where Alcyon differs from
HAProxy it says so. What Alcyon refuses to load is in [differences.md](differences.md).

## How the process is laid out

Two layouts, depending on whether the master CLI is asked for:

- `-W -S <socket>` / `-Ws -S <socket>` (the shipped unit, as HAProxy's): **a master process and
  a worker process**, as in HAProxy. The master runs no proxy; it holds the `-S` socket and
  starts the worker (the same binary). A reload (`reload` on the master socket, or SIGUSR2 to
  the master) starts a new worker, which takes the listening sockets over from the serving one
  and soft-stops it. The master's PID never changes: it is in the pidfile and it is systemd's
  `MAINPID`. `show proc` lists master and workers. See "Master CLI" below.
- `-W` / `-Ws` without `-S`: one process with worker threads. A reload starts a **new Alcyon
  process**, which takes the listening sockets over from the old one and then tells the old one
  to soft-stop; the pidfile and systemd's `MAINPID` move to the new process.
- `-S` without `-W` is refused, as by HAProxy (`a master CLI socket was defined, but
  master-worker mode (-W) is not enabled.`, exit 1).

The worker itself is one process with threads (`nbthread`), not several processes.

## Install

```
install -m 0755 target/release/alcyon /usr/local/sbin/alcyon
install -d /etc/alcyon
install -m 0644 contrib/systemd/alcyon.service /etc/systemd/system/alcyon.service
$EDITOR /etc/alcyon/alcyon.cfg
systemctl daemon-reload
systemctl enable --now alcyon
```

`contrib/systemd/alcyon.service` is HAProxy's unit with the names changed: `Type=notify`,
`ExecStart=alcyon -Ws -f $CONFIG -p $PIDFILE $EXTRAOPTS`, `KillMode=mixed`,
the same commented sandboxing options. Differences from HAProxy's:

- `EXTRAOPTS=-S /run/alcyon-master.sock` (HAProxy's: `/run/haproxy-master.sock`), so the service
  runs as master + worker. No `conf.d` directory by default. `-f` accepts a directory, as in HAProxy
  (`*.cfg` files, lexical order, dot-files skipped); add `-f /etc/alcyon/conf.d` to `ExecStart` if
  you use one.
- Put overrides in `/etc/default/alcyon` or `/etc/sysconfig/alcyon`: `CONFIG=`, `PIDFILE=`,
  `EXTRAOPTS=`.
- Check it with `contrib/systemd/test-unit.sh` (runs `systemd-analyze verify` on a copy; skips
  if `systemd-analyze` is missing).

### What `-Ws` sends to systemd (read from `crates/alcyon-rt/src/systemd.rs`, observed on a `NOTIFY_SOCKET`)

With `-S` (the shipped unit) the master sends everything, and `MAINPID` is always the master:
`READY=1` once the first worker listens, `RELOADING=1` at each reload, `READY=1` when the new
worker listens (`STATUS=Reload failed!` with it if the new worker exited), `STOPPING=1` on
SIGUSR1 / SIGTERM (test: `master_cli.rs`, `under_systemd_the_master_stays_the_main_pid...`).
Without `-S`:

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
alcyon -f /etc/alcyon/alcyon.cfg -c
```

Prints `Configuration file is valid.` and exits 0; on a parse error prints one line and exits 1.
Measured against HAProxy 3.5-dev8 on the same bad file: both exit 1. The messages differ:

```
Alcyon:    Configuration parsing error: line 3, col 3: unknown keyword 'foo' in 'frontend' section
HAProxy: [ALERT] (n) : config : parsing [/tmp/t168/bad.cfg:3] : unknown keyword 'foo' in 'frontend' section
```

**Alcyon's message names the line but not the file.** With several `-f` files, find the file
yourself. A missing file: `Cannot open configuration file/directory '<path>': No such file or
directory`, exit 1. `ExecReload` runs `-c` first, so a bad configuration fails `systemctl reload`
before any signal is sent.

## Reload

```
systemctl reload alcyon          # ExecReload: alcyon -c, then kill -USR2 $MAINPID
echo reload | socat - /run/alcyon-master.sock     # the same, with the result (master CLI)
```

With the master (`-S`, the shipped unit), `$MAINPID` is the master and SIGUSR2 makes it start a
new worker; the paragraphs below describe the single-process layout (`-W` without `-S`), which is
what T166 measured under load. The master layout was tested with requests sent in a loop
through a valid and a failed reload (none failed; `crates/alcyon-rt/tests/it/master_cli.rs`), not
with the 100-reload measurement.

Needs `-W` or `-Ws`. Verified on one reload with the `-Ws` command line: the new process took the
listening socket over (`[NOTICE] took over 1 listening socket(s) from ...`), systemd got
`MAINPID=` of the new PID, the old process exited 0 and the pidfile changed, with a request served
by each. Connections already open finish on the old process. `hard-stop-after <t>` in `global`
bounds how long the old one lingers (measured on a plain soft stop: a request in flight with `hard-stop-after 2s` was cut
about 2 s after SIGUSR1).

Under load (T166): `tools/measure/reload_under_load.py`, 8 keep-alive clients, 2 long
downloads, one WebSocket, `hard-stop-after 4s`, SIGUSR2 every second, 100 reloads, nbthread 1,
release build, same machine:

| | HAProxy 3.5-dev8 | Alcyon |
|---|---|---|
| failed requests / resets | 0 / 0 | 0 / 0 |
| requests that met a closed keep-alive connection (client retried) | 23 | 0 |
| responses with `Connection: close` from the old process | 777 | 800 |
| long downloads cut | 0 | 0 |
| WebSocket on the old process closed after its reload | 3.2-4.3 s (FIN) | 4.0-4.1 s (FIN or RST) |
| old process gone after its reload, max / median | 4.35 s / 1.85 s | 4.15 s / 1.70 s |
| reload time (SIGUSR2 to new process) max | 0.04 s | 0.05 s |
| RSS master (HAProxy) / serving process (Alcyon), reload 10 -> 100 | 20984 -> 20844 kB | 8184 -> 8148 kB |
| all processes' RSS, peak during reloads | 377 MB | 33 MB |
| fds, net of TCP connections, reload 10 -> 100 | 10 -> 12 (one per live worker) | 6 -> 6 |
| SIGUSR1 with a download in flight | completes, exit | completes, exit |

As in HAProxy, a stopping process answers every request it reads with `Connection: close` and
closes idle connections only when it has nothing else to run, so a client under constant load is
told to reconnect rather than having its connection closed between two requests. A client that is
idle when the stop comes is closed; a request it sends at that instant can meet the close (the
retried case above), as with HAProxy. `crates/alcyon-rt/tests/it/reload_under_load.rs` runs 10 reloads
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

`systemctl stop alcyon` sends SIGTERM (fast). For a graceful stop use
`systemctl kill -s USR1 alcyon` and wait for the service to leave `active`.

## Logs

- Alcyon uses HAProxy's `log` directive and writes in the HAProxy syslog format
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
row come back, `show info` is `Name: Alcyon`. The CSV fields monitoring reads are made equal to
HAProxy's after the same traffic in T165.

## Runtime API

Declare `stats socket /run/alcyon/admin.sock mode 600 level admin` in `global` (needs
`/run/alcyon` to exist and be writable: add `RuntimeDirectory=alcyon` to the unit; the shipped unit
does not). Talk to it as with HAProxy, e.g. `echo "show stat" | socat - /run/alcyon/admin.sock`.

Commands that exist (from `help` and run): `help`, `prompt`, `quit`, `set timeout cli`,
`show info`, `show pools`, `show stat`, `show table`, `show servers state`, `show errors`,
`show backend`, `show version`, `clear counters`, `enable|disable health`,
`enable|disable server`, `set server <b>/<s> state|maxconn|weight`, `set maxconn
server|global|frontend|backend`, `set weight`, `shutdown sessions server|backend`.
Run: `set server b/s1 weight 5` then `disable server b/s1` and `show servers state` showed
weight 5 and admin state 1.

Runtime changes are not persisted by themselves. As with HAProxy, save them before a reload
(`echo "show servers state" | socat - /run/alcyon.sock > /var/lib/alcyon/state`) and point
`server-state-file` (or `server-state-base` + `load-server-state-from-file local`) at it with
`load-server-state-from-file global` in `defaults`: the new process starts each server with the
saved admin state (maint, drain), operational state, weight (unless the configured weight
changed), `disable health`, last check status, port and check port, and a server written as a
name starts on the saved address (`init-addr last`, the default `last,libc`), so a reload keeps
the addresses DNS gave; a `srv_fqdn` changed from HAProxy's CLI is kept with `resolvers` (T490,
tests in `crates/alcyon-rt/tests/it/server_state_file.rs` and `resolvers.rs`). `srv_use_ssl`, check
address and agent columns are not applied and the start says so.

## Master CLI

`alcyon -W -S /run/alcyon-master.sock[,mode,600] -f ...`, then `socat - /run/alcyon-master.sock`. The
commands and their output are HAProxy 3.5's master CLI (measured side by side; see
`tasks/T200-master-cli.md`): `help`, `show proc`, `reload`, `hard-reload`,
`show startup-logs`, `show version`, `echo`, `show cli level`, `operator`, `user`,
`show env [var]`, `prompt`, `quit`, and `@1 <cmd>` / `@!<pid> <cmd>` / `@master <cmd>`, which
run a command on the serving worker's own CLI (`@1 show info`, `@1 show stat`, ...).

```
$ echo "show proc" | socat - /run/alcyon-master.sock
#<PID>          <type>          <reloads>       <uptime>        <version>
4120            master          1 [failed: 0]   0d00h05m12s     0.1.0
# workers
4388            worker          0               0d00h00m03s     0.1.0
# old workers
4122            worker          1               0d00h05m12s     0.1.0
```

`reload` answers `Success=1` or `Success=0`, `--`, and the startup logs of the new worker (its
configuration errors on a failure). A failed reload leaves the serving worker serving; as in
HAProxy, `show proc` then lists it under "old workers" until the next successful reload, and
`@1` still reaches it. The master exits when the serving worker dies on its own (HAProxy's
default `exit-on-failure`), with the worker's code. A worker exits when its master is gone.

`-S` options: `mode <octal>` only; any other (`level`, `user`, ...) is refused at startup with
`Can't create the master's CLI.` Not done: `show proc debug` prints the plain table; `@1` with
no command (HAProxy's worker interactive mode) prints nothing.

## Does not work yet

- Runtime map and ACL commands (`add map`, `show map`, `show acl`, ...): "Unknown command". The
  milestone lists them.
- `show sess`, `show servers conn`: "Unknown command".
- Error messages from `-c` do not name the file.
- A connection refused by a server is reported only after the connect timeout (3 s in my test
  where HAProxy answers 503 at once): T170.
- Unix-socket syslog target: not verified (above).
- Reload under load repeated 100 times, RSS and fd stability: not measured.
- Everything the parser refuses (HTTP/3, Lua, SPOE, peers, cache, FastCGI, compression, ...):
  [differences.md](differences.md).
