<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE. -->

# systemd unit for Ibex release candidates

`ibex.service` is HAProxy's `admin/systemd/haproxy.service.in` with the names changed and the
sandboxing on. Ibex supports what the unit needs: `-Ws` (master-worker, `Type=notify`: it sends
`READY=1`, `RELOADING=1`, `STOPPING=1`), `-p` pidfile, `-S` master socket, `-c` check, and a reload
on SIGUSR2 sent to the master (`MAINPID`, which never changes with `-S`). Details: `docs/operating.md`.

```
install -m 0755 target/release/ibex /usr/local/sbin/ibex
install -d /etc/ibex/certs
install -m 0644 examples/personal-website.cfg /etc/ibex/ibex.cfg
install -m 0644 tools/systemd/ibex.service /etc/systemd/system/ibex.service
systemd-analyze verify /etc/systemd/system/ibex.service
systemctl daemon-reload && systemctl enable --now ibex
```

- Settings can be overridden in `/etc/default/ibex` (`CONFIG=`, `PIDFILE=`, `EXTRAOPTS=`).
- `RuntimeDirectory=ibex` creates `/run/ibex` for the pidfile, the master socket and a
  `stats socket /run/ibex/admin.sock`.
- `systemctl reload ibex` runs `ibex -c` first; a bad configuration fails the reload and the
  running worker keeps serving.
- `systemctl stop` is a fast stop (SIGTERM). For a graceful one: `systemctl kill -s USR1 ibex`.
- The sandbox (`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`, a syscall
  filter) has been checked with `systemd-analyze verify` and by running the `ExecStart` /
  `ExecReload` lines by hand, not under a running systemd. If the service fails to start with a
  permission error, comment out the sandbox lines one at a time and report which one it was.
