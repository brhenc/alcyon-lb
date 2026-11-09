<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE. -->

# systemd unit for Alcyon release candidates

`alcyon.service` is HAProxy's `admin/systemd/haproxy.service.in` with the names changed and the
sandboxing on. Alcyon supports what the unit needs: `-Ws` (master-worker, `Type=notify`: it sends
`READY=1`, `RELOADING=1`, `STOPPING=1`), `-p` pidfile, `-S` master socket, `-c` check, and a reload
on SIGUSR2 sent to the master (`MAINPID`, which never changes with `-S`). Details: `docs/operating.md`.

```
install -m 0755 target/release/alcyon /usr/local/sbin/alcyon
install -d /etc/alcyon/certs
install -m 0644 examples/personal-website.cfg /etc/alcyon/alcyon.cfg
install -m 0644 tools/systemd/alcyon.service /etc/systemd/system/alcyon.service
systemd-analyze verify /etc/systemd/system/alcyon.service
systemctl daemon-reload && systemctl enable --now alcyon
```

- Settings can be overridden in `/etc/default/alcyon` (`CONFIG=`, `PIDFILE=`, `EXTRAOPTS=`).
- `RuntimeDirectory=alcyon` creates `/run/alcyon` for the pidfile, the master socket and a
  `stats socket /run/alcyon/admin.sock`.
- `systemctl reload alcyon` runs `alcyon -c` first; a bad configuration fails the reload and the
  running worker keeps serving.
- `systemctl stop` is a fast stop (SIGTERM). For a graceful one: `systemctl kill -s USR1 alcyon`.
- The sandbox (`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`, a syscall
  filter) has been checked with `systemd-analyze verify` and by running the `ExecStart` /
  `ExecReload` lines by hand, not under a running systemd. If the service fails to start with a
  permission error, comment out the sandbox lines one at a time and report which one it was.
