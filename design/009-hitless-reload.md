# Alcyon Design: Hitless Reload

This document details the mechanics of HAProxy's hitless reload based on the 3.5 tree and evaluates how Alcyon should achieve the same properties without adopting HAProxy's legacy architecture.

## Part 1 — What HAProxy actually does

HAProxy's hitless reload requires the combination of soft stop, FD handover, and SO_REUSEPORT. Each solves a specific part of the connection drop window.

### Soft stop
Soft stop allows a process to finish serving established connections without accepting new ones.
- **Handling:** `src/haproxy.c:2609` registers `sig_soft_stop` as the handler for `SIGUSR1`. This calls `soft_stop()` (`src/proxy.c:3961`), which sets the `stopping` flag and initiates `do_soft_stop_now()` (`src/proxy.c:3904`).
- **Draining:** `do_soft_stop_now()` calls `protocol_stop_now()` (`src/protocol.c:413`), which unbinds all listening sockets. Existing connections continue to be processed.
- **Completion:** The main loop (`src/haproxy.c:3117`) checks `if ((jobs - unstoppable_jobs) == 0)`. When active jobs reach zero, the process breaks out of the loop and terminates naturally.
- **Hard-stop limit:** If `hard-stop-after` is configured, `do_soft_stop_now()` schedules a `hard_stop` task (`src/proxy.c:3860`), which forces termination (`killed = 2`) once the delay expires.

### FD handover
FD handover ensures that the listening sockets (and their kernel-level accept queues) are physically transferred to the new process, leaving no gap in listening.
- **Retrieval:** When started with `-x <unix_socket>`, the new process calls `sock_get_old_sockets()` (`src/sock.c:469`), which connects to the old process and sends the `_getsocks` command.
- **Transfer:** The old process's CLI parses `_getsocks` (`src/cli.c:2750`) and loops through its listeners, using `_getsocks_send_one` to pass the file descriptors over the Unix socket via `SCM_RIGHTS`.
- **The Gap:** Without FD handover, when the old process closes its listening port, the kernel drops any pending connections that were already in the socket's accept queue, resulting in `RST` packets being sent to clients (`doc/management.txt:720-750`). FD passing completely avoids this because the same kernel socket is kept alive.

### Where `SO_REUSEPORT` fits
`SO_REUSEPORT` is a **complement** to FD handover, not an alternative.
- As documented in `doc/management.txt:720-745`, `SO_REUSEPORT` allows the new process to bind *before* the old process unbinds, eliminating the `Connection Refused` window for *new* SYNs.
- However, it does **not** solve the second race condition: any connections left in the old process's accept queue when it soft-stops will still be dropped and receive an `RST`. Only FD handover shares the exact same socket and queue, making the reload genuinely hitless.

### mworker V3
Introduced in HAProxy 3.1 (`doc/internals/mworker.md`), V3 ensures a failed config reload does not disrupt the running process:
- **Discovery:** The master process performs a light "discovery" parse of only master-specific keywords so its event loop isn't blocked.
- **Forking:** It forks a new worker with `PROC_O_INIT` (`src/haproxy.c:3827`).
- **Validation:** The new worker parses the full configuration. If successful, it sends a `READY` message over the mCLI socketpair (`src/haproxy.c:4013-4080`).
- **The Guarantee:** The master explicitly waits to receive `READY` before sending `SIGUSR1` to the old worker (`src/haproxy.c:3827-3840`). If the new worker fails to parse (exiting early), it never sends `READY`, the master receives `SIGCHLD`, and the old worker continues serving traffic uninterrupted.

## Part 2 — The master-worker question

**Claim:** Master-worker is being deprecated.
**Result:** False. The claim conflates the deprecation of a specific global keyword with the deprecation of the mode itself.

- **Keyword removed, mode active:** Commit `5a6ce0481` (2026-06-30) explicitly states: *MAJOR: mworker: remove deprecated "master-worker" global keyword... Now using it results in an error message inviting to start haproxy with -W or -Ws instead.* `src/cfgparse-global.c:973` enforces this by rejecting the bare keyword but pointing users to the command-line flags.
- **No replacement planned:** A search of the git log for `socket activation`, `FDSTORE`, and `mworker V4` reveals no active replacements for the fork-and-exec reload mechanism. The `sd_notify` integration (`src/systemd.c`, introduced in 3.0) signals state to systemd but does not replace the worker management. V3 is the settled design.

## Part 3 — What Alcyon would have to build

Alcyon is a single-process Rust binary with an async scheduler. It does not carry HAProxy's `nbproc` history.

**1. Soft stop alone**
- **Action:** Install a `SIGUSR1` handler in `crates/alcyon-rt/src/bin/alcyon.rs`, unbind listeners, and wait for active async tasks to drain before exiting.
- **What breaks:** The reload becomes graceful but not hitless. As soon as the listener drops, clients in the accept queue receive `RST`s.

**2. FD handover**
- **Action:** Implement an IPC socket in the runtime/CLI where the old process can send its FDs via `SCM_RIGHTS`. The startup sequence in `alcyon.rs` must attempt to connect to this socket and adopt the FDs before binding anew.
- **Value:** This is what actually guarantees zero connection drops. Without it, high-traffic hitless reload is impossible.

**3. Adopt master-worker at all?**
- **Action:** Alcyon **should not** copy the master-worker structure.
- **Why:** HAProxy's master process exists to supervise multiple workers and to offload heavy config parsing from a single-threaded event loop. Alcyon doesn't have these constraints.
- **Alternative:** Alcyon can achieve the exact same V3 property (failed reload leaves the old process serving) through a standalone `ExecReload` workflow paired with FD handover:
  1. Systemd spawns a *new* Alcyon process.
  2. The new process parses the config. If it fails, it exits (the old process is entirely unaware and unaffected).
  3. If parsing succeeds, the new process connects to the old process's IPC socket and requests the FDs.
  4. Only after safely binding the FDs does the new process send `SIGUSR1` to the old process to trigger a soft stop.

This reaches HAProxy's exact behavioral guarantees without imitating its structural legacy.

## Part 4 — As implemented (`eaddcd6`, `ed51cb9`, and the SIGUSR2 commit after them)

Parts 1 and 2 above were implemented as written. Part 3's workflow was not, because it
cannot work under systemd:

> 1. Systemd spawns a *new* Alcyon process.

`ExecReload` commands must exit, so a process started by one cannot become the server; and
under `Type=notify`, when the main PID exits with no successor named, systemd treats the
service as failed. That is the exact failure the "haproxy-systemd-wrapper" history in
`doc/internals/mworker.md` describes. HAProxy solves it with a master whose PID never
changes. Alcyon has no master and cannot re-exec in place without discarding every
in-flight session, so the serving PID *must* change on reload. What makes that safe:

- **The running process starts its successor**, on `SIGUSR2` (`-W` / `-Ws`), with the same
  arguments plus `-x <private socket> -sf <own pid>`. The unit file is HAProxy's:
  `ExecReload=... -c` then `ExecReload=/bin/kill -USR2 $MAINPID`.
- **The successor's `-sf` is the success signal.** It is only sent once every worker is
  listening. On receiving it, the old process sends `MAINPID=<new>` / `READY=1` itself --
  it is still the main PID at that moment, so this works under the default
  `NotifyAccess=main` -- and only then drains.
- **The old process must not send `STOPPING=1` while handing over.** It is still the main
  PID when it begins to drain, and systemd would read that as the service stopping in the
  middle of a reload.
- **A successor that exits instead is a failed reload**: `READY=1` / `STATUS=Reload failed!`,
  and the old process goes on serving. Its pidfile is only written after takeover, so it
  keeps naming the process that is actually serving.
- **The handover socket is private**: a fresh 0700 directory, not the stats socket, so a
  SIGUSR2 reload needs no `expose-fd listeners` and nothing else on the host can connect
  and take the listeners.

`-x` against an operator-managed stats socket with `expose-fd listeners` also works, for
reloads done by hand as `alcyon -f cfg -x <sock> -sf <pid>`.

### Not done

- **QUIC.** Listeners are not handed over and QUIC connections are not drained: a QUIC
  connection lives on the listening UDP socket, so sharing it between two processes would
  deliver each one's datagrams to the other. HTTP/3 connections are cut at reload.
- **HTTP/2 soft stop** does not send GOAWAY; H2 sessions drain until `hard-stop-after`.
- **`SIGTTOU`/`SIGTTIN`** (pause/resume listeners) are not handled.

### Evidence

`crates/alcyon-rt/tests/it/soft_stop.rs` and `tests/reload.rs` drive the real binary.
`harness/systemd_reload.sh` drives `admin/systemd/alcyon.service` through `systemctl --user`
under continuous load: three reloads, a reload onto a broken config (refused, `MainPID`
unchanged, `Reload failed!`), a recovering reload, and a stop. Four runs, 27,002 requests,
one failure; 40 SIGUSR2 reloads without systemd, 21,743 requests, none. The one failure was
a response whose body arrived without its status line or headers -- not reproduced since,
and nothing in the handover can drop bytes from an established connection, so it is
recorded here as an open observation in the response path rather than as explained.
