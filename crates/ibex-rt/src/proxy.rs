// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy 1.0.2 process_cli(), process_srv() and process_task()
// (haproxy.c), and from mainline's src/stream.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stream engine for `mode tcp`.
//!
//! HAProxy 1.0.2's `process_cli()` and `process_srv()` are the specification. Each
//! inspects both sides, advances at most one state, and returns whether anything
//! changed; `process_task()` runs them until neither does. That "iterate to quiescence"
//! shape is preserved here, because it is what makes the two directions compose without
//! either needing to know the other's internals.
//!
//! The mux layer is absent by design, not by omission: in `mode tcp` HAProxy uses
//! `mux_pt`, the passthrough mux, which adds no framing. The seam is real ([`Mux`] in
//! `ibex-proto`), and an H1 mux slots in at exactly the point where this module moves
//! bytes between [`Buf`]s.
//!
//! [`Mux`]: ibex_proto::Mux

use crate::buf::Buf;
use crate::raw::{self, Io};
use ibex_proto::endpoint::ScState;
use ibex_sched::Tick;
use std::io;
use std::os::fd::{AsFd, OwnedFd};

/// Default per-direction buffer. HAProxy 1.0 used `BUFSIZE` 8192.
pub const BUFSIZE: usize = 16 * 1024;

/// Why a session ended. Reported to logs and to `show sess`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Ending {
    /// Both directions completed normally.
    Complete,
    /// The client went away.
    ClientAbort,
    /// The server went away.
    ServerAbort,
    /// No server could be reached after exhausting retries.
    ConnectFailed,
    /// A timeout fired. Carries which one, for the log.
    Timeout(Which),
    /// An unexpected I/O error.
    Error,
}

/// Which side a timeout belongs to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Which {
    Client,
    Server,
    Connect,
}

/// What a side wants from the poller next.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Want {
    pub read: bool,
    pub write: bool,
}

/// Timeouts, in milliseconds. Zero means "not set", matching 1.0's config semantics.
#[derive(Copy, Clone, Debug, Default)]
pub struct Timeouts {
    pub client: u32,
    pub server: u32,
    pub connect: u32,
}

/// One TCP session: two connections, two buffers, two state machines.
///
/// 1.0's `struct task` held exactly this — `cli_fd`/`srv_fd`, `cli_state`/`srv_state`,
/// `req`/`rep` — plus the task itself. Here the task lives in the scheduler and this
/// holds only the session, which is the split described in `design/001-layering.md`.
pub struct TcpSession {
    pub cli: OwnedFd,
    pub srv: Option<OwnedFd>,
    pub cli_state: ScState,
    pub srv_state: ScState,
    /// Client to server.
    pub req: Buf,
    /// Server to client.
    pub rep: Buf,
    pub timeouts: Timeouts,
    /// Connect attempts left before giving up.
    pub conn_retries: u16,
    /// Deadline for the operation currently in flight on each side.
    pub cli_exp: Tick,
    pub srv_exp: Tick,
    pub conn_exp: Tick,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ending: Option<Ending>,
}

impl TcpSession {
    #[must_use]
    pub fn new(cli: OwnedFd, timeouts: Timeouts, retries: u16, now: Tick) -> Self {
        let mut s = TcpSession {
            cli,
            srv: None,
            cli_state: ScState::Established,
            srv_state: ScState::Init,
            req: Buf::with_capacity(BUFSIZE),
            rep: Buf::with_capacity(BUFSIZE),
            timeouts,
            conn_retries: retries,
            cli_exp: Tick::ETERNITY,
            srv_exp: Tick::ETERNITY,
            conn_exp: Tick::ETERNITY,
            bytes_in: 0,
            bytes_out: 0,
            ending: None,
        };
        s.arm_client(now);
        s
    }

    fn arm_client(&mut self, now: Tick) {
        self.cli_exp = if self.timeouts.client == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.client)
        };
    }

    fn arm_server(&mut self, now: Tick) {
        self.srv_exp = if self.timeouts.server == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.server)
        };
    }

    /// Attaches a server-side connection that is still connecting.
    pub fn attach_server(&mut self, fd: OwnedFd, now: Tick) {
        self.srv = Some(fd);
        self.srv_state = ScState::Connecting;
        self.conn_exp = if self.timeouts.connect == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.connect)
        };
    }

    /// The server connection completed.
    pub fn server_connected(&mut self, now: Tick) {
        self.srv_state = ScState::Established;
        self.conn_exp = Tick::ETERNITY;
        self.arm_server(now);
    }

    /// The server connection failed. Returns `true` if a retry remains.
    pub fn server_failed(&mut self) -> bool {
        self.srv = None;
        self.conn_exp = Tick::ETERNITY;
        if self.conn_retries > 0 {
            self.conn_retries -= 1;
            self.srv_state = ScState::Init;
            true
        } else {
            self.srv_state = ScState::Error;
            self.ending.get_or_insert(Ending::ConnectFailed);
            false
        }
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self.cli_state, ScState::Closed | ScState::Error)
            && matches!(self.srv_state, ScState::Closed | ScState::Error)
    }

    // ---- the two state machines --------------------------------------------------

    /// Advances the client side. Returns `true` if anything changed.
    ///
    /// Mirrors 1.0's `process_cli()`, minus the HTTP header states: in `mode tcp` the
    /// client starts in `CL_STDATA`, which is `ScState::Established` here.
    fn process_cli(&mut self) -> io::Result<bool> {
        let mut changed = false;

        if self.cli_state == ScState::Established {
            // Read from the client into the request buffer, but only while there is
            // room. A full buffer is backpressure: we stop reading, the socket buffer
            // fills, and TCP flow control slows the client. Reading regardless would
            // mean buffering without bound on behalf of a slow server.
            if !self.req.is_full() {
                let dst = self.req.writable();
                match raw::recv(self.cli.as_fd(), dst)? {
                    Io::Done(0) | Io::Closed => {
                        self.cli_state = ScState::Closed;
                        self.ending.get_or_insert(Ending::ClientAbort);
                        changed = true;
                    }
                    Io::Done(n) => {
                        self.req.commit(n);
                        self.bytes_in += n as u64;
                        changed = true;
                    }
                    Io::WouldBlock => {}
                }
            }

            // Write any response data back to the client.
            if !self.rep.is_empty() {
                match raw::send(self.cli.as_fd(), self.rep.readable())? {
                    Io::Done(n) if n > 0 => {
                        self.rep.consume(n);
                        self.bytes_out += n as u64;
                        changed = true;
                    }
                    Io::Closed => {
                        self.cli_state = ScState::Closed;
                        self.ending.get_or_insert(Ending::ClientAbort);
                        changed = true;
                    }
                    Io::Done(_) | Io::WouldBlock => {}
                }
            }
        }

        // The server is finished and everything it sent has been delivered: tell the
        // client no more is coming. Draining before shutting down is what preserves
        // data on a half-close.
        if matches!(self.srv_state, ScState::Closed | ScState::Error)
            && self.rep.is_empty()
            && self.cli_state == ScState::Established
        {
            raw::shutdown_write(self.cli.as_fd());
            self.cli_state = ScState::Closed;
            self.ending.get_or_insert(if self.srv_state == ScState::Error {
                Ending::ServerAbort
            } else {
                Ending::Complete
            });
            changed = true;
        }

        Ok(changed)
    }

    /// Advances the server side. Returns `true` if anything changed.
    ///
    /// Mirrors 1.0's `process_srv()`.
    fn process_srv(&mut self) -> io::Result<bool> {
        let mut changed = false;

        match self.srv_state {
            ScState::Init => {
                // 1.0: while idle, give up if the client is gone and has left nothing
                // behind. Connecting to a server for a client that has already
                // vanished is pure waste, and under a connection flood it is the
                // difference between absorbing the flood and amplifying it.
                if matches!(self.cli_state, ScState::Closed | ScState::Error)
                    && self.req.is_empty()
                {
                    self.srv_state = ScState::Closed;
                    changed = true;
                }
                // Otherwise the caller performs the connect and calls attach_server.
            }

            ScState::Connecting => {
                // Completion is reported by write readiness; the caller checks
                // SO_ERROR and calls server_connected or server_failed.
            }

            ScState::Established => {
                if self.srv.is_none() {
                    self.srv_state = ScState::Error;
                    return Ok(true);
                }

                // Each syscall borrows the fd for exactly its own duration. Holding
                // one borrow across the whole arm would conflict with mutating the
                // buffers and the state, which is the borrow checker correctly
                // objecting to aliasing that C leaves to the programmer.
                if !self.req.is_empty() {
                    let r = {
                        let sfd = self.srv.as_ref().map(AsFd::as_fd).ok_or_else(|| {
                            io::Error::from(io::ErrorKind::NotConnected)
                        })?;
                        raw::send(sfd, self.req.readable())?
                    };
                    match r {
                        Io::Done(n) if n > 0 => {
                            self.req.consume(n);
                            changed = true;
                        }
                        Io::Closed => {
                            self.srv_state = ScState::Closed;
                            self.ending.get_or_insert(Ending::ServerAbort);
                            changed = true;
                        }
                        Io::Done(_) | Io::WouldBlock => {}
                    }
                }

                if self.srv_state == ScState::Established && !self.rep.is_full() {
                    let r = {
                        let sfd = self.srv.as_ref().map(AsFd::as_fd).ok_or_else(|| {
                            io::Error::from(io::ErrorKind::NotConnected)
                        })?;
                        let dst = self.rep.writable();
                        raw::recv(sfd, dst)?
                    };
                    match r {
                        Io::Done(0) | Io::Closed => {
                            self.srv_state = ScState::Closed;
                            changed = true;
                        }
                        Io::Done(n) => {
                            self.rep.commit(n);
                            changed = true;
                        }
                        Io::WouldBlock => {}
                    }
                }

                // The client is finished and everything it sent has been forwarded.
                if matches!(self.cli_state, ScState::Closed | ScState::Error)
                    && self.req.is_empty()
                    && self.srv_state == ScState::Established
                {
                    if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                        raw::shutdown_write(sfd);
                    }
                    changed = true;
                    // Stay Established: the server may still be sending, and a
                    // half-closed client must still receive it.
                    self.cli_state = ScState::Closed;
                }
            }

            ScState::Queue | ScState::Assigned | ScState::Ready => {}
            ScState::Closed | ScState::Error => {}
        }

        Ok(changed)
    }

    /// Runs both sides until neither changes state.
    ///
    /// Mirrors 1.0's `process_task()`. The iteration bound is not decoration: each pass
    /// is driven by data the peer controls, so an unbounded loop here is a
    /// denial-of-service primitive. On exhaustion we return normally and the scheduler
    /// re-queues us, which costs a little latency and cannot hang the thread.
    ///
    /// # Errors
    /// Propagates unexpected I/O failures.
    pub fn process(&mut self, now: Tick) -> io::Result<()> {
        for _ in 0..16 {
            let a = self.process_cli()?;
            let b = self.process_srv()?;
            if !a && !b {
                break;
            }
            if self.cli_state == ScState::Established {
                self.arm_client(now);
            }
            if self.srv_state == ScState::Established {
                self.arm_server(now);
            }
        }
        Ok(())
    }

    /// Applies whichever timeout has fired, if any.
    pub fn check_timeouts(&mut self, now: Tick) -> bool {
        if self.conn_exp.is_expired(now) && self.srv_state == ScState::Connecting {
            self.conn_exp = Tick::ETERNITY;
            self.srv_state = ScState::Error;
            self.ending.get_or_insert(Ending::Timeout(Which::Connect));
            return true;
        }
        if self.cli_exp.is_expired(now) && self.cli_state == ScState::Established {
            self.cli_state = ScState::Error;
            self.ending.get_or_insert(Ending::Timeout(Which::Client));
            return true;
        }
        if self.srv_exp.is_expired(now) && self.srv_state == ScState::Established {
            self.srv_state = ScState::Error;
            self.ending.get_or_insert(Ending::Timeout(Which::Server));
            return true;
        }
        false
    }

    /// The earliest deadline across both sides, for the scheduler's wait queue.
    #[must_use]
    pub fn next_expiry(&self) -> Tick {
        self.cli_exp.earliest(self.srv_exp).earliest(self.conn_exp)
    }

    /// What each side needs from the poller.
    ///
    /// Derived from buffer occupancy, which is what makes backpressure work: a full
    /// request buffer stops us asking for client readability, the client's socket
    /// buffer fills, and TCP slows the sender.
    #[must_use]
    pub fn interests(&self) -> (Want, Want) {
        let cli = Want {
            read: self.cli_state == ScState::Established && !self.req.is_full(),
            write: self.cli_state == ScState::Established && !self.rep.is_empty(),
        };
        let srv = match self.srv_state {
            ScState::Connecting => Want { read: false, write: true },
            ScState::Established => Want {
                read: !self.rep.is_full(),
                write: !self.req.is_empty(),
            },
            _ => Want::default(),
        };
        (cli, srv)
    }
}
