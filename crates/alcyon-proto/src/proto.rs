// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/protocol-t.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! L4: the socket layer. `HAProxy`'s `struct protocol`, reached through
//! `connection->ctrl`.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;

/// Which address family and socket type a protocol serves.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProtoKind {
    TcpV4,
    TcpV6,
    UnixStream,
}

/// Operations at the socket layer: bind, listen, accept, connect.
///
/// Deliberately **not** async. `HAProxy` is a readiness-driven state machine, not a
/// coroutine system, and Alcyon keeps that: file descriptors are non-blocking, operations
/// return [`io::ErrorKind::WouldBlock`], and the scheduler re-runs the task when the
/// poller reports readiness. Introducing `async fn` here would mean every connection
/// holds a suspended future whose size we do not control — the opposite of the 32-byte
/// discipline applied to tasks.
pub trait Protocol {
    /// Family and socket type this implementation serves.
    fn kind(&self) -> ProtoKind;

    /// Human-readable name, as it appears in `show fd` output.
    fn name(&self) -> &'static str;

    /// Creates a listening socket. `reuse_port` is required for thread-per-core, where
    /// every thread binds its own listener rather than sharing one.
    ///
    /// # Errors
    /// Propagates the underlying socket, bind or listen failure.
    fn bind(&self, addr: SocketAddr, backlog: u32, reuse_port: bool) -> io::Result<RawFd>;

    /// Accepts one connection. Returns `Ok(None)` when the queue is drained
    /// (`WouldBlock`), which is the normal loop-termination condition rather than an
    /// error.
    ///
    /// # Errors
    /// Propagates accept failures other than `WouldBlock`.
    fn accept(&self, listener: RawFd) -> io::Result<Option<(RawFd, SocketAddr)>>;

    /// Starts a non-blocking connect. `Ok(false)` means the connection is still in
    /// progress and completion will be reported by write readiness.
    ///
    /// # Errors
    /// Propagates socket creation or connect failures other than `EINPROGRESS`.
    fn connect(&self, addr: SocketAddr) -> io::Result<(RawFd, bool)>;

    /// Peer address of an established socket.
    ///
    /// # Errors
    /// Propagates `getpeername` failure.
    fn peer_addr(&self, fd: RawFd) -> io::Result<SocketAddr>;
}
