// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/raw_sock.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `raw_sock`: the null transport. Bytes pass through untouched.

use rustix::io::Errno;
use rustix::net::{
    self, AddressFamily, Ipv4Addr, Ipv6Addr, SocketAddrAny, SocketAddrV4, SocketAddrV6,
    SocketFlags, SocketType,
};
use std::cell::Cell;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{BorrowedFd, OwnedFd};

/// Outcome of a transport read or write.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Io {
    /// Moved `n` bytes.
    Done(usize),
    /// Not ready. The caller must wait for readiness rather than retry.
    WouldBlock,
    /// The peer shut down its write side (clean EOF / FIN).
    Eof,
    /// The peer closed, reset, or the connection failed.
    Closed,
}

thread_local! {
    static READS: Cell<u64> = const { Cell::new(0) };
    static READS_BLOCKED: Cell<u64> = const { Cell::new(0) };
}

/// Read syscalls [`recv`] has made on this thread, and how many of them the kernel
/// answered with `EAGAIN`: a read made before the poller said there was anything to
/// read. `HAProxy` makes almost none of the second kind (`fd_cant_recv`); the counts are
/// how a test holds Ibex to that.
#[must_use]
pub fn read_counters() -> (u64, u64) {
    (READS.with(Cell::get), READS_BLOCKED.with(Cell::get))
}

/// Reads into `buf`.
///
/// `EAGAIN` becomes [`Io::WouldBlock`] rather than an error, `Ok(0)` becomes [`Io::Eof`],
/// and a peer reset becomes [`Io::Closed`]. Both are ordinary control flow for a proxy:
/// a client vanishing mid-request is normal traffic, not an exceptional condition, and
/// treating it as an error would mean every call site distinguishing it again.
///
/// # Errors
/// Propagates genuinely unexpected failures.
pub fn recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Io> {
    if buf.is_empty() {
        return Ok(Io::Done(0));
    }
    READS.with(|c| c.set(c.get() + 1));
    match rustix::io::read(fd, buf) {
        Ok(0) => Ok(Io::Eof),
        Ok(n) => Ok(Io::Done(n)),
        Err(Errno::AGAIN | Errno::INTR) => {
            READS_BLOCKED.with(|c| c.set(c.get() + 1));
            Ok(Io::WouldBlock)
        }
        Err(Errno::CONNRESET | Errno::PIPE | Errno::NOTCONN | Errno::TIMEDOUT) => Ok(Io::Closed),
        Err(e) => Err(e.into()),
    }
}

/// Writes from `buf`.
///
/// # Errors
/// Propagates genuinely unexpected failures.
pub fn send(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<Io> {
    if buf.is_empty() {
        return Ok(Io::Done(0));
    }
    match rustix::io::write(fd, buf) {
        Ok(n) => Ok(Io::Done(n)),
        Err(Errno::AGAIN | Errno::INTR) => Ok(Io::WouldBlock),
        Err(Errno::CONNRESET | Errno::PIPE | Errno::NOTCONN | Errno::TIMEDOUT) => Ok(Io::Closed),
        Err(e) => Err(e.into()),
    }
}

/// Shuts down the read direction.
pub fn shutdown_read(fd: BorrowedFd<'_>) {
    let _ = rustix::net::shutdown(fd, rustix::net::Shutdown::Read);
}

/// Shuts down the write direction, sending FIN while leaving reads open.
///
/// This is what makes half-close work: the proxy must be able to tell one side that no
/// more data is coming without tearing down the other direction.
pub fn shutdown_write(fd: BorrowedFd<'_>) {
    let _ = rustix::net::shutdown(fd, rustix::net::Shutdown::Write);
}

/// Shuts down both read and write directions.
pub fn shutdown_both(fd: BorrowedFd<'_>) {
    let _ = rustix::net::shutdown(fd, rustix::net::Shutdown::ReadWrite);
}

/// Converts a [`SocketAddr`] to a [`SocketAddrAny`].
#[must_use]
pub fn to_any(addr: SocketAddr) -> SocketAddrAny {
    match addr {
        SocketAddr::V4(v4) => SocketAddrAny::V4(SocketAddrV4::new(
            Ipv4Addr::from(v4.ip().octets()),
            v4.port(),
        )),
        SocketAddr::V6(v6) => SocketAddrAny::V6(SocketAddrV6::new(
            Ipv6Addr::from(v6.ip().octets()),
            v6.port(),
            v6.flowinfo(),
            v6.scope_id(),
        )),
    }
}

/// Converts a [`SocketAddrAny`] to a [`SocketAddr`].
#[must_use]
pub fn from_any(a: &SocketAddrAny) -> Option<SocketAddr> {
    match a {
        SocketAddrAny::V4(v4) => Some(SocketAddr::new(
            std::net::Ipv4Addr::from(v4.ip().octets()).into(),
            v4.port(),
        )),
        SocketAddrAny::V6(v6) => Some(SocketAddr::new(
            std::net::Ipv6Addr::from(v6.ip().octets()).into(),
            v6.port(),
        )),
        _ => None,
    }
}

/// Initiates a non-blocking TCP connect.
///
/// Returns `(fd, is_connected_immediately)`. If the connect is in progress,
/// `is_connected_immediately` is `false`.
///
/// # Errors
/// Returns an error if socket creation fails or if `connect` fails immediately with an error other than `EINPROGRESS`.
pub fn connect(addr: SocketAddr) -> io::Result<(OwnedFd, bool)> {
    let family = match addr {
        SocketAddr::V4(_) => AddressFamily::INET,
        SocketAddr::V6(_) => AddressFamily::INET6,
    };
    let fd = net::socket_with(
        family,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;

    // Disable Nagle's algorithm matching HAProxy
    let _ = net::sockopt::set_tcp_nodelay(&fd, true);

    let any = to_any(addr);
    match net::connect_any(&fd, &any) {
        Ok(()) => Ok((fd, true)),
        Err(Errno::INPROGRESS) => Ok((fd, false)),
        Err(e) => Err(e.into()),
    }
}

/// Checks the connection status of a non-blocking connecting socket.
///
/// Returns `Ok(None)` if connected successfully, or `Ok(Some(err))` if connection failed with a socket error.
///
/// # Errors
/// Returns an error if the `getsockopt` syscall fails.
pub fn check_connect_error(fd: BorrowedFd<'_>) -> io::Result<Option<io::Error>> {
    match net::sockopt::get_socket_error(fd) {
        Ok(Ok(())) => Ok(None),
        Ok(Err(errno)) => Ok(Some(errno.into())),
        Err(e) => Err(e.into()),
    }
}

/// Resets the connection immediately with an active TCP RST by configuring `SO_LINGER` 0.
pub fn abort_with_rst(fd: BorrowedFd<'_>) {
    let _ = net::sockopt::set_socket_linger(fd, Some(std::time::Duration::ZERO));
}

/// Discards the connection quietly: sets TTL to 1 (so emitted RST packets expire
/// at the first hop and do not reach the client) and linger 0.
pub fn silent_drop(fd: BorrowedFd<'_>, is_ipv6: bool) {
    if is_ipv6 {
        let _ = net::sockopt::set_ipv6_unicast_hops(fd, Some(1));
    } else {
        let _ = net::sockopt::set_ip_ttl(fd, 1);
    }
    let _ = net::sockopt::set_socket_linger(fd, Some(std::time::Duration::ZERO));
}

/// Checks if an idle connection is still clean and open.
///
/// Returns `true` if the socket is alive, open, and has no pending unread bytes.
/// Returns `false` if the socket has received FIN/EOF, RST, error, or unexpected bytes.
#[must_use]
pub fn is_idle_conn_alive(fd: BorrowedFd<'_>) -> bool {
    let mut buf = [0u8; 1];
    matches!(
        net::recv(fd, &mut buf, net::RecvFlags::PEEK | net::RecvFlags::DONTWAIT),
        Err(Errno::AGAIN)
    )
}
