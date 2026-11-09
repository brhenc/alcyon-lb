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
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
    static WRITES: Cell<u64> = const { Cell::new(0) };
}

/// Write syscalls [`send`] has made on this thread. A response that leaves in several
/// writes when one would do costs a syscall each, and on a client that waits for the whole
/// response, a delayed-ACK round trip for the segments Nagle holds back (T186).
#[must_use]
pub fn write_counters() -> u64 {
    WRITES.with(Cell::get)
}

/// Read syscalls [`recv`] has made on this thread, and how many of them the kernel
/// answered with `EAGAIN`: a read made before the poller said there was anything to
/// read. `HAProxy` makes almost none of the second kind (`fd_cant_recv`); the counts are
/// how a test holds Alcyon to that.
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
/// Reads what is queued on `fd` without consuming it (`MSG_PEEK`). For the bytes that
/// come before a protocol another layer owns: a PROXY header ahead of a TLS handshake
/// is parsed from a peek, then exactly its length is taken with [`recv`], so not one
/// byte of the ClientHello behind it is read away from rustls.
///
/// # Errors
/// Socket errors other than the ones [`Io`] stands for.
pub fn peek(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Io> {
    if buf.is_empty() {
        return Ok(Io::Done(0));
    }
    match net::recv(fd, buf, net::RecvFlags::PEEK | net::RecvFlags::DONTWAIT) {
        Ok(0) => Ok(Io::Eof),
        Ok(n) => Ok(Io::Done(n)),
        Err(Errno::AGAIN | Errno::INTR) => Ok(Io::WouldBlock),
        Err(Errno::CONNRESET | Errno::PIPE | Errno::NOTCONN | Errno::TIMEDOUT) => Ok(Io::Closed),
        Err(e) => Err(e.into()),
    }
}

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

/// `show info` `TotalBytesOut`, in shards so the threads that write do not share one
/// cache line: `HAProxy` keeps it per thread (`th_ctx->out_bytes`) and sums on read.
#[repr(align(128))]
struct OutShard(AtomicU64);

const OUT_SHARDS: usize = 64;
static OUT_BYTES: [OutShard; OUT_SHARDS] = [const { OutShard(AtomicU64::new(0)) }; OUT_SHARDS];
static OUT_NEXT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static OUT_SHARD: usize = OUT_NEXT.fetch_add(1, Ordering::Relaxed) % OUT_SHARDS;
}

/// Counts `n` bytes written to a socket by a path that does not go through [`send`]
/// (the CLI applet's `std` stream).
pub fn count_out(n: usize) {
    OUT_SHARD.with(|&i| OUT_BYTES[i].0.fetch_add(n as u64, Ordering::Relaxed));
}

/// Every byte written to a client, server, health-check or CLI socket since start
/// (`raw_sock_from_buf` -> `increment_send_rate`): on TLS, the records on the wire.
#[must_use]
pub fn bytes_out() -> u64 {
    OUT_BYTES.iter().map(|s| s.0.load(Ordering::Relaxed)).sum()
}

/// Writes from `buf`, counting what was written in [`bytes_out`].
///
/// # Errors
/// Propagates genuinely unexpected failures.
pub fn send(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<Io> {
    let r = send_uncounted(fd, buf);
    if let Ok(Io::Done(n)) = r {
        count_out(n);
    }
    r
}

/// [`send`] for a hop inside Alcyon that `HAProxy` does not have (the QUIC listener feeding
/// an HTTP/3 request to its engine): not in [`bytes_out`].
///
/// # Errors
/// Propagates genuinely unexpected failures.
pub fn send_uncounted(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<Io> {
    if buf.is_empty() {
        return Ok(Io::Done(0));
    }
    WRITES.with(|c| c.set(c.get() + 1));
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
    connect_opts(addr, false)
}

/// [`connect`], with TCP Fast Open when `tfo` (server `tfo`): `TCP_FASTOPEN_CONNECT`, which
/// makes the kernel send the first write in the SYN, as `HAProxy`'s `MSG_FASTOPEN` does.
///
/// # Errors
/// As [`connect`].
pub fn connect_opts(addr: SocketAddr, tfo: bool) -> io::Result<(OwnedFd, bool)> {
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
    if crate::globalconn::past_maxsock(fd.as_raw_fd()) {
        // "socket(): not enough free sockets": the socket is closed on return.
        return Err(Errno::MFILE.into());
    }

    // Disable Nagle's algorithm matching HAProxy
    let _ = net::sockopt::set_tcp_nodelay(&fd, true);
    if tfo {
        // Best effort, like HAProxy: without kernel support the connect is a plain one.
        let _ = nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::TcpFastOpenConnect, &true);
    }

    let any = to_any(addr);
    match net::connect_any(&fd, &any) {
        Ok(()) => Ok((fd, true)),
        Err(Errno::INPROGRESS) => Ok((fd, false)),
        Err(e) => Err(e.into()),
    }
}

/// The local address of a connected, or connecting, IP socket (`getsockname`): for a server
/// connection, what `%bi` and `%bp` print. `None` for a socket that is not an IP one.
#[must_use]
pub fn local_addr(fd: BorrowedFd<'_>) -> Option<SocketAddr> {
    match net::getsockname(fd).ok()? {
        SocketAddrAny::V4(a) => Some(SocketAddr::V4(a)),
        SocketAddrAny::V6(a) => Some(SocketAddr::V6(std::net::SocketAddrV6::new(*a.ip(), a.port(), 0, 0))),
        _ => None,
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

/// Whether the connection has been reset by its peer, without consuming the error.
#[must_use]
pub fn reset_pending(fd: BorrowedFd<'_>) -> bool {
    use rustix::event::{poll, PollFd, PollFlags};
    let mut fds = [PollFd::new(&fd, PollFlags::empty())];
    matches!(poll(&mut fds, 0), Ok(n) if n > 0) && fds[0].revents().contains(PollFlags::ERR)
}

/// Whether this process may put a TCP socket in repair mode (`CAP_NET_ADMIN`): probed once on a
/// scratch socket, since the answer is the process's and does not change.
#[must_use]
pub fn can_tcp_repair() -> bool {
    static CAN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CAN.get_or_init(|| {
        net::socket(AddressFamily::INET, SocketType::STREAM, None)
            .is_ok_and(|fd| nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::TcpRepair, &1u32).is_ok())
    })
}

/// Discards the connection quietly. `ttl` 0 is plain `silent-drop`: as `HAProxy` (`tcp_exec_action_silent_drop`)
/// first tries `TCP_REPAIR`, after which the close sends nothing at all (the client's socket just hangs), and
/// only when that is refused (no `CAP_NET_ADMIN`) falls back to TTL 1. Any other `ttl` is `rst-ttl`: the TTL is
/// set to `ttl` and linger to 0, so the reset the close emits expires `ttl` hops away.
pub fn silent_drop(fd: BorrowedFd<'_>, is_ipv6: bool, ttl: u8) {
    let ttl = if ttl == 0 {
        if nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::TcpRepair, &1u32).is_ok() {
            return;
        }
        1
    } else {
        ttl
    };
    if is_ipv6 {
        let _ = net::sockopt::set_ipv6_unicast_hops(fd, Some(ttl));
    } else {
        let _ = net::sockopt::set_ip_ttl(fd, u32::from(ttl));
    }
    let _ = net::sockopt::set_socket_linger(fd, Some(std::time::Duration::ZERO));
}
