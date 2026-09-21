// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/raw_sock.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `raw_sock`: the null transport. Bytes pass through untouched.

use rustix::io::Errno;
use std::io;
use std::os::fd::BorrowedFd;

/// Outcome of a transport read or write.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Io {
    /// Moved `n` bytes. `n == 0` from a read means end of stream.
    Done(usize),
    /// Not ready. The caller must wait for readiness rather than retry.
    WouldBlock,
    /// The peer closed, or the connection failed.
    Closed,
}

/// Reads into `buf`.
///
/// `EAGAIN` becomes [`Io::WouldBlock`] rather than an error, and a peer reset becomes
/// [`Io::Closed`]. Both are ordinary control flow for a proxy: a client vanishing
/// mid-request is normal traffic, not an exceptional condition, and treating it as an
/// error would mean every call site distinguishing it again.
///
/// # Errors
/// Propagates genuinely unexpected failures.
pub fn recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Io> {
    if buf.is_empty() {
        return Ok(Io::Done(0));
    }
    match rustix::io::read(fd, buf) {
        Ok(0) => Ok(Io::Closed),
        Ok(n) => Ok(Io::Done(n)),
        Err(Errno::AGAIN | Errno::INTR) => Ok(Io::WouldBlock),
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

/// Shuts down the write direction, sending FIN while leaving reads open.
///
/// This is what makes half-close work: the proxy must be able to tell one side that no
/// more data is coming without tearing down the other direction.
pub fn shutdown_write(fd: BorrowedFd<'_>) {
    let _ = rustix::net::shutdown(fd, rustix::net::Shutdown::Write);
}
