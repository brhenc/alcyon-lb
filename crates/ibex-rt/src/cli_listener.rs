// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The sockets a `stats socket` listens on and its connections arrive on (T246): a unix
//! socket file, a Linux abstract socket (`abns@`, `abnsz@`) or TCP (`ipv4@`, `ipv6@`,
//! `host:port`). The CLI applet and the engine's accept path see only [`CliListener`] and
//! [`CliStream`], so a change to how the CLI accepts composes with the kinds of socket.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

/// The backlog of `HAProxy`'s TCP CLI listeners, as `ss -lt` shows it on the oracle.
const TCP_BACKLOG: i32 = 10;

/// A listening CLI socket.
#[derive(Debug)]
pub enum CliListener {
    /// A unix socket file or an abstract socket.
    Unix(UnixListener),
    Tcp(TcpListener),
}

/// One accepted CLI connection.
#[derive(Debug)]
pub enum CliStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl From<UnixListener> for CliListener {
    fn from(l: UnixListener) -> Self {
        Self::Unix(l)
    }
}

impl From<UnixStream> for CliStream {
    fn from(s: UnixStream) -> Self {
        Self::Unix(s)
    }
}

impl CliListener {
    /// Whether this is a TCP stats socket, which `SIGTTOU` pauses ([`Self::pause_tcp`]).
    #[must_use]
    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// `SIGTTOU` on a TCP stats socket: out of the listening state, so a connect is refused
    /// until [`Self::resume_tcp`] (`tcp_suspend_receiver`, measured on 3.5-dev8-885761-29).
    ///
    /// # Errors
    /// What `connect(AF_UNSPEC)` reports.
    pub fn pause_tcp(&self) -> io::Result<()> {
        rustix::net::connect_unspec(self.as_fd()).map_err(Into::into)
    }

    /// `SIGTTIN`: listens again.
    ///
    /// # Errors
    /// What `listen` reports.
    pub fn resume_tcp(&self) -> io::Result<()> {
        rustix::net::listen(self.as_fd(), TCP_BACKLOG).map_err(Into::into)
    }

    /// Accepts one connection, non-blocking.
    ///
    /// # Errors
    /// What `accept` returns, `WouldBlock` included.
    pub fn accept(&self) -> io::Result<CliStream> {
        let s = match self {
            Self::Unix(l) => CliStream::Unix(l.accept()?.0),
            Self::Tcp(l) => CliStream::Tcp(l.accept()?.0),
        };
        s.set_nonblocking(true)?;
        Ok(s)
    }

    /// Binds a Linux abstract socket: `name` zero-padded to the whole `sun_path` when
    /// `padded` (`abns@`, `HAProxy`'s `AF_CUST_ABNS`), as written otherwise (`abnsz@`).
    /// Abstract sockets have no file: nothing to unlink, no `mode` to apply.
    ///
    /// # Errors
    /// The name is too long, or bind/listen fails (`EADDRINUSE` while another process holds
    /// the name).
    pub fn bind_abstract(name: &str, padded: bool) -> io::Result<Self> {
        use std::os::linux::net::SocketAddrExt;
        let mut bytes = name.as_bytes().to_vec();
        if padded {
            bytes.resize(107, 0);
        }
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&bytes)?;
        let l = UnixListener::bind_addr(&addr)?;
        l.set_nonblocking(true)?;
        Ok(Self::Unix(l))
    }

    /// Binds a TCP CLI listener on `addr`, or adopts the one the previous process handed
    /// over (`-x`, [`crate::handover`]). It is bound with `SO_REUSEADDR` and `SO_REUSEPORT`
    /// as every Ibex and `HAProxy` TCP listener is, so the new process of a `-sf` reload binds
    /// it while the old one still holds it; and it is registered for `_getsocks` so the next
    /// reload can take it over in turn.
    ///
    /// # Errors
    /// Socket creation, bind or listen failure.
    pub fn bind_tcp(addr: SocketAddr) -> io::Result<Self> {
        use rustix::net::{AddressFamily, SocketFlags, SocketType};
        let fd: OwnedFd = if let Some(fd) = crate::handover::take_inherited(0, addr).pop() {
            fd
        } else {
            let family = if addr.is_ipv4() { AddressFamily::INET } else { AddressFamily::INET6 };
            let fd = rustix::net::socket_with(family, SocketType::STREAM, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK, None)?;
            rustix::net::sockopt::set_socket_reuseaddr(&fd, true)?;
            rustix::net::sockopt::set_socket_reuseport(&fd, true)?;
            rustix::net::bind(&fd, &addr)?;
            rustix::net::listen(&fd, TCP_BACKLOG)?;
            fd
        };
        crate::handover::expose(addr, fd.as_fd())?;
        let l = TcpListener::from(fd);
        l.set_nonblocking(true)?;
        Ok(Self::Tcp(l))
    }
}

impl CliStream {
    /// # Errors
    /// What `fcntl` returns.
    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.set_nonblocking(on),
            Self::Tcp(s) => s.set_nonblocking(on),
        }
    }

    /// The unix stream, which alone can carry descriptors (`_getsocks`).
    #[must_use]
    pub fn as_unix(&self) -> Option<&UnixStream> {
        match self {
            Self::Unix(s) => Some(s),
            Self::Tcp(_) => None,
        }
    }
}

impl Read for CliStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for CliStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsFd for CliListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Unix(l) => l.as_fd(),
            Self::Tcp(l) => l.as_fd(),
        }
    }
}

impl AsRawFd for CliListener {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

impl AsFd for CliStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Unix(s) => s.as_fd(),
            Self::Tcp(s) => s.as_fd(),
        }
    }
}

impl AsRawFd for CliStream {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unix_cli_stream_reads_writes_and_flushes() {
        let (a, b) = UnixStream::pair().expect("pair");
        let mut a = CliStream::from(a);
        let mut b = CliStream::from(b);
        a.write_all(b"x").expect("write");
        a.flush().expect("flush");
        let mut buf = [0u8; 1];
        b.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"x");
        assert!(a.as_unix().is_some());
        assert_eq!(a.as_raw_fd(), a.as_fd().as_raw_fd());
    }
}
