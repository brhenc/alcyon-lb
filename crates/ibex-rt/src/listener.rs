// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/listener.c and src/proto_tcp.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Listening sockets, one per thread via `SO_REUSEPORT`.

use rustix::io::Errno;
use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

/// A listening socket owned by one thread.
///
/// Under thread-per-core each thread binds its own listener on the same address with
/// `SO_REUSEPORT`, so the kernel distributes incoming connections and there is no
/// shared accept queue to contend on.
///
/// This is a deliberate divergence from `HAProxy`, which shares one listening fd across
/// threads and then redistributes accepted connections itself through per-thread accept
/// rings with power-of-two-choices balancing (`src/listener.c:1700`). `HAProxy`'s way
/// gives it explicit control over placement; `SO_REUSEPORT` gives the kernel that
/// control and costs nothing to implement.
///
/// The trade is real and worth stating: the kernel hashes by 4-tuple, so distribution
/// is even across *connections* but blind to how expensive each one is. `HAProxy`'s
/// scheme can see queue depth. If that asymmetry shows up as imbalance under load, the
/// fix is to adopt `HAProxy`'s accept-ring approach — which is why connection placement
/// stays behind this type rather than leaking into the accept path.
pub struct Listener {
    fd: OwnedFd,
    addr: SocketAddr,
    /// Index of the proxy configuration this listener belongs to.
    pub proxy: u32,
    /// Per-listener connection cap. Zero means unlimited.
    pub maxconn: u32,
    /// Connections currently alive on this listener.
    pub nbconn: u32,
}

impl Listener {
    /// Binds a listening socket with `SO_REUSEPORT` and `SO_REUSEADDR`.
    ///
    /// # Errors
    /// Propagates socket creation, bind or listen failure.
    pub fn bind(addr: SocketAddr, backlog: i32, proxy: u32) -> io::Result<Self> {
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

        net::sockopt::set_socket_reuseaddr(&fd, true)?;
        // The whole point: every thread binds the same address, and the kernel
        // distributes connections across them.
        net::sockopt::set_socket_reuseport(&fd, true)?;

        let any = to_any(addr);
        net::bind_any(&fd, &any)?;
        net::listen(&fd, backlog)?;

        Ok(Listener {
            fd,
            addr,
            proxy,
            maxconn: 0,
            nbconn: 0,
        })
    }

    /// Borrow the underlying descriptor, for registering with a [`crate::Poller`].
    #[must_use]
    pub fn borrowed_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }

    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// True when this listener has reached its connection cap and should stop
    /// accepting. `HAProxy` stops polling the listener rather than accepting and closing,
    /// so the backlog applies backpressure instead of the proxy burning syscalls.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.maxconn != 0 && self.nbconn >= self.maxconn
    }

    /// Accepts one connection.
    ///
    /// `Ok(None)` means the queue is drained, which is the normal loop-termination
    /// condition rather than an error. Transient per-connection errors — a client that
    /// vanished between `epoll` and `accept`, or a momentary resource shortage — are
    /// also reported as `None` rather than failing the listener, matching `HAProxy`:
    /// one bad connection must never take down a listening socket.
    ///
    /// # Errors
    /// Propagates non-transient accept failures.
    pub fn accept(&self) -> io::Result<Option<(OwnedFd, SocketAddr)>> {
        match net::acceptfrom_with(
            self.fd.as_fd(),
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        ) {
            Ok((fd, addr)) => {
                let peer = addr
                    .as_ref()
                    .and_then(from_any)
                    .unwrap_or_else(|| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));
                Ok(Some((fd, peer)))
            }
            // Two distinct meanings, one response.
            //
            // AGAIN: the queue is drained. The normal way an accept loop ends.
            //   (EWOULDBLOCK is not listed separately: on Linux it is the same value,
            //   and naming both makes the second arm unreachable.)
            //
            // CONNABORTED/INTR/MFILE/NFILE/NOBUFS/NOMEM: this *connection* failed --
            //   a client that vanished between epoll and accept, or a momentary
            //   resource shortage. The listener itself is fine, and failing it would
            //   let one bad connection take down a bind. HAProxy makes the same
            //   distinction for the same reason.
            // Kept as one arm because the bodies are identical; the distinction is
            // documented above rather than encoded, since clippy is right that two
            // arms returning the same value is noise.
            Err(
                Errno::AGAIN
                | Errno::CONNABORTED
                | Errno::INTR
                | Errno::MFILE
                | Errno::NFILE
                | Errno::NOBUFS
                | Errno::NOMEM,
            ) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

use crate::raw::{from_any, to_any};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn loopback0() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    #[test]
    fn binds_and_reports_its_address() {
        let l = Listener::bind(loopback0(), 128, 0).expect("bind");
        assert!(l.raw_fd() >= 0);
    }

    #[test]
    fn accept_on_an_idle_listener_returns_none_not_an_error() {
        // The loop-termination condition. If this were an error the accept loop would
        // have to distinguish it every time round.
        let l = Listener::bind(loopback0(), 128, 0).expect("bind");
        assert!(l.accept().expect("accept must not fail").is_none());
    }

    #[test]
    fn several_threads_can_bind_the_same_port() {
        // The property thread-per-core depends on. Without SO_REUSEPORT the second
        // bind fails with EADDRINUSE.
        let first = Listener::bind(loopback0(), 128, 0).expect("first bind");
        let addr = rustix::net::getsockname(first.fd.as_fd()).expect("getsockname");
        let bound = from_any(&addr).expect("v4 address");
        let second = Listener::bind(bound, 128, 0).expect("second bind on same port");
        assert_eq!(second.addr().port(), bound.port());
    }

    #[test]
    fn maxconn_zero_means_unlimited() {
        let mut l = Listener::bind(loopback0(), 128, 0).expect("bind");
        l.nbconn = 1_000_000;
        assert!(!l.is_full(), "maxconn 0 must never report full");
        l.maxconn = 10;
        assert!(l.is_full());
        l.nbconn = 9;
        assert!(!l.is_full());
    }
}
