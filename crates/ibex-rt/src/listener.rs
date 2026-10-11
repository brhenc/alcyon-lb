// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/listener.c and src/proto_tcp.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Listening sockets, one per thread via `SO_REUSEPORT`.

use rustix::io::Errno;
use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
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
    /// Per-listener connection cap. Zero means unlimited. Shared with the proxy's
    /// `maxconn`, so `set maxconn frontend` reaches every worker's listeners (T177), as
    /// `cli_parse_set_maxconn_frontend` sets every listener's.
    pub maxconn: crate::srv_rt::ConnLimit,
    /// Server-side TLS for this bind, from `bind ... ssl crt <file>`.
    ///
    /// Per listener rather than per proxy because that is how `HAProxy` scopes it: one
    /// frontend commonly carries `bind :80` beside `bind :443 ssl crt`, and the two must
    /// not share a transport. `None` is plaintext.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// `bind ... name <n>`, what `so_name` reads.
    pub name: Option<Arc<str>>,
    /// The listener's numeric id (`luid`), what `so_id` reads; 0 until the engine sets it.
    pub luid: u32,
    /// `bind ... accept-proxy` (or `accept-proxy-v2`): connections this bind accepts start
    /// with a PROXY header. Per bind, as in `HAProxy` (`BC_O_ACC_PROXY`).
    pub accept_proxy: bool,
    /// `accept-proxy-v2`: the header must be v2.
    pub accept_proxy_v2: bool,
}

/// `tcp-ut` and `cc` of a `bind` line. A refusal by the kernel (an algorithm that is not
/// loaded, say) is reported and the socket is served without the option, as `HAProxy` does
/// (`tcp_bind_listener` warns and keeps the listener).
fn apply_tuning(fd: &OwnedFd, tuning: &ibex_config::ast::SocketTuning) {
    if let Some(ut) = tuning.tcp_user_timeout {
        let ms = u32::try_from(ut.as_millis()).unwrap_or(u32::MAX);
        warn_if_refused("the TCP user timeout", net::sockopt::set_tcp_user_timeout(fd, ms));
    }
    if let Some(mss) = tuning.mss {
        warn_if_refused("the MSS", nix::sys::socket::setsockopt(fd, nix::sys::socket::sockopt::TcpMaxSeg, &mss));
    }
    if let Some(algo) = &tuning.congestion {
        warn_if_refused("the congestion control", net::sockopt::set_tcp_congestion(fd, algo));
    }
}

/// The one place a refused socket option is reported (HAProxy: a warning, the listener is kept).
fn warn_if_refused<E: std::fmt::Display>(what: &str, r: Result<(), E>) {
    if let Err(e) = r {
        eprintln!("[WARNING] bind: cannot set {what}: {e}");
    }
}

impl Listener {
    /// Binds a listening socket with `SO_REUSEPORT` and `SO_REUSEADDR`.
    ///
    /// # Errors
    /// Propagates socket creation, bind or listen failure.
    pub fn bind(addr: SocketAddr, backlog: i32, proxy: u32) -> io::Result<Self> {
        Self::bind_tuned(addr, backlog, proxy, &ibex_config::ast::SocketTuning::default())
    }

    /// [`Listener::bind`] with the socket options of a `bind` line.
    ///
    /// # Errors
    /// Propagates socket creation, bind or listen failure.
    pub fn bind_tuned(addr: SocketAddr, backlog: i32, proxy: u32, tuning: &ibex_config::ast::SocketTuning) -> io::Result<Self> {
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
        if family == AddressFamily::INET6 {
            // `v6only` / `v4v6` on the bind line; otherwise Ibex's own default (v6 only).
            let _ = net::sockopt::set_ipv6_v6only(&fd, tuning.v6only.unwrap_or(true));
        }
        apply_tuning(&fd, tuning);

        let any = to_any(addr);
        net::bind_any(&fd, &any)?;
        net::listen(&fd, tuning.backlog.map_or(backlog, |b| i32::try_from(b).unwrap_or(i32::MAX)))?;

        let bound_addr = if addr.port() == 0 {
            net::getsockname(&fd)
                .ok()
                .and_then(|sa| match sa {
                    rustix::net::SocketAddrAny::V4(v4) => Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                        *v4.ip(),
                        v4.port(),
                    ))),
                    rustix::net::SocketAddrAny::V6(v6) => Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                        *v6.ip(),
                        v6.port(),
                        v6.flowinfo(),
                        v6.scope_id(),
                    ))),
                    _ => None,
                })
                .unwrap_or(addr)
        } else {
            addr
        };

        Ok(Listener {
            fd,
            addr: bound_addr,
            proxy,
            maxconn: crate::srv_rt::ConnLimit::default(),
            tls: None,
            name: None,
            accept_proxy: false,
            accept_proxy_v2: false,
            luid: 0,
        })
    }

    /// Takes over a listening socket inherited from the previous process through
    /// `-x` (see [`crate::handover`]), instead of binding a new one. Taking the same
    /// socket is what keeps its accept queue -- connections the kernel had already
    /// completed for the old process -- from being reset when that process exits.
    ///
    /// The descriptor is checked before it is trusted: it must be a listening TCP socket
    /// bound to `addr`. It is set non-blocking and re-`listen`ed with this config's
    /// backlog, which is how Linux changes the backlog of a listening socket.
    ///
    /// # Errors
    /// Refuses a descriptor that is not a listening TCP socket on `addr`.
    pub fn adopt(
        fd: OwnedFd,
        addr: SocketAddr,
        backlog: i32,
        proxy: u32,
        tuning: &ibex_config::ast::SocketTuning,
    ) -> io::Result<Self> {
        let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("inherited socket for {addr}: {why}"));
        if net::sockopt::get_socket_type(&fd)? != SocketType::STREAM {
            return Err(bad("not a stream socket"));
        }
        if !net::sockopt::get_socket_acceptconn(&fd)? {
            return Err(bad("not listening"));
        }
        let local = match net::getsockname(&fd)? {
            rustix::net::SocketAddrAny::V4(v4) => SocketAddr::V4(std::net::SocketAddrV4::new(*v4.ip(), v4.port())),
            rustix::net::SocketAddrAny::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(
                *v6.ip(),
                v6.port(),
                v6.flowinfo(),
                v6.scope_id(),
            )),
            _ => return Err(bad("not an inet socket")),
        };
        if local != addr {
            return Err(bad(&format!("bound to {local}")));
        }
        rustix::io::ioctl_fionbio(&fd, true)?;
        apply_tuning(&fd, tuning);
        net::listen(&fd, tuning.backlog.map_or(backlog, |b| i32::try_from(b).unwrap_or(i32::MAX)))?;
        Ok(Listener {
            fd,
            addr,
            proxy,
            maxconn: crate::srv_rt::ConnLimit::default(),
            tls: None,
            name: None,
            accept_proxy: false,
            accept_proxy_v2: false,
            luid: 0,
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
    pub fn is_full(&self) -> bool {
        self.maxconn.is_full()
    }

    /// Accepts one connection.
    ///
    /// `Ok(None)` means the queue is drained, which is the normal loop-termination
    /// condition rather than an error. A client that vanished between `epoll` and
    /// `accept` is also `None`: one bad connection must never take down a listening socket.
    ///
    /// # Errors
    /// Every other failure, among them running out of descriptors or memory (`EMFILE`,
    /// `ENFILE`, `ENOBUFS`, `ENOMEM`): the connection is still queued and the listener
    /// still ready, so the caller must stop polling it for a while (`HAProxy`'s
    /// `CO_AC_PAUSE`) rather than call again at once (T237).
    pub fn accept(&self) -> io::Result<Option<(OwnedFd, SocketAddr)>> {
        match net::acceptfrom_with(
            self.fd.as_fd(),
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        ) {
            // Past `maxsock`: closed, and reported as out of fds so the listener pauses.
            Ok((fd, _)) if crate::globalconn::past_maxsock(fd.as_raw_fd()) => Err(Errno::MFILE.into()),
            Ok((fd, addr)) => {
                let peer = addr
                    .as_ref()
                    .and_then(from_any)
                    .unwrap_or_else(|| SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0));
                // HAProxy sets TCP_NODELAY on every accepted TCP socket (session_accept_fd).
                // Without it a response written in several segments (anything over the
                // initial window, e.g. 64 KB) stalls ~40 ms on Nagle + the client's delayed
                // ACK (T185). Failure is ignored: UNIX sockets have no such option.
                let _ = net::sockopt::set_tcp_nodelay(&fd, true);
                Ok(Some((fd, peer)))
            }
            // Two distinct meanings, one response.
            //
            // AGAIN: the queue is drained. The normal way an accept loop ends.
            //   (EWOULDBLOCK is not listed separately: on Linux it is the same value,
            //   and naming both makes the second arm unreachable.)
            //
            // CONNABORTED/INTR: this *connection* failed -- a client that vanished
            //   between epoll and accept, or a signal. The listener itself is fine.
            //   Out of fds or memory is not here: the connection stays queued, and
            //   reporting "drained" left the caller polling a listener that is ready
            //   again at once (T237).
            Err(Errno::AGAIN | Errno::CONNABORTED | Errno::INTR) => Ok(None),
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
        (0..1_000_000).for_each(|_| l.maxconn.inc());
        assert!(!l.is_full(), "maxconn 0 must never report full");
        l.maxconn.set(1_000_000);
        assert!(l.is_full());
        l.maxconn.dec();
        assert!(!l.is_full());
    }

    /// `adopt` is the check on a descriptor received from another process over
    /// `SCM_RIGHTS`. Whatever arrives is refused unless it is a listening TCP socket on the
    /// address this bind asks for.
    #[test]
    fn adopt_takes_a_matching_listening_socket_and_serves_on_it() {
        let orig = Listener::bind(loopback0(), 16, 0).expect("bind");
        let addr = orig.addr();
        let fd = orig.borrowed_fd().try_clone_to_owned().expect("dup");
        let adopted = Listener::adopt(fd, addr, 16, 7, &ibex_config::ast::SocketTuning::default()).expect("adopt");
        assert_eq!(adopted.addr(), addr);
        assert_eq!(adopted.proxy, 7);
        let _c = std::net::TcpStream::connect(addr).expect("connect");
        let mut got = None;
        for _ in 0..100 {
            if let Some(conn) = adopted.accept().expect("accept") {
                got = Some(conn);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(got.is_some(), "the adopted socket must accept connections");
    }

    #[test]
    fn adopt_refuses_a_socket_bound_elsewhere() {
        let orig = Listener::bind(loopback0(), 16, 0).expect("bind");
        let other = Listener::bind(loopback0(), 16, 0).expect("bind other");
        let fd = orig.borrowed_fd().try_clone_to_owned().expect("dup");
        let err = Listener::adopt(fd, other.addr(), 16, 0, &ibex_config::ast::SocketTuning::default()).err().expect("must refuse");
        assert!(err.to_string().contains("bound to"), "{err}");
    }

    #[test]
    fn adopt_refuses_a_socket_that_is_not_listening() {
        let fd = net::socket_with(AddressFamily::INET, SocketType::STREAM, SocketFlags::CLOEXEC, None)
            .expect("socket");
        let err = Listener::adopt(fd, loopback0(), 16, 0, &ibex_config::ast::SocketTuning::default()).err().expect("must refuse");
        assert!(err.to_string().contains("not listening"), "{err}");
    }

    #[test]
    fn adopt_refuses_a_datagram_socket() {
        let fd = net::socket_with(AddressFamily::INET, SocketType::DGRAM, SocketFlags::CLOEXEC, None)
            .expect("socket");
        let err = Listener::adopt(fd, loopback0(), 16, 0, &ibex_config::ast::SocketTuning::default()).err().expect("must refuse");
        assert!(err.to_string().contains("not a stream socket"), "{err}");
    }

    #[test]
    fn adopt_takes_an_ipv6_listening_socket() {
        let Ok(orig) = Listener::bind(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)), 16, 0) else {
            return; // no IPv6 loopback on this host
        };
        let addr = orig.addr();
        let fd = orig.borrowed_fd().try_clone_to_owned().expect("dup");
        let adopted = Listener::adopt(fd, addr, 16, 0, &ibex_config::ast::SocketTuning::default()).expect("adopt v6");
        assert_eq!(adopted.addr(), addr);
    }
}
