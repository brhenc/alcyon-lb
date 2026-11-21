//! The `socks4` server keyword: the server's connection goes to the SOCKS4 proxy named
//! on the line, which is asked to dial the server itself (`src/connection.c`'s
//! `conn_send_socks4_proxy_request` and `conn_recv_socks4_proxy_response`);
//! `check-via-socks4` puts the health checks through the same tunnel.
//!
//! The request is 16 bytes, the reply 8. The traffic side keeps no state of its own:
//! the handshake's two phases are the session's `SOCKS4_SEND` / `SOCKS4_RECV` flags, the
//! request is rebuilt on the stack from the (fixed) target on every drive, and the reply
//! is peeked all-or-nothing exactly as `HAProxy` reads it (`recv(.., MSG_PEEK)`). The
//! check side keeps the same two progress bits in the pooled `CheckRun`. Nothing here
//! allocates per connection.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::BorrowedFd;

/// The SOCKS4 CONNECT request, whole: `VN CD DSTPORT DSTIP`, then `userid`
/// NUL-terminated, "HAProxy" as `HAProxy` sends it — 16 bytes.
pub const REQ_LEN: usize = 16;
/// The reply: `VN CD DSTPORT DSTIP`, 8 bytes (`SOCKS4_HS_RSP_LEN`).
pub const RSP_LEN: usize = 8;
/// `CD` of a reply that grants the request (90; 91, 92 and 93 reject it).
const RSP_GRANTED: u8 = 90;

/// The 16-byte request for `target`, the address the proxy dials. `DSTIP` mirrors
/// `HAProxy`'s `is_inet_addr` (`include/haproxy/tools.h:731-743`): for IPv4, the 4 IPv4
/// bytes; for IPv6, the first non-zero 32-bit word of `sin6_addr` (or `0.0.0.0` if all
/// zero).
#[must_use]
#[inline]
pub fn request(target: SocketAddr) -> [u8; REQ_LEN] {
    let mut req = [0u8; REQ_LEN];
    req[0] = 0x04;
    req[1] = 0x01;
    let port = target.port();
    req[2] = (port >> 8) as u8;
    req[3] = port as u8;
    match target.ip() {
        IpAddr::V4(ip) => req[4..8].copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => {
            if let Some(word) = ip.octets().chunks_exact(4).find(|w| *w != [0, 0, 0, 0]) {
                req[4..8].copy_from_slice(word);
            }
        }
    }
    req[8..15].copy_from_slice(b"HAProxy");
    req[15] = 0;
    req
}

/// `true` when the SOCKS4 proxy and server have different IP address families
/// (`AF_INET` vs `AF_INET6`), which `HAProxy`'s `sock_create_server_socket` +
/// `tcp_connect_server` rejects with `EINVAL` (`CO_ER_SOCK_ERR`).
#[must_use]
#[inline]
pub const fn family_mismatch(proxy: SocketAddr, target: SocketAddr) -> bool {
    proxy.is_ipv6() != target.is_ipv6()
}

/// The two phases of a handshake in flight, one per `CO_FL_SOCKS4_*`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hs {
    /// Bytes of the 16-byte request already written (`0..=REQ_LEN`).
    pub sent: u8,
    /// The 8-byte reply is not yet read (`CO_FL_SOCKS4_RECV`).
    pub receiving: bool,
}

impl Hs {
    /// Initial handshake state: request not sent yet, reply awaited.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self { sent: 0, receiving: true }
    }

    /// The 16-byte request still has bytes to write (`CO_FL_SOCKS4_SEND`).
    #[must_use]
    #[inline]
    pub const fn sending(self) -> bool {
        (self.sent as usize) < REQ_LEN
    }

    /// The handshake is over: the request went out and the reply granted it.
    #[must_use]
    #[inline]
    pub const fn done(self) -> bool {
        !self.sending() && !self.receiving
    }
}

/// A health check's `socks4` tunnel (`check-via-socks4`): where the proxy is, the address
/// the proxy dials (the check's target), and the handshake's progress. It lives in the
/// pooled `CheckRun`, not on `ServerCheckState`, so the per-checked-server struct keeps
/// its size bound.
#[derive(Clone, Copy, Debug)]
pub struct CheckState {
    /// The proxy's address: the check's socket's peer.
    pub proxy_addr: SocketAddr,
    /// The address the proxy dials (the check's own target).
    pub target: SocketAddr,
    /// The handshake's two phases.
    pub hs: Hs,
}

/// What the handshake failed with: the `CO_ER_SOCKS4_*` of `include/haproxy/connection-t.h`,
/// numbered as there (fetchable through `fc_err`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// `CO_ER_SOCKS4_SEND`: a write error on the proxy's socket.
    Send,
    /// `CO_ER_SOCKS4_RECV`: the proxy closed before the 8-byte reply, or its read failed.
    Recv,
    /// `CO_ER_SOCKS4_DENY`: the reply's `CD` is not 90.
    Deny,
    /// `CO_ER_SOCKS4_ABORT`: the server's read error aborted the handshake.
    Abort,
}

impl Fail {
    /// `conn_err_code_str`.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Fail::Send => "SOCKS4 Proxy write error during handshake",
            Fail::Recv => "SOCKS4 Proxy read error during handshake",
            Fail::Deny => "SOCKS4 Proxy deny the request",
            Fail::Abort => "SOCKS4 Proxy handshake aborted by server",
        }
    }

    /// Health-check failure status (`HCHK_STATUS_*`): `CO_FL_WAIT_L4_CONN` is still set
    /// during `SEND` (`L4CON`) and cleared once the request has been written (`SOCKERR`).
    #[must_use]
    pub const fn check_status(self) -> (&'static str, &'static str) {
        match self {
            Fail::Send => ("L4CON", "Layer4 connection problem"),
            Fail::Recv | Fail::Deny | Fail::Abort => ("SOCKERR", "Socket error"),
        }
    }
}

/// Where a step of the handshake stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// More I/O is wanted; the poller will bring the session back.
    Pending,
    /// The reply granted the request: the tunnel carries traffic now.
    Done,
    /// Failed; the `Fail` names the `CO_ER_SOCKS4_*`.
    Failed(Fail),
}

/// The `CO_FL_SOCKS4_SEND` / `CO_FL_SOCKS4_RECV` phases of the handshake, non-blocking,
/// with no state beyond `hs`: the 16-byte request is rebuilt on the stack from `target`
/// and sent (resuming from `hs.sent` on partial writes), and the 8-byte reply is
/// taken in only once it is whole (`HAProxy` peeks for the 8 and acts once they are all
/// there).
#[inline]
pub fn step(fd: BorrowedFd<'_>, target: SocketAddr, hs: &mut Hs) -> Step {
    use crate::raw::Io;

    // What is left of the request goes first: `conn_send_socks4_proxy_request` sends it
    // whole before it looks at a reply.
    if hs.sending() {
        let req = request(target);
        while (hs.sent as usize) < REQ_LEN {
            match crate::raw::send(fd, &req[hs.sent as usize..]) {
                Ok(Io::Done(n)) if n > 0 => hs.sent += u8::try_from(n).unwrap_or(REQ_LEN as u8),
                Ok(Io::WouldBlock) => return Step::Pending,
                // A write error, or the socket gone, while the request is out.
                _ => return Step::Failed(Fail::Send),
            }
        }
    }

    // The 8-byte reply, all-or-nothing: `conn_recv_socks4_proxy_response` peeks, checks
    // the status byte once the 8 are there, and then consumes them.
    if hs.receiving {
        let mut buf = [0u8; RSP_LEN];
        return match crate::raw::peek(fd, &mut buf) {
            Ok(Io::Done(RSP_LEN)) => {
                if buf[1] != RSP_GRANTED {
                    // `line[1] != 90`: the proxy refuses the request.
                    return Step::Failed(Fail::Deny);
                }
                // Consume the 8 peeked bytes; the tunnel is open once they are gone.
                let mut sink = [0u8; RSP_LEN];
                let _ = crate::raw::recv(fd, &mut sink);
                hs.receiving = false;
                Step::Done
            }
            // Fewer than 8 are in yet: wait for the rest of the reply.
            Ok(Io::Done(_)) | Ok(Io::WouldBlock) => Step::Pending,
            // The proxy closed before the reply was whole.
            Ok(Io::Eof) => Step::Failed(Fail::Recv),
            // A hard read error on the proxy's socket aborts the handshake.
            Ok(Io::Closed) | Err(_) => Step::Failed(Fail::Abort),
        };
    }

    Step::Done
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn request_encodes_v4_and_v6_targets() {
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            request(v4),
            [0x04, 0x01, 0x1f, 0x90, 127, 0, 0, 1, b'H', b'A', b'P', b'r', b'o', b'x', b'y', 0]
        );
        let v6: SocketAddr = "[::1]:443".parse().unwrap();
        let r6 = request(v6);
        assert_eq!(&r6[..8], &[0x04, 0x01, 0x01, 0xbb, 0, 0, 0, 1]);
        assert_eq!(&r6[8..], b"HAProxy\0");

        let v6_doc: SocketAddr = "[2001:db8::1:5]:8080".parse().unwrap();
        let r6_doc = request(v6_doc);
        assert_eq!(&r6_doc[..8], &[0x04, 0x01, 0x1f, 0x90, 0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(&r6_doc[8..], b"HAProxy\0");

        let v6_unspec: SocketAddr = "[::]:443".parse().unwrap();
        let r6_unspec = request(v6_unspec);
        assert_eq!(&r6_unspec[..8], &[0x04, 0x01, 0x01, 0xbb, 0, 0, 0, 0]);
        assert_eq!(&r6_unspec[8..], b"HAProxy\0");

        assert!(family_mismatch(v4, v6));
        assert!(family_mismatch(v6, v4));
        assert!(!family_mismatch(v4, v4));
        assert!(!family_mismatch(v6, v6_doc));
    }

    #[test]
    fn step_handles_pending_partial_send_eof_deny_abort_and_done() {
        let target: SocketAddr = "10.0.0.1:80".parse().unwrap();

        // Done when already finished.
        let mut hs_done = Hs { sent: REQ_LEN as u8, receiving: false };
        assert!(hs_done.done());
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(step(a.as_fd(), target, &mut hs_done), Step::Done);

        // Partial peek -> Pending, then full 8-byte granted reply -> Done.
        let (cli, mut srv) = UnixStream::pair().unwrap();
        cli.set_nonblocking(true).unwrap();
        let mut hs = Hs::new();
        assert_eq!(step(cli.as_fd(), target, &mut hs), Step::Pending);
        assert!(!hs.sending());
        assert!(hs.receiving);
        let mut got = [0u8; REQ_LEN];
        srv.read_exact(&mut got).unwrap();
        assert_eq!(got, request(target));

        srv.write_all(&[0x00, 0x5a, 0x00]).unwrap();
        assert_eq!(step(cli.as_fd(), target, &mut hs), Step::Pending);
        srv.write_all(&[0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(step(cli.as_fd(), target, &mut hs), Step::Done);
        assert!(hs.done());

        // Deny (0x5B).
        let (cli, mut srv) = UnixStream::pair().unwrap();
        cli.set_nonblocking(true).unwrap();
        let mut hs = Hs::new();
        srv.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(step(cli.as_fd(), target, &mut hs), Step::Failed(Fail::Deny));

        // EOF during recv -> Fail::Recv.
        let (cli, srv) = UnixStream::pair().unwrap();
        cli.set_nonblocking(true).unwrap();
        let mut hs = Hs::new();
        drop(srv);
        // Send fails on broken pipe if we haven't sent yet; test recv EOF after sent.
        assert_eq!(step(cli.as_fd(), target, &mut hs), Step::Failed(Fail::Send));

        let (cli, srv) = UnixStream::pair().unwrap();
        cli.set_nonblocking(true).unwrap();
        drop(srv);
        let mut hs = Hs { sent: REQ_LEN as u8, receiving: true };
        assert_eq!(step(cli.as_fd(), target, &mut hs), Step::Failed(Fail::Recv));

        // Hard error on peek -> Fail::Abort (e.g. a pipe fd, not a socket -> ENOTSOCK).
        let (r_pipe, _w_pipe) = std::io::pipe().unwrap();
        let mut hs = Hs { sent: REQ_LEN as u8, receiving: true };
        assert_eq!(step(r_pipe.as_fd(), target, &mut hs), Step::Failed(Fail::Abort));

        // Send WouldBlock -> Pending, then resumes from `hs.sent`.
        let (cli, mut srv) = UnixStream::pair().unwrap();
        cli.set_nonblocking(true).unwrap();
        // Fill the send buffer so `send` returns EAGAIN/WouldBlock.
        let fill = [0xAAu8; 65536];
        while matches!(crate::raw::send(cli.as_fd(), &fill), Ok(crate::raw::Io::Done(n)) if n > 0) {}
        let mut hs = Hs::new();
        let res = step(cli.as_fd(), target, &mut hs);
        assert!(matches!(res, Step::Pending));
        // Drain srv so send buffer frees up and resume.
        srv.set_nonblocking(true).unwrap();
        let mut sink = [0u8; 65536];
        while matches!(srv.read(&mut sink), Ok(n) if n > 0) {}
        srv.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(step(cli.as_fd(), target, &mut hs), Step::Done);

        assert!(!Fail::Send.text().is_empty());
        assert!(!Fail::Recv.text().is_empty());
        assert!(!Fail::Deny.text().is_empty());
        assert!(!Fail::Abort.text().is_empty());
        assert_eq!(Fail::Send.check_status().0, "L4CON");
        assert_eq!(Fail::Deny.check_status().0, "SOCKERR");
    }
}
