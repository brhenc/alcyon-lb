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

/// The 16-byte request for `target`, the address the proxy dials. A non-IPv4
/// `target` names `0.0.0.0`, as `is_inet_addr` does for a destination that is not an
/// IPv4 address.
#[must_use]
#[inline]
pub fn request(target: SocketAddr) -> [u8; REQ_LEN] {
    let mut req = [0u8; REQ_LEN];
    req[0] = 0x04;
    req[1] = 0x01;
    let port = target.port();
    req[2] = (port >> 8) as u8;
    req[3] = port as u8;
    if let IpAddr::V4(ip) = target.ip() {
        req[4..8].copy_from_slice(&ip.octets());
    }
    req[8..15].copy_from_slice(b"HAProxy");
    req[15] = 0;
    req
}

/// The two phases of a handshake in flight, one per `CO_FL_SOCKS4_*`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hs {
    /// The 16-byte request is not yet fully written (`CO_FL_SOCKS4_SEND`).
    pub sending: bool,
    /// The 8-byte reply is not yet read (`CO_FL_SOCKS4_RECV`).
    pub receiving: bool,
}

impl Hs {
    /// The handshake is over: the request went out and the reply granted it.
    #[must_use]
    #[inline]
    pub fn done(self) -> bool {
        !self.sending && !self.receiving
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
    /// `conn_err_code_name`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Fail::Send => "SOCKS4_SEND",
            Fail::Recv => "SOCKS4_RECV",
            Fail::Deny => "SOCKS4_DENY",
            Fail::Abort => "SOCKS4_ABORT",
        }
    }

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
}

/// Where a step of the handshake stands.
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
/// and sent whole (a connected socket's send buffer holds it), and the 8-byte reply is
/// taken in only once it is whole (`HAProxy` peeks for the 8 and acts once they are all
/// there). `hs` is the caller's progress; the bits only ever clear.
#[inline]
pub fn step(fd: BorrowedFd<'_>, target: SocketAddr, hs: &mut Hs) -> Step {
    use crate::raw::Io;

    // What is left of the request goes first: `conn_send_socks4_proxy_request` sends it
    // whole before it looks at a reply.
    if hs.sending {
        let req = request(target);
        let mut off = 0usize;
        loop {
            match crate::raw::send(fd, &req[off..]) {
                Ok(Io::Done(n)) if n > 0 => {
                    off += n;
                    if off == REQ_LEN {
                        hs.sending = false;
                        break;
                    }
                }
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
                // Consume the reply; the tunnel is open once the 8 are gone.
                let mut sink = [0u8; RSP_LEN];
                match crate::raw::recv(fd, &mut sink) {
                    Ok(Io::Done(RSP_LEN)) => {
                        hs.receiving = false;
                        Step::Done
                    }
                    // The 8 were peeked, so they are present; a short read here is a read
                    // error, not a slow proxy.
                    _ => Step::Failed(Fail::Recv),
                }
            }
            // Fewer than 8 are in yet: wait for the rest of the reply.
            Ok(Io::Done(_)) | Ok(Io::WouldBlock) => Step::Pending,
            // The proxy closed before the reply was whole.
            Ok(Io::Eof) => Step::Failed(Fail::Recv),
            // A hard read error on the proxy's socket aborts the handshake.
            Ok(Io::Closed) | Err(_) => Step::Failed(Fail::Abort),
        }
    }

    Step::Done
}
