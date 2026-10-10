// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/xprt_handshake.c and src/ssl_sock.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The client-side transport: plaintext, or TLS over the same socket.
//!
//! `HAProxy` stacks transports (`xprt_ops`) so the layer above does not know whether
//! bytes were encrypted. [`ClientXprt`] is that seam, and it deliberately mirrors
//! [`crate::raw`]'s signatures so a call site reads the same either way -- the plaintext
//! arm is a direct call to `raw::recv`/`raw::send` with nothing in between.
//!
//! ## Why this drives rustls directly
//!
//! `ibex-tls` exposes `RustlsTransport::recv`/`send`, and they look like socket calls but
//! are not: they move bytes between `ctx.rx_raw`/`ctx.tx_raw` and the caller's buffer,
//! leaving the caller to do the syscalls and to copy through those two `Vec`s. That costs
//! an allocation and a `drain` memmove on every read and write, on the data path.
//!
//! So this holds a `RustlsContext` for ownership and introspection -- it is the
//! `Transport::Ctx`, so the layering is unchanged -- but performs the socket I/O with
//! rustls's own non-blocking API, `read_tls`/`write_tls` against the fd. That is what
//! that API is for, and it copies once instead of three times.

use crate::raw::{self, Io};
use ibex_tls::TlsSession;
use ibex_tls::RustlsContext;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};

/// Adapts a raw fd to `io::Read`/`io::Write` for rustls's `read_tls`/`write_tls`.
///
/// rustls needs `WouldBlock` reported as an error of that kind, which is the one place
/// the project wants the errno rather than [`Io`].
///
/// `drained` is whether the last read left the socket empty: shorter than asked, or
/// `EAGAIN` (see [`TlsConn::sock_drained`]).
struct Sock<'a>(BorrowedFd<'a>, bool);

impl Read for Sock<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r = raw::recv(self.0, buf)?;
        self.1 = match r {
            Io::Done(n) => n < buf.len(),
            Io::WouldBlock => true,
            Io::Eof | Io::Closed => false,
        };
        match r {
            Io::Done(n) => Ok(n),
            Io::Eof => Ok(0),
            Io::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            Io::Closed => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }
}

impl Write for Sock<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match raw::send(self.0, buf)? {
            Io::Done(n) => Ok(n),
            Io::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            Io::Closed | Io::Eof => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Per-connection TLS state.
#[allow(clippy::struct_excessive_bools)] // independent facts about the stream, not a state machine
pub struct TlsConn {
    ctx: RustlsContext,
    /// The peer sent `close_notify`: the stream ended where it said it would.
    peer_closed: bool,
    /// The socket hit EOF while the TLS stream was still open.
    ///
    /// This is a truncation attack unless `close_notify` arrived first: an attacker who
    /// can inject a TCP FIN ends the stream early, and a proxy that reports it as a clean
    /// end will forward a partial body as though it were complete.
    truncated: bool,
    /// The handshake failed (a refused certificate, a peer that is not speaking TLS, a
    /// peer gone mid-handshake). For a server connection this is a connect failure:
    /// `HAProxy` retries it and answers 503 `SC` when the retries are spent.
    failed: bool,
    /// Bytes that go on the wire in plaintext before the ClientHello: a PROXY protocol
    /// header to a `send-proxy` server, which `HAProxy` writes from its `xprt_handshake`
    /// layer under `ssl_sock`, and which the peer's `accept-proxy` reads before its own
    /// handshake. `prefix_sent` is how much of it is out.
    prefix: Vec<u8>,
    prefix_sent: usize,
    /// The last read of the socket left it empty (a read shorter than asked, or
    /// `EAGAIN`). With no plaintext left in rustls either, there is nothing to read until
    /// the poller says so, as for a plaintext socket (`fd_cant_recv`). Not knowing this,
    /// the TLS side read until `EAGAIN` on every pass: 7 of 9 reads a request (T186).
    sock_drained: bool,
}

impl TlsConn {
    #[must_use]
    pub fn new(ctx: RustlsContext) -> Self {
        Self {
            ctx,
            peer_closed: false,
            truncated: false,
            failed: false,
            prefix: Vec::new(),
            prefix_sent: 0,
            sock_drained: false,
        }
    }

    #[must_use]
    pub const fn handshake_failed(&self) -> bool {
        self.failed
    }

    /// Sets the plaintext bytes written before the handshake. Only before it started.
    pub fn set_plain_prefix(&mut self, bytes: Vec<u8>) {
        self.prefix = bytes;
        self.prefix_sent = 0;
    }

    /// Writes what is left of the plaintext prefix. `Ok(true)` once it is all out.
    fn send_prefix(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        while self.prefix_sent < self.prefix.len() {
            match raw::send(fd, &self.prefix[self.prefix_sent..])? {
                Io::Done(n) => self.prefix_sent += n,
                Io::WouldBlock => return Ok(false),
                Io::Closed | Io::Eof => return Err(io::ErrorKind::ConnectionReset.into()),
            }
        }
        Ok(true)
    }

    fn session(&mut self) -> Option<&mut TlsSession> {
        self.ctx.session.as_mut()
    }

    /// True while rustls has bytes it needs to put on the wire.
    ///
    /// The caller must poll for writability whenever this holds, even with no application
    /// data queued: a handshake is mostly the server talking, and the plaintext path only
    /// asks to write when its response buffer is non-empty.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        self.prefix_sent < self.prefix.len()
            || match &self.ctx.session {
                Some(TlsSession::Server(c)) => c.wants_write(),
                Some(TlsSession::Client(c)) => c.wants_write(),
                None => false,
            }
    }

    #[must_use]
    pub const fn handshake_done(&self) -> bool {
        self.ctx.handshake_done
    }

    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.ctx.tls_info.alpn.as_deref()
    }

    /// Pushes everything rustls has queued onto the socket.
    ///
    /// Called from both directions. A partial write is not an error: rustls keeps the
    /// remainder and [`Self::wants_write`] stays true, so the poller brings us back.
    fn flush(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let mut sock = Sock(fd, false);
        loop {
            let wants = match self.ctx.session.as_ref() {
                Some(TlsSession::Server(c)) => c.wants_write(),
                Some(TlsSession::Client(c)) => c.wants_write(),
                None => false,
            };
            if !wants {
                return Ok(());
            }
            let res = match self.ctx.session.as_mut() {
                Some(TlsSession::Server(c)) => c.write_tls(&mut sock),
                Some(TlsSession::Client(c)) => c.write_tls(&mut sock),
                None => return Ok(()),
            };
            match res {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                // Nothing left to write to. The read side reports how the stream ended;
                // failing here would mask a truncation behind a write error.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads ciphertext off the socket and hands it to rustls.
    ///
    /// Returns `Ok(false)` at end of stream.
    fn fill(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        let mut sock = Sock(fd, false);
        let r = self.fill_from(&mut sock);
        self.sock_drained = sock.1;
        r
    }

    fn fill_from(&mut self, sock: &mut Sock<'_>) -> io::Result<bool> {
        let fd = sock.0;
        loop {
            let wants = match self.ctx.session.as_ref() {
                Some(TlsSession::Server(c)) => c.wants_read(),
                Some(TlsSession::Client(c)) => c.wants_read(),
                None => false,
            };
            if !wants {
                return Ok(true);
            }
            let res = match self.ctx.session.as_mut() {
                Some(TlsSession::Server(c)) => c.read_tls(sock),
                Some(TlsSession::Client(c)) => c.read_tls(sock),
                None => return Ok(true),
            };
            match res {
                Ok(0) => return Ok(false),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(true),
                // A reset peer is an end of stream, not a failure. `raw::recv` already
                // maps ECONNRESET to `Io::Closed` and the plaintext path treats that as
                // an ordinary close; propagating an error here instead would turn every
                // abruptly-dropped TLS connection into a logged failure.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(false),
                Err(e) => return Err(e),
            }
            // Process after every read: a record may complete mid-buffer, and an alert
            // must be acted on before more bytes are pulled in behind it.
            let state = match self.ctx.session.as_mut() {
                Some(TlsSession::Server(c)) => c.process_new_packets(),
                Some(TlsSession::Client(c)) => c.process_new_packets(),
                None => return Ok(true),
            };
            match state {
                Ok(st) => {
                    if st.peer_has_closed() {
                        self.peer_closed = true;
                    }
                    if st.plaintext_bytes_to_read() > 0 {
                        return Ok(true);
                    }
                }
                Err(e) => {
                    // A rustls error carries an alert that the peer is owed. Flush it
                    // before the socket goes away, then report.
                    let _ = self.flush(fd);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
    }

    /// Drives the handshake. `Ok(true)` once it is complete.
    fn handshake(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        if self.ctx.handshake_done {
            return Ok(true);
        }
        if self.failed {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "TLS handshake failed"));
        }
        let r = match self.send_prefix(fd) {
            Ok(true) => self.handshake_step(fd),
            Ok(false) => Ok(false),
            Err(e) => Err(e),
        };
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn handshake_step(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        // Flush first: the very first thing a server does is answer a ClientHello it has
        // already been given, and there may be nothing to read yet.
        self.flush(fd)?;

        let open = self.fill(fd)?;
        self.flush(fd)?;

        let handshaking = match self.ctx.session.as_ref() {
            Some(TlsSession::Server(c)) => c.is_handshaking(),
            Some(TlsSession::Client(c)) => c.is_handshaking(),
            None => false,
        };
        if !handshaking {
            self.ctx.handshake_done = true;
            self.ctx.update_tls_info();
            return Ok(true);
        }
        if !open {
            // The peer went away mid-handshake. Not a truncation of application data --
            // there is none yet -- but it is not a completed connection either.
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(false)
    }
}

/// The suite as `HAProxy` names it (`SSL_CIPHER_get_name`, OpenSSL's) from rustls's name for it:
/// the TLS 1.3 ones carry the IANA name there (rustls writes it `TLS13_...`), the TLS 1.2 ones
/// are OpenSSL's own spelling. A suite not
/// in the table keeps the name rustls gave it.
fn openssl_cipher_name(iana: &str) -> &str {
    match iana {
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "ECDHE-ECDSA-AES128-GCM-SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "ECDHE-ECDSA-AES256-GCM-SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-ECDSA-CHACHA20-POLY1305",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => "ECDHE-RSA-AES128-GCM-SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => "ECDHE-RSA-AES256-GCM-SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-RSA-CHACHA20-POLY1305",
        "TLS13_AES_128_GCM_SHA256" => "TLS_AES_128_GCM_SHA256",
        "TLS13_AES_256_GCM_SHA384" => "TLS_AES_256_GCM_SHA384",
        "TLS13_CHACHA20_POLY1305_SHA256" => "TLS_CHACHA20_POLY1305_SHA256",
        other => other,
    }
}

fn facts_of(info: &ibex_tls::RustlsTlsInfo) -> ibex_sample::SslFacts<'_> {
    ibex_sample::SslFacts {
        used: true,
        sni: info.sni.as_deref(),
        cipher: info.cipher.as_deref().map(openssl_cipher_name),
        protocol: info.protocol_version.as_deref(),
        has_crt: info.peer_has_cert,
        resumed: info.session_resumed,
    }
}

/// The transport under a client connection.
///
/// `Plain` costs nothing: the arms below compile to the same `raw::recv`/`raw::send` the
/// call sites used before this existed. `Tls` is boxed because a rustls session is several
/// kilobytes and most sessions in a mixed deployment are not encrypted -- an unboxed
/// variant would put that on every [`crate::proxy::TcpSession`] whether used or not.
pub enum ClientXprt {
    Plain,
    Tls(Box<TlsConn>),
}

impl ClientXprt {
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        matches!(self, ClientXprt::Tls(_))
    }

    /// What the `ssl_fc*` fetches read of the session: nothing for plaintext, and for TLS
    /// what the handshake settled. Borrows only; no allocation.
    #[must_use]
    pub fn ssl_facts(&self) -> ibex_sample::SslFacts<'_> {
        match self {
            ClientXprt::Plain => ibex_sample::SslFacts::default(),
            ClientXprt::Tls(t) => facts_of(&t.ctx.tls_info),
        }
    }

    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        match self {
            ClientXprt::Plain => None,
            ClientXprt::Tls(t) => t.alpn(),
        }
    }

    /// True when the transport itself needs the socket to be writable.
    ///
    /// The plaintext path never does -- it writes only what the stream layer hands it.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        match self {
            ClientXprt::Plain => false,
            ClientXprt::Tls(t) => t.wants_write(),
        }
    }

    /// True once bytes may flow. Plaintext is ready immediately.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        match self {
            ClientXprt::Plain => true,
            ClientXprt::Tls(t) => t.handshake_done(),
        }
    }

    /// True once the handshake has failed (a protocol error, or the client gone before it
    /// completed): the connection is not, and will not be, usable.
    #[must_use]
    pub fn handshake_failed(&self) -> bool {
        match self {
            ClientXprt::Plain => false,
            ClientXprt::Tls(t) => t.handshake_failed(),
        }
    }

    /// True when the stream ended without `close_notify`.
    #[must_use]
    pub fn was_truncated(&self) -> bool {
        match self {
            ClientXprt::Plain => false,
            ClientXprt::Tls(t) => t.was_truncated(),
        }
    }

    /// Drives any pending handshake. `Ok(true)` when the transport is ready.
    ///
    /// # Errors
    /// Propagates a failed handshake or a peer that vanished during one.
    pub fn handshake(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        match self {
            ClientXprt::Plain => Ok(true),
            ClientXprt::Tls(t) => t.handshake(fd),
        }
    }

    /// Reads plaintext, mirroring [`raw::recv`].
    ///
    /// # Errors
    /// Propagates socket failures and TLS protocol errors.
    pub fn recv(&mut self, fd: BorrowedFd<'_>, dst: &mut [u8]) -> io::Result<Io> {
        match self {
            ClientXprt::Plain => raw::recv(fd, dst),
            ClientXprt::Tls(t) => {
                if !t.handshake(fd)? {
                    return Ok(Io::WouldBlock);
                }
                let open = t.fill(fd)?;
                // Always flush: processing a record can queue a key update, a session
                // ticket or an alert, none of which the stream layer knows to ask for.
                t.flush(fd)?;

                let n = match t.session() {
                    Some(TlsSession::Server(c)) => c.reader().read(dst),
                    Some(TlsSession::Client(c)) => c.reader().read(dst),
                    None => return Ok(Io::Closed),
                };
                match n {
                    Ok(n) if n > 0 => Ok(Io::Done(n)),
                    // No plaintext available. What that means depends on how the stream
                    // ended, and the order matters.
                    //
                    // `close_notify` is the TLS peer saying "that was all of it", and it
                    // arrives while the socket is still open -- so this has to be checked
                    // before the socket state, or a cleanly-closed stream spins on
                    // WouldBlock forever waiting for an EOF that has already been
                    // superseded.
                    //
                    // A socket that ended without it is a truncation: an attacker who can
                    // inject a FIN cuts the stream short, and answering `Eof` would hand
                    // a partial body upstream as a complete one.
                    Ok(_) | Err(_) if t.peer_closed => Ok(Io::Eof),
                    Ok(_) | Err(_) if !open => {
                        t.truncated = true;
                        Ok(Io::Closed)
                    }
                    Ok(_) => Ok(Io::WouldBlock),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Io::WouldBlock),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Whether the read that returned `r` for `asked` bytes left nothing to read until
    /// the poller reports the socket again: a short read or `EAGAIN` for plaintext; for
    /// TLS, that and a socket the last ciphertext read emptied too (rustls holds no
    /// plaintext once a read of it comes back short).
    #[must_use]
    pub fn drained(&self, r: Io, asked: usize) -> bool {
        let plain = match r {
            Io::WouldBlock => true,
            Io::Done(n) => n < asked,
            Io::Eof | Io::Closed => false,
        };
        match self {
            ClientXprt::Plain => plain,
            ClientXprt::Tls(t) => plain && t.sock_drained,
        }
    }

    /// Writes plaintext, mirroring [`raw::send`].
    ///
    /// # Errors
    /// Propagates socket failures.
    pub fn send(&mut self, fd: BorrowedFd<'_>, src: &[u8]) -> io::Result<Io> {
        match self {
            ClientXprt::Plain => raw::send(fd, src),
            ClientXprt::Tls(t) => {
                if !t.handshake(fd)? {
                    return Ok(Io::WouldBlock);
                }
                let n = match t.session() {
                    Some(TlsSession::Server(c)) => c.writer().write(src),
                    Some(TlsSession::Client(c)) => c.writer().write(src),
                    None => return Ok(Io::Closed),
                };
                let taken = match n {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                    Err(e) => return Err(e),
                };
                t.flush(fd)?;
                if taken == 0 {
                    Ok(Io::WouldBlock)
                } else {
                    // Accepted into the TLS session, not yet necessarily on the wire.
                    // The stream layer may drop its copy: rustls owns the remainder and
                    // `wants_write` keeps the poller coming back until it is flushed.
                    Ok(Io::Done(taken))
                }
            }
        }
    }

    /// Sends `close_notify` so the peer can tell a finished stream from a cut one.
    pub fn send_close_notify(&mut self, fd: BorrowedFd<'_>) {
        if let ClientXprt::Tls(t) = self {
            match t.session() {
                Some(TlsSession::Server(c)) => c.send_close_notify(),
                Some(TlsSession::Client(c)) => c.send_close_notify(),
                None => return,
            }
            let _ = t.flush(fd);
        }
    }
}

impl std::fmt::Debug for ClientXprt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientXprt::Plain => f.write_str("ClientXprt::Plain"),
            ClientXprt::Tls(t) => f
                .debug_struct("ClientXprt::Tls")
                .field("handshake_done", &t.handshake_done())
                .field("truncated", &t.was_truncated())
                .finish(),
        }
    }
}

/// Builds a server-side TLS transport for an accepted connection.
///
/// # Errors
/// Propagates rustls session setup failure.
pub fn accept_tls(
    fd: &impl AsRawFd,
    config: std::sync::Arc<rustls::ServerConfig>,
) -> io::Result<ClientXprt> {
    let conn = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    Ok(ClientXprt::Tls(Box::new(TlsConn::new(
        RustlsContext::new_server(fd.as_raw_fd(), conn),
    ))))
}

#[cfg(test)]
mod tests {
    use super::openssl_cipher_name;

    /// The names `HAProxy` (OpenSSL) reports for the TLS 1.2 suites rustls can negotiate;
    /// the TLS 1.3 names are the same in both.
    #[test]
    fn cipher_names_are_openssls() {
        assert_eq!(openssl_cipher_name("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), "ECDHE-ECDSA-AES128-GCM-SHA256");
        assert_eq!(openssl_cipher_name("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"), "ECDHE-RSA-AES256-GCM-SHA384");
        assert_eq!(openssl_cipher_name("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"), "ECDHE-RSA-CHACHA20-POLY1305");
        assert_eq!(openssl_cipher_name("TLS13_AES_256_GCM_SHA384"), "TLS_AES_256_GCM_SHA384");
        // One the table does not know keeps rustls's name.
        assert_eq!(openssl_cipher_name("TLS_FUTURE_SUITE"), "TLS_FUTURE_SUITE");
    }
}

/// The transport under a backend server connection.
///
/// `Plain` costs nothing: the arms compile to the same `raw::recv`/`raw::send` calls
/// as before. `Tls` is boxed to keep [`crate::proxy::TcpSession`] small on plaintext paths.
pub enum ServerXprt {
    Plain,
    Tls(Box<TlsConn>),
}

impl ServerXprt {
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        matches!(self, ServerXprt::Tls(_))
    }

    /// What the `ssl_bc*` fetches read of the session; `None` for a plaintext connection.
    #[must_use]
    pub fn ssl_facts(&self) -> Option<ibex_sample::SslFacts<'_>> {
        match self {
            ServerXprt::Plain => None,
            ServerXprt::Tls(t) => Some(facts_of(&t.ctx.tls_info)),
        }
    }

    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        match self {
            ServerXprt::Plain => None,
            ServerXprt::Tls(t) => t.alpn(),
        }
    }

    /// The name sent in SNI, known from the start of the connection.
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        match self {
            ServerXprt::Plain => None,
            ServerXprt::Tls(t) => t.ctx.client_sni.as_deref(),
        }
    }

    /// True once the handshake has failed: the connection is not, and will not be, usable.
    #[must_use]
    pub fn handshake_failed(&self) -> bool {
        match self {
            ServerXprt::Plain => false,
            ServerXprt::Tls(t) => t.handshake_failed(),
        }
    }

    #[must_use]
    pub fn tls_info(&self) -> Option<&dyn ibex_proto::transport::TlsInfo> {
        match self {
            ServerXprt::Plain => None,
            ServerXprt::Tls(t) => Some(&t.ctx.tls_info),
        }
    }

    /// True when the transport itself needs the socket to be writable.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        match self {
            ServerXprt::Plain => false,
            ServerXprt::Tls(t) => t.wants_write(),
        }
    }

    /// True once bytes may flow. Plaintext is ready immediately.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        match self {
            ServerXprt::Plain => true,
            ServerXprt::Tls(t) => t.handshake_done(),
        }
    }

    /// True when the stream ended without `close_notify`.
    #[must_use]
    pub fn was_truncated(&self) -> bool {
        match self {
            ServerXprt::Plain => false,
            ServerXprt::Tls(t) => t.was_truncated(),
        }
    }

    /// Drives any pending handshake. `Ok(true)` when the transport is ready.
    ///
    /// # Errors
    /// Propagates a failed handshake, certificate verification failure, or broken connection.
    pub fn handshake(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        match self {
            ServerXprt::Plain => Ok(true),
            ServerXprt::Tls(t) => t.handshake(fd),
        }
    }

    /// Reads plaintext from backend, mirroring [`raw::recv`].
    ///
    /// # Errors
    /// Propagates socket failures and TLS protocol errors.
    pub fn recv(&mut self, fd: BorrowedFd<'_>, dst: &mut [u8]) -> io::Result<Io> {
        match self {
            ServerXprt::Plain => raw::recv(fd, dst),
            ServerXprt::Tls(t) => {
                if !t.handshake(fd)? {
                    return Ok(Io::WouldBlock);
                }
                let open = t.fill(fd)?;
                t.flush(fd)?;

                let n = match t.session() {
                    Some(TlsSession::Server(c)) => c.reader().read(dst),
                    Some(TlsSession::Client(c)) => c.reader().read(dst),
                    None => return Ok(Io::Closed),
                };
                match n {
                    Ok(n) if n > 0 => Ok(Io::Done(n)),
                    Ok(_) | Err(_) if t.peer_closed => Ok(Io::Eof),
                    Ok(_) | Err(_) if !open => {
                        t.truncated = true;
                        Ok(Io::Closed)
                    }
                    Ok(_) => Ok(Io::WouldBlock),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Io::WouldBlock),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Writes plaintext to backend, mirroring [`raw::send`].
    ///
    /// # Errors
    /// Propagates socket failures.
    pub fn send(&mut self, fd: BorrowedFd<'_>, src: &[u8]) -> io::Result<Io> {
        match self {
            ServerXprt::Plain => raw::send(fd, src),
            ServerXprt::Tls(t) => {
                if !t.handshake(fd)? {
                    return Ok(Io::WouldBlock);
                }
                let n = match t.session() {
                    Some(TlsSession::Server(c)) => c.writer().write(src),
                    Some(TlsSession::Client(c)) => c.writer().write(src),
                    None => return Ok(Io::Closed),
                };
                let taken = match n {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                    Err(e) => return Err(e),
                };
                t.flush(fd)?;
                if taken == 0 {
                    Ok(Io::WouldBlock)
                } else {
                    Ok(Io::Done(taken))
                }
            }
        }
    }

    /// Sends `close_notify` so the backend server can tell a finished stream from a cut one.
    pub fn send_close_notify(&mut self, fd: BorrowedFd<'_>) {
        if let ServerXprt::Tls(t) = self {
            match t.session() {
                Some(TlsSession::Server(c)) => c.send_close_notify(),
                Some(TlsSession::Client(c)) => c.send_close_notify(),
                None => return,
            }
            let _ = t.flush(fd);
        }
    }
}

impl std::fmt::Debug for ServerXprt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerXprt::Plain => f.write_str("ServerXprt::Plain"),
            ServerXprt::Tls(t) => f
                .debug_struct("ServerXprt::Tls")
                .field("handshake_done", &t.handshake_done())
                .field("truncated", &t.was_truncated())
                .finish(),
        }
    }
}

/// Builds an outbound client-side TLS transport to connect to an upstream backend server.
///
/// The recorded SNI is the name that goes on the wire: a DNS name when the config sends
/// SNI, nothing for an IP address (rustls never sends one) or when `enable_sni` is off.
///
/// rustls refuses a session only for a client config that asks for something this
/// proxy never configures (Encrypted Client Hello), so setup has no failure of its own
/// to report here: a session that did not come up is a transport already marked failed,
/// and the first handshake step reports it as every other handshake failure -- a connect
/// failure that `HAProxy` retries and answers 503 `SC` for.
pub fn connect_tls(
    fd: &impl AsRawFd,
    config: std::sync::Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
) -> ServerXprt {
    let sni_str = match &server_name {
        rustls::pki_types::ServerName::DnsName(dns) if config.enable_sni => Some(dns.as_ref().to_string()),
        _ => None,
    };
    let conn = rustls::ClientConnection::new(config, server_name).ok();
    let mut tls = TlsConn::new(RustlsContext::new_client_session(fd.as_raw_fd(), conn, sni_str));
    tls.failed = tls.ctx.session.is_none();
    ServerXprt::Tls(Box::new(tls))
}
