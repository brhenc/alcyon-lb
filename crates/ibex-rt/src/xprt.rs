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
//!
//! ## Buffers (T440)
//!
//! The TLS side runs on rustls 0.24, which owns no buffers: the ciphertext read off the socket
//! goes into a pooled [`Buf`] and is decrypted there in place, the plaintext copied out of it
//! straight into the stream layer's buffer; what rustls encrypts is appended to the session's
//! own output `Vec` ([`ibex_tls::conn::TlsCtx`]), made once per connection and never grown
//! after the handshake. A steady-state request over TLS allocates nothing.

use crate::buf::Buf;
use crate::raw::{self, Io};
use ibex_tls::conn::{Plain, TlsCtx};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// How many of a connection's first bytes are kept to tell why its handshake failed.
const HEAD_LEN: usize = 11;

/// Why a client's TLS handshake failed, as `HAProxy` words it in the log
/// (`session_embryonic_build_legacy_err`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HsFail {
    /// The client left without sending a byte (`CO_ER_SSL_EMPTY`).
    Empty,
    /// The client left after part of a handshake (`CO_ER_SSL_ABORT`).
    Abort,
    /// The bytes were not an acceptable handshake: the OpenSSL-style error text.
    Error(String),
    /// The client sent at least the start of a handshake message in whole records and then
    /// left, its FIN arriving alone: `SSL handshake failure`, with no error text.
    Bare,
}

impl HsFail {
    /// `option dontlognull` does not log a client that left (`session_kill_embryonic`).
    #[must_use]
    pub const fn is_null(&self) -> bool {
        !matches!(self, Self::Error(_) | Self::Bare)
    }

    /// `conn->err_code` (`CO_ER_SSL_EMPTY`, or `CO_ER_SSL_HANDSHAKE`): `fc_err`. A client that
    /// leaves part-way logs the same text and code as one that leaves at once (measured).
    #[must_use]
    pub const fn code(&self) -> i64 {
        match self {
            Self::Empty | Self::Abort => 24,
            Self::Error(_) | Self::Bare => 34,
        }
    }

    /// `conn_err_code_name`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Empty | Self::Abort => "SSL_EMPTY",
            Self::Error(_) | Self::Bare => "SSL_HANDSHAKE",
        }
    }

    /// `conn_err_code_str`: the log line's message without OpenSSL's error text.
    #[must_use]
    pub const fn text(&self) -> &'static str {
        match self {
            Self::Empty | Self::Abort => "Connection closed during SSL handshake",
            Self::Error(_) | Self::Bare => "SSL handshake failure",
        }
    }

    /// OpenSSL's error (`ssl_fc_err`, `ssl_fc_err_str`), for a handshake it refused:
    /// `error:0A00009C:SSL routines::http request` is `0x0A00009C` and that text.
    #[must_use]
    pub fn openssl_error(&self) -> Option<(i64, &str)> {
        let Self::Error(e) = self else { return None };
        let code = i64::from_str_radix(e.strip_prefix("error:")?.get(..8)?, 16).ok()?;
        Some((code, e))
    }

    /// The message of `HAProxy`'s log line.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Empty | Self::Abort => "Connection closed during SSL handshake".to_string(),
            Self::Error(e) => format!("SSL handshake failure ({e})"),
            Self::Bare => "SSL handshake failure".to_string(),
        }
    }
}

/// OpenSSL's error for bytes that opened no TLS record: an HTTP request is recognised
/// (`SSL_R_HTTP_REQUEST`), anything else is a wrong version.
fn non_tls_error(head: &[u8]) -> String {
    let http = [&b"GET "[..], b"POST ", b"HEAD ", b"PUT ", b"CONNECT "].iter().any(|m| head.starts_with(m));
    if http {
        "error:0A00009C:SSL routines::http request".to_string()
    } else {
        "error:0A00010B:SSL routines::wrong version number".to_string()
    }
}

/// What OpenSSL says, and sends, for a handshake that rustls refused (measured on `HAProxy`
/// 3.5-dev8). `first` is the first byte the client sent. Returns the error text and the alert
/// description OpenSSL puts on the wire (`None`: it sends nothing). Errors with no OpenSSL
/// equivalent mapped here keep rustls's own words (`error:0A000000`) and rustls's alert.
fn openssl_error(e: &rustls24::Error, first: Option<u8>) -> Option<(&'static str, Option<u8>)> {
    use rustls24::error::{InvalidMessage, PeerIncompatible};
    use rustls24::Error;
    match e {
        Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon) => Some(("error:0A0000C1:SSL routines::no shared cipher", Some(40))),
        Error::InappropriateMessage { .. } | Error::InappropriateHandshakeMessage { .. } | Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge) => {
            Some(("error:0A0000F4:SSL routines::unexpected message", Some(10)))
        }
        // The client's first record is an alert: the handshake wanted a ClientHello.
        Error::AlertReceived(_) if first == Some(0x15) => Some(("error:0A0000F4:SSL routines::unexpected message", Some(10))),
        Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion) => Some(("error:0A00010B:SSL routines::wrong version number", None)),
        _ => None,
    }
}

/// The first byte of a TLS record is its content type, 20 to 23.
fn looks_like_tls(head: &[u8]) -> bool {
    head.first().is_some_and(|b| (0x14..=0x17).contains(b))
}

/// The ciphertext read off the socket, in a pooled [`Buf`]: rustls 0.24 decrypts the records
/// in it, in place, and the plaintext is copied out from there (T440).
///
/// A record longer than the buffer (a standard `Buf` is `tune.bufsize`, 16 KiB, and a full TLS
/// record is a little more) grows it, once; a handshake message up to `MAX_INPUT` too.
struct TlsRx {
    buf: Buf,
    eof: bool,
    closed: bool,
}

/// rustls's own bound on buffered handshake data (`VecInput`): 64 KiB, and a record.
const MAX_INPUT: usize = 0xffff + 16_384 + 2048 + 5;

impl rustls24::TlsInputBuffer for TlsRx {
    fn slice_mut(&mut self) -> &mut [u8] {
        self.buf.readable_mut()
    }
    fn discard(&mut self, n: usize) {
        self.buf.consume(n);
    }
    fn received_close_notify(&mut self) {
        self.closed = true;
    }
    fn has_seen_eof(&self) -> bool {
        self.eof
    }
}

impl ibex_tls::conn::TlsInput for TlsRx {
    fn storage(&self) -> &[u8] {
        self.buf.raw_slice()
    }
}

/// One read of the socket: what came, and whether the socket was left empty.
enum Read1 {
    Bytes,
    WouldBlock,
    End,
}

/// Per-connection TLS state.
#[allow(clippy::struct_excessive_bools)] // independent facts about the stream, not a state machine
pub struct TlsConn {
    ctx: TlsCtx,
    rx: TlsRx,
    /// T320: this connection in `CurrSslConns` and `CumSslConns` while it exists.
    _counted: crate::stats::SslConnCount,
    /// T460: the crypto provider of the configuration this connection started with, whose
    /// handshake count (`show ssl crypto-provider`) it adds to once complete.
    provider: ibex_tls::TlsCryptoProvider,
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
    /// Why a client handshake failed, once it has.
    fail: Option<HsFail>,
    /// The first bytes the client sent.
    head: Vec<u8>,
    /// Bytes the client has sent in all, and whether its end of stream came in a read of its
    /// own, after those bytes (not with them).
    rx_total: usize,
    late_eof: bool,
    /// The FIN was already queued behind the bytes of a read (`MSG_PEEK` saw it).
    eof_with_data: bool,
    /// The `legacy_version` of the ClientHello has been looked at.
    legacy_checked: bool,
    /// OpenSSL's text for the error rustls refused the handshake with, when it has one.
    ossl_text: Option<&'static str>,
    /// Bytes that go on the wire in plaintext before the ClientHello: a PROXY protocol
    /// header to a `send-proxy` server, which `HAProxy` writes from its `xprt_handshake`
    /// layer under `ssl_sock`, and which the peer's `accept-proxy` reads before its own
    /// handshake. `prefix_sent` is how much of it is out.
    prefix: Vec<u8>,
    prefix_sent: usize,
    /// The last read of the socket left it empty (a read shorter than asked, or
    /// `EAGAIN`). With no plaintext left either, there is nothing to read until the poller
    /// says so, as for a plaintext socket (`fd_cant_recv`). Not knowing this, the TLS side
    /// read until `EAGAIN` on every pass: 7 of 9 reads a request (T186).
    sock_drained: bool,
    /// Our `close_notify` is queued: a second call (the explicit shutdown, then the session's
    /// end) must not send another.
    notified: bool,
    /// The bytes of this read, for the `ClientHello` capture while it runs.
    tap: Vec<u8>,
    /// A record refused after the plaintext before it was handed over: the next read's.
    rx_err: Option<io::Error>,
}

impl TlsConn {
    #[must_use]
    fn new(ctx: TlsCtx, provider: ibex_tls::TlsCryptoProvider) -> Self {
        Self {
            ctx,
            // Its memory is taken at the first read (S5: one that cannot be had fails that
            // stream, not the process).
            rx: TlsRx { buf: Buf::unallocated(crate::buf::BufClass::Standard), eof: false, closed: false },
            _counted: crate::stats::SslConnCount::new(),
            provider,
            truncated: false,
            failed: false,
            fail: None,
            head: Vec::new(),
            rx_total: 0,
            late_eof: false,
            eof_with_data: false,
            legacy_checked: false,
            ossl_text: None,
            prefix: Vec::new(),
            prefix_sent: 0,
            sock_drained: false,
            notified: false,
            tap: Vec::new(),
            rx_err: None,
        }
    }

    #[must_use]
    pub const fn handshake_failed(&self) -> bool {
        self.failed
    }

    /// Why the handshake failed, for the log.
    #[must_use]
    pub const fn failure(&self) -> Option<&HsFail> {
        self.fail.as_ref()
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

    /// True while there are bytes to put on the wire.
    ///
    /// The caller must poll for writability whenever this holds, even with no application
    /// data queued: a handshake is mostly the server talking, and the plaintext path only
    /// asks to write when its response buffer is non-empty.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        self.prefix_sent < self.prefix.len() || self.ctx.wants_write()
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

    /// Pushes the queued ciphertext onto the socket.
    ///
    /// Called from both directions. A partial write is not an error: the rest stays queued
    /// and [`Self::wants_write`] stays true, so the poller brings us back.
    fn flush(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        while self.ctx.wants_write() {
            match raw::send(fd, self.ctx.pending_tx())? {
                // Nothing left to write to (`Closed`, `Eof`): the read side reports how the
                // stream ended; failing here would mask a truncation behind a write error.
                Io::Done(0) | Io::WouldBlock | Io::Closed | Io::Eof => return Ok(()),
                Io::Done(n) => self.ctx.tx_done(n),
            }
        }
        Ok(())
    }

    /// Reads the socket once into the input buffer. Never while a record's plaintext is
    /// still in it (the buffer may move its bytes to make room).
    fn read_once(&mut self, fd: BorrowedFd<'_>) -> io::Result<Read1> {
        debug_assert!(!self.ctx.has_plain());
        if !self.rx.buf.alloc_for(crate::buf_wait::Class::MuxRx) {
            return Err(crate::buf::oom());
        }
        if self.rx.buf.ensure_writable(4096).is_empty() {
            // Full of a record or a handshake message not complete yet.
            let len = self.rx.buf.len();
            // Not reached with rustls 0.24.0-dev.2: it refuses a handshake message over 0xffff
            // as soon as its header is in, and takes every complete record, so the input holds
            // at most one message and one record, under MAX_INPUT. Kept as the memory bound.
            if len >= MAX_INPUT { return Err(io::Error::new(io::ErrorKind::InvalidData, "TLS message too large")); }
            // Not reached (above): a growth that cannot be had leaves the buffer full, and the
            // read below reads nothing.
            let _ = self.rx.buf.grow_capacity((len + 16_384 + 2048 + 5).min(MAX_INPUT));
        }
        let w = self.rx.buf.ensure_writable(1);
        let room = w.len();
        let r = raw::recv(fd, w)?;
        Ok(match r {
            Io::Done(n) => {
                // The first bytes a client sends tell a TLS handshake from a stranger's bytes.
                let keep = HEAD_LEN.saturating_sub(self.head.len()).min(n);
                self.head.extend_from_slice(&w[..keep]);
                if self.ctx.tapping() {
                    self.tap.extend_from_slice(&w[..n]);
                }
                self.rx.buf.commit(n);
                self.rx_total += n;
                self.sock_drained = n < room;
                Read1::Bytes
            }
            Io::WouldBlock => {
                self.sock_drained = true;
                Read1::WouldBlock
            }
            // A reset peer is an end of stream, not a failure. `raw::recv` already maps
            // ECONNRESET to `Io::Closed` and the plaintext path treats that as an ordinary
            // close; an error here instead would turn every abruptly-dropped TLS
            // connection into a logged failure.
            Io::Eof | Io::Closed => {
                self.sock_drained = false;
                self.rx.eof = true;
                Read1::End
            }
        })
    }

    /// Feeds the handshake what the input buffer holds, and maps a refusal to what OpenSSL
    /// says and sends.
    fn process_handshake(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let r = self.ctx.handshake(&mut self.rx);
        // After rustls has read them, so that the tap knows the version the server chose.
        if !self.tap.is_empty() {
            let bytes = std::mem::take(&mut self.tap);
            self.ctx.tap_client_bytes(&bytes);
        }
        let Err(e) = r else { return Ok(()) };
        let first = self.head.first().copied();
        let tls = looks_like_tls(&self.head);
        if let Some((text, alert)) = if tls { openssl_error(&e, first) } else { None } {
            // OpenSSL's alert, not rustls's: send it before the socket goes away.
            self.ossl_text = Some(text);
            self.ctx.tx_done(usize::MAX);
            if let Some(a) = alert {
                let _ = raw::send(fd, &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, a]);
            }
        } else if tls {
            // A rustls error carries an alert that the peer is owed. Flush it before the
            // socket goes away, then report.
            let _ = self.flush(fd);
        } else {
            // Not to a stranger's bytes: OpenSSL sends nothing to those either.
            self.ctx.tx_done(usize::MAX);
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Reads the handshake's bytes off the socket and processes them. `Ok(false)` at end of
    /// stream.
    fn fill_handshake(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        let prior = self.rx_total;
        loop {
            if !self.ctx.is_handshaking() {
                return Ok(true);
            }
            match self.read_once(fd)? {
                Read1::Bytes => {
                    if self.ctx.awaiting_hello() {
                        if let Some(e) = self.refuse_old_legacy_version(fd) {
                            return Err(e);
                        }
                    }
                    if matches!(raw::peek(fd, &mut [0u8; 1]), Ok(Io::Eof)) {
                        self.eof_with_data = true;
                    }
                    self.process_handshake(fd)?;
                }
                Read1::WouldBlock => return Ok(true),
                Read1::End => {
                    if self.rx_total == prior && prior > 0 && !self.eof_with_data {
                        self.late_eof = true;
                    }
                    return Ok(false);
                }
            }
        }
    }

    /// OpenSSL refuses a ClientHello whose `legacy_version` is below TLS 1.0 (`bad legacy
    /// version`), which rustls takes: it answers with a fatal alert in a record of that version,
    /// `protocol_version` below SSL 3.0 and `handshake_failure` for SSL 3.0 (measured on
    /// `HAProxy`).
    fn refuse_old_legacy_version(&mut self, fd: BorrowedFd<'_>) -> Option<io::Error> {
        if self.legacy_checked || self.head.len() < HEAD_LEN {
            return None;
        }
        self.legacy_checked = true;
        let head = &self.head;
        // A handshake record whose first message is a ClientHello: version at byte 9.
        if head[0] != 0x16 || head[5] != 0x01 || head[9] > 0x03 || (head[9] == 0x03 && head[10] >= 0x01) {
            return None;
        }
        let alert = if head[9] == 0x03 { 40 } else { 70 };
        self.ossl_text = Some("error:0A000124:SSL routines::bad legacy version");
        let _ = raw::send(fd, &[0x15, head[9], head[10], 0x00, 0x02, 0x02, alert]);
        self.ctx.session = None;
        Some(io::Error::new(io::ErrorKind::InvalidData, "bad legacy version"))
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
        if let Err(e) = &r {
            // No buffer to read into (`read_once`): nothing was read, the stream may wait for
            // one and come back (S6b).
            if crate::buf::is_oom(e) {
                return r;
            }
            self.failed = true;
            self.fail = Some(if e.kind() == io::ErrorKind::UnexpectedEof {
                // The first record was a whole handshake record with a message header in it, and
                // the FIN came after it, alone: OpenSSL was waiting in the middle of a message.
                let whole_record = self.head.len() >= 5 && self.head[0] == 0x16 && {
                    let len = usize::from(u16::from_be_bytes([self.head[3], self.head[4]]));
                    len >= 4 && self.rx_total >= 5 + len
                };
                if self.head.is_empty() {
                    HsFail::Empty
                } else if self.late_eof && whole_record {
                    HsFail::Bare
                } else {
                    HsFail::Abort
                }
            } else if let Some(text) = self.ossl_text {
                HsFail::Error(text.to_string())
            } else if looks_like_tls(&self.head) {
                HsFail::Error(format!("error:0A000000:SSL routines::{e}"))
            } else {
                HsFail::Error(non_tls_error(&self.head))
            });
        }
        r
    }

    /// Never without a session: every way it goes (`connect_tls` without one, a refused
    /// legacy version, a failed handshake) sets `failed`, which [`Self::handshake`] checks first.
    fn handshake_step(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        // Flush first: a client's ClientHello is queued from the start, and a server may
        // have answered bytes it was given already.
        self.flush(fd)?;
        let open = self.fill_handshake(fd)?;
        self.flush(fd)?;
        if self.ctx.handshake_done {
            // Once: `handshake` returns before this step from now on.
            ibex_tls::provider::count_handshake(self.provider);
            return Ok(true);
        }
        if !open {
            // The peer went away mid-handshake. Not a truncation of application data --
            // there is none yet -- but it is not a completed connection either.
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(false)
    }

    /// Reads plaintext, mirroring [`raw::recv`].
    fn recv(&mut self, fd: BorrowedFd<'_>, dst: &mut [u8]) -> io::Result<Io> {
        // Past the handshake the session stays (only a failed handshake loses it).
        if !self.handshake(fd)? {
            return Ok(Io::WouldBlock);
        }
        if dst.is_empty() {
            // Nowhere to put a byte: decrypting a record now would only leave it pending.
            self.flush(fd)?;
            return Ok(Io::WouldBlock);
        }
        if let Some(e) = self.rx_err.take() {
            return Err(e);
        }
        let mut open = !rustls24::TlsInputBuffer::has_seen_eof(&self.rx);
        let mut short = false;
        loop {
            let got = self.read_records(dst);
            // Always flush: a record can queue a key update or an alert, which the stream
            // layer does not know to ask for.
            self.flush(fd)?;
            match got {
                Ok(Plain::Data(n)) => return Ok(Io::Done(n)),
                // `close_notify` is the TLS peer saying "that was all of it", and it arrives
                // while the socket is still open -- so it is looked at before the socket state,
                // or a cleanly-closed stream spins on WouldBlock waiting for an EOF that has
                // already been superseded.
                Ok(Plain::Closed) => return Ok(Io::Eof),
                Ok(Plain::More) => {}
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
            if !open {
                // A socket that ended without `close_notify` is a truncation: an attacker who
                // can inject a FIN cuts the stream short, and answering `Eof` would hand a
                // partial body upstream as a complete one.
                self.truncated = true;
                return Ok(Io::Closed);
            }
            if short {
                // The socket gave all it had and no record is complete yet.
                return Ok(Io::WouldBlock);
            }
            match self.read_once(fd)? {
                Read1::Bytes => short = self.sock_drained,
                Read1::WouldBlock => return Ok(Io::WouldBlock),
                Read1::End => open = false,
            }
        }
    }

    /// Copies the plaintext of as many complete records as `dst` takes. A short count means
    /// the input holds no other complete record (as a short read of a socket means it is
    /// empty: [`ClientXprt::drained`]). An error after some data is reported by the next call.
    fn read_records(&mut self, dst: &mut [u8]) -> Result<Plain, rustls24::Error> {
        let mut n = 0;
        loop {
            match self.ctx.read_plain(&mut self.rx, &mut dst[n..]) {
                Ok(Plain::Data(k)) => {
                    n += k;
                    if n == dst.len() {
                        return Ok(Plain::Data(n));
                    }
                }
                Ok(_) if n > 0 => return Ok(Plain::Data(n)),
                Err(e) if n > 0 => {
                    self.rx_err = Some(io::Error::new(io::ErrorKind::InvalidData, e));
                    return Ok(Plain::Data(n));
                }
                other => return other,
            }
        }
    }

    /// Writes plaintext, mirroring [`raw::send`].
    fn send(&mut self, fd: BorrowedFd<'_>, src: &[u8]) -> io::Result<Io> {
        if !self.handshake(fd)? {
            return Ok(Io::WouldBlock);
        }
        self.flush(fd)?;
        let taken = self.ctx.write_plain(src).map_err(io::Error::other)?;
        self.flush(fd)?;
        if taken == 0 {
            Ok(Io::WouldBlock)
        } else {
            // Encrypted, not yet necessarily on the wire. The stream layer may drop its
            // copy: the session holds the rest and `wants_write` keeps the poller coming
            // back until it is out.
            Ok(Io::Done(taken))
        }
    }

    /// Sends `close_notify` so the peer can tell a finished stream from a cut one.
    fn send_close_notify(&mut self, fd: BorrowedFd<'_>) {
        if self.notified || self.ctx.session.is_none() {
            return;
        }
        self.ctx.close_notify();
        self.notified = true;
        let _ = self.flush(fd);
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

pub(crate) fn facts_of(info: &ibex_tls::RustlsTlsInfo) -> ibex_sample::SslFacts<'_> {
    ibex_sample::SslFacts {
        used: true,
        sni: info.sni.as_deref(),
        cipher: info.cipher.as_deref().map(openssl_cipher_name),
        protocol: info.protocol_version.as_deref(),
        alpn: info.alpn.as_deref(),
        has_crt: info.peer_has_cert,
        local_crt: info.local_cert.as_ref().and_then(ibex_tls::LocalCert::leaf),
        resumed: info.session_resumed,
        capture: info.capture.as_ref(),
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

    /// What the handshake settled, for TLS: copied once for the streams of an HTTP/2
    /// connection, which read it after the connection's own entry (T280).
    #[must_use]
    pub fn tls_info(&self) -> Option<&ibex_tls::RustlsTlsInfo> {
        match self {
            ClientXprt::Plain => None,
            ClientXprt::Tls(t) => Some(&t.ctx.tls_info),
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

    /// Why the client's handshake failed.
    #[must_use]
    pub fn failure(&self) -> Option<&HsFail> {
        match self {
            ClientXprt::Plain => None,
            ClientXprt::Tls(t) => t.failure(),
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
            ClientXprt::Tls(t) => t.recv(fd, dst),
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
            ClientXprt::Tls(t) => t.send(fd, src),
        }
    }

    /// Sends `close_notify` so the peer can tell a finished stream from a cut one.
    pub fn send_close_notify(&mut self, fd: BorrowedFd<'_>) {
        if let ClientXprt::Tls(t) = self {
            t.send_close_notify(fd);
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

/// Builds a server-side TLS transport for an accepted connection. Nothing can fail here:
/// the handshake runs later, on the connection's first reads.
#[must_use]
pub fn accept_tls(fd: &impl AsRawFd, config: std::sync::Arc<ibex_tls::tcp::BindTls>) -> ClientXprt {
    accept_tls_capturing(fd, config, 0, false)
}

/// As [`accept_tls`], keeping `capture_size` bytes of the `ClientHello`
/// (`tune.ssl.capture-buffer-size`) for the `ssl_fc_cipherlist_*` fetches; 0 captures nothing.
/// `ja4_spec` is `ibex.ja4-compat spec`; it reaches `ssl_fc_ja4` through the capture.
#[must_use]
pub fn accept_tls_capturing(fd: &impl AsRawFd, config: std::sync::Arc<ibex_tls::tcp::BindTls>, capture_size: usize, ja4_spec: bool) -> ClientXprt {
    let _ = fd.as_raw_fd();
    // T460: the bind's build on the provider active now (`set ssl crypto-provider`).
    let config = config.into_current();
    let provider = config.provider;
    let mut ctx = TlsCtx::accept(config);
    ctx.enable_capture(capture_size);
    ctx.set_ja4_spec(ja4_spec);
    ClientXprt::Tls(Box::new(TlsConn::new(ctx, provider)))
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

    /// Every suite the small table maps agrees with the generated id table
    /// (`ibex_tls::cipher_names`), by the suite's IANA id.
    #[test]
    fn cipher_names_agree_with_the_id_table() {
        for (iana, id) in [
            ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02b_u16),
            ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xc02c),
            ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca9),
            ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc02f),
            ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xc030),
            ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xcca8),
            ("TLS13_AES_128_GCM_SHA256", 0x1301),
            ("TLS13_AES_256_GCM_SHA384", 0x1302),
            ("TLS13_CHACHA20_POLY1305_SHA256", 0x1303),
        ] {
            assert_eq!(Some(openssl_cipher_name(iana)), ibex_tls::cipher_names::openssl_cipher_name_by_id(id), "{iana}");
        }
    }

    /// A plaintext client has no handshake to fail: a read error on it is an ordinary
    /// close, never the TLS-handshake-failure path in `proxy.rs`.
    #[test]
    fn a_plain_client_never_fails_a_handshake() {
        let x = super::ClientXprt::Plain;
        assert!(x.is_ready());
        assert!(!x.handshake_failed());
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
            ServerXprt::Tls(t) => t.recv(fd, dst),
        }
    }

    /// Writes plaintext to backend, mirroring [`raw::send`].
    ///
    /// # Errors
    /// Propagates socket failures.
    pub fn send(&mut self, fd: BorrowedFd<'_>, src: &[u8]) -> io::Result<Io> {
        match self {
            ServerXprt::Plain => raw::send(fd, src),
            ServerXprt::Tls(t) => t.send(fd, src),
        }
    }

    /// Sends `close_notify` so the backend server can tell a finished stream from a cut one.
    pub fn send_close_notify(&mut self, fd: BorrowedFd<'_>) {
        if let ServerXprt::Tls(t) = self {
            t.send_close_notify(fd);
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
// The config is only borrowed by the session setup, but every caller holds a clone to hand over.
#[allow(clippy::needless_pass_by_value)]
pub fn connect_tls(
    fd: &impl AsRawFd,
    config: std::sync::Arc<rustls24::ClientConfig>,
    server_name: rustls24::pki_types::ServerName<'static>,
) -> ServerXprt {
    connect_tls_on(fd, config, server_name, ibex_tls::provider::active())
}

/// [`connect_tls`] for a `config` built on `provider`, which its handshake is counted under.
#[must_use]
#[allow(clippy::needless_pass_by_value)] // as `connect_tls`
pub fn connect_tls_on(
    fd: &impl AsRawFd,
    config: std::sync::Arc<rustls24::ClientConfig>,
    server_name: rustls24::pki_types::ServerName<'static>,
    provider: ibex_tls::TlsCryptoProvider,
) -> ServerXprt {
    let _ = fd.as_raw_fd();
    let sni_str = match &server_name {
        rustls24::pki_types::ServerName::DnsName(dns) if config.enable_sni => Some(dns.as_ref().to_string()),
        _ => None,
    };
    let mut tls = TlsConn::new(TlsCtx::connect(&config, server_name, sni_str), provider);
    tls.failed = tls.ctx.session.is_none();
    ServerXprt::Tls(Box::new(tls))
}
