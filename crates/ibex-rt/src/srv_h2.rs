// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 to a server, one stream at a time (T540, slice B-H2 of T535): the transport layer
//! that puts [`H2SrvCodec`] between the session's HTTP/1.1 text and the connection.
//!
//! The request head is given as the blocks of the session's HTX ([`H2Layer::send_head`], X8:
//! nothing written as text or read back); its body, and the response, go as HTTP/1.1 text, as
//! they do to every server. A request with no blocks (a health check) and the first request of
//! a connection whose h2 layer is installed inside that send are text throughout:
//! [`H2Layer::send`] gives the request text to [`H2SrvCodec::send_request`] and writes the frames it made; [`H2Layer::recv`] reads frames
//! into the caller's buffer, gives them to [`H2SrvCodec::receive`] and hands back the
//! response text in their place. Below it is the connection's own transport, cleartext
//! (`proto h2`) or TLS (`alpn h2` selected, or `proto h2` with `ssl`).
//!
//! Installed (`ServerXprt::H2`) where the handshake ends with `h2` selected, which is in
//! `ServerXprt::handshake` or inside the first `send`/`recv` (T535: installing only in the
//! handshake gave intermittent 502s), and at `attach_server_to` for `proto h2`.
//!
//! An error ends the connection for the session as `HAProxy` logs it: the codec's GOAWAY or
//! RST_STREAM is flushed and the session reads a close (`Io::Closed`), a 502 `SH--` before
//! the head and a truncated `SD--` after; [`H2Layer::bad_response`] makes it `PH--`.

use crate::raw::Io;
use crate::xprt::ServerXprt;
use ibex_proto::h2_srv::{H2SrvCodec, SrvH2Error};
use std::io;
use std::os::fd::BorrowedFd;

/// The h2 codec of one server connection and the transport under it.
pub struct H2Layer {
    /// Cleartext or TLS, never another `H2`.
    pub(crate) inner: ServerXprt,
    /// From this thread's `h2c_srv` pool.
    codec: ibex_alloc::PoolBox<H2SrvCodec>,
    /// What ended the connection for the session, once it ended.
    err: Option<SrvH2Error>,
    /// The transport read its end.
    eof: bool,
    /// The last request bytes could not go: the server's window is spent. Cleared by any
    /// read, which may carry its WINDOW_UPDATE: until then the session does not ask to write.
    blocked: bool,
}

impl H2Layer {
    /// `inner` speaking h2 from now on; `None` when the `h2c_srv` pool has no memory.
    #[must_use]
    pub fn new(inner: ServerXprt) -> Option<Self> {
        Some(Self { inner, codec: H2SrvCodec::take()?, err: None, eof: false, blocked: false })
    }

    /// Frames still to write, or the transport's own bytes.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        !self.codec.output().is_empty() || self.inner.wants_write()
    }

    /// The request text cannot move until the server grants window.
    #[must_use]
    pub const fn send_blocked(&self) -> bool {
        self.blocked
    }

    /// The connection may carry another request: no stream open, none of the codec's
    /// reasons not to (GOAWAY, an error, a request cut short), and not ended.
    #[must_use]
    pub fn reusable(&self) -> bool {
        self.err.is_none() && !self.eof && self.codec.is_idle() && self.codec.reusable()
    }

    /// Streams opened on this connection.
    #[must_use]
    pub fn streams(&self) -> u32 {
        self.codec.streams()
    }

    /// The server's response was malformed: `HAProxy` logs `PH--`.
    #[must_use]
    pub fn bad_response(&self) -> bool {
        self.err == Some(SrvH2Error::BadResponse)
    }

    /// The trailer section that followed the last response's content-length body (T559).
    pub fn take_late_trailers(&mut self) -> Option<ibex_alloc::PoolBox<Vec<u8>>> {
        self.codec.take_late_trailers()
    }

    fn fail(&mut self, e: SrvH2Error) {
        self.err.get_or_insert(e);
    }

    /// Writes the codec's frames. `Ok(false)` when the connection is gone.
    fn flush(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        while !self.codec.output().is_empty() {
            match self.inner.send_under_h2(fd, self.codec.output())? {
                Io::Done(n) if n > 0 => self.codec.advance_output(n),
                Io::Done(_) | Io::WouldBlock => break,
                Io::Closed | Io::Eof => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Takes the request head as the blocks of its HTX (X8), nothing read as text: `Done(1)`
    /// when the codec wrote its HEADERS, `Closed` after an error (as [`Self::send`]). The
    /// body follows through [`Self::send`]. `chunked`: see [`H2SrvCodec::send_head`].
    ///
    /// # Errors
    /// The transport's.
    pub fn send_head(&mut self, fd: BorrowedFd<'_>, htx: ibex_proto::htx::HtxSliceRef<'_>, chunked: bool) -> io::Result<Io> {
        // On a layer that failed before, the codec's own refusal (or a stream opened on a
        // connection about to close) changes nothing: the verdict is `Closed` either way.
        if let Err(e) = self.codec.send_head(htx, chunked) {
            self.fail(e);
        }
        let _ = self.flush(fd)?;
        Ok(if self.err.is_some() { Io::Closed } else { Io::Done(1) })
    }

    /// Takes request text, as [`crate::raw::send`] takes bytes: `Done(n)` for the `n` bytes
    /// of `src` the codec took. After an error, `Closed`.
    ///
    /// # Errors
    /// The transport's.
    pub fn send(&mut self, fd: BorrowedFd<'_>, src: &[u8]) -> io::Result<Io> {
        if self.err.is_some() {
            let _ = self.flush(fd)?;
            return Ok(Io::Closed);
        }
        let used = if src.is_empty() {
            0
        } else {
            match self.codec.send_request(src) {
                Ok(n) => n,
                Err(e) => {
                    self.fail(e);
                    let _ = self.flush(fd)?;
                    return Ok(Io::Closed);
                }
            }
        };
        self.blocked = used == 0 && !src.is_empty();
        if !self.flush(fd)? && used == 0 {
            return Ok(Io::Closed);
        }
        Ok(if used > 0 { Io::Done(used) } else { Io::WouldBlock })
    }

    /// Gives response text, as [`crate::raw::recv`] gives bytes. `dst` is also where the
    /// frames are read to: the codec keeps what it was given.
    ///
    /// The text of a response cut short comes first, then `Closed`; the end of the
    /// transport is `Eof` once the text is all taken, and so is an idle connection that
    /// cannot carry another request (a GOAWAY): the idle pool closes it then.
    ///
    /// # Errors
    /// The transport's.
    pub fn recv(&mut self, fd: BorrowedFd<'_>, dst: &mut [u8]) -> io::Result<Io> {
        if dst.is_empty() {
            return Ok(Io::WouldBlock);
        }
        loop {
            let text = self.codec.response();
            if !text.is_empty() {
                let n = text.len().min(dst.len());
                dst[..n].copy_from_slice(&text[..n]);
                self.codec.advance_response(n);
                // WINDOW_UPDATE once the text is all taken; the socket is rarely full.
                let _ = self.flush(fd)?;
                return Ok(Io::Done(n));
            }
            if self.err.is_some() {
                let _ = self.flush(fd)?;
                return Ok(Io::Closed);
            }
            if self.eof || (self.codec.is_idle() && !self.codec.reusable()) {
                return Ok(Io::Eof);
            }
            match self.inner.recv_under_h2(fd, dst)? {
                Io::Done(0) | Io::WouldBlock => {
                    let _ = self.flush(fd)?;
                    return Ok(Io::WouldBlock);
                }
                Io::Done(n) => {
                    self.blocked = false;
                    if let Err(e) = self.codec.receive(&dst[..n]) {
                        self.fail(e);
                    }
                    // A SETTINGS ACK, a PING's, a WINDOW_UPDATE: out at once, also from the
                    // idle pool, which only reads.
                    if !self.flush(fd)? {
                        self.eof = true;
                    }
                }
                Io::Eof => self.eof = true,
                Io::Closed => return Ok(Io::Closed),
            }
        }
    }
}

impl std::fmt::Debug for H2Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Layer").field("inner", &self.inner).field("err", &self.err).field("eof", &self.eof).finish_non_exhaustive()
    }
}
