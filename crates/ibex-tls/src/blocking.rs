// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A TLS session over a blocking stream, on rustls 0.24 and the active provider (T461): what
//! the log-forward TLS binds (server) and the ring TLS servers (client) run on, a thread each.
//! It drives [`TlsCtx`], the same session the event loop's TLS runs on, so a configuration
//! from [`crate::tcp`] (and its provider, and the swap) serves both.

use std::io::{self, Read, Write};
use std::sync::Arc;

use ibex_config::TlsCryptoProvider;
use rustls24::pki_types::ServerName;
use rustls24::ClientConfig;

use crate::conn::{Plain, TlsCtx, VecInput};
use crate::provider;
use crate::tcp::BindTls;

/// A TLS session over `S`, the handshake run on the first read or write.
pub struct BlockingTls<S> {
    ctx: TlsCtx,
    input: VecInput,
    sock: S,
    provider: TlsCryptoProvider,
    counted: bool,
}

fn tls_error(e: rustls24::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl<S: Read + Write> BlockingTls<S> {
    /// The server side of a connection `sock` accepted on `bind` (its current build).
    pub fn accept(bind: &Arc<BindTls>, sock: S) -> Self {
        let bind = Arc::clone(bind).into_current();
        let provider = bind.provider;
        Self { ctx: TlsCtx::accept(bind), input: VecInput::default(), sock, provider, counted: false }
    }

    /// The client side of a connection to `name` over `sock`, on `config` (built on `provider`).
    ///
    /// # Errors
    /// rustls refuses to start a session on `config`.
    pub fn connect(config: &Arc<ClientConfig>, provider: TlsCryptoProvider, name: ServerName<'static>, sock: S) -> io::Result<Self> {
        let ctx = TlsCtx::connect(config, name, None);
        // A session rustls refused to start is not handshaking: no ClientHello to send.
        ctx.is_handshaking().then_some(()).ok_or_else(|| io::Error::other("TLS client session refused"))?;
        Ok(Self { ctx, input: VecInput::default(), sock, provider, counted: false })
    }

    fn flush_tx(&mut self) -> io::Result<()> {
        while self.ctx.wants_write() {
            let n = self.sock.write(self.ctx.pending_tx())?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.ctx.tx_done(n);
        }
        self.sock.flush()
    }

    /// Reads ciphertext; 0 at end of stream.
    fn fill(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 16 * 1024];
        let n = self.sock.read(&mut buf)?;
        if n == 0 {
            self.input.set_eof();
        } else {
            self.input.extend(&buf[..n], &self.ctx);
        }
        Ok(n)
    }

    fn handshake(&mut self) -> io::Result<()> {
        while self.ctx.is_handshaking() {
            let r = self.ctx.handshake(&mut self.input);
            // The alert of a failure goes out too.
            self.flush_tx()?;
            r.map_err(tls_error)?;
            if self.ctx.is_handshaking() && self.fill()? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        if !self.counted {
            self.counted = true;
            provider::count_handshake(self.provider);
        }
        Ok(())
    }
}

impl<S: Read + Write> Read for BlockingTls<S> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        self.handshake()?;
        loop {
            let r = self.ctx.read_plain(&mut self.input, dst);
            self.flush_tx()?;
            match r.map_err(tls_error)? {
                Plain::Data(n) => return Ok(n),
                Plain::Closed => return Ok(0),
                Plain::More => {
                    if self.fill()? == 0 {
                        return Ok(0);
                    }
                }
            }
        }
    }
}

impl<S: Read + Write> Write for BlockingTls<S> {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        if src.is_empty() {
            return Ok(0);
        }
        self.handshake()?;
        // `flush_tx` leaves the send buffer empty, so `write_plain` takes at least one byte.
        let n = self.ctx.write_plain(src).map_err(tls_error)?;
        self.flush_tx()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_tx()
    }
}
