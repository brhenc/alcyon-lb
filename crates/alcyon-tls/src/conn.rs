// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A TLS-over-TCP session on rustls 0.24, in buffers the caller owns (T440).
//!
//! rustls 0.23's buffered connections copy every record through buffers of their own and
//! allocate a few times per request doing it (`tradeoff.md` 6.20). 0.24 takes the input
//! buffer from its caller and decrypts in it, in place, and appends what it encrypts to a
//! `Vec` the caller passes in. So:
//!
//! - **Input** is the caller's, through [`TlsInput`] (the runtime's pooled `Buf`). The
//!   plaintext of a record is read straight out of it. When the caller's buffer cannot take a
//!   whole record, the rest stays where rustls decrypted it ([`TlsCtx::read_plain`]), and the
//!   caller must not add bytes to the input until [`TlsCtx::has_plain`] says it is drained
//!   (adding may move them).
//! - **Output** is a `Vec` of [`TX_CAP`] bytes from the `tls_tx` pool, held only while the
//!   session has ciphertext for the socket (taken when rustls has something to send, given back
//!   by [`TlsCtx::tx_done`] when it is all on the wire, as `HAProxy` releases an empty buffer):
//!   an idle connection holds none. [`TlsCtx::write_plain`] never lets it grow past [`TX_CAP`]:
//!   a steady-state record allocates nothing.
//!
//! The handshake is rustls 0.24's typestate one. A server session starts as an acceptor so that
//! the `ClientHello` is seen before the configuration is chosen: the certificate it gets (for
//! `ssl_f_*`) and `HAProxy`'s ALPN rule (a client whose list has nothing in common with the
//! bind's is answered without ALPN, where rustls alone would abort).

use crate::capture::HelloTap;
use crate::tcp::BindTls;
use crate::transport::RustlsTlsInfo;
use alcyon_proto::transport::VerifyResult;
use rustls24::client::{ClientHandshake, ClientSide};
use rustls24::pki_types::ServerName;
use rustls24::server::{ServerHandshake, ServerSide};
use rustls24::split::{ReceiveTraffic, ReceiveTrafficState, SendTraffic};
use rustls24::enums::ProtocolVersion;
use rustls24::{ClientConfig, ConnectionOutputs, Error, HandshakeKind, NeedsInput, TlsInputBuffer};
use std::sync::Arc;

pub use rustls24::TlsInputBuffer as InputBuffer;

/// The most ciphertext a session holds for the socket: two full records and their overhead.
/// The output `Vec` is made with this capacity and never grows past it after the handshake.
pub const TX_CAP: usize = 2 * (16_384 + 512);

/// A `tls_tx` chunk. Under `tune.alcyon.ssl-zero-buffers on-free` it is not wiped when given back;
/// the pool's free (trim, budget, thread exit, stop) drops it, and this `Drop` wipes all of its
/// capacity (T553). Under `on` the session wiped it at the give-back already.
pub struct TxChunk(Vec<u8>);

impl Drop for TxChunk {
    fn drop(&mut self) {
        if self.0.capacity() != 0 && alcyon_alloc::ssl_wipe_deferred() {
            let cap = self.0.capacity();
            self.0.clear();
            self.0.resize(cap, 0);
            alcyon_alloc::wipe_ssl_fast(&mut self.0);
        }
    }
}

impl alcyon_alloc::Poolable for TxChunk {
    fn footprint(&self) -> usize {
        self.0.capacity()
    }
    fn reset(&mut self, _wipe: bool) {
        self.0.clear();
    }
    fn keep(&self, max_footprint: usize) -> bool {
        self.0.capacity() != 0 && self.0.capacity() <= max_footprint
    }
    fn try_new() -> Option<Self> {
        TxChunk::made()
    }
}

impl TxChunk {
    /// A new chunk of [`TX_CAP`]: what a miss in `TlsCtx::tx_take` and the pool's own
    /// construction ([`alcyon_alloc::Poolable::try_new`]) both make.
    fn made() -> Option<Self> {
        Some(TxChunk(Vec::with_capacity(TX_CAP)))
    }
}

alcyon_alloc::declare_pool!(
    /// `show pools` `tls_tx`: the ciphertext a TLS session has for the socket (T541). One chunk is
    /// [`TX_CAP`]: two records of 16,384 bytes of plaintext (the TLS maximum) and 512 bytes each
    /// for the header, nonce/IV, MAC or tag and padding of either protocol version; a chunk that
    /// grew (a handshake with a long certificate chain) is freed on give, not pooled.
    static TLS_TX: Pool<TxChunk> = alcyon_alloc::PoolSpec::new("tls_tx").size(TX_CAP).max_item(TX_CAP);
);

/// Lists the `tls_tx` pool in `show pools` from the start.
pub fn register_pools() {
    TLS_TX.register();
}

/// Ciphertext buffers this thread's `tls_tx` pool holds (`show pools`: cached).
#[must_use]
pub fn tx_pool_cached() -> usize {
    TLS_TX.local_count()
}

/// Per-record overhead allowed for when deciding how much plaintext fits in the output: a
/// record header, an explicit nonce (TLS 1.2) or content type (TLS 1.3), and a tag.
const RECORD_OVERHEAD: usize = 64;

/// The input buffer of a session: rustls's [`TlsInputBuffer`], plus the memory its window is
/// in, so that a record's plaintext left behind by a short read can be found again.
pub trait TlsInput: TlsInputBuffer {
    /// All of the memory the [`TlsInputBuffer::slice_mut`] window is in. Bytes before the
    /// window (discarded) stay in place until the caller adds bytes to the buffer.
    fn storage(&self) -> &[u8];
}

/// What [`TlsCtx::read_plain`] got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plain {
    /// This many bytes were copied out (never 0).
    Data(usize),
    /// No complete record: read more ciphertext first.
    More,
    /// The peer sent `close_notify`: nothing more comes.
    Closed,
}

/// The two halves of a session once the handshake is done.
pub struct Traffic<S: rustls24::SideData> {
    send: Option<SendTraffic>,
    recv: Option<ReceiveTraffic<S>>,
}

/// Where a session is.
pub enum Session {
    /// A server waiting for the `ClientHello`, with what it may answer with.
    Hello(rustls24::NeedsInput<ServerSide>, Arc<BindTls>),
    /// A server handshake past the `ClientHello` (the bind is kept for the one code path).
    ServerHs(NeedsInput<ServerSide>, Arc<BindTls>),
    /// A client handshake.
    ClientHs(NeedsInput<ClientSide>),
    Server(Traffic<ServerSide>),
    Client(Traffic<ClientSide>),
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Hello(..) => "Session::Hello",
            Self::ServerHs(..) => "Session::ServerHs",
            Self::ClientHs(_) => "Session::ClientHs",
            Self::Server(_) => "Session::Server",
            Self::Client(_) => "Session::Client",
        })
    }
}

/// A TLS session over TCP and what it learned: the runtime's per-connection TLS state.
#[allow(clippy::struct_excessive_bools)] // independent connection flags
#[derive(Debug)]
pub struct TlsCtx {
    /// `None` once the session failed or was closed.
    pub session: Option<Session>,
    pub is_server: bool,
    pub handshake_done: bool,
    pub client_sni: Option<String>,
    pub tls_info: RustlsTlsInfo,
    /// Ciphertext for the peer: `tx[tx_sent..]` is not on the wire yet.
    /// Empty, with no capacity, while the session has none; else a `tls_tx` chunk.
    tx: Vec<u8>,
    tx_sent: usize,
    /// `tx` came from the pool (counted in use there), not from the allocator after a refusal.
    tx_pooled: bool,
    /// The most `tx` held since it was taken: what [`Self::tx_release`] wipes.
    tx_hw: usize,
    /// A record's plaintext the caller's buffer could not take, in [`TlsInput::storage`].
    plain: (usize, usize),
    /// The peer sent `close_notify`.
    pub peer_closed: bool,
    /// The `ClientHello` capture while the handshake runs (server side, size > 0 only).
    hello_tap: Option<Box<HelloTap>>,
    /// The version the server chose is TLS 1.2 (read off its `ServerHello`): the tap stops at
    /// the client's `ChangeCipherSpec` then. rustls's handshake does not tell it.
    tls12: bool,
    /// The server accepted the `ClientHello` (the session no longer waits for it).
    hello_seen: bool,
}

impl Drop for TlsCtx {
    /// The ciphertext this connection produced does not stay in the heap for the next
    /// allocation to find (`tune.alcyon.ssl-zero-buffers`, see [`wipe_vec`]): the whole capacity, `clear` keeps it.
    fn drop(&mut self) {
        self.tx_release();
    }
}

/// Zeroes all of `v`'s memory, written or not, under `tune.alcyon.ssl-zero-buffers` (default on):
/// `tune.alcyon.zero-buffers` (default off) is the plain I/O buffers'.
pub(crate) fn wipe_vec(v: &mut Vec<u8>) {
    let cap = v.capacity();
    v.resize(cap, 0);
    alcyon_alloc::wipe_ssl(v);
}

impl TlsCtx {
    fn new(is_server: bool, session: Option<Session>, client_sni: Option<String>) -> Self {
        Self {
            session,
            is_server,
            handshake_done: false,
            client_sni,
            tls_info: RustlsTlsInfo { peer_verify: VerifyResult::NotRequested, ..Default::default() },
            tx: Vec::new(),
            tx_sent: 0,
            tx_pooled: false,
            tx_hw: 0,
            plain: (0, 0),
            peer_closed: false,
            hello_tap: None,
            tls12: false,
            hello_seen: false,
        }
    }

    /// A server session, waiting for its `ClientHello`.
    #[must_use]
    pub fn accept(bind: Arc<BindTls>) -> Self {
        Self::new(true, Some(Session::Hello(ServerHandshake::start(), bind)), None)
    }

    /// A client session to `name`, its `ClientHello` queued. A session rustls refuses to make
    /// (a client config that cannot work) has none: the caller marks it failed.
    #[must_use]
    pub fn connect(config: &Arc<ClientConfig>, name: ServerName<'static>, sni: Option<String>) -> Self {
        let mut ctx = Self::new(false, None, sni);
        ctx.tx_take();
        ctx.session = Self::start_client(config, name, &mut ctx.tx);
        // The key share was just generated (T462).
        alcyon_alloc::scrub_stack();
        ctx
    }

    /// The client's first flight. Not inlined, so that its frames are below the scrub.
    #[inline(never)]
    fn start_client(config: &Arc<ClientConfig>, name: ServerName<'static>, tx: &mut Vec<u8>) -> Option<Session> {
        config.connect(name).start_handshake(tx).ok().map(Session::ClientHs)
    }

    /// Captures the `ClientHello` of this server-side session, keeping `size` bytes
    /// (`tune.ssl.capture-buffer-size`). 0 captures nothing and allocates nothing.
    pub fn enable_capture(&mut self, size: usize) {
        self.hello_tap = HelloTap::new(size).map(Box::new);
    }

    /// `alcyon.ja4-compat`: `true` for `spec`. Call after [`Self::enable_capture`].
    pub fn set_ja4_spec(&mut self, spec: bool) {
        if let Some(tap) = self.hello_tap.as_mut() {
            tap.set_ja4_spec(spec);
        }
    }

    /// Whether the `ClientHello` capture still wants the client's bytes.
    #[must_use]
    pub fn tapping(&self) -> bool {
        self.hello_tap.is_some()
    }

    /// Shows bytes the client sent, in order, to the `ClientHello` capture.
    pub fn tap_client_bytes(&mut self, data: &[u8]) {
        if let Some(tap) = self.hello_tap.as_mut() {
            tap.feed(data, self.tls12);
        }
    }

    /// Ciphertext waiting for the socket.
    #[must_use]
    pub fn pending_tx(&self) -> &[u8] {
        &self.tx[self.tx_sent..]
    }

    /// `n` bytes of [`Self::pending_tx`] went out.
    pub fn tx_done(&mut self, n: usize) {
        self.tx_sent = self.tx_sent.saturating_add(n).min(self.tx.len());
        if self.tx_sent == self.tx.len() {
            self.tx_release();
        }
    }

    /// Makes `tx` a pooled chunk if it is not one. A refused take (memory is short) falls back
    /// to an allocation of the same size, which [`Self::tx_release`] frees.
    fn tx_take(&mut self) {
        if self.tx.capacity() == 0 {
            match TLS_TX.take_counted(TxChunk::made) {
                Some(mut c) => {
                    self.tx = std::mem::take(&mut c.0);
                    self.tx_pooled = true;
                }
                None => {
                    self.tx = Vec::with_capacity(TX_CAP);
                    self.tx_pooled = false;
                }
            }
        }
    }

    /// Gives `tx` back, wiped (`tune.alcyon.ssl-zero-buffers`) as far as it was ever written.
    fn tx_release(&mut self) {
        self.tx_sent = 0;
        if self.tx.capacity() == 0 {
            return;
        }
        self.tx_hw = self.tx_hw.max(self.tx.len());
        let mut v = std::mem::take(&mut self.tx);
        let pooled = std::mem::take(&mut self.tx_pooled);
        // `on-free`: a chunk going back to the pool is wiped by `TxChunk::drop` when the pool
        // frees it (T553); one that is not pooled is freed here, so it is wiped here.
        if !(pooled && alcyon_alloc::ssl_wipe_deferred()) {
            // `clear` and `drain` leave the old bytes past `len`: they are still in the capacity.
            if self.tx_hw > v.len() {
                v.resize(self.tx_hw, 0);
            }
            alcyon_alloc::wipe_ssl_fast(&mut v);
        }
        v.clear();
        self.tx_hw = 0;
        if pooled {
            TLS_TX.give_counted(TxChunk(v));
        }
    }

    /// Capacity of the ciphertext buffer this session holds now (0 while it has none).
    #[must_use]
    pub fn tx_capacity(&self) -> usize {
        self.tx.capacity()
    }

    /// Whether the session has ciphertext for the socket.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        self.tx_sent < self.tx.len()
    }

    /// A record's plaintext is still waiting for [`Self::read_plain`]: the caller must not add
    /// bytes to the input buffer until it is gone.
    #[must_use]
    pub const fn has_plain(&self) -> bool {
        self.plain.0 < self.plain.1
    }

    /// Whether the handshake is still running (or never started: no session).
    #[must_use]
    pub fn is_handshaking(&self) -> bool {
        matches!(self.session, Some(Session::Hello(..) | Session::ServerHs(..) | Session::ClientHs(_)))
    }

    /// Whether the session waits for the `ClientHello`.
    #[must_use]
    pub fn awaiting_hello(&self) -> bool {
        matches!(self.session, Some(Session::Hello(..)))
    }

    /// Feeds the ciphertext in `input` to the handshake. Anything to send is queued
    /// ([`Self::pending_tx`]), including the alert of a failure. On an error the session is gone.
    ///
    /// # Errors
    /// rustls refused the handshake.
    pub fn handshake(&mut self, input: &mut dyn TlsInputBuffer) -> Result<(), Error> {
        let was_done = self.handshake_done;
        let r = self.handshake_step(input);
        // What rustls and ring left on the stack below this frame (moved-from keys, `Copy` HMAC
        // outputs, the ECDH point, assembly spills) goes before anything else runs, on every exit
        // including the step that finishes the handshake: `tune.alcyon.ssl-zero-buffers` (T462,
        // `tradeoff.md` 6.27). Not per record, nor on a call after the handshake (no crypto ran).
        if !was_done {
            alcyon_alloc::scrub_stack();
        }
        r
    }

    /// [`Self::handshake`] before the scrub. Not inlined: its frame (which holds the handshake
    /// states rustls hands back by value) is below the caller's, inside the scrubbed range.
    #[inline(never)]
    fn handshake_step(&mut self, input: &mut dyn TlsInputBuffer) -> Result<(), Error> {
        self.tx_take();
        let r = self.handshake_loop(input);
        if self.tx.is_empty() {
            self.tx_release();
        }
        r
    }

    fn handshake_loop(&mut self, input: &mut dyn TlsInputBuffer) -> Result<(), Error> {
        loop {
            let Some(session) = self.session.take() else { return Ok(()) };
            match session {
                Session::Hello(n, bind) | Session::ServerHs(n, bind) => {
                    let next = n.process(input, &mut self.tx)?;
                    if self.server_next(next, bind)? {
                        return Ok(());
                    }
                }
                Session::ClientHs(n) => {
                    let next = n.process(input, &mut self.tx)?;
                    if self.client_next(next)? {
                        return Ok(());
                    }
                }
                done @ (Session::Server(_) | Session::Client(_)) => {
                    self.session = Some(done);
                    return Ok(());
                }
            }
        }
    }

    /// Takes the server handshake's next state. `Ok(true)`: wait for more input; `Ok(false)`:
    /// process what the input holds again.
    fn server_next(&mut self, next: ServerHandshake, bind: Arc<BindTls>) -> Result<bool, Error> {
        match srv_state(next)? {
            Srv::Wait(n) => {
                self.session = Some(if self.hello_seen { Session::ServerHs(n, bind) } else { Session::Hello(n, bind) });
                Ok(true)
            }
            Srv::Hello(accepted) => {
                self.hello_seen = true;
                let hello = accepted.client_hello();
                // The certificate this ClientHello gets, for `ssl_f_*`: the resolver
                // answers the same way when rustls asks it.
                self.tls_info.local_cert = bind.resolver.credentials_for(&hello).map(crate::transport::LocalCert::Tcp);
                let ours = &bind.config.alpn_protocols;
                let disjoint = !ours.is_empty()
                    && hello.alpn().is_some_and(|mut theirs| theirs.all(|t| !ours.iter().any(|o| o.as_ref() == t)));
                let config = Arc::clone(if disjoint { &bind.no_alpn } else { &bind.config });
                let start = self.tx.len();
                let next = accepted.choose_config(config, &mut self.tx);
                self.tls12 = server_hello_is_tls12(&self.tx[start..]);
                self.server_next(next?, bind)?;
                // The rest of the input may hold more of the client's flight.
                Ok(false)
            }
            Srv::Done(split) => {
                self.finish(&split.outputs, split.side_outputs.server_name().map(|n| n.as_ref().to_string()));
                let t = Traffic { send: Some(split.send), recv: Some(split.receive) };
                self.session = Some(Session::Server(t));
                Ok(true)
            }
        }
    }

    /// Takes the client handshake's next state. `Ok(true)`: wait for more input; `Ok(false)`:
    /// process what the input holds again.
    fn client_next(&mut self, next: ClientHandshake) -> Result<bool, Error> {
        match cli_state(next)? {
            Cli::Wait(n) => {
                self.session = Some(Session::ClientHs(n));
                Ok(true)
            }
            Cli::Verify(v) => {
                let next = v.with_config(&mut self.tx)?;
                self.client_next(next)?;
                // The rest of the flight (`CertificateVerify`, `Finished`) is still in the
                // input: rustls stopped at the identity to verify.
                Ok(false)
            }
            Cli::Done(split) => {
                self.finish(&split.outputs, self.client_sni.clone());
                let t = Traffic { send: Some(split.send), recv: Some(split.receive) };
                self.session = Some(Session::Client(t));
                Ok(true)
            }
        }
    }

    /// The handshake is done: what it settled, for the logs and the `ssl_*` fetches.
    fn finish(&mut self, outputs: &ConnectionOutputs, sni: Option<String>) {
        self.handshake_done = true;
        let info = &mut self.tls_info;
        info.sni = sni;
        info.cipher = outputs.negotiated_cipher_suite().map(|cs| format!("{:?}", cs.suite()));
        // rustls 0.24 implements TLS 1.2 and 1.3 only: a session is one or the other.
        info.protocol_version =
            outputs.protocol_version().map(|pv| if pv == ProtocolVersion::TLSv1_3 { "TLSv1.3" } else { "TLSv1.2" }.to_string());
        self.tls12 = outputs.protocol_version() == Some(ProtocolVersion::TLSv1_2);
        info.alpn = outputs.alpn_protocol().map(|p| p.as_ref().to_vec());
        info.session_resumed =
            matches!(outputs.handshake_kind(), Some(HandshakeKind::Resumed | HandshakeKind::ResumedWithHelloRetryRequest));
        // A server asks no client for a certificate (no `verify` on binds yet); a client got the
        // server's chain, verified, or the handshake would have failed.
        let has_peer = outputs.peer_identity().is_some();
        info.peer_has_cert = has_peer;
        info.peer_verify = if has_peer { VerifyResult::Ok } else { VerifyResult::NotRequested };
        // No ClientHello comes after the handshake (rustls does not renegotiate): the tap
        // and its buffers go now (`ssl_sock_capture_free_func` frees with the connection).
        if let Some(tap) = self.hello_tap.take() {
            self.tls_info.capture = tap.into_capture();
        }
    }

    /// Copies decrypted application data into `dst`, from what is left of the last record
    /// first, then from the next complete record in `input`. Anything the receive side queues
    /// for the peer (a key update, an alert) goes to [`Self::pending_tx`].
    ///
    /// # Errors
    /// The record could not be decrypted or was not acceptable; the receive side is gone and
    /// its alert is queued.
    pub fn read_plain<I: TlsInput>(&mut self, input: &mut I, dst: &mut [u8]) -> Result<Plain, Error> {
        if self.has_plain() {
            let (a, b) = self.plain;
            let n = (b - a).min(dst.len());
            let Some(src) = input.storage().get(a..a + n) else {
                self.plain = (0, 0);
                return Err(Error::General("lost plaintext".into()));
            };
            dst[..n].copy_from_slice(src);
            self.plain.0 += n;
            return Ok(Plain::Data(n));
        }
        // Nothing is queued for the peer by most reads: they get a buffer with no capacity, and
        // what a key update or an alert wrote there moves to a pooled chunk afterwards.
        let mut side = Vec::new();
        let r = loop {
            let out = if self.tx.capacity() == 0 { &mut side } else { &mut self.tx };
            let r = match &mut self.session {
                Some(Session::Server(t)) => read_traffic(t, input, dst, out),
                Some(Session::Client(t)) => read_traffic(t, input, dst, out),
                _ => return Ok(Plain::More),
            };
            // An empty record was all this read found: the next complete one may follow it
            // in the input already, and `More` would send the caller to an empty socket.
            // Each turn consumes a record, so this ends with the input.
            if !matches!(r, Ok((Plain::More, _, true))) {
                break r.map(|(p, rest, _)| (p, rest));
            }
        };
        if !side.is_empty() {
            self.tx_take();
            self.tx.extend_from_slice(&side);
            alcyon_alloc::wipe_ssl_fast(&mut side);
        }
        match r {
            Ok((Plain::Data(n), rest)) => {
                self.plain = rest;
                Ok(Plain::Data(n))
            }
            Ok((Plain::Closed, _)) => {
                self.peer_closed = true;
                Ok(Plain::Closed)
            }
            Ok((p, _)) => Ok(p),
            Err(e) => Err(e),
        }
    }

    /// Encrypts as much of `src` as the output has room for; how much that was (0: the socket
    /// must take some of [`Self::pending_tx`] first).
    ///
    /// # Errors
    /// The send side is closed or broken.
    pub fn write_plain(&mut self, src: &[u8]) -> Result<usize, Error> {
        if self.tx_sent > 0 {
            // Room at the front: what is on the wire already need not be kept.
            self.tx_hw = self.tx_hw.max(self.tx.len());
            self.tx.drain(..self.tx_sent);
            self.tx_sent = 0;
        }
        let room = TX_CAP.saturating_sub(self.tx.len());
        let n = src.len().min(room.saturating_sub((room / 16_384 + 1) * RECORD_OVERHEAD));
        if n == 0 {
            return Ok(0);
        }
        self.tx_take();
        let r = match &mut self.session {
            Some(Session::Server(t)) => Self::write_on(t.send.as_mut(), &src[..n], &mut self.tx),
            Some(Session::Client(t)) => Self::write_on(t.send.as_mut(), &src[..n], &mut self.tx),
            _ => Err(Error::HandshakeNotComplete),
        };
        if r.is_err() && self.tx.is_empty() {
            self.tx_release();
        }
        r
    }

    fn write_on(send: Option<&mut SendTraffic>, src: &[u8], tx: &mut Vec<u8>) -> Result<usize, Error> {
        let Some(send) = send else { return Err(Error::General("send side closed".into())) };
        send.write(src.into(), tx)?;
        Ok(src.len())
    }

    /// Queues `close_notify` (once; nothing during the handshake).
    pub fn close_notify(&mut self) {
        let send = match &mut self.session {
            Some(Session::Server(t)) => t.send.take(),
            Some(Session::Client(t)) => t.send.take(),
            _ => None,
        };
        if let Some(send) = send {
            self.tx_take();
            let _ = send.close(&mut self.tx);
        }
    }
}

/// The server handshake states Alcyon takes.
enum Srv {
    Wait(NeedsInput<ServerSide>),
    Hello(rustls24::server::Accepted<rustls24::Tcp>),
    Done(rustls24::split::SplitConnection<ServerSide>),
}

/// rustls yields `VerifyClientIdentity` only to a config with a client verifier, and a bind
/// has none (`with_no_client_auth`); the enum is `non_exhaustive`. Either is a failure.
fn srv_state(s: ServerHandshake) -> Result<Srv, Error> {
    Ok(match s {
        ServerHandshake::NeedsInput(n) => Srv::Wait(n),
        ServerHandshake::Accepted(a) => Srv::Hello(a),
        ServerHandshake::Complete(c) => Srv::Done(c), _ => return Err(Error::General("unexpected server handshake state".into())),
    })
}

/// The client handshake states.
enum Cli {
    Wait(NeedsInput<ClientSide>),
    Verify(rustls24::VerifyPeerIdentity<ClientSide, rustls24::Tcp>),
    Done(rustls24::split::SplitConnection<ClientSide>),
}

/// rustls 0.24.0-dev.2 has these three client states; the enum is `non_exhaustive`.
fn cli_state(s: ClientHandshake) -> Result<Cli, Error> {
    Ok(match s {
        ClientHandshake::NeedsInput(n) => Cli::Wait(n),
        ClientHandshake::VerifyServerIdentity(v) => Cli::Verify(v),
        ClientHandshake::Complete(c) => Cli::Done(c), _ => return Err(Error::General("unexpected client handshake state".into())),
    })
}

/// One read of the receive side of `t`: the plaintext copied into `dst`, where in the
/// input's storage the rest of the record is (empty when it all fit), and whether the record
/// read was an empty one. A receive side that is gone (`close_notify` seen) reads as closed.
fn read_traffic<S: rustls24::SideData, I: TlsInput>(
    t: &mut Traffic<S>,
    input: &mut I,
    dst: &mut [u8],
    tx: &mut Vec<u8>,
) -> Result<(Plain, (usize, usize), bool), Error> {
    let Some(recv) = t.recv.take() else { return Ok((Plain::Closed, (0, 0), false)) };
    let base = input.storage().as_ptr() as usize;
    let mut out = (Plain::More, (0, 0));
    let mut flush = false;
    let mut empty = false;
    // rustls processes every message up to the next application data record (or the end of
    // the complete records) in one call: no data and `ReadMore` means read the socket.
    let first = match recv.read(input) {
        Ok(s) => s,
        Err(e) => {
            // The alert went to the send side: put it on the wire.
            pump(t, tx);
            return Err(e);
        }
    };
    let mut state = match first {
        ReceiveTrafficState::Available(mut data) => {
            let bytes = data.data();
            // An empty record (a peer may send one) copies nothing; the caller reads on.
            empty = bytes.is_empty();
            let n = bytes.len().min(dst.len());
            dst[..n].copy_from_slice(&bytes[..n]);
            let at = (bytes.as_ptr() as usize).wrapping_sub(base);
            let rest = if n < bytes.len() { (at + n, at + bytes.len()) } else { (0, 0) };
            out = (if n > 0 { Plain::Data(n) } else { Plain::More }, rest);
            data.into_next()
        }
        // The same states, re-typed: `first` borrows `input`, the loop's states do not.
        ReceiveTrafficState::FlushSender(f) => ReceiveTrafficState::FlushSender(f),
        ReceiveTrafficState::ReadMore(r) => ReceiveTrafficState::ReadMore(r),
        ReceiveTrafficState::CloseNotify => ReceiveTrafficState::CloseNotify,
    };
    loop {
        state = match state {
            ReceiveTrafficState::FlushSender(f) => {
                flush = true;
                f.into_next()
            }
            ReceiveTrafficState::ReadMore(r) => {
                t.recv = Some(r);
                break;
            }
            // Only `read` yields data: rustls's `into_next` (of `FlushSender` and of
            // `ReceivedApplicationData`) returns `FlushSender`, `ReadMore` or `CloseNotify`, so
            // this is `CloseNotify`.
            end @ (ReceiveTrafficState::CloseNotify | ReceiveTrafficState::Available(_)) => {
                debug_assert!(matches!(end, ReceiveTrafficState::CloseNotify));
                // With data in this same read, the next read reports the close.
                if out.0 == Plain::More {
                    out.0 = Plain::Closed;
                }
                break;
            }
        };
    }
    if flush {
        pump(t, tx);
    }
    Ok((out.0, out.1, empty))
}

/// Moves what the receive side queued for the peer into `tx`.
fn pump<S: rustls24::SideData>(t: &mut Traffic<S>, tx: &mut Vec<u8>) {
    if let Some(send) = t.send.as_mut() {
        let _ = send.write(rustls24::crypto::cipher::OutboundPlain::new_empty(), tx);
    }
}

/// Whether the `ServerHello` at the start of `out` chose a TLS 1.2 suite (TLS 1.3's are 0x13xx).
fn server_hello_is_tls12(out: &[u8]) -> bool {
    // record header (5), handshake header (4), legacy_version (2), random (32), session id.
    if out.first() != Some(&0x16) || out.get(5) != Some(&0x02) {
        return false;
    }
    let Some(&sid) = out.get(43) else { return false };
    out.get(44 + usize::from(sid)).is_some_and(|&hi| hi != 0x13)
}

/// A session's input, owned (tests, and callers that hold their ciphertext in a `Vec`).
#[derive(Debug, Default)]
pub struct VecInput {
    buf: Vec<u8>,
    start: usize,
    eof: bool,
    closed: bool,
}

impl VecInput {
    /// Appends ciphertext. Compacts first only when `ctx` holds no plaintext in it.
    pub fn extend(&mut self, data: &[u8], ctx: &TlsCtx) {
        if self.start > 0 && !ctx.has_plain() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The socket hit end of stream.
    pub fn set_eof(&mut self) {
        self.eof = true;
    }

    /// Bytes not consumed yet.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len() - self.start
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for VecInput {
    fn drop(&mut self) {
        wipe_vec(&mut self.buf);
    }
}

impl TlsInputBuffer for VecInput {
    fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..]
    }
    fn discard(&mut self, n: usize) {
        self.start = (self.start + n).min(self.buf.len());
    }
    fn received_close_notify(&mut self) {
        self.closed = true;
    }
    fn has_seen_eof(&self) -> bool {
        self.eof
    }
}

impl TlsInput for VecInput {
    fn storage(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod wipe_tests {
    use super::wipe_vec;
    use std::sync::Mutex;

    /// `tune.alcyon.zero-buffers` is process-wide: the tests take turns.
    static SETTING: Mutex<()> = Mutex::new(());

    /// What `TlsCtx` (output buffer) and `VecInput` (input buffer, decrypted plaintext) run on
    /// release: with `tune.alcyon.ssl-zero-buffers` on (the default) all of the capacity reads
    /// back zeros whatever `tune.alcyon.zero-buffers` (the plain I/O buffers', off by default)
    /// says; with it off the secret is still in the freed memory.
    #[test]
    fn released_tls_buffers_follow_ssl_zero_buffers_and_not_zero_buffers() {
        let _turn = SETTING.lock().unwrap();
        let secret = b"decrypted-secret-0123456789";
        for zero_buffers in [true, false] {
            alcyon_alloc::set_zero_buffers(zero_buffers);
            for ssl in [true, false] {
                alcyon_alloc::set_ssl_zero_buffers(ssl);
                let mut v = Vec::with_capacity(256);
                v.extend_from_slice(secret);
                wipe_vec(&mut v);
                assert_eq!(v.len(), 256, "ssl {ssl}: the whole capacity is covered");
                let kept = &v[..secret.len()] == secret;
                assert_eq!(kept, !ssl, "zero-buffers {zero_buffers}, ssl-zero-buffers {ssl}: secret kept = {kept}");
            }
        }
        alcyon_alloc::set_zero_buffers(false);
        alcyon_alloc::set_ssl_zero_buffers(true);
    }
}

#[cfg(test)]
mod pool_tests {
    use super::{tx_pool_cached, TLS_TX, TX_CAP};

    /// `Pool::take` and the prefill make a chunk with `Poolable::try_new`: it has the size of
    /// every other `tls_tx` chunk (not capacity 0, which `keep` refuses on the way back), and
    /// goes to the pool on drop.
    #[test]
    fn a_chunk_the_pool_makes_has_the_chunk_size_and_is_kept_when_given_back() {
        alcyon_alloc::drain_local_pools();
        assert_eq!(tx_pool_cached(), 0);
        let c = TLS_TX.take().expect("a miss makes a chunk");
        assert!(c.0.capacity() >= TX_CAP, "capacity {}", c.0.capacity());
        drop(c);
        assert_eq!(tx_pool_cached(), 1, "kept: the chunk is of the pool's size");
        TLS_TX.prefill(2);
        assert_eq!(tx_pool_cached(), 3, "a prefill adds chunks");
        alcyon_alloc::drain_local_pools();
    }
}
