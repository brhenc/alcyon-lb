// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/connection-t.h (struct xprt_ops).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! L5/L6: the transport layer. `HAProxy`'s `struct xprt_ops`.
//!
//! # The leak this trait exists to seal
//!
//! `HAProxy`'s `xprt_ops` is a 25-method vtable implemented by `raw_sock` and `ssl_sock`,
//! and it is *almost* provider-agnostic. Sitting in the middle of it is:
//!
//! ```c
//! struct ssl_sock_ctx *(*get_ssl_sock_ctx)(struct connection *);
//! ```
//!
//! An OpenSSL-shaped type in the generic interface. Beyond that one method, the TLS
//! sample fetches (`ssl_fc_sni`, `ssl_fc_cipher`, `ssl_c_verify`, …) reach into provider
//! types directly. The abstraction is nominal rather than real, which is why supporting
//! `WolfSSL` and AWS-LC upstream has been such a long grind.
//!
//! **There is no equivalent escape hatch here.** Everything a caller might want from a
//! TLS session is reachable through [`TlsInfo`] as typed data, so a provider's own types
//! never cross the boundary. That is what makes carrying two providers at once
//! tractable rather than aspirational.

use std::io;

/// Which transport is in use. Reported by `show fd` and `show sess`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TransportKind {
    /// Plain sockets, no transformation.
    Raw,
    /// TLS via rustls.
    Rustls,
    /// TLS via OpenSSL / `BoringSSL`.
    OpenSsl,
}

/// Result of peer certificate verification.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VerifyResult {
    /// No client certificate was requested.
    NotRequested,
    /// A certificate was presented and verified.
    Ok,
    /// A certificate was presented and rejected. Carries the provider-neutral reason.
    Failed(VerifyError),
    /// A certificate was requested but none was presented.
    Missing,
}

/// Provider-neutral certificate rejection reasons.
///
/// `HAProxy` exposes `ssl_c_verify` as a raw OpenSSL error integer, which ties every
/// consumer to OpenSSL's error numbering. These are the cases `HAProxy`'s own
/// documentation actually distinguishes, named rather than numbered.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum VerifyError {
    Expired,
    NotYetValid,
    SelfSigned,
    UntrustedRoot,
    Revoked,
    HostnameMismatch,
    ChainTooLong,
    Other,
}

/// Everything a sample fetch, log format or ACL may learn about a TLS session.
///
/// This is the sealed replacement for `HAProxy`'s `get_ssl_sock_ctx` plus its provider-
/// specific fetches. Each method corresponds to a documented `ssl_*` sample fetch, so
/// the fetch layer is implemented against *this* rather than against a TLS library.
pub trait TlsInfo {
    /// `ssl_fc_sni` — server name requested by the client.
    fn sni(&self) -> Option<&str>;
    /// `ssl_fc_cipher` — negotiated cipher suite, IANA name.
    fn cipher(&self) -> Option<&str>;
    /// `ssl_fc_protocol` — negotiated protocol version, e.g. `"TLSv1.3"`.
    fn protocol_version(&self) -> Option<&str>;
    /// `ssl_fc_alpn` — negotiated ALPN protocol.
    fn alpn(&self) -> Option<&[u8]>;
    /// `ssl_fc_is_resumed` — whether the session was resumed.
    fn session_resumed(&self) -> bool;
    /// `ssl_c_verify` — peer certificate verification outcome.
    fn peer_verify(&self) -> VerifyResult;
    /// `ssl_c_s_dn` — peer certificate subject distinguished name.
    fn peer_subject_dn(&self) -> Option<&str>;
    /// `ssl_c_i_dn` — peer certificate issuer distinguished name.
    fn peer_issuer_dn(&self) -> Option<&str>;
    /// `ssl_c_notafter` — peer certificate expiry, seconds since the Unix epoch.
    fn peer_not_after(&self) -> Option<i64>;
    /// `ssl_fc_has_crt` — whether a peer certificate was presented at all.
    fn peer_has_cert(&self) -> bool;
}

/// Byte transport between the socket layer and the mux.
///
/// Stackable: `HAProxy` layers `xprt_handshake` above `raw_sock` for PROXY protocol and
/// removes it once the handshake completes. [`Transport::is_handshake_done`] is the
/// hook that supports the same pattern.
pub trait Transport {
    /// Per-connection state owned by this transport.
    type Ctx;

    fn kind(&self) -> TransportKind;

    /// Prepares per-connection state.
    ///
    /// # Errors
    /// Propagates provider setup failure.
    fn init(&self, fd: std::os::fd::RawFd, is_server: bool) -> io::Result<Self::Ctx>;

    /// Reads up to `buf.len()` bytes. `Ok(0)` means end of stream;
    /// [`io::ErrorKind::WouldBlock`] means not ready.
    ///
    /// # Errors
    /// Propagates transport read failures.
    fn recv(&self, ctx: &mut Self::Ctx, buf: &mut [u8]) -> io::Result<usize>;

    /// Writes as much of `buf` as it can.
    ///
    /// # Errors
    /// Propagates transport write failures.
    fn send(&self, ctx: &mut Self::Ctx, buf: &[u8]) -> io::Result<usize>;

    /// Drives a pending handshake. `Ok(true)` once complete.
    ///
    /// Classified [`alcyon_sched::Class::Heavy`] by the caller, because a TLS handshake
    /// is the canonical asymmetric-cost operation: cheap to request, expensive to
    /// serve. See `design/003-scheduler.md`.
    ///
    /// # Errors
    /// Propagates handshake failure.
    fn handshake(&self, ctx: &mut Self::Ctx) -> io::Result<bool>;

    fn is_handshake_done(&self, ctx: &Self::Ctx) -> bool;

    /// Shuts down the write direction.
    ///
    /// # Errors
    /// Propagates shutdown failure.
    fn shutdown_write(&self, ctx: &mut Self::Ctx) -> io::Result<()>;

    /// Releases per-connection state.
    fn close(&self, ctx: &mut Self::Ctx);

    /// TLS session facts, or `None` for transports that are not TLS.
    ///
    /// **This is the whole abstraction.** A provider's own types never appear here, so
    /// no consumer can become OpenSSL-shaped the way `HAProxy`'s sample fetches did.
    fn tls_info<'a>(&self, ctx: &'a Self::Ctx) -> Option<&'a dyn TlsInfo>;
}
