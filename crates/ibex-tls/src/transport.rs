// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! `RustlsTransport` implementing `ibex_proto::transport::Transport` and `TlsInfo`.
//!
//! Provides a pure memory-safe TLS transport layer under `#![forbid(unsafe_code)]`.
//! Non-blocking I/O is driven cleanly through pre-allocated in-memory ciphertext buffers.

use crate::arena::TlsSession;
use ibex_proto::transport::{TlsInfo, Transport, TransportKind, VerifyResult};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::io::{self, Cursor, Read, Write};
use std::os::fd::RawFd;
use std::sync::Arc;

/// Cached TLS session attributes implementing the sealed [`TlsInfo`] trait.
#[derive(Clone, Debug)]
pub struct RustlsTlsInfo {
    pub sni: Option<String>,
    pub cipher: Option<String>,
    pub protocol_version: Option<String>,
    pub alpn: Option<Vec<u8>>,
    pub session_resumed: bool,
    pub peer_verify: VerifyResult,
    pub peer_subject_dn: Option<String>,
    pub peer_issuer_dn: Option<String>,
    pub peer_not_after: Option<i64>,
    pub peer_has_cert: bool,
}

impl Default for RustlsTlsInfo {
    fn default() -> Self {
        Self {
            sni: None,
            cipher: None,
            protocol_version: None,
            alpn: None,
            session_resumed: false,
            peer_verify: VerifyResult::NotRequested,
            peer_subject_dn: None,
            peer_issuer_dn: None,
            peer_not_after: None,
            peer_has_cert: false,
        }
    }
}

impl TlsInfo for RustlsTlsInfo {
    fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    fn cipher(&self) -> Option<&str> {
        self.cipher.as_deref()
    }

    fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    fn session_resumed(&self) -> bool {
        self.session_resumed
    }

    fn peer_verify(&self) -> VerifyResult {
        self.peer_verify
    }

    fn peer_subject_dn(&self) -> Option<&str> {
        self.peer_subject_dn.as_deref()
    }

    fn peer_issuer_dn(&self) -> Option<&str> {
        self.peer_issuer_dn.as_deref()
    }

    fn peer_not_after(&self) -> Option<i64> {
        self.peer_not_after
    }

    fn peer_has_cert(&self) -> bool {
        self.peer_has_cert
    }
}

/// Per-connection context for [`RustlsTransport`].
#[derive(Debug)]
pub struct RustlsContext {
    pub fd: RawFd,
    pub is_server: bool,
    pub handshake_done: bool,
    pub session: Option<TlsSession>,
    pub client_sni: Option<String>,
    pub tls_info: RustlsTlsInfo,
    /// Pending incoming raw TLS wire ciphertext to feed into rustls.
    pub rx_raw: Vec<u8>,
    /// Pending outgoing raw TLS wire ciphertext produced by rustls to send over socket.
    pub tx_raw: Vec<u8>,
}

impl RustlsContext {
    /// Creates a new server-side TLS context.
    #[must_use]
    pub fn new_server(fd: RawFd, conn: ServerConnection) -> Self {
        Self {
            fd,
            is_server: true,
            handshake_done: false,
            session: Some(TlsSession::Server(conn)),
            client_sni: None,
            tls_info: RustlsTlsInfo {
                peer_verify: VerifyResult::NotRequested,
                ..Default::default()
            },
            rx_raw: Vec::with_capacity(16_384),
            tx_raw: Vec::with_capacity(16_384),
        }
    }

    /// Creates a new client-side TLS context.
    #[must_use]
    pub fn new_client(fd: RawFd, conn: ClientConnection, sni: Option<String>) -> Self {
        Self {
            fd,
            is_server: false,
            handshake_done: false,
            session: Some(TlsSession::Client(conn)),
            client_sni: sni,
            tls_info: RustlsTlsInfo {
                peer_verify: VerifyResult::NotRequested,
                ..Default::default()
            },
            rx_raw: Vec::with_capacity(16_384),
            tx_raw: Vec::with_capacity(16_384),
        }
    }

    /// Appends incoming encrypted wire data to `rx_raw`.
    pub fn feed_raw_input(&mut self, data: &[u8]) {
        self.rx_raw.extend_from_slice(data);
    }

    /// Drains and returns all outgoing encrypted wire data from `tx_raw`.
    pub fn take_raw_output(&mut self) -> Vec<u8> {
        let out = self.tx_raw.clone();
        self.tx_raw.clear();
        out
    }

    /// Returns the number of bytes waiting in the outgoing ciphertext queue.
    #[must_use]
    pub fn raw_output_len(&self) -> usize {
        self.tx_raw.len()
    }

    /// Updates cached [`TlsInfo`] metadata upon handshake completion.
    pub fn update_tls_info(&mut self) {
        match &self.session {
            Some(TlsSession::Server(conn)) => {
                self.tls_info.sni = conn.server_name().map(ToString::to_string);
                self.tls_info.cipher = conn
                    .negotiated_cipher_suite()
                    .and_then(|cs| cs.suite().as_str())
                    .map(ToString::to_string);
                self.tls_info.protocol_version = conn.protocol_version().map(|pv| match pv {
                    rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
                    rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
                    _ => format!("{pv:?}"),
                });
                self.tls_info.alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
                self.tls_info.session_resumed =
                    conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed);

                if let Some(certs) = conn.peer_certificates() {
                    self.tls_info.peer_has_cert = !certs.is_empty();
                    self.tls_info.peer_verify = if certs.is_empty() {
                        VerifyResult::Missing
                    } else {
                        VerifyResult::Ok
                    };
                } else {
                    self.tls_info.peer_has_cert = false;
                    self.tls_info.peer_verify = VerifyResult::NotRequested;
                }
            }
            Some(TlsSession::Client(conn)) => {
                self.tls_info.sni = self.client_sni.clone();
                self.tls_info.cipher = conn
                    .negotiated_cipher_suite()
                    .and_then(|cs| cs.suite().as_str())
                    .map(ToString::to_string);
                self.tls_info.protocol_version = conn.protocol_version().map(|pv| match pv {
                    rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
                    rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
                    _ => format!("{pv:?}"),
                });
                self.tls_info.alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
                self.tls_info.session_resumed =
                    conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed);

                if let Some(certs) = conn.peer_certificates() {
                    self.tls_info.peer_has_cert = !certs.is_empty();
                    self.tls_info.peer_verify = VerifyResult::Ok;
                } else {
                    self.tls_info.peer_has_cert = false;
                    self.tls_info.peer_verify = VerifyResult::NotRequested;
                }
            }
            None => {}
        }
    }
}

/// Pure memory-safe TLS transport implementation using `rustls 0.23`.
#[derive(Clone, Debug, Default)]
pub struct RustlsTransport {
    server_config: Option<Arc<ServerConfig>>,
    client_config: Option<Arc<ClientConfig>>,
    default_server_name: Option<ServerName<'static>>,
}

impl RustlsTransport {
    /// Creates a new transport with the provided server configuration.
    #[must_use]
    pub fn new_server(server_config: Arc<ServerConfig>) -> Self {
        Self {
            server_config: Some(server_config),
            client_config: None,
            default_server_name: None,
        }
    }

    /// Creates a new transport with the provided client configuration and default SNI name.
    #[must_use]
    pub fn new_client(client_config: Arc<ClientConfig>, server_name: ServerName<'static>) -> Self {
        Self {
            server_config: None,
            client_config: Some(client_config),
            default_server_name: Some(server_name),
        }
    }

    /// Creates a dual transport supporting both server and client configurations.
    #[must_use]
    pub fn new_dual(
        server_config: Option<Arc<ServerConfig>>,
        client_config: Option<Arc<ClientConfig>>,
        server_name: Option<ServerName<'static>>,
    ) -> Self {
        Self {
            server_config,
            client_config,
            default_server_name: server_name,
        }
    }
}

impl Transport for RustlsTransport {
    type Ctx = RustlsContext;

    fn kind(&self) -> TransportKind {
        TransportKind::Rustls
    }

    fn init(&self, fd: RawFd, is_server: bool) -> io::Result<Self::Ctx> {
        if is_server {
            let config = self.server_config.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Missing server TLS config")
            })?;
            let conn = ServerConnection::new(config).map_err(io::Error::other)?;
            Ok(RustlsContext::new_server(fd, conn))
        } else {
            let config = self.client_config.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Missing client TLS config")
            })?;
            let server_name = self.default_server_name.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Missing client server name")
            })?;
            let sni_str = match &server_name {
                ServerName::DnsName(dns) => Some(dns.as_ref().to_string()),
                ServerName::IpAddress(ip) => Some(format!("{ip:?}")),
                _ => None,
            };
            let conn = ClientConnection::new(config, server_name).map_err(io::Error::other)?;
            Ok(RustlsContext::new_client(fd, conn, sni_str))
        }
    }

    fn handshake(&self, ctx: &mut Self::Ctx) -> io::Result<bool> {
        if ctx.handshake_done {
            return Ok(true);
        }

        match &mut ctx.session {
            Some(TlsSession::Server(conn)) => {
                if !ctx.rx_raw.is_empty() {
                    let mut cursor = Cursor::new(&ctx.rx_raw);
                    let _ = conn.read_tls(&mut cursor);
                    #[allow(clippy::cast_possible_truncation)]
                    let consumed = cursor.position() as usize;
                    ctx.rx_raw.drain(..consumed);
                    let _ = conn
                        .process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                if conn.wants_write() {
                    let _ = conn.write_tls(&mut ctx.tx_raw);
                }
                if !conn.is_handshaking() {
                    ctx.handshake_done = true;
                    ctx.update_tls_info();
                    return Ok(true);
                }
            }
            Some(TlsSession::Client(conn)) => {
                if !ctx.rx_raw.is_empty() {
                    let mut cursor = Cursor::new(&ctx.rx_raw);
                    let _ = conn.read_tls(&mut cursor);
                    #[allow(clippy::cast_possible_truncation)]
                    let consumed = cursor.position() as usize;
                    ctx.rx_raw.drain(..consumed);
                    let _ = conn
                        .process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                if conn.wants_write() {
                    let _ = conn.write_tls(&mut ctx.tx_raw);
                }
                if !conn.is_handshaking() {
                    ctx.handshake_done = true;
                    ctx.update_tls_info();
                    return Ok(true);
                }
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "TLS session not initialized",
                ));
            }
        }

        Ok(ctx.handshake_done)
    }

    fn is_handshake_done(&self, ctx: &Self::Ctx) -> bool {
        ctx.handshake_done
    }

    fn recv(&self, ctx: &mut Self::Ctx, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !ctx.handshake_done {
            let _ = self.handshake(ctx)?;
            if !ctx.handshake_done {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        match &mut ctx.session {
            Some(TlsSession::Server(conn)) => {
                if !ctx.rx_raw.is_empty() {
                    let mut cursor = Cursor::new(&ctx.rx_raw);
                    let _ = conn.read_tls(&mut cursor);
                    #[allow(clippy::cast_possible_truncation)]
                    let consumed = cursor.position() as usize;
                    ctx.rx_raw.drain(..consumed);
                    let _ = conn
                        .process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                match conn.reader().read(buf) {
                    Ok(n) => Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                    Err(e) => Err(e),
                }
            }
            Some(TlsSession::Client(conn)) => {
                if !ctx.rx_raw.is_empty() {
                    let mut cursor = Cursor::new(&ctx.rx_raw);
                    let _ = conn.read_tls(&mut cursor);
                    #[allow(clippy::cast_possible_truncation)]
                    let consumed = cursor.position() as usize;
                    ctx.rx_raw.drain(..consumed);
                    let _ = conn
                        .process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                match conn.reader().read(buf) {
                    Ok(n) => Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                    Err(e) => Err(e),
                }
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TLS session closed",
            )),
        }
    }

    fn send(&self, ctx: &mut Self::Ctx, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !ctx.handshake_done {
            let _ = self.handshake(ctx)?;
            if !ctx.handshake_done {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        match &mut ctx.session {
            Some(TlsSession::Server(conn)) => {
                let written = conn.writer().write(buf)?;
                let _ = conn.write_tls(&mut ctx.tx_raw);
                Ok(written)
            }
            Some(TlsSession::Client(conn)) => {
                let written = conn.writer().write(buf)?;
                let _ = conn.write_tls(&mut ctx.tx_raw);
                Ok(written)
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TLS session closed",
            )),
        }
    }

    fn shutdown_write(&self, ctx: &mut Self::Ctx) -> io::Result<()> {
        match &mut ctx.session {
            Some(TlsSession::Server(conn)) => {
                conn.send_close_notify();
                let _ = conn.write_tls(&mut ctx.tx_raw);
                Ok(())
            }
            Some(TlsSession::Client(conn)) => {
                conn.send_close_notify();
                let _ = conn.write_tls(&mut ctx.tx_raw);
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn close(&self, ctx: &mut Self::Ctx) {
        ctx.session = None;
        ctx.rx_raw.clear();
        ctx.tx_raw.clear();
    }

    fn tls_info<'a>(&self, ctx: &'a Self::Ctx) -> Option<&'a dyn TlsInfo> {
        Some(&ctx.tls_info)
    }
}
