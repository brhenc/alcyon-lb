// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/log.c (syslog_fd_handler, syslog_io_handler,
// syslog_process_message).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `log-forward` sections: receive syslog messages and send each to the section's `log`
//! targets.
//!
//! `dgram-bind` listens on UDP, one message per datagram; `bind` listens on TCP (plain or
//! TLS) or a UNIX stream socket, where both framings of RFC 6587 are read: octet counting
//! (`<len> <message>`) when a message starts with a digit, a line feed otherwise. Every
//! message is taken apart (`loghdr::parse`) so that each target can write it under its own
//! `format`, or under the shape it arrived in when it has none. The listeners are threads:
//! logging is off the data path, and one blocked collector must not slow it.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ibex_config::{Config, LogForwardBind, LogForwardHost, LogForwardSection};

use crate::loghdr::{parse, Meta};
use crate::syslog::{facility_code, level_code, sample_admits, SyslogTarget};

/// A running section: what the listener threads share.
struct Forwarder {
    targets: Vec<SyslogTarget>,
    /// One sampling cursor per target (`syslog::sample_admits`).
    cursors: Vec<AtomicU64>,
    assume_ntf: bool,
    dont_parse: bool,
    host: LogForwardHost,
    maxconn: usize,
    conns: AtomicUsize,
    timeout: Option<Duration>,
}

impl Forwarder {
    /// Sends one received message to every target (`syslog_process_message`).
    fn process(&self, peer: Option<IpAddr>, raw: &[u8]) {
        // A trailing line feed or NUL is not part of the message (`__do_send_log`).
        let mut end = raw.len();
        while end > 0 && (raw[end - 1] == b'\n' || raw[end - 1] == 0) {
            end -= 1;
        }
        let msg = &raw[..end];
        let (mut level, mut facility, mut meta, mut text) = (-1i32, -1i32, Meta::default(), msg);
        if !self.dont_parse {
            let p = parse(msg);
            (level, facility, meta, text) = (p.level, p.facility, p.meta, p.text);
        }
        let src = peer.map(|ip| ip.to_string());
        let mut host = Vec::new();
        if let (Some(src), false) = (src.as_deref(), self.dont_parse) {
            match self.host {
                LogForwardHost::Keep => {}
                LogForwardHost::Replace => host.extend_from_slice(src.as_bytes()),
                LogForwardHost::Fill => {
                    if meta.host.is_empty() {
                        host.extend_from_slice(src.as_bytes());
                    }
                }
                LogForwardHost::Append => {
                    host.extend_from_slice(meta.host);
                    if !meta.host.is_empty() {
                        host.push(b',');
                    }
                    host.extend_from_slice(src.as_bytes());
                }
            }
            if !host.is_empty() {
                meta.host = &host;
            }
        }
        if text.is_empty() {
            return;
        }
        for (target, cursor) in self.targets.iter().zip(&self.cursors) {
            // A message with no priority has level -1, which no filter turns away.
            if level > i32::from(level_code(target.max_level())) {
                continue;
            }
            if let Some(sample) = target.sample() {
                if !sample_admits(sample, cursor) {
                    continue;
                }
            }
            let fac = u8::try_from(facility).unwrap_or_else(|_| facility_code(target.facility()));
            let _ = target.send_meta(u8::try_from(level.max(0)).unwrap_or(0), fac, &meta, text);
        }
    }

    /// Reads one connection's messages until it closes or goes idle.
    fn serve_stream(&self, stream: impl Read, peer: Option<IpAddr>) {
        let mut r = BufReader::new(stream);
        let mut buf = Vec::new();
        // A message is at most one buffer (`tune.bufsize`); a longer one ends the connection,
        // as it does in HAProxy (measured, T239).
        let cap = crate::buf::get_bufsize();
        loop {
            let first = match r.fill_buf() {
                Ok(b) if !b.is_empty() => b[0],
                _ => return,
            };
            buf.clear();
            if !self.assume_ntf && first.is_ascii_digit() {
                // Octet counting: `<len> <message>`.
                let mut len = 0usize;
                let mut byte = [0u8; 1];
                loop {
                    if r.read_exact(&mut byte).is_err() {
                        return;
                    }
                    match byte[0] {
                        b' ' => break,
                        c if c.is_ascii_digit() && len < 1 << 20 => len = len * 10 + usize::from(c - b'0'),
                        _ => return,
                    }
                }
                if len > cap {
                    return;
                }
                buf.resize(len, 0);
                if r.read_exact(&mut buf).is_err() {
                    return;
                }
            } else {
                // An error leaves nothing to forward: the next read ends the connection.
                let n = (&mut r).take(cap as u64).read_until(b'\n', &mut buf).unwrap_or(0);
                buf.truncate(n);
                if n >= cap && buf.last() != Some(&b'\n') {
                    return;
                }
            }
            self.process(peer, &buf);
        }
    }

    /// Takes a connection if the section has room (`maxconn`).
    fn admit(self: &Arc<Self>) -> Option<Admission> {
        if self.conns.fetch_add(1, Ordering::AcqRel) >= self.maxconn {
            self.conns.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Admission(Arc::clone(self)))
    }
}

/// A connection counted against `maxconn`, released when it is dropped.
struct Admission(Arc<Forwarder>);

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::AcqRel);
    }
}

fn started() -> &'static Mutex<HashSet<String>> {
    static S: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> io::Result<()> {
    std::thread::Builder::new().name(name.to_string()).spawn(f).map(|_| ())
}

/// Starts the rings and `log-forward` sections of `config`: the buffers exist, the listeners
/// are bound and their threads run. Called again with the same configuration (each worker
/// builds its engine from it) it does nothing.
///
/// # Errors
/// An unknown ring named by a `log` line, an address that cannot be bound, or an `ssl`
/// listener whose certificate cannot be loaded: the same things `HAProxy` refuses to start on.
pub fn start(config: &Config) -> io::Result<()> {
    for ring in &config.rings {
        crate::ring::start(ring);
    }
    check_ring_targets(config)?;
    check_debug_sinks(config)?;
    for section in &config.log_forwards {
        let key = format!("{section:?}");
        if !started().lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key) {
            continue;
        }
        start_section(config, section)?;
    }
    Ok(())
}

/// Every sink a `debug()` converter named while the configuration was read must exist
/// (`smp_check_debug`: "debug converter: sink 'x' doesn't exist."). It also points `debug()`
/// at the runtime's sinks.
///
/// # Errors
/// The first destination that is neither `stdout`, `stderr`, `buf0`, `dpapi` nor a `ring`.
pub fn check_debug_sinks(config: &Config) -> io::Result<()> {
    ibex_sample::set_debug_sink(crate::ring::debug_write);
    for dest in ibex_sample::take_debug_destinations() {
        if !crate::ring::sink_exists(&dest, &config.rings) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("debug converter: sink '{dest}' doesn't exist.")));
        }
    }
    Ok(())
}

/// A `log ring@x` line must name a `ring` section.
fn check_ring_targets(config: &Config) -> io::Result<()> {
    let mut logs: Vec<(&str, &ibex_config::LogConfig)> = Vec::new();
    if let Some(g) = &config.global {
        logs.extend(g.logs.iter().map(|l| ("global", l)));
    }
    if let Some(d) = &config.defaults {
        logs.extend(d.logs.iter().map(|l| ("defaults", l)));
    }
    for l in &config.listens {
        logs.extend(l.logs.iter().map(|c| (l.name.as_str(), c)));
    }
    for f in &config.frontends {
        logs.extend(f.logs.iter().map(|c| (f.name.as_str(), c)));
    }
    for b in &config.backends {
        logs.extend(b.logs.iter().map(|c| (b.name.as_str(), c)));
    }
    for lf in &config.log_forwards {
        logs.extend(lf.logs.iter().map(|c| (lf.name.as_str(), c)));
    }
    for (section, log) in logs {
        if let ibex_config::LogTarget::Ring(name) = &log.target {
            if !config.rings.iter().any(|r| r.name == *name) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("log directive declared in section '{section}' uses unknown ring named '{name}'."),
                ));
            }
        }
    }
    Ok(())
}

fn start_section(config: &Config, section: &LogForwardSection) -> io::Result<()> {
    let mut targets: Vec<SyslogTarget> = section.logs.iter().map(SyslogTarget::new).collect();
    if section.log_global {
        if let Some(g) = &config.global {
            targets.extend(g.logs.iter().map(SyslogTarget::new));
        }
    }
    let fwd = Arc::new(Forwarder {
        cursors: targets.iter().map(|_| AtomicU64::new(0)).collect(),
        targets,
        assume_ntf: section.assume_ntf,
        dont_parse: section.dont_parse,
        host: section.host,
        maxconn: section.maxconn as usize,
        conns: AtomicUsize::new(0),
        timeout: section.timeout_client,
    });
    for addr in &section.dgram_binds {
        let sock = UdpSocket::bind(addr).map_err(|e| bind_error(&section.name, &addr.to_string(), &e))?;
        let fwd = Arc::clone(&fwd);
        spawn(&format!("logfwd-{}", section.name), move || {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                fwd.process(Some(from.ip()), &buf[..n]);
            }
        })?;
    }
    for bind in &section.binds {
        match bind {
            LogForwardBind::Tcp(b) => {
                let tls = if b.ssl {
                    if b.crt.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("'{}': bind {} has 'ssl' but no 'crt'", section.name, b.addr),
                        ));
                    }
                    ibex_tls::install_default_crypto_provider();
                    let mut b = b.clone();
                    // A syslog stream has no application protocol to negotiate.
                    b.alpn = vec!["http/1.1".to_string()];
                    Some(ibex_tls::TlsConfig::from_bind_config(&b).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidInput, format!("'{}': bind {} ssl: {e}", section.name, b.addr))
                    })?)
                } else {
                    None
                };
                let listener = TcpListener::bind(b.addr).map_err(|e| bind_error(&section.name, &b.addr.to_string(), &e))?;
                let fwd = Arc::clone(&fwd);
                spawn(&format!("logfwd-{}", section.name), move || {
                    for conn in listener.incoming().flatten() {
                        let Some(slot) = fwd.admit() else { continue };
                        let (fwd, tls) = (Arc::clone(&fwd), tls.clone());
                        let _ = spawn("logfwd-conn", move || {
                            let _slot = slot;
                            let peer = conn.peer_addr().ok().map(|a| a.ip());
                            let _ = conn.set_read_timeout(fwd.timeout);
                            match tls {
                                Some(cfg) => {
                                    if let Ok(c) = rustls::ServerConnection::new(cfg) {
                                        fwd.serve_stream(rustls::StreamOwned::new(c, conn), peer);
                                    }
                                }
                                None => fwd.serve_stream(conn, peer),
                            }
                        });
                    }
                })?;
            }
            LogForwardBind::Unix { path, mode } => {
                let _ = std::fs::remove_file(path);
                let listener = UnixListener::bind(path).map_err(|e| bind_error(&section.name, path, &e))?;
                if let Some(m) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(*m))?;
                }
                let fwd = Arc::clone(&fwd);
                spawn(&format!("logfwd-{}", section.name), move || {
                    for conn in listener.incoming().flatten() {
                        let Some(slot) = fwd.admit() else { continue };
                        let fwd = Arc::clone(&fwd);
                        let _ = spawn("logfwd-conn", move || {
                            let _slot = slot;
                            let _ = conn.set_read_timeout(fwd.timeout);
                            fwd.serve_stream(conn, None);
                        });
                    }
                })?;
            }
        }
    }
    Ok(())
}

fn bind_error(section: &str, addr: &str, e: &io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("log-forward '{section}': cannot bind {addr}: {e}"))
}
