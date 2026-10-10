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
//!
//! On a reload the `bind` and `dgram-bind` sockets go to the new worker through `-x` /
//! `_getsocks` ([`crate::handover`]), as `HAProxy`'s do, and are bound with `SO_REUSEPORT`
//! when nothing was handed over; once the old worker is soft-stopping ([`soft_stop`]) its
//! listener threads stop taking messages and connections and close their sockets.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ibex_config::{Config, LogForwardBind, LogForwardHost, LogForwardSection};

use crate::handover::Kind;
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
        while read_frame(&mut r, self.assume_ntf, cap, &mut buf) {
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

/// Set by [`soft_stop`]: the listener threads leave, closing their sockets.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// How often a listener thread looks at [`STOPPING`].
const STOP_POLL: Duration = Duration::from_millis(200);

/// Soft stop (`SIGUSR1`): the log-forward listeners stop taking messages and connections
/// within [`STOP_POLL`] and close, as the proxies' listeners do. Without it a stopping
/// worker kept reading the sockets it shares with its successor and forwarded part of the
/// messages under the old configuration. Connections already accepted are served on.
pub fn soft_stop() {
    STOPPING.store(true, Ordering::Relaxed);
}

fn stopping() -> bool {
    STOPPING.load(Ordering::Relaxed)
}

/// Waits until `fd` is readable; `false` once the process is stopping.
fn wait_readable(fd: impl AsFd) -> bool {
    use rustix::event::{poll, PollFd, PollFlags};
    let timeout = i32::try_from(STOP_POLL.as_millis()).unwrap_or(200);
    while !stopping() {
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        if matches!(poll(&mut fds, timeout), Ok(n) if n > 0) {
            return true;
        }
    }
    false
}

/// A transient accept failure (the descriptor table full...) is retried after a pause
/// rather than in a spin.
fn accept_failed(e: &io::Error) {
    if !matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The sockets for one `dgram-bind` (`Kind::Udp`) or TCP `bind` (`Kind::Tcp`): what the old
/// process handed over, or one bound here with `SO_REUSEPORT`, so that a process started
/// without `-x` (`-sf` alone) can bind beside the old one. Each is exposed for the next
/// reload.
fn sockets(kind: Kind, addr: SocketAddr) -> io::Result<Vec<OwnedFd>> {
    use rustix::net::{self as net, sockopt, AddressFamily, SocketFlags, SocketType};
    let want = if kind == Kind::Udp { SocketType::DGRAM } else { SocketType::STREAM };
    let mut out: Vec<OwnedFd> = crate::handover::take_inherited_all(kind, addr)
        .into_iter()
        .filter(|fd| {
            sockopt::get_socket_type(fd).is_ok_and(|t| t == want)
                && (kind == Kind::Udp || sockopt::get_socket_acceptconn(fd).unwrap_or(false))
                && local_addr(fd) == Some(addr)
        })
        .collect();
    if out.is_empty() {
        let family = if addr.is_ipv4() { AddressFamily::INET } else { AddressFamily::INET6 };
        let fd = net::socket_with(family, want, SocketFlags::CLOEXEC, None)?;
        sockopt::set_socket_reuseaddr(&fd, true)?;
        sockopt::set_socket_reuseport(&fd, true)?;
        net::bind(&fd, &addr)?;
        if kind == Kind::Tcp {
            net::listen(&fd, 128)?;
        }
        out.push(fd);
    }
    for fd in &out {
        crate::handover::expose_kind(kind, addr, fd.as_fd())?;
    }
    Ok(out)
}

/// The address `fd` is bound to; `None` for a socket that is not an ip one (never
/// registered under an ip address, see `sockets`).
fn local_addr(fd: &OwnedFd) -> Option<SocketAddr> {
    use rustix::net::SocketAddrAny;
    let any = rustix::net::getsockname(fd).ok()?;
    if let SocketAddrAny::V4(a) = any {
        return Some(SocketAddr::V4(a));
    }
    let SocketAddrAny::V6(a) = any else { return None };
    Some(SocketAddr::V6(std::net::SocketAddrV6::new(*a.ip(), a.port(), 0, 0)))
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

/// One `dgram-bind` socket's thread: a message per datagram, until the soft stop.
fn serve_dgram(name: &str, sock: UdpSocket, fwd: Arc<Forwarder>) -> io::Result<()> {
    // Blocking with a timeout, so that the thread sees a soft stop.
    sock.set_nonblocking(false)?;
    sock.set_read_timeout(Some(STOP_POLL))?;
    spawn(&format!("logfwd-{name}"), move || {
        let mut buf = vec![0u8; 65536];
        while !stopping() {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => fwd.process(Some(from.ip()), &buf[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                Err(_) => break,
            }
        }
    })
}

/// One TCP `bind` socket's thread: accepts until the soft stop, a thread per connection.
fn serve_tcp(name: &str, listener: TcpListener, fwd: Arc<Forwarder>, tls: Option<Arc<rustls::ServerConfig>>) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    spawn(&format!("logfwd-{name}"), move || {
        while wait_readable(&listener) {
            let conn = match listener.accept() {
                Ok((c, _)) => c,
                Err(e) => {
                    accept_failed(&e);
                    continue;
                }
            };
            let Ok(()) = conn.set_nonblocking(false) else { continue };
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
    })
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
        let socks = sockets(Kind::Udp, *addr).map_err(|e| bind_error(&section.name, &addr.to_string(), &e))?;
        for fd in socks {
            serve_dgram(&section.name, UdpSocket::from(fd), Arc::clone(&fwd))?;
        }
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
                let socks = sockets(Kind::Tcp, b.addr).map_err(|e| bind_error(&section.name, &b.addr.to_string(), &e))?;
                for fd in socks {
                    serve_tcp(&section.name, TcpListener::from(fd), Arc::clone(&fwd), tls.clone())?;
                }
            }
            LogForwardBind::Unix { path, mode } => {
                let _ = std::fs::remove_file(path);
                let listener = UnixListener::bind(path).map_err(|e| bind_error(&section.name, path, &e))?;
                if let Some(m) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(*m))?;
                }
                listener.set_nonblocking(true)?;
                let fwd = Arc::clone(&fwd);
                spawn(&format!("logfwd-{}", section.name), move || {
                    while wait_readable(&listener) {
                        let conn = match listener.accept() {
                            Ok((c, _)) => c,
                            Err(e) => {
                                accept_failed(&e);
                                continue;
                            }
                        };
                        let Ok(()) = conn.set_nonblocking(false) else { continue };
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

/// Reads the next message of a syslog stream (RFC 6587) into `buf`: octet counting
/// (`<len> <message>`) when it starts with a digit, unless `assume_ntf`; otherwise up to
/// and including the LF. A message longer than `cap` bytes is refused. `false`: the stream
/// ended, failed, is malformed or too long, and the connection is dropped.
pub fn read_frame(r: &mut impl BufRead, assume_ntf: bool, cap: usize, buf: &mut Vec<u8>) -> bool {
    let first = match r.fill_buf() {
        Ok(b) if !b.is_empty() => b[0],
        _ => return false,
    };
    buf.clear();
    if !assume_ntf && first.is_ascii_digit() {
        // Octet counting: `<len> <message>`.
        let mut len = 0usize;
        let mut byte = [0u8; 1];
        loop {
            if r.read_exact(&mut byte).is_err() {
                return false;
            }
            match byte[0] {
                b' ' => break,
                c if c.is_ascii_digit() && len < 1 << 20 => len = len * 10 + usize::from(c - b'0'),
                _ => return false,
            }
        }
        if len > cap {
            return false;
        }
        buf.resize(len, 0);
        if r.read_exact(buf).is_err() {
            return false;
        }
    } else {
        // An error leaves nothing to forward: the next read ends the connection.
        let n = (&mut *r).take(cap as u64).read_until(b'\n', buf).unwrap_or(0);
        buf.truncate(n);
        if n >= cap && buf.last() != Some(&b'\n') {
            return false;
        }
    }
    true
}
