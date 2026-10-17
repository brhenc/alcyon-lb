// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/ring.c and src/sink.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `ring` sections: in-memory buffers of log events.
//!
//! A `log ring@<name> <facility>` line (`SyslogTarget`'s ring sink) writes each event, under
//! the ring's `format`, into the buffer; the newest events replace the oldest when it is
//! full. `show events <name>` dumps the buffer, and a `server` line makes a forwarder thread
//! stream the events to a syslog collector over TCP, TLS or a UNIX socket, reconnecting
//! when it drops.
//!
//! The write path takes one mutex and allocates nothing: the header is built in a
//! per-thread scratch buffer and the event is copied into storage reserved when the ring
//! was created.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use ibex_config::{RingFormat, RingSection, RingServer, RingServerAddr};

use crate::loghdr::{build_header, Meta};

/// The bytes a record costs on top of its text: its length, as 4 bytes.
const RECORD_OVERHEAD: usize = 4;

struct Store {
    data: VecDeque<u8>,
    /// The absolute offset (bytes ever stored) of `data[0]`.
    base: u64,
}

/// One ring: a section's buffer, its description and where it is forwarded.
pub struct Ring {
    pub name: String,
    pub description: String,
    format: RingFormat,
    /// An event, header included, is cut here; `usize::MAX` for no cut.
    maxlen: usize,
    size: usize,
    store: Mutex<Store>,
    news: Condvar,
}

thread_local! {
    /// The header of the event being written: reused, so a write allocates nothing once warm.
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

impl Ring {
    fn new(section: &RingSection) -> Self {
        Ring {
            name: section.name.clone(),
            description: section.description.clone().unwrap_or_else(|| section.name.clone()),
            format: section.format,
            maxlen: section.maxlen.unwrap_or(usize::MAX),
            size: section.size,
            store: Mutex::new(Store { data: VecDeque::with_capacity(section.size), base: 0 }),
            news: Condvar::new(),
        }
    }

    /// The header the events are written under (`format`).
    #[must_use]
    pub const fn format(&self) -> RingFormat {
        self.format
    }

    /// Writes one event: the header the ring's format asks for, then `text`.
    ///
    /// `logger_maxlen` is the `len` of the `log` line, of which one byte is kept back for the
    /// line feed a forwarder adds (`__do_send_log`). The event is cut to the shorter of that
    /// and the ring's `maxlen`; one that cannot fit the ring at all is dropped.
    pub fn write(&self, facility: u8, level: u8, meta: &Meta, logger_maxlen: usize, text: &[u8]) {
        SCRATCH.with(|scratch| {
            let mut hdr = scratch.borrow_mut();
            hdr.clear();
            if self.format != RingFormat::Raw {
                build_header(&mut hdr, Some(self.format), facility, level, meta);
            }
            let limit = self.maxlen.min(logger_maxlen.saturating_sub(1));
            let hlen = hdr.len().min(limit);
            let tlen = text.len().min(limit - hlen);
            self.push(&hdr[..hlen], &text[..tlen]);
        });
    }

    fn push(&self, head: &[u8], text: &[u8]) {
        let len = head.len() + text.len();
        let need = len + RECORD_OVERHEAD;
        if need > self.size {
            return;
        }
        let prefix = u32::try_from(len).unwrap_or(u32::MAX);
        let mut st = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Room is made by dropping whole records from the oldest end.
        while st.data.len() + need > self.size {
            let mut raw = [0u8; RECORD_OVERHEAD];
            for (i, b) in raw.iter_mut().enumerate() {
                *b = st.data[i];
            }
            let old = RECORD_OVERHEAD + u32::from_le_bytes(raw) as usize;
            st.data.drain(..old);
            st.base += old as u64;
        }
        st.data.extend(prefix.to_le_bytes());
        st.data.extend(head.iter().copied());
        st.data.extend(text.iter().copied());
        drop(st);
        self.news.notify_all();
    }

    /// The record at `*pos` (an absolute offset), advancing past it. A position the ring has
    /// since dropped moves to the oldest event.
    fn read_at(&self, st: &Store, pos: &mut u64) -> Option<Vec<u8>> {
        if *pos < st.base {
            *pos = st.base;
        }
        let at = usize::try_from(*pos - st.base).ok()?;
        if at >= st.data.len() {
            return None;
        }
        let mut raw = [0u8; RECORD_OVERHEAD];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = st.data[at + i];
        }
        let len = u32::from_le_bytes(raw) as usize;
        let start = at + RECORD_OVERHEAD;
        let rec: Vec<u8> = st.data.range(start..start + len).copied().collect();
        *pos += (RECORD_OVERHEAD + len) as u64;
        Some(rec)
    }

    /// Every event in the ring, oldest first, each followed by `delim`. With `sanitize`,
    /// blanks become a space and every other control or non-ASCII byte a `?`, so that
    /// captured data cannot steer a terminal (`ring_dump_*` with `APPCTX_FL_...`SANITIZE).
    #[must_use]
    pub fn dump(&self, delim: u8, sanitize: bool) -> Vec<u8> {
        let st = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::with_capacity(st.data.len());
        let mut pos = st.base;
        while let Some(rec) = self.read_at(&st, &mut pos) {
            if sanitize {
                out.extend(rec.iter().map(|&b| match b {
                    b' ' | b'\t' => b' ',
                    0x00..=0x1f | 0x7f..=0xff => b'?',
                    _ => b,
                }));
            } else {
                out.extend_from_slice(&rec);
            }
            out.push(delim);
        }
        out
    }

    /// Blocks until there is a record at `*pos`, and returns it.
    fn wait_next(&self, pos: &mut u64) -> Vec<u8> {
        let mut st = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(rec) = self.read_at(&st, pos) {
                return rec;
            }
            st = self.news.wait(st).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

type Registry = Mutex<Vec<(String, Arc<Ring>)>>;

fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
}

/// The built-in sinks `buf0` and `dpapi`: in-memory buffers that exist whatever the
/// configuration says, and that `debug()` writes to by default. Their events carry the
/// `timed` header (`<level>` and an ISO time), as `show events buf0` prints them.
fn builtin(name: &str) -> Option<&'static Arc<Ring>> {
    static B: OnceLock<[Arc<Ring>; 2]> = OnceLock::new();
    let rings = B.get_or_init(|| {
        let make = |name: &str, description: &str| {
            Arc::new(Ring::new(&RingSection {
                name: name.to_string(),
                description: Some(description.to_string()),
                format: RingFormat::Timed,
                maxlen: None,
                size: 16384,
                timeout_connect: Duration::from_secs(5),
                timeout_server: Duration::from_secs(5),
                servers: Vec::new(),
            }))
        };
        [make("buf0", "in-memory ring buffer"), make("dpapi", "DPAPI ring buffer")]
    });
    rings.iter().find(|r| r.name == name)
}

/// Whether `name` is a sink `debug()` can write to: `stdout`, `stderr`, a built-in buffer or
/// a `ring` of the configuration.
#[must_use]
pub fn sink_exists(name: &str, rings: &[RingSection]) -> bool {
    matches!(name, "stdout" | "stderr" | "buf0" | "dpapi") || rings.iter().any(|r| r.name == name)
}

/// `sink_write` of one `debug()` line to the sink `name` (nothing for a name that is none).
pub fn debug_write(name: &str, line: &[u8]) {
    match name {
        "stdout" | "stderr" => {
            let mut out = line.to_vec();
            out.push(b'\n');
            let _ = if name == "stdout" { io::stdout().write_all(&out) } else { io::stderr().write_all(&out) };
        }
        _ => {
            if let Some(r) = builtin(name).cloned().or_else(|| find(name)) {
                r.write(0, 0, &Meta::default(), usize::MAX, line);
            }
        }
    }
}

/// The ring named `name`.
#[must_use]
pub fn find(name: &str) -> Option<Arc<Ring>> {
    let reg = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.iter().find(|(_, r)| r.name == name).map(|(_, r)| Arc::clone(r))
}

/// Every ring, in the order the sections were read.
#[must_use]
pub fn all() -> Vec<Arc<Ring>> {
    let reg = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.iter().map(|(_, r)| Arc::clone(r)).collect()
}

/// Creates the ring of `section` and starts forwarding it to its servers. Called again with
/// the same section (every worker builds its engine from the same configuration) it does
/// nothing.
pub fn start(section: &RingSection) {
    let key = format!("{section:?}");
    let ring = {
        let mut reg = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if reg.iter().any(|(k, _)| *k == key) {
            return;
        }
        let ring = Arc::new(Ring::new(section));
        reg.retain(|(_, r)| r.name != section.name);
        reg.push((key, Arc::clone(&ring)));
        ring
    };
    for server in &section.servers {
        let (ring, server) = (Arc::clone(&ring), server.clone());
        let (connect, write) = (section.timeout_connect, section.timeout_server);
        let name = format!("ring-{}", section.name);
        let spawned = std::thread::Builder::new().name(name.clone()).spawn(move || forward(&ring, &server, connect, write));
        spawned.map(|_| ()).unwrap_or_else(|e| crate::stderr_line!("[ibex] {name}: cannot start the forwarder: {e}"));
    }
}

/// What a forwarder writes to.
type Out = Box<dyn Write + Send>;

/// A stream a forwarder can wrap in TLS.
trait Stream: io::Read + Write + Send {}
impl<T: io::Read + Write + Send> Stream for T {}

fn connect(server: &RingServer, connect_timeout: Duration, write_timeout: Duration) -> io::Result<Out> {
    let write_timeout = Some(write_timeout.max(Duration::from_millis(1)));
    // The stream, and the name a TLS handshake over it asks for.
    let (sock, sni): (Box<dyn Stream>, String) = match &server.addr {
        RingServerAddr::Tcp(addr) => {
            let s = TcpStream::connect_timeout(addr, connect_timeout.max(Duration::from_millis(1)))?;
            s.set_write_timeout(write_timeout)?;
            s.set_nodelay(true)?;
            (Box::new(s), addr.ip().to_string())
        }
        RingServerAddr::Unix(path) => {
            let s = UnixStream::connect(path)?;
            s.set_write_timeout(write_timeout)?;
            (Box::new(s), "localhost".to_string())
        }
    };
    if !server.ssl {
        return Ok(Box::new(sock));
    }
    let name = ibex_tls::parse_server_name(&sni).map_err(io::Error::other)?;
    Ok(Box::new(client_tls(sock, name)?))
}

/// A TLS client over `sock`. The only verification a ring server offers is `verify none`.
fn client_tls<S: io::Read + Write + Send + 'static>(
    sock: S,
    name: rustls::pki_types::ServerName<'static>,
) -> io::Result<rustls::StreamOwned<rustls::ClientConnection, S>> {
    ibex_tls::install_default_crypto_provider();
    let opts = ibex_tls::BackendTlsOptions { verify_required: false, ..ibex_tls::BackendTlsOptions::default() };
    let cfg = ibex_tls::build_backend_client_config(&opts).map_err(io::Error::other)?;
    let conn = rustls::ClientConnection::new(cfg, name).map_err(io::Error::other)?;
    Ok(rustls::StreamOwned::new(conn, sock))
}

/// The forwarder of one `server` line: connects, then writes every event the ring holds and
/// every one it receives, one per line (or length-prefixed with `log-proto octet-count`).
/// A broken connection is retried; the event that was in flight is sent again.
fn forward(ring: &Ring, server: &RingServer, connect_timeout: Duration, write_timeout: Duration) {
    let mut pos = 0u64;
    let mut pending: Option<Vec<u8>> = None;
    loop {
        let mut out = match connect(server, connect_timeout, write_timeout) {
            Ok(o) => o,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        loop {
            let rec = match pending.take() {
                Some(r) => r,
                None => ring.wait_next(&mut pos),
            };
            let mut frame = Vec::with_capacity(rec.len() + 8);
            if server.octet_count {
                frame.extend_from_slice(format!("{} ", rec.len()).as_bytes());
                frame.extend_from_slice(&rec);
            } else {
                frame.extend_from_slice(&rec);
                frame.push(b'\n');
            }
            if out.write_all(&frame).and_then(|()| out.flush()).is_err() {
                pending = Some(rec);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `show events [-0rswn] [<sink>]`'s arguments.
pub struct ShowEvents {
    pub sink: Option<String>,
    pub delim: u8,
    pub sanitize: bool,
    /// `-n`: start at the end of the ring, where there is nothing to show without `-w`.
    pub from_end: bool,
}

/// Parses what follows `show events`. `-w` (wait for more events) is refused: a CLI
/// session here answers a command once.
///
/// # Errors
/// An option this build does not have, or a second sink name.
pub fn parse_show_events(args: &[&str]) -> Result<ShowEvents, String> {
    let mut out = ShowEvents { sink: None, delim: b'\n', sanitize: false, from_end: false };
    for arg in args {
        if let Some(opts) = arg.strip_prefix('-') {
            for c in opts.chars() {
                match c {
                    '0' => out.delim = 0,
                    's' => out.sanitize = true,
                    'r' => out.sanitize = false,
                    // Seeks to the end: with no `-w` there is nothing to show.
                    'n' => out.from_end = true,
                    'w' => return Err("show events: option -w (wait for new events) is not implemented".to_string()),
                    other => return Err(format!("show events: unknown option -{other}")),
                }
            }
        } else if out.sink.is_some() {
            return Err("show events: only one sink may be dumped".to_string());
        } else {
            out.sink = Some((*arg).to_string());
        }
    }
    Ok(out)
}

/// The text `show events` answers with.
#[must_use]
pub fn show_events(args: &[&str]) -> Vec<u8> {
    let req = match parse_show_events(args) {
        Ok(r) => r,
        Err(e) => return format!("{e}\n").into_bytes(),
    };
    let Some(name) = req.sink else {
        let mut out = String::from(
            "Supported events sinks are listed below. Add combinations of -0(zero), -w(wait), -n(new), -r(raw), -s(anitize). Any key to stop.\n\
             \x20   stdout     : type=fd, 0 dropped, standard output (fd#1)\n\
             \x20   stderr     : type=fd, 0 dropped, standard output (fd#2)\n\
             \x20   buf0       : type=buffer, 0 dropped, in-memory ring buffer\n\
             \x20   dpapi      : type=buffer, 0 dropped, DPAPI ring buffer\n",
        );
        for r in all() {
            out.push_str(&format!("    {:<10} : type=buffer, 0 dropped, {}\n", r.name, r.description));
        }
        return out.into_bytes();
    };
    match builtin(&name).cloned().or_else(|| find(&name)) {
        Some(_) if req.from_end => Vec::new(),
        Some(r) => r.dump(req.delim, req.sanitize),
        None => format!("No such sink: {name}\n").into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(size: usize) -> RingSection {
        RingSection {
            name: "t".into(),
            description: None,
            format: RingFormat::Raw,
            maxlen: None,
            size,
            timeout_connect: Duration::from_secs(1),
            timeout_server: Duration::from_secs(1),
            servers: Vec::new(),
        }
    }

    fn put(r: &Ring, text: &[u8]) {
        r.write(16, 6, &Meta::default(), 1024, text);
    }

    #[test]
    fn the_newest_events_replace_the_oldest_when_the_ring_is_full() {
        let r = Ring::new(&section(40));
        for t in [&b"aaaaaaaa"[..], b"bbbbbbbb", b"cccccccc", b"dddddddd"] {
            put(&r, t);
        }
        // 12 bytes a record, 40 bytes: three fit.
        assert_eq!(r.dump(b'\n', false), b"bbbbbbbb\ncccccccc\ndddddddd\n");
    }

    #[test]
    fn an_event_longer_than_the_ring_is_dropped_and_maxlen_cuts() {
        let mut s = section(64);
        s.maxlen = Some(5);
        let r = Ring::new(&s);
        put(&r, b"0123456789");
        assert_eq!(r.dump(b'\n', false), b"01234\n");
        let tiny = Ring::new(&section(8));
        put(&tiny, b"0123456789");
        assert!(tiny.dump(b'\n', false).is_empty());
    }

    #[test]
    fn the_logger_len_keeps_a_byte_for_the_line_feed() {
        let r = Ring::new(&section(256));
        r.write(16, 6, &Meta::default(), 8, b"0123456789");
        assert_eq!(r.dump(b'\n', false), b"0123456\n");
    }

    #[test]
    fn sanitizing_blanks_to_a_space_and_everything_else_to_a_question_mark() {
        let r = Ring::new(&section(256));
        put(&r, b"A\x1b[2J\tB\nC\xaaD");
        assert_eq!(r.dump(b'\n', true), b"A?[2J B?C?D\n");
        assert_eq!(r.dump(0, false), b"A\x1b[2J\tB\nC\xaaD\0");
    }

    #[test]
    fn a_header_is_built_by_the_ring_format() {
        let mut s = section(256);
        s.format = RingFormat::Short;
        let r = Ring::new(&s);
        put(&r, b"hi");
        assert_eq!(r.dump(b'\n', false), b"<6>hi\n");
    }

    #[test]
    fn a_reader_that_fell_behind_resumes_at_the_oldest_event_the_ring_has_left() {
        let r = Ring::new(&section(40));
        for t in [&b"aaaaaaaa"[..], b"bbbbbbbb", b"cccccccc", b"dddddddd"] {
            put(&r, t);
        }
        let mut pos = 0;
        assert_eq!(r.wait_next(&mut pos), b"bbbbbbbb");
        assert_eq!(r.wait_next(&mut pos), b"cccccccc");
    }

    #[test]
    fn show_events_options() {
        assert!(parse_show_events(&["-n"]).expect("ok").from_end);
        assert!(parse_show_events(&["-w"]).is_err());
        assert!(parse_show_events(&["-x"]).is_err());
        assert!(parse_show_events(&["a", "b"]).is_err());
        let p = parse_show_events(&["-0s", "r"]).expect("ok");
        assert_eq!((p.delim, p.sanitize, p.sink.as_deref()), (0, true, Some("r")));
        let p = parse_show_events(&["-s", "-r", "r"]).expect("ok");
        assert!(!p.sanitize);
    }
}
