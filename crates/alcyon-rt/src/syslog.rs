// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/log.c (RFC 3164 emission) and doc/configuration.txt.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Syslog emission over UDP, RFC 3164 format.
//!
//! # Why UDP and why never fail
//!
//! `HAProxy` logs over UDP by default and treats logging as strictly best-effort: a
//! syslog collector that is slow, full or gone must not slow down or stall traffic.
//! Every send here is non-blocking and every error is discarded, deliberately. The one
//! thing a proxy must not do is block a request on a log write.
//!
//! The format is RFC 3164, which `HAProxy` emits by default:
//!
//! ```text
//! <PRI>MMM DD HH:MM:SS HOSTNAME TAG: MESSAGE
//! ```
//!
//! `PRI` is `facility * 8 + severity`, which is why both are carried per target rather
//! than being a single number.

use alcyon_config::{LogConfig, LogFacility, LogLevel, LogSample, LogTarget, RingFormat};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::os::fd::AsFd;
use std::sync::Arc;

use crate::loghdr::{build_header, Meta};
use crate::ring::Ring;

/// Lines that could not be written because the descriptor was full (`DroppedLogs`).
static DROPPED_LOGS: AtomicU64 = AtomicU64::new(0);

/// Total lines dropped for want of room in `stdout`/`stderr`, as `show info` reports it.
#[must_use]
pub fn dropped_logs() -> u64 {
    DROPPED_LOGS.load(Ordering::Relaxed)
}

/// Writes `line` (which already ends with its line feed) to fd 1 or 2 without ever blocking.
///
/// `HAProxy` (`fd_write_frag_line`) makes the descriptor `O_NONBLOCK` the first time it
/// writes to it, unless it is a terminal, and drops a line it cannot write, counting it in
/// `DroppedLogs`. A reader that stalls (journald, a container log driver, `^S`) must never
/// stall a worker. One `write(2)`: a line within `PIPE_BUF` is never interleaved with
/// another thread's.
pub(crate) fn write_fd_nonblocking(fd: i32, line: &[u8]) -> bool {
    use std::io::IsTerminal;
    use std::sync::atomic::AtomicU8;
    // Bit 0 / bit 1: fd 1 / fd 2 has been set non-blocking (or is a terminal).
    static PREPARED: AtomicU8 = AtomicU8::new(0);
    let (out, err) = (std::io::stdout(), std::io::stderr());
    let (bit, owned) = if fd == 2 { (2, err.as_fd()) } else { (1, out.as_fd()) };
    if PREPARED.load(Ordering::Relaxed) & bit == 0 {
        let tty = if fd == 2 { std::io::stderr().is_terminal() } else { std::io::stdout().is_terminal() };
        // A terminal keeps its flags (set back unchanged); anything else becomes non-blocking.
        let extra = if tty { rustix::fs::OFlags::empty() } else { rustix::fs::OFlags::NONBLOCK };
        let _ = rustix::fs::fcntl_getfl(owned).and_then(|f| rustix::fs::fcntl_setfl(owned, f | extra));
        PREPARED.fetch_or(bit, Ordering::Relaxed);
    }
    let res = rustix::io::write(owned, line);
    // Only a full descriptor is a drop; EPIPE and the like are the reader's choice.
    DROPPED_LOGS.fetch_add(u64::from(res == Err(rustix::io::Errno::AGAIN)), Ordering::Relaxed);
    res.is_ok_and(|n| n > 0)
}

/// Writes one runtime diagnostic line (`eprintln!`'s bytes: the message and one line feed) to fd 2 and never panics, whatever state fd 2 is in.
///
/// `log stderr` makes fd 2 `O_NONBLOCK` (see [`write_fd_nonblocking`]); `eprintln!` then
/// panics on `EAGAIN` ("failed printing to stderr") and the crash hook aborts the process.
/// `HAProxy` simply loses a message it cannot write. A message that does not fit is dropped
/// and counted in `DroppedLogs`, as a log line is; `EPIPE` and the like are the reader's
/// choice and drop it silently. Does not change the descriptor's flags.
pub fn eprint_line(args: std::fmt::Arguments<'_>) {
    use std::fmt::Write as _;
    let mut text = String::new();
    let _ = text.write_fmt(args);
    text.push('\n'); // exactly one, as eprintln! does: a message ending in "\n" keeps its blank line
    let mut rest = text.as_bytes();
    let fd = std::io::stderr();
    while !rest.is_empty() {
        match rustix::io::retry_on_intr(|| rustix::io::write(fd.as_fd(), rest)) {
            Ok(n) if n > 0 => rest = &rest[n..],
            res => {
                DROPPED_LOGS.fetch_add(u64::from(res == Err(rustix::io::Errno::AGAIN)), Ordering::Relaxed);
                return;
            }
        }
    }
}

/// `eprintln!` for anything that can run once `log stderr` has made fd 2 non-blocking:
/// writes through [`eprint_line`], so a full stderr drops the message instead of panicking.
#[macro_export]
macro_rules! stderr_line {
    ($($arg:tt)*) => { $crate::syslog::eprint_line(format_args!($($arg)*)) };
}

/// Sends `line` to the unix datagram socket at `path` (`@name`: the abstract namespace).
fn send_unix(sock: &UnixDatagram, path: &str, line: &[u8]) -> bool {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr as UnixAddr;
    match path.strip_prefix('@') {
        Some(name) => UnixAddr::from_abstract_name(name).and_then(|a| sock.send_to_addr(line, &a)).is_ok(),
        None => sock.send_to(line, path).is_ok(),
    }
}

/// Splits the `name[pid]` tag the engine hands over into its two header fields.
fn split_tag(tag: &str) -> (&str, &str) {
    match tag.strip_suffix(']').and_then(|t| t.rsplit_once('[')) {
        Some((name, pid)) => (name, pid),
        None => (tag, ""),
    }
}

/// Numeric facility code, as RFC 3164 defines them.
#[must_use]
pub const fn facility_code(f: LogFacility) -> u8 {
    match f {
        LogFacility::Kern => 0,
        LogFacility::User => 1,
        LogFacility::Mail => 2,
        LogFacility::Daemon => 3,
        LogFacility::Auth => 4,
        LogFacility::Syslog => 5,
        LogFacility::Lpr => 6,
        LogFacility::News => 7,
        LogFacility::Uucp => 8,
        LogFacility::Cron => 9,
        LogFacility::Auth2 => 10,
        LogFacility::Ftp => 11,
        LogFacility::Ntp => 12,
        LogFacility::Audit => 13,
        LogFacility::Alert => 14,
        LogFacility::Cron2 => 15,
        LogFacility::Local0 => 16,
        LogFacility::Local1 => 17,
        LogFacility::Local2 => 18,
        LogFacility::Local3 => 19,
        LogFacility::Local4 => 20,
        LogFacility::Local5 => 21,
        LogFacility::Local6 => 22,
        LogFacility::Local7 => 23,
    }
}

/// Numeric severity code.
#[must_use]
pub const fn level_code(l: LogLevel) -> u8 {
    match l {
        LogLevel::Emerg => 0,
        LogLevel::Alert => 1,
        LogLevel::Crit => 2,
        LogLevel::Err => 3,
        LogLevel::Warning => 4,
        LogLevel::Notice => 5,
        LogLevel::Info => 6,
        LogLevel::Debug => 7,
    }
}

/// `PRI` value: facility shifted above severity.
#[must_use]
pub const fn priority(f: LogFacility, l: LogLevel) -> u8 {
    facility_code(f) * 8 + level_code(l)
}

/// One configured syslog destination.
/// Where a target writes.
///
/// `HAProxy` supports both a syslog server and an already-open descriptor, and the second
/// is what a container or systemd unit uses -- there is no syslog daemon to talk to, and
/// the supervisor collects stdout. Sending those lines to 127.0.0.1:514 instead means
/// they go nowhere at all.
enum Sink {
    /// A syslog server over UDP.
    Udp(SocketAddr, Option<UdpSocket>),
    /// A syslog daemon's unix datagram socket (`log /dev/log local0`): the path as written
    /// (`@name` is an abstract one), and the socket the lines leave from.
    Unix(String, Option<UnixDatagram>),
    /// The process's own standard output.
    Stdout,
    /// The process's own standard error.
    Stderr,
    /// A `ring` section's buffer (`ring@<name>`).
    Ring(Arc<Ring>),
    /// Configured but unwritable: `fd@<n>` for some other descriptor. Lines are dropped rather than sent somewhere they were not addressed to.
    ///
    /// Writing to an arbitrary inherited descriptor needs `BorrowedFd::borrow_raw`, which
    /// is unsafe, and this crate forbids unsafe. `stdout` and `stderr` are the cases that
    /// matter -- they are how a container or systemd unit collects logs -- and they have
    /// safe accessors. Supporting the rest means either inheriting the descriptor through
    /// a typed owner at startup or relaxing the crate's rule, and neither is worth doing
    /// speculatively.
    Discard,
}

/// A `log-profile` resolved for a target: its `on <step>` lines with compiled formats,
/// looked up per log step at send time. A target keeps one only when a `log` line named a
/// profile, so a proxy without profiles holds none and pays nothing for them.
pub struct ResolvedProfile {
    /// The profile's name, as written on the `log` line: targets are interned by it, so two
    /// `log` lines naming different profiles are different loggers even at one collector.
    pub name: String,
    /// The profile's `log-tag`, which overrides the tag of every line it sends.
    pub log_tag: Option<String>,
    /// The profile's `on` lines, in the order written.
    pub steps: Vec<ResolvedStep>,
}

/// One `on <step> [drop] [format <fmt>] [sd <sd_fmt>]` line, its formats compiled once.
pub struct ResolvedStep {
    pub step: alcyon_config::ast::logging::LogProfileStepKind,
    pub drop: bool,
    pub format: Option<Arc<crate::logfmt::LogFormat>>,
    pub sd: Option<Arc<crate::logfmt::LogFormat>>,
}

/// How a profile resolves a log step.
pub enum StepResolution<'p> {
    /// No profile, no matching step (and no `on any`), or a step with neither `format` nor
    /// `sd`: the proxy's own line stands.
    Normal,
    /// The step says `drop`: send nothing.
    Drop,
    /// The step's `format` and/or `sd` replace the proxy's line's message and/or
    /// structured data.
    Override {
        format: Option<&'p crate::logfmt::LogFormat>,
        sd: Option<&'p crate::logfmt::LogFormat>,
    },
}

impl ResolvedProfile {
    /// The step for `origin`: the one named after it, else `on any`.
    pub fn resolve(&self, origin: alcyon_config::ast::logging::LogProfileStepKind) -> StepResolution<'_> {
        use alcyon_config::ast::logging::LogProfileStepKind as K;
        let step = self
            .steps
            .iter()
            .find(|s| s.step == origin)
            .or_else(|| self.steps.iter().find(|s| s.step == K::Any));
        match step {
            Some(s) if s.drop => StepResolution::Drop,
            Some(s) if s.format.is_some() || s.sd.is_some() => StepResolution::Override {
                format: s.format.as_deref(),
                sd: s.sd.as_deref(),
            },
            _ => StepResolution::Normal,
        }
    }
}

pub struct SyslogTarget {
    facility: LogFacility,
    /// Level used when a message does not carry its own.
    default_level: LogLevel,
    /// Minimum severity to emit. Messages less severe are dropped.
    ///
    /// `log <addr> <facility> <level>` in `HAProxy` sets a *maximum level* filter: only
    /// messages at that level or more severe are sent. Severity counts downward, so
    /// "more severe" means a smaller code.
    max_level: LogLevel,
    /// `len <n>`: lines longer than this are truncated, not split. A syslog datagram has
    /// no continuation, so a split line is two malformed records rather than one long one.
    max_len: usize,
    sink: Sink,
    /// `sample <ranges>:<size>`. Which lines it keeps depends on a cursor that belongs to
    /// each proxy, not to the target: see [`sample_admits`].
    sample: Option<Box<LogSample>>,
    /// `format <fmt>`: the header the line is written under. `None` lets the message's own
    /// fields choose it (`LOG_FORMAT_UNSPEC`).
    format: Option<RingFormat>,
    /// `profile <name>`: the resolved `log-profile` the line is sent under, or `None` when
    /// the `log` line named no profile. `Box`ed so a target without a profile holds eight
    /// bytes, not the profile's tables.
    profile: Option<Box<ResolvedProfile>>,
}

impl SyslogTarget {
    /// Binds a sending socket for `cfg`.
    ///
    /// A bind failure is not fatal: the target is kept and simply never sends. Refusing
    /// to start because a log socket could not be created would make logging able to
    /// take down the proxy, which is the opposite of best-effort.
    ///
    /// `profile` is the `log-profile` the `log` line named, already looked up by the caller;
    /// its `on` formats are compiled here, once.
    #[must_use]
    pub fn new(cfg: &LogConfig, profile: Option<&alcyon_config::ast::logging::LogProfileSection>) -> Self {
        let sink = match &cfg.target {
            LogTarget::Udp(addr) => {
                let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                let sock = UdpSocket::bind(bind_addr).ok().and_then(|s| {
                    s.set_nonblocking(true).ok()?;
                    Some(s)
                });
                Sink::Udp(*addr, sock)
            }
            LogTarget::Ring(name) => match crate::ring::find(name) {
                Some(r) => Sink::Ring(r),
                None => {
                    crate::stderr_line!("[alcyon] warning: log target ring@{name} names no ring section; these lines are dropped");
                    Sink::Discard
                }
            },
            LogTarget::Fd(1) => Sink::Stdout,
            LogTarget::Fd(2) => Sink::Stderr,
            LogTarget::Fd(other) => {
                crate::stderr_line!(
                    "[alcyon] warning: log target fd@{other} is not supported; only \
                     stdout (fd@1), stderr (fd@2) and a syslog address are written"
                );
                Sink::Discard
            }
            LogTarget::Unix(path) => {
                let sock = UnixDatagram::unbound().ok().and_then(|s| {
                    s.set_nonblocking(true).ok()?;
                    Some(s)
                });
                Sink::Unix(path.clone(), sock)
            }
        };
        SyslogTarget {
            facility: cfg.facility,
            default_level: cfg.level.unwrap_or(LogLevel::Info),
            max_level: cfg.level.unwrap_or(LogLevel::Debug),
            max_len: cfg.max_len,
            sink,
            sample: cfg.sample.clone(),
            format: cfg.format.as_deref().and_then(RingFormat::from_name),
            profile: profile.map(|p| Box::new(Self::resolve_profile(p))),
        }
    }

    /// Compiles a `log-profile`'s step formats once, into the target's resolved copy.
    fn resolve_profile(p: &alcyon_config::ast::logging::LogProfileSection) -> ResolvedProfile {
        ResolvedProfile {
            name: p.name.clone(),
            // `syslog_tag` format (`<name>[<pid>]`) so `split_tag` preserves the process
            // PID when `log-profile` overrides the tag (`hdr.metadata[LOG_META_TAG]`).
            log_tag: p.log_tag.as_deref().map(|t| format!("{t}[{}]", std::process::id())),
            steps: p
                .steps
                .iter()
                .map(|s| ResolvedStep {
                    step: s.step,
                    drop: s.drop,
                    format: s.format.as_deref().map(Self::compile_format).flatten(),
                    sd: s.sd.as_deref().map(Self::compile_format).flatten(),
                })
                .collect(),
        }
    }

    /// Compiles a profile step's `format`/`sd`, once. A step format that does not compile
    /// keeps its step but sends the proxy's line, the way a proxy whose own `log-format`
    /// will not compile keeps logging nothing.
    fn compile_format(fmt: &str) -> Option<Arc<crate::logfmt::LogFormat>> {
        crate::logfmt::LogFormat::compile(fmt, crate::engine::sample_registry()).ok().map(Arc::new)
    }

    /// True if a message at `level` passes this target's filter.
    #[must_use]
    pub fn accepts(&self, level: LogLevel) -> bool {
        level_code(level) <= level_code(self.max_level)
    }

    /// Sends one message. Errors are intentionally discarded.
    ///
    /// Returns whether the datagram was handed to the kernel, which is useful in tests
    /// but is not a delivery guarantee -- UDP never gives one.
    #[must_use]
    pub fn send(&self, level: LogLevel, tag: &str, hostname: &str, msg: impl AsRef<[u8]>) -> bool {
        self.send_sd(level, tag, hostname, b"", msg.as_ref())
    }

    /// [`SyslogTarget::send`] with the line's STRUCTURED-DATA (`log-format-sd`), which only
    /// an rfc5424 header writes; empty is `-`.
    #[must_use]
    pub fn send_sd(&self, level: LogLevel, tag: &str, hostname: &str, sd: &[u8], msg: &[u8]) -> bool {
        if !self.accepts(level) {
            return false;
        }
        let (name, pid) = split_tag(tag);
        let meta = Meta { host: hostname.as_bytes(), tag: name.as_bytes(), pid: pid.as_bytes(), stdata: sd, ..Meta::default() };
        self.deliver(level_code(level), facility_code(self.facility), &meta, msg)
    }

    /// True when the lines sent here have a STRUCTURED-DATA field: `format rfc5424`, or a
    /// ring whose format is.
    #[must_use]
    pub fn writes_sd(&self) -> bool {
        match &self.sink {
            Sink::Ring(r) => r.format() == RingFormat::Rfc5424,
            _ => self.format == Some(RingFormat::Rfc5424),
        }
    }

    /// Sends a message that carries its own header fields, as a `log-forward` section does:
    /// the line is written under this target's `format`, or the one `meta` calls for.
    /// The level filter and sampling are the caller's.
    #[must_use]
    pub fn send_meta(&self, level: u8, facility: u8, meta: &Meta, msg: &[u8]) -> bool {
        self.deliver(level, facility, meta, msg)
    }

    fn deliver(&self, level: u8, facility: u8, meta: &Meta, msg: &[u8]) -> bool {
        match &self.sink {
            Sink::Ring(ring) => {
                ring.write(facility, level, meta, self.max_len, msg);
                true
            }
            // A UDP target whose socket would not bind, and anything configured but
            // unwritable.
            Sink::Discard | Sink::Udp(_, None) | Sink::Unix(_, None) => false,
            Sink::Unix(path, Some(sock)) => self.with_line(level, facility, meta, msg, |line| send_unix(sock, path, line)),
            Sink::Udp(addr, Some(sock)) => self.with_line(level, facility, meta, msg, |line| sock.send_to(line, *addr).is_ok()),
            // A descriptor is a stream, so unlike a datagram there is no frame boundary to mark
            // the end of the line: a newline terminates the record.
            // Flushed on every line. Rust's stdout is block-buffered when it is a pipe, which is
            // exactly how a supervisor or container runtime collects it, so without this the logs
            // appear in 8 KiB bursts or not at all before a restart. A log nobody sees until the
            // buffer fills is not a log.
            Sink::Stdout => self.with_line(level, facility, meta, msg, |line| write_fd_nonblocking(1, line)),
            Sink::Stderr => self.with_line(level, facility, meta, msg, |line| write_fd_nonblocking(2, line)),
        }
    }

    /// Builds the line (header, then the message cut to `len`) in the per-thread buffer and
    /// hands it to `f`.
    fn with_line<R>(&self, level: u8, facility: u8, meta: &Meta, msg: &[u8], f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
        // The line being built is a `scratch_bytes` buffer: sending one allocates nothing once warm.
        crate::reuse::with_bytes(|line| {
            build_header(line, self.format, facility, level, meta);
            line.extend_from_slice(msg);
            // The datagram or line ends with a line feed that `len` counts
            // (measured on 3.5-dev8-885761-29: `len 80` sends 79 bytes and `\n`).
            line.truncate(self.max_len.saturating_sub(1));
            // One line feed, not two for a forwarded message that came with its own (measured:
            // `HAProxy` forwards `hello` and `hello\n` alike as `hello\n`).
            if line.last() != Some(&b'\n') { line.push(b'\n'); }
            f(line)
        })
    }

    /// Sends at this target's configured default level.
    #[must_use]
    pub fn send_default(&self, tag: &str, hostname: &str, msg: impl AsRef<[u8]>) -> bool {
        self.send(self.default_level, tag, hostname, msg)
    }

    /// The facility this target stamps into each message's PRI.
    ///
    /// Exposed so the engine can recognise two configured targets as the same collector
    /// and share one socket between them.
    /// True when two configured targets would write to the same place.
    ///
    /// Used to intern targets so one collector gets one socket, and so `stdout` named by
    /// two sections is written through one sink rather than two interleaving partial
    /// lines into the same descriptor.
    #[must_use]
    pub fn same_destination(&self, cfg: &LogConfig) -> bool {
        if self.facility != cfg.facility {
            return false;
        }
        match (&self.sink, &cfg.target) {
            (Sink::Udp(a, _), LogTarget::Udp(b)) => a == b,
            (Sink::Unix(a, _), LogTarget::Unix(b)) => a == b,
            (Sink::Stdout, LogTarget::Fd(1)) | (Sink::Stderr, LogTarget::Fd(2)) => true,
            (Sink::Ring(r), LogTarget::Ring(n)) => r.name == *n,
            _ => false,
        }
    }

    /// True when `cfg` is this target in every respect: destination, filters, length,
    /// sampling and profile. Only such a target may be shared between two `log` lines; one
    /// that differed in level or `sample` would apply the first line's settings to both.
    #[must_use]
    pub fn same_logger(&self, cfg: &LogConfig) -> bool {
        self.same_destination(cfg)
            && self.default_level == cfg.level.unwrap_or(LogLevel::Info)
            && self.max_level == cfg.level.unwrap_or(LogLevel::Debug)
            && self.max_len == cfg.max_len
            && self.sample == cfg.sample
            && self.format == cfg.format.as_deref().and_then(RingFormat::from_name)
            && self.profile.as_ref().map(|p| p.name.as_str()) == cfg.profile.as_deref()
    }

    /// The `sample` setting, if any.
    /// The most verbose level this target takes (its `log` line's `<level>`).
    #[must_use]
    pub const fn max_level(&self) -> LogLevel {
        self.max_level
    }

    #[must_use]
    pub fn sample(&self) -> Option<&LogSample> {
        self.sample.as_deref()
    }

    /// The `log-profile` the line is sent under, `None` when the `log` line named none.
    #[must_use]
    pub fn profile(&self) -> Option<&ResolvedProfile> {
        self.profile.as_deref()
    }

    #[must_use]
    pub const fn facility(&self) -> LogFacility {
        self.facility
    }

    /// The UDP address, for targets that have one.
    #[must_use]
    pub const fn addr(&self) -> Option<SocketAddr> {
        match &self.sink {
            Sink::Udp(a, _) => Some(*a),
            // Not a network target: stdout, stderr, and anything configured but
            // unwritable.
            _ => None,
        }
    }
}

/// Formats an RFC 3164 line.
///
/// The timestamp is deliberately `MMM DD HH:MM:SS` with a space-padded day, which is
/// what the RFC specifies and what collectors parse positionally -- a zero-padded day
/// is a common and quietly incompatible mistake.
#[must_use]
pub fn format_rfc3164(pri: u8, tag: &str, hostname: &str, msg: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    // Local time, as `HAProxy` prints it (`localtime_r`).
    let c = crate::localtime::Civil::local(now);
    // The hostname only when there is one: `HAProxy` sends none unless
    // `log-send-hostname` is set.
    let sep = if hostname.is_empty() { "" } else { " " };
    format!(
        "<{pri}>{} {:>2} {:02}:{:02}:{:02} {hostname}{sep}{tag}: {msg}",
        c.month_name(),
        c.day,
        c.hour,
        c.minute,
        c.second
    )
}

/// Whether the next line passes `sample`, advancing `cursor` (`process_send_log`,
/// `src/log.c`).
///
/// The cursor holds the current range in its high 32 bits and the position of the last
/// line within `size` in its low 32, exactly as `HAProxy`'s `lb.curr_rg_idx` does, and is
/// advanced with a compare-and-swap so threads sharing it agree on every line's position.
/// `HAProxy` keeps one per logger *per proxy* (`log global` and `defaults` copy the
/// logger), so the caller owns it, not the target.
pub fn sample_admits(sample: &LogSample, cursor: &AtomicU64) -> bool {
    // The parser never builds these; a hand-built one samples nothing out.
    if sample.ranges.is_empty() || sample.size == 0 {
        return true;
    }
    let mut cur = cursor.load(Ordering::Relaxed);
    loop {
        let next_idx = (cur & 0xFFFF_FFFF) + 1;
        let mut rg = cur >> 32;
        let range = &sample.ranges[usize::try_from(rg).unwrap_or(0) % sample.ranges.len()];
        let in_range = u64::from(*range.start()) <= next_idx && next_idx <= u64::from(*range.end());
        if in_range && next_idx == u64::from(*range.end()) {
            rg = (rg + 1) % sample.ranges.len() as u64;
        }
        let next = (rg << 32) | (next_idx % u64::from(sample.size));
        match cursor.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return in_range,
            Err(seen) => cur = seen,
        }
    }
}

#[cfg(test)]
mod local_time_tests {
    use super::format_rfc3164;
    use crate::localtime::Civil;

    /// The header's time is local, as `HAProxy`'s is (`localtime_r`): it printed
    /// `Oct  3 16:46:00` on a host in +0200 while UTC read 14:46.
    #[test]
    fn the_header_carries_local_time() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
        let line = format_rfc3164(134, "t", "h", "m");
        let c = Civil::local(now);
        let want = format!("<134>{} {:>2} {:02}:{:02}", c.month_name(), c.day, c.hour, c.minute);
        // A minute may turn between the two clock reads; the hour and date may not.
        assert!(line.starts_with(&want[..want.len() - 3]), "{line:?} vs {want:?}");
    }

    /// Without `log-send-hostname` `HAProxy` puts no hostname in the header:
    /// `<134>Oct  3 16:46:00 lt[1589592]: A r=...`.
    #[test]
    fn no_hostname_means_none_in_the_header() {
        let line = format_rfc3164(134, "lt[7]", "", "m");
        // The tag follows the time (`HH:MM:SS `) directly.
        let at = line.find("lt[7]: m").expect("tag");
        assert!(line.as_bytes()[at - 1] == b' ' && line.as_bytes()[at - 2].is_ascii_digit(), "{line:?}");
    }
}

/// Writes to stderr without blocking and counting a drop, for the master relaying a worker's
/// stderr and its own messages (`bin/alcyon/master.rs`): a stalled stderr must not stall the
/// thread that drains the worker's pipe, and through it the worker.
pub fn write_stderr_nonblocking(line: &[u8]) -> bool {
    write_fd_nonblocking(2, line)
}
