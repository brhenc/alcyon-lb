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

use ibex_config::{LogConfig, LogFacility, LogLevel, LogTarget};
use std::net::{SocketAddr, UdpSocket};

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
    /// The process's own standard output.
    Stdout,
    /// The process's own standard error.
    Stderr,
    /// Configured but unwritable: `fd@<n>` for some other descriptor, or a unix socket
    /// path. Lines are dropped rather than sent somewhere they were not addressed to.
    ///
    /// Writing to an arbitrary inherited descriptor needs `BorrowedFd::borrow_raw`, which
    /// is unsafe, and this crate forbids unsafe. `stdout` and `stderr` are the cases that
    /// matter -- they are how a container or systemd unit collects logs -- and they have
    /// safe accessors. Supporting the rest means either inheriting the descriptor through
    /// a typed owner at startup or relaxing the crate's rule, and neither is worth doing
    /// speculatively.
    Discard,
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
}

impl SyslogTarget {
    /// Binds a sending socket for `cfg`.
    ///
    /// A bind failure is not fatal: the target is kept and simply never sends. Refusing
    /// to start because a log socket could not be created would make logging able to
    /// take down the proxy, which is the opposite of best-effort.
    #[must_use]
    pub fn new(cfg: &LogConfig) -> Self {
        let sink = match &cfg.target {
            LogTarget::Udp(addr) => {
                let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                let sock = UdpSocket::bind(bind_addr).ok().and_then(|s| {
                    s.set_nonblocking(true).ok()?;
                    Some(s)
                });
                Sink::Udp(*addr, sock)
            }
            LogTarget::Fd(1) => Sink::Stdout,
            LogTarget::Fd(2) => Sink::Stderr,
            LogTarget::Fd(other) => {
                eprintln!(
                    "[ibex] warning: log target fd@{other} is not supported; only \
                     stdout (fd@1), stderr (fd@2) and a syslog address are written"
                );
                Sink::Discard
            }
            LogTarget::Unix(path) => {
                eprintln!(
                    "[ibex] warning: log target '{path}' is a unix socket, which is not \
                     implemented; these lines are dropped"
                );
                Sink::Discard
            }
        };
        SyslogTarget {
            facility: cfg.facility,
            default_level: cfg.level.unwrap_or(LogLevel::Info),
            max_level: cfg.level.unwrap_or(LogLevel::Debug),
            max_len: cfg.max_len,
            sink,
        }
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
    pub fn send(&self, level: LogLevel, tag: &str, hostname: &str, msg: &str) -> bool {
        if !self.accepts(level) {
            return false;
        }
        let mut line = format_rfc3164(priority(self.facility, level), tag, hostname, msg);
        if line.len() > self.max_len {
            // On a char boundary, so the result is still a valid line rather than a
            // partial UTF-8 sequence a collector will reject.
            let mut cut = self.max_len;
            while cut > 0 && !line.is_char_boundary(cut) {
                cut -= 1;
            }
            line.truncate(cut);
        }
        match &self.sink {
            Sink::Udp(addr, Some(sock)) => sock.send_to(line.as_bytes(), *addr).is_ok(),
            // A UDP target whose socket would not bind, and anything configured but
            // unwritable. Both drop the line; neither is worth a separate arm.
            Sink::Udp(_, None) | Sink::Discard => false,
            // A newline terminates the record: a descriptor is a stream, so unlike a
            // datagram there is no frame boundary to mark the end of the line.
            // Flushed on every line. Rust's stdout is block-buffered when it is a pipe,
            // which is exactly how a supervisor or container runtime collects it, so
            // without this the logs appear in 8 KiB bursts or not at all before a
            // restart. A log nobody sees until the buffer fills is not a log.
            //
            // One `write` per line either way: the flush pushes the same bytes the
            // write_all just buffered, and a syslog line is far below any coalescing
            // worth having.
            Sink::Stdout => {
                line.push('\n');
                let mut out = std::io::stdout().lock();
                std::io::Write::write_all(&mut out, line.as_bytes()).is_ok()
                    && std::io::Write::flush(&mut out).is_ok()
            }
            Sink::Stderr => {
                line.push('\n');
                let mut out = std::io::stderr().lock();
                std::io::Write::write_all(&mut out, line.as_bytes()).is_ok()
                    && std::io::Write::flush(&mut out).is_ok()
            }
        }
    }

    /// Sends at this target's configured default level.
    #[must_use]
    pub fn send_default(&self, tag: &str, hostname: &str, msg: &str) -> bool {
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
            (Sink::Stdout, LogTarget::Fd(1)) | (Sink::Stderr, LogTarget::Fd(2)) => true,
            _ => false,
        }
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
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let (month, day, hour, minute, second) = local_timestamp();
    let month_name = MONTHS[(month as usize).saturating_sub(1).min(11)];
    format!(
        "<{pri}>{month_name} {day:>2} {hour:02}:{minute:02}:{second:02} \
         {hostname} {tag}: {msg}"
    )
}

/// Civil time from the system clock: (month, day, hour, minute, second).
///
/// Computed directly rather than pulled in as a dependency; the proxy needs no more
/// calendar than this, and `chrono` would be a large addition for one format string.
fn local_timestamp() -> (u32, u32, u32, u32, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86_400;
    let secs = now % 86_400;
    let hour = u32::try_from(secs / 3600).unwrap_or(0);
    let minute = u32::try_from((secs % 3600) / 60).unwrap_or(0);
    let second = u32::try_from(secs % 60).unwrap_or(0);

    // Civil-from-days, Howard Hinnant's algorithm, shifted to a March-based year so
    // the leap day lands at the end and needs no special case.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let _ = era; // the year is not part of an RFC 3164 timestamp
    (
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
        hour,
        minute,
        second,
    )
}
