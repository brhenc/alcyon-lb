// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/log.c (RFC 3164 emission) and doc/configuration.txt.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Syslog emission over UDP, RFC 3164 format.
//!
//! # Why UDP and why never fail
//!
//! HAProxy logs over UDP by default and treats logging as strictly best-effort: a
//! syslog collector that is slow, full or gone must not slow down or stall traffic.
//! Every send here is non-blocking and every error is discarded, deliberately. The one
//! thing a proxy must not do is block a request on a log write.
//!
//! The format is RFC 3164, which HAProxy emits by default:
//!
//! ```text
//! <PRI>MMM DD HH:MM:SS HOSTNAME TAG: MESSAGE
//! ```
//!
//! `PRI` is `facility * 8 + severity`, which is why both are carried per target rather
//! than being a single number.

use ibex_config::{LogConfig, LogFacility, LogLevel};
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
pub struct SyslogTarget {
    addr: SocketAddr,
    facility: LogFacility,
    /// Level used when a message does not carry its own.
    default_level: LogLevel,
    /// Minimum severity to emit. Messages less severe are dropped.
    ///
    /// `log <addr> <facility> <level>` in HAProxy sets a *maximum level* filter: only
    /// messages at that level or more severe are sent. Severity counts downward, so
    /// "more severe" means a smaller code.
    max_level: LogLevel,
    sock: Option<UdpSocket>,
}

impl SyslogTarget {
    /// Binds a sending socket for `cfg`.
    ///
    /// A bind failure is not fatal: the target is kept and simply never sends. Refusing
    /// to start because a log socket could not be created would make logging able to
    /// take down the proxy, which is the opposite of best-effort.
    #[must_use]
    pub fn new(cfg: &LogConfig) -> Self {
        let bind_addr = if cfg.addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = UdpSocket::bind(bind_addr).ok().and_then(|s| {
            s.set_nonblocking(true).ok()?;
            Some(s)
        });
        SyslogTarget {
            addr: cfg.addr,
            facility: cfg.facility,
            default_level: cfg.level.unwrap_or(LogLevel::Info),
            max_level: cfg.level.unwrap_or(LogLevel::Debug),
            sock,
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
    pub fn send(&self, level: LogLevel, tag: &str, hostname: &str, msg: &str) -> bool {
        if !self.accepts(level) {
            return false;
        }
        let Some(ref sock) = self.sock else { return false };
        let line = format_rfc3164(priority(self.facility, level), tag, hostname, msg);
        sock.send_to(line.as_bytes(), self.addr).is_ok()
    }

    /// Sends at this target's configured default level.
    pub fn send_default(&self, tag: &str, hostname: &str, msg: &str) -> bool {
        self.send(self.default_level, tag, hostname, msg)
    }

    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Formats an RFC 3164 line.
///
/// The timestamp is deliberately `MMM DD HH:MM:SS` with a space-padded day, which is
/// what the RFC specifies and what collectors parse positionally -- a zero-padded day
/// is a common and quietly incompatible mistake.
#[must_use]
pub fn format_rfc3164(pri: u8, tag: &str, hostname: &str, msg: &str) -> String {
    let (mon, day, h, m, s) = local_timestamp();
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon_name = MONTHS[(mon as usize).saturating_sub(1).min(11)];
    format!("<{pri}>{mon_name} {day:>2} {h:02}:{m:02}:{s:02} {hostname} {tag}: {msg}")
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
    let (h, m, s) = (
        u32::try_from(secs / 3600).unwrap_or(0),
        u32::try_from((secs % 3600) / 60).unwrap_or(0),
        u32::try_from(secs % 60).unwrap_or(0),
    );

    // Civil-from-days, Howard Hinnant's algorithm, shifted to a March-based year so
    // the leap day lands at the end and needs no special case.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let _ = era;
    (
        u32::try_from(mth).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
        h,
        m,
        s,
    )
}
