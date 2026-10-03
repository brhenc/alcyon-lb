// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// The format a proxy's per-transaction log lines use: its own `log-format`, or one of
/// `HAProxy`'s defaults chosen by `option httplog` / `option tcplog` (with `clf`, the
/// Common Log Format variant). The last of these in a section wins, as in `HAProxy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFormatSpec {
    Custom(String),
    Http { clf: bool },
    Tcp { clf: bool },
}

/// `capture request header <name> len <n>` / `capture response header ...`: a slot whose
/// value `%hr`/`%hs` print and `capture.req.hdr(<n>)` fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderCapture {
    pub name: String,
    pub len: usize,
    /// Its index among the section's capture slots, which `capture request header` and
    /// `http-request capture` (without `id`) take in declaration order.
    pub slot: usize,
}

/// Syslog destination configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Where the lines go.
    pub target: LogTarget,
    /// Syslog facility.
    pub facility: LogFacility,
    /// Optional syslog log level.
    pub level: Option<LogLevel>,
    /// `len <n>`: maximum line length, truncated beyond it.
    ///
    /// `HAProxy` defaults to 1024 and accepts 80..=65535. A line longer than this is cut
    /// rather than split, because a syslog datagram has no continuation.
    pub max_len: usize,
    /// `format <fmt>`: the wire format, as written. Only `rfc3164` is emitted today.
    pub format: Option<String>,
    /// `sample <ranges>:<size>`: of every `size` lines, send those whose position
    /// (1-based) falls in one of `ranges`.
    pub sample: Option<Box<LogSample>>,
}

/// `log ... sample <ranges>:<size>` (`src/log.c`, `smp_log_range`).
///
/// The ranges are sorted and do not overlap, and the highest bound is at most `size`;
/// the parser refuses anything else, as `HAProxy` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSample {
    pub ranges: Vec<std::ops::RangeInclusive<u32>>,
    pub size: u32,
}

/// Where a `log` line sends its output.
///
/// `HAProxy` treats `stdout` and `stderr` as aliases for `fd@1` and `fd@2`
/// (`src/log.c`), which is how a container or a systemd unit collects logs without a
/// syslog daemon. Parsing them as an address rejected the canonical configuration -- it
/// accounted for 19 reg-test failures, all from one line in a shared include.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogTarget {
    /// A syslog server over UDP.
    Udp(SocketAddr),
    /// An already-open file descriptor: `fd@<n>`, `stdout`, `stderr`.
    Fd(i32),
    /// A unix datagram socket path.
    Unix(String),
}

impl LogTarget {
    /// The UDP address, if this is one. Used where only a network target makes sense.
    #[must_use]
    pub const fn udp_addr(&self) -> Option<SocketAddr> {
        match self {
            LogTarget::Udp(a) => Some(*a),
            _ => None,
        }
    }
}

/// Syslog facilities supported by `HAProxy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFacility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Auth2,
    Ftp,
    Ntp,
    Audit,
    Alert,
    Cron2,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

/// Syslog log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

