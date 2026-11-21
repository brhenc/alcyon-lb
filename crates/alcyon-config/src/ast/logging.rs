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
    /// `option httpslog`: `httplog` and the TLS fields.
    Https,
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
    /// The line of the `log` directive, for the startup check of a `profile` that does not
    /// exist (`log directive declared in proxy section 'fe' in file '...' at line 5 ...`).
    pub line: usize,
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
    /// `profile <name>`: the `log-profile` section whose per-step formats this target
    /// uses instead of the proxy's `log-format` at each step it names.
    pub profile: Option<String>,
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

/// `log-steps` bitmask flags for the five standard stream steps.
pub const LOG_STEP_ACCEPT: u8 = 0x01;
pub const LOG_STEP_REQUEST: u8 = 0x02;
pub const LOG_STEP_CONNECT: u8 = 0x04;
pub const LOG_STEP_RESPONSE: u8 = 0x08;
pub const LOG_STEP_CLOSE: u8 = 0x20;
pub const LOG_STEP_ALL: u8 = LOG_STEP_ACCEPT | LOG_STEP_REQUEST | LOG_STEP_CONNECT | LOG_STEP_RESPONSE | LOG_STEP_CLOSE;

/// The steps a `log-profile` names with `on <step>`, the seven `HAProxy` has always known
/// and the extra ones registered by the `do-log` actions (`src/log.c`, `log_orig_register`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogProfileStepKind {
    Accept,
    Request,
    Connect,
    Response,
    Close,
    Error,
    Any,
    HttpReq,
    HttpRes,
    HttpAfterRes,
    TcpReqConn,
    TcpReqSess,
    TcpReqCont,
    TcpResCont,
}

impl LogProfileStepKind {
    /// `HAProxy`'s spelling, as it is checked against the `on` argument and printed in the
    /// error for a name it does not know.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Request => "request",
            Self::Connect => "connect",
            Self::Response => "response",
            Self::Close => "close",
            Self::Error => "error",
            Self::Any => "any",
            Self::HttpReq => "http-req",
            Self::HttpRes => "http-res",
            Self::HttpAfterRes => "http-after-res",
            Self::TcpReqConn => "tcp-req-conn",
            Self::TcpReqSess => "tcp-req-sess",
            Self::TcpReqCont => "tcp-req-cont",
            Self::TcpResCont => "tcp-res-cont",
        }
    }

    /// The name `%OG` prints for a line emitted from this origin
    /// (`src/log.c`, `log_orig_to_str`): the five transaction steps as `txn_<step>`,
    /// `error` as `sess_error`, and the `do-log` extras as their registered names.
    pub const fn og_name(self) -> &'static str {
        match self {
            Self::Accept => "txn_accept",
            Self::Request => "txn_request",
            Self::Connect => "txn_connect",
            Self::Response => "txn_response",
            Self::Close => "txn_close",
            Self::Error => "sess_error",
            Self::Any => "any",
            Self::HttpReq => "http-req",
            Self::HttpRes => "http-res",
            Self::HttpAfterRes => "http-after-res",
            Self::TcpReqConn => "tcp-req-conn",
            Self::TcpReqSess => "tcp-req-sess",
            Self::TcpReqCont => "tcp-req-cont",
            Self::TcpResCont => "tcp-res-cont",
        }
    }

    /// The steps in the order the `on` error lists them: the seven first, then the extras
    /// in the order their `do-log` actions register them (`http_act.c`, then `tcp_act.c`).
    pub const ALL: [Self; 14] = [
        Self::Accept,
        Self::Request,
        Self::Connect,
        Self::Response,
        Self::Close,
        Self::Error,
        Self::Any,
        Self::HttpReq,
        Self::HttpRes,
        Self::HttpAfterRes,
        Self::TcpReqConn,
        Self::TcpReqSess,
        Self::TcpReqCont,
        Self::TcpResCont,
    ];
}

/// One `on <step> [drop] [format <fmt>] [sd <sd_fmt>]` line of a `log-profile`
/// (`src/log.c`, `cfg_parse_log_profile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogProfileStep {
    pub step: LogProfileStepKind,
    /// `drop`: nothing is sent for this step.
    pub drop: bool,
    /// `format <fmt>`: the line for this step, as written.
    pub format: Option<String>,
    /// `sd <sd_fmt>`: the STRUCTURED-DATA of this step's line.
    pub sd: Option<String>,
}

/// A `log-profile` section: a named set of per-step formats a `log ... profile <name>`
/// line uses (`doc/configuration.txt`, "log-profile <name>").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogProfileSection {
    pub name: String,
    /// The line the section was declared at, for the duplicate-name error.
    pub line: usize,
    /// The `log-tag` line: overrides the tag for every step this profile is used for.
    pub log_tag: Option<String>,
    /// The `on` lines, in the order written. A step named twice keeps both: `HAProxy`
    /// re-parses the step, so the later `format`/`sd` replace the earlier and `drop` is
    /// whatever the combined lines leave.
    pub steps: Vec<LogProfileStep>,
    /// Every `format` and `sd` string parsed in this section (with its 1-based line),
    /// including lines later replaced by another `on <step>`, so load-time validation
    /// compiles all of them as `HAProxy`'s `cfg_parse_log_profile` does.
    pub format_strings: Vec<(usize, String)>,
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
    /// `ring@<name>`: the events go into that `ring` section's buffer.
    Ring(String),
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

#[cfg(test)]
mod tests {
    use super::LogProfileStepKind;

    #[test]
    fn every_step_kind_has_non_empty_name_and_og_name() {
        for kind in LogProfileStepKind::ALL {
            assert!(!kind.name().is_empty());
            assert!(!kind.og_name().is_empty());
        }
        assert_eq!(LogProfileStepKind::Any.og_name(), "any");
        assert_eq!(LogProfileStepKind::TcpResCont.og_name(), "tcp-res-cont");
    }
}

