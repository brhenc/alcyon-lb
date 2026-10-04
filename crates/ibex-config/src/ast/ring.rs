// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `ring` and `log-forward` sections (`src/sink.c`, `src/log.c`).

use std::net::SocketAddr;
use std::time::Duration;

use super::{BindConfig, LogConfig};

/// The header a ring puts in front of each message (`log_formats` in `src/log.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingFormat {
    /// The text only; the default of a ring.
    Raw,
    Iso,
    Local,
    Rfc3164,
    Rfc5424,
    Short,
    Priority,
    Timed,
}

impl RingFormat {
    /// `get_log_format`: the name a `format` line gives.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "raw" => Self::Raw,
            "iso" => Self::Iso,
            "local" => Self::Local,
            "rfc3164" => Self::Rfc3164,
            "rfc5424" => Self::Rfc5424,
            "short" => Self::Short,
            "priority" => Self::Priority,
            "timed" => Self::Timed,
            _ => return None,
        })
    }
}

/// Where a ring's `server` line sends the events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingServerAddr {
    Tcp(SocketAddr),
    /// A UNIX stream socket.
    Unix(String),
}

/// A `server` line of a `ring` section: a syslog collector the ring is forwarded to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingServer {
    pub name: String,
    pub addr: RingServerAddr,
    /// `ssl`: the connection is TLS (`verify none` is the only verification supported).
    pub ssl: bool,
    /// `log-proto octet-count`: each event is sent as `<len> <event>` (RFC 6587) instead of
    /// being terminated by a line feed.
    pub octet_count: bool,
}

/// A `ring` section: an in-memory buffer of log events, readable with `show events` and
/// forwarded to its `server` lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingSection {
    pub name: String,
    pub description: Option<String>,
    pub format: RingFormat,
    /// `maxlen`: an event, header included, is cut to this length. `None`: not cut.
    pub maxlen: Option<usize>,
    /// `size`: the storage in bytes (`BUFSIZE`, 16384, by default).
    pub size: usize,
    pub timeout_connect: Duration,
    pub timeout_server: Duration,
    pub servers: Vec<RingServer>,
}

/// A `bind` line of a `log-forward` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogForwardBind {
    /// A TCP listener, plain or `ssl crt ...`.
    Tcp(BindConfig),
    /// A UNIX stream listener, with its `mode`.
    Unix { path: String, mode: Option<u32> },
}

/// A `log-forward` section: it receives syslog messages and sends each to its `log` targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogForwardSection {
    pub name: String,
    pub binds: Vec<LogForwardBind>,
    /// `dgram-bind`: UDP listeners.
    pub dgram_binds: Vec<SocketAddr>,
    pub logs: Vec<LogConfig>,
    /// `maxconn`: concurrent stream connections (10 by default).
    pub maxconn: u32,
    /// `timeout client`.
    pub timeout_client: Option<Duration>,
    /// `log global`: the `global` section's `log` lines are targets too.
    pub log_global: bool,
    /// `option assume-rfc6587-ntf`: a stream is always newline-framed.
    pub assume_ntf: bool,
    /// `option dont-parse-log`: messages are relayed without being parsed.
    pub dont_parse: bool,
    /// `option host`.
    pub host: LogForwardHost,
}

/// `option host` of a `log-forward` section: what the forwarded message's hostname field
/// becomes (`PR_O3_LOGF_HOST_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogForwardHost {
    Replace,
    /// The default.
    Fill,
    Keep,
    Append,
}
