// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// Global section configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalSection {
    /// Number of worker threads.
    pub nbthread: Option<u32>,
    /// Runtime admin socket path.
    pub stats_socket: Option<String>,
    /// Permissions mode for admin socket.
    pub stats_socket_mode: Option<u32>,
    /// Privilege level for admin socket.
    pub stats_socket_level: Option<String>,
    /// `stats socket ... expose-fd listeners`: the socket may hand this process's listening
    /// sockets to a new process during a reload (`_getsocks`, `-x`).
    pub stats_socket_expose_fd: bool,
    /// Maximum rewrite size in bytes.
    pub maxrewrite: Option<usize>,
    /// Buffer size in bytes (`tune.bufsize`).
    pub bufsize: Option<usize>,
    /// Small buffer size in bytes (`tune.bufsize.small`).
    pub bufsize_small: Option<usize>,
    /// Large buffer size in bytes (`tune.bufsize.large`).
    pub bufsize_large: Option<usize>,
    /// Maximum total streams per HTTP/2 connection (`tune.h2.fe.max-total-streams`). Default: 0 (unlimited).
    pub h2_max_total_streams: Option<usize>,
    /// Glitches threshold before graceful GOAWAY and hard close (`tune.h2.fe.glitches-threshold`). Default: 0 (disabled).
    pub h2_glitches_threshold: Option<usize>,
    /// Global maximum connection limit.
    pub maxconn: Option<u32>,
    /// Background daemon mode.
    pub daemon: bool,
    /// Master-worker mode.
    pub master_worker: bool,
    /// User name for privilege dropping.
    pub user: Option<String>,
    /// Group name for privilege dropping.
    pub group: Option<String>,
    /// Chroot directory.
    pub chroot: Option<String>,
    /// Pidfile path.
    pub pidfile: Option<String>,
    /// Hard stop timeout on reload/exit.
    pub hard_stop_after: Option<Duration>,
    /// Max SSL connection limit.
    pub maxsslconn: Option<u32>,
    /// Default SSL bind ciphers.
    pub ssl_default_bind_ciphers: Option<String>,
    /// Default SSL bind options.
    pub ssl_default_bind_options: Option<String>,
    /// Default SSL server ciphers.
    pub ssl_default_server_ciphers: Option<String>,
    /// Default SSL server options.
    pub ssl_default_server_options: Option<String>,
    /// Syslog targets declared here. Proxy sections inherit these with `log global`,
    /// which is how the canonical `HAProxy` configuration declares logging.
    pub logs: Vec<LogConfig>,
    /// Global variables initialized at startup via `set-var` and `set-var-fmt`.
    pub set_vars: Vec<GlobalSetVar>,
    /// Global log tag (`log-tag`). Defaults to "haproxy".
    pub log_tag: Option<std::sync::Arc<str>>,
}

/// Global variable initialized at startup via `set-var` or `set-var-fmt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalSetVar {
    /// Variable name (e.g. `proc.foo`).
    pub name: String,
    /// Expression or format string.
    pub expr: String,
    /// Whether this variable uses format-string interpolation (`set-var-fmt`).
    pub is_fmt: bool,
}

