// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// A set of HTTP status codes (100..=599), as `http-err-codes` and `http-fail-codes` build it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusCodeSet([u64; 8]);

impl StatusCodeSet {
    /// No code at all.
    pub const EMPTY: Self = Self([0; 8]);
    const LOW: u16 = 100;
    const HIGH: u16 = 599;

    /// What `HAProxy` counts as an error without `http-err-codes`: 400 to 499.
    #[must_use]
    pub fn default_err() -> Self {
        let mut s = Self::default();
        s.apply(true, 400, 499);
        s
    }

    /// What `HAProxy` counts as a failure without `http-fail-codes`: 500 to 599 except 501 and 505.
    #[must_use]
    pub fn default_fail() -> Self {
        let mut s = Self::default();
        s.apply(true, 500, 599);
        s.apply(false, 501, 501);
        s.apply(false, 505, 505);
        s
    }

    #[must_use]
    pub fn contains(&self, code: u16) -> bool {
        (Self::LOW..=Self::HIGH).contains(&code) && self.0[usize::from(code - Self::LOW) / 64] & (1 << (usize::from(code - Self::LOW) % 64)) != 0
    }

    fn apply(&mut self, add: bool, lo: u16, hi: u16) {
        for code in lo..=hi {
            let (w, b) = (usize::from(code - Self::LOW) / 64, usize::from(code - Self::LOW) % 64);
            if add {
                self.0[w] |= 1 << b;
            } else {
                self.0[w] &= !(1 << b);
            }
        }
    }

    /// Applies one argument of `http-err-codes`/`http-fail-codes`, `[+-]{low[-{high}]}[,...]`
    /// (`http_parse_status_ranges`): the sign sticks along the comma list, and an element
    /// with no sign empties the set before adding its codes.
    ///
    /// # Errors
    /// The `HAProxy` message, without the `config : parsing [file:line] :` prefix.
    pub fn parse_arg(&mut self, kw: &str, arg: &str) -> Result<(), String> {
        let form = || format!("Ranges must be in the form [+-]{{low[-{{high}}]}}[,...].");
        let bytes = arg.as_bytes();
        let mut i = 0;
        let mut sign: Option<bool> = None;
        let bad_pos = |pos: usize| format!("Invalid status codes range '{arg}' in '{kw}' at position {pos}. {}", form());
        let num = |i: &mut usize| -> Option<u16> {
            let start = *i;
            while *i < bytes.len() && bytes[*i].is_ascii_digit() {
                *i += 1;
            }
            if *i == start {
                return None;
            }
            arg[start..*i].parse::<u16>().ok()
        };
        loop {
            let mut elem_sign = sign;
            if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                elem_sign = Some(bytes[i] == b'+');
                sign = elem_sign;
                i += 1;
            }
            let at = i;
            let Some(lo) = num(&mut i) else {
                return Err(bad_pos(at));
            };
            let mut hi = lo;
            if i < bytes.len() && bytes[i] == b'-' {
                i += 1;
                let at = i;
                hi = num(&mut i).ok_or_else(|| bad_pos(at))?;
            }
            if !(Self::LOW..=Self::HIGH).contains(&lo) || !(Self::LOW..=Self::HIGH).contains(&hi) || lo > hi {
                return Err(format!("Invalid status codes range '{arg}' in '{kw}'."));
            }
            match elem_sign {
                Some(add) => self.apply(add, lo, hi),
                None => {
                    self.0 = [0; 8];
                    self.apply(true, lo, hi);
                }
            }
            if i >= bytes.len() {
                return Ok(());
            }
            if bytes[i] != b',' {
                return Err(bad_pos(i));
            }
            i += 1;
        }
    }
}

/// A `stats socket` line after the first (the first fills [`GlobalSection::stats_socket`]
/// and its companions).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatsSocket {
    pub path: String,
    pub mode: Option<u32>,
    pub level: Option<String>,
    pub expose_fd: bool,
}

/// Global section configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalSection {
    /// `http-err-codes`: the statuses that count as an error (`http_err_cnt`), if set.
    pub http_err_codes: Option<StatusCodeSet>,
    /// `http-fail-codes`: the statuses that count as a failure (`http_fail_cnt`), if set.
    pub http_fail_codes: Option<StatusCodeSet>,
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
    /// `stats timeout`: how long a CLI connection may stay idle, on every stats socket
    /// (`HAProxy`'s CLI frontend `timeout client`, 10 s when unset).
    pub stats_timeout: Option<Duration>,
    /// The `stats socket` lines after the first, in order: `HAProxy` binds every one.
    pub extra_stats_sockets: Vec<StatsSocket>,
    /// Maximum rewrite size in bytes.
    pub maxrewrite: Option<usize>,
    /// `tune.idle-pool.shared off`: each worker takes only the idle server connections it
    /// released itself (the default, `on` or `full`, lets it take another worker's).
    pub idle_pool_unshared: bool,
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
    /// The version bounds `ssl-default-bind-options` sets: what a `bind` that names none gets.
    pub ssl_default_bind_versions: TlsRange,
    /// The version bounds `ssl-default-server-options` sets, for `server` lines.
    pub ssl_default_server_versions: TlsRange,
    /// Syslog targets declared here. Proxy sections inherit these with `log global`,
    /// which is how the canonical `HAProxy` configuration declares logging.
    pub logs: Vec<LogConfig>,
    /// Global variables initialized at startup via `set-var` and `set-var-fmt`.
    pub set_vars: Vec<GlobalSetVar>,
    /// `crt-base <dir>`: where a relative `crt` path of a `bind` or `server` is read.
    pub crt_base: Option<String>,
    /// `ca-base <dir>`: where a relative `ca-file` / `crl-file` path of a `server` is read.
    pub ca_base: Option<String>,
    /// `ssl-server-verify`: the `verify` of a `server` line that does not say; `None` is
    /// the keyword absent, which is `required`.
    pub ssl_server_verify: Option<crate::SslVerify>,
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

