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
/// `tune.vars.*-max-size` and `tune.vars.from-map.max`: `unsigned int` in `HAProxy` (src/vars.c),
/// 0 for no limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VarsLimits {
    pub global: u32,
    pub proc_: u32,
    pub sess: u32,
    pub txn: u32,
    pub reqres: u32,
    pub check: u32,
    /// `tune.vars.from-map.max`; `set-vars-from-map` is refused by the parser, so nothing reads it yet.
    pub from_map_max: u32,
}

/// Where `ibex.debug.panic` makes a stream's run panic (T447): when a request whose path
/// starts with `path` has its head parsed, or, with `at_response`, has its response head;
/// `under_lock`: while holding a shared lock, which the panic poisons.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DebugPanic {
    pub at_response: bool,
    pub under_lock: bool,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatsSocket {
    /// The unix socket path; for the other forms, [`StatsAddr::name`].
    pub path: String,
    /// What the socket listens on.
    pub addr: StatsAddr,
    pub mode: Option<u32>,
    pub level: Option<String>,
    pub expose_fd: bool,
}

/// What a `stats socket` listens on (`str2sa_range`, src/tools.c, with the forms Ibex serves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsAddr {
    /// A unix socket file (`/path`, `unix@path`, `uxst@path`).
    Unix(String),
    /// A Linux abstract socket: `abns@name` binds the name zero-padded to the whole
    /// `sun_path`, as `HAProxy` does; `abnsz@name` (`padded == false`) binds it as written.
    Abstract { name: String, padded: bool },
    /// A TCP listener (`ipv4@`, `ipv6@`, `tcp@`, `ip@`, `host:port`).
    Tcp(std::net::SocketAddr),
}

impl Default for StatsAddr {
    fn default() -> Self {
        Self::Unix(String::new())
    }
}

impl StatsAddr {
    /// The name `HAProxy`'s `show cli sockets` prints for it: `unix@/p`, `abns@n` (for
    /// `abnsz@` too), `ipv4@1.2.3.4:5`, `ipv6@[::1]:5`.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Unix(p) => format!("unix@{p}"),
            Self::Abstract { name, .. } => format!("abns@{name}"),
            Self::Tcp(a @ std::net::SocketAddr::V4(_)) => format!("ipv4@{a}"),
            Self::Tcp(a @ std::net::SocketAddr::V6(_)) => format!("ipv6@{a}"),
        }
    }
}

/// Global section configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalSection {
    /// `node <name>`: the name `show info` and the stats page report (`global.node`); `None` is the host name.
    pub node: Option<String>,
    /// `description <text>`: `show info`'s `description` and the stats page's `show-desc` text (`global.desc`).
    pub description: Option<String>,
    /// `h1-case-adjust` and `h1-case-adjust-file`: `(from, to)` pairs in the order given, `from`
    /// unique (`add_hdr_case_adjust`).
    pub h1_case_adjust: Vec<(String, String)>,
    /// `http-err-codes`: the statuses that count as an error (`http_err_cnt`), if set.
    pub http_err_codes: Option<StatusCodeSet>,
    /// `http-fail-codes`: the statuses that count as a failure (`http_fail_cnt`), if set.
    pub http_fail_codes: Option<StatusCodeSet>,
    /// Number of worker threads.
    pub nbthread: Option<u32>,
    /// Runtime admin socket path (for a TCP or abstract socket, [`StatsAddr::name`]).
    pub stats_socket: Option<String>,
    /// What the first `stats socket` listens on; set whenever `stats_socket` is.
    pub stats_socket_addr: Option<StatsAddr>,
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
    /// `stats maxconn`: how many CLI connections are served at once, on every stats socket
    /// (10 when unset, `HAProxy`'s default).
    pub stats_maxconn: Option<u32>,
    /// The `stats socket` lines after the first, in order: `HAProxy` binds every one.
    pub extra_stats_sockets: Vec<StatsSocket>,
    /// Maximum rewrite size in bytes.
    pub maxrewrite: Option<usize>,
    /// `ibex.debug.panic <request|response> <path-prefix>`: a test-only fault (T447), accepted
    /// only in builds with `debug_assertions`.
    pub debug_panic: Option<DebugPanic>,
    /// `tune.maxaccept`: how many connections one listener wakeup accepts in a row before
    /// the thread goes back to its other work; `-1` (any negative) is no limit, `0` the
    /// default (`HAProxy`'s `MAX_ACCEPT`, 4; Ibex: no limit, `docs/differences.md`). The
    /// first one set stays (`HAProxy` warns on a second and continues).
    pub maxaccept: Option<i32>,
    /// `tune.idle-pool.shared off`: each worker takes only the idle server connections it
    /// released itself (the default, `on` or `full`, lets it take another worker's).
    pub idle_pool_unshared: bool,
    /// `no strict-limits`: when the soft limit on open files cannot be raised to `maxsock`,
    /// warn and run with the hard limit instead of refusing to start (`strict-limits`, the
    /// default).
    pub no_strict_limits: bool,
    /// `tune.pool-high-fd-ratio`: the percentage of `maxsock` in use past which no released
    /// server connection is kept idle (25 when unset).
    pub pool_high_fd_ratio: Option<u8>,
    /// `tune.pool-low-fd-ratio`: the percentage of `maxsock` in use past which a server keeps
    /// no more idle connections than it was seen to need (20 when unset).
    pub pool_low_fd_ratio: Option<u8>,
    /// The `tune.vars.*` limits (T364 S5).
    pub vars_limits: VarsLimits,
    /// `tune.ibex.zero-buffers on|off` (Ibex-only): zero a buffer's used bytes when it is released. On when unset.
    pub zero_buffers: Option<bool>,
    /// `tune.ibex.crypto-provider ring|ring-ibex` (Ibex-only, T460): the rustls crypto provider
    /// of every TCP TLS configuration. Vanilla ring when unset.
    pub crypto_provider: Option<TlsCryptoProvider>,
    /// Buffer size in bytes (`tune.bufsize`).
    pub bufsize: Option<usize>,
    /// Small buffer size in bytes (`tune.bufsize.small`).
    pub bufsize_small: Option<usize>,
    /// Large buffer size in bytes (`tune.bufsize.large`).
    pub bufsize_large: Option<usize>,
    /// `tune.h2.max-concurrent-streams`: the HTTP/2 concurrent-stream limit of both sides (0: none given). Default: 100.
    pub h2_max_concurrent_streams: Option<u32>,
    /// `tune.h2.fe.max-concurrent-streams`: the same for frontends, over the global one when not 0.
    pub h2_fe_max_concurrent_streams: Option<u32>,
    /// `tune.h2.fe.rxbuf`: the bytes a frontend HTTP/2 connection may hold for its streams (default: one 16 KB buffer per allowed stream).
    pub h2_fe_rxbuf: Option<usize>,
    /// Maximum total streams per HTTP/2 connection (`tune.h2.fe.max-total-streams`). Default: 0 (unlimited).
    pub h2_max_total_streams: Option<usize>,
    /// Glitches threshold before graceful GOAWAY and hard close (`tune.h2.fe.glitches-threshold`). Default: 0 (disabled).
    pub h2_glitches_threshold: Option<usize>,
    /// Global maximum connection limit.
    pub maxconn: Option<u32>,
    /// The memory budget in megabytes, `-m` on the command line (`global.rlimit_memmax`): it
    /// sizes `maxconn` and is what `Memmax_MB` shows; it is not a limit on the process.
    pub memmax_mb: Option<u32>,
    /// Background daemon mode.
    pub daemon: bool,
    /// Master-worker mode.
    pub master_worker: bool,
    /// User name for privilege dropping.
    pub user: Option<String>,
    /// Group name for privilege dropping.
    pub group: Option<String>,
    /// Chroot directory (`chroot`), entered once the listeners are bound.
    pub chroot: Option<String>,
    /// The uid to switch to, from `uid` or `user` (resolved with `getpwnam` while parsing,
    /// as `HAProxy` does). Applied only when above 0 (`set_identity`, src/haproxy.c).
    pub uid: Option<i32>,
    /// The gid to switch to, from `gid` or `group`. Applied only when above 0.
    pub gid: Option<i32>,
    /// Non-fatal messages of the `global` keywords, printed while the configuration loads.
    pub load_warnings: Vec<LoadWarning>,
    /// Pidfile path.
    pub pidfile: Option<String>,
    /// Hard stop timeout on reload/exit.
    pub hard_stop_after: Option<Duration>,
    /// `warn-blocked-traffic-after`: the watchdog's tick and warning delay, 1 to 1000 ms.
    pub warn_blocked_traffic_after: Option<Duration>,
    /// `ibex.watchdog-warn-only` (Ibex only): the watchdog warns but never aborts.
    pub ibex_watchdog_warn_only: bool,
    /// `tune.ssl.capture-buffer-size` (or its deprecated alias `tune.ssl.capture-cipherlist-size`):
    /// the bytes of each TLS connection's `ClientHello` capture (`global_ssl.capture_buffer_size`);
    /// 0, the default, captures nothing and the `ssl_fc_cipherlist_*` fetches give no sample.
    pub tune_ssl_capture_buffer_size: usize,
    /// One of the two spellings was given: a second one is refused (`pool_head_ssl_capture`).
    pub tune_ssl_capture_configured: bool,
    /// `ibex.ja4-compat spec` (Ibex-only): `ssl_fc_ja4` follows the JA4 specification text where
    /// FoxIO's tools differ; false (`foxio`, the default) follows the tools.
    pub ibex_ja4_compat_spec: bool,
    /// `ibex.ja4-compat` was given: a second one is refused.
    pub ibex_ja4_compat_configured: bool,
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
    /// `no-memory-trimming`: never call the allocator's `malloc_trim`.
    pub no_memory_trimming: bool,
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
    /// 1-based line of the configuration it is written on.
    pub line: usize,
}


/// A message `HAProxy` prints while it parses a line and then goes on (`ERR_WARN`, or an
/// `ERR_ALERT` that is not fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadWarning {
    /// 1-based line of the merged configuration text.
    pub line: usize,
    /// `true` for `[ALERT]`, `false` for `[WARNING]`.
    pub alert: bool,
    /// The text after `parsing [file:line] :`.
    pub text: String,
    /// How `HAProxy` frames the text on the line.
    pub style: WarnStyle,
}

/// The frame `HAProxy` puts around a message of the configuration load; each message has its
/// own, the space before the colon included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WarnStyle {
    /// `config : parsing [file:line] : text`
    #[default]
    Spaced,
    /// As `Spaced`, and the message HAProxy formats ends in a newline of its own, so a blank
    /// line follows (`'chroot' is already specified`).
    SpacedBlank,
    /// `config : parsing [file:line]: text`
    Tight,
    /// `config : [file:line] : text`
    At,
}

/// The rustls crypto provider TLS over TCP runs on (`tune.ibex.crypto-provider`, T460).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum TlsCryptoProvider {
    /// Upstream ring (`rustls-ring`): the default.
    #[default]
    Ring,
    /// The ring fork that wipes key material when it is freed (`vendor/ringibex`, feature
    /// `zeroize`, through `vendor/rustls-ringibex`).
    RingIbex,
}

impl TlsCryptoProvider {
    /// Every provider, in the order `show ssl crypto-provider` lists them.
    pub const ALL: [Self; 2] = [Self::Ring, Self::RingIbex];

    /// The provider a configuration or CLI name means.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ring" => Some(Self::Ring),
            "ring-ibex" => Some(Self::RingIbex),
            _ => None,
        }
    }

    /// The name the configuration and the CLI use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ring => "ring",
            Self::RingIbex => "ring-ibex",
        }
    }
}
