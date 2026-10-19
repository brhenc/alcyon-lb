// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/fd.c, src/ev_epoll.c, src/listener.c and src/haproxy.c
// (run_poll_loop). Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors.
// See LICENSE in the repository root.

//! The runtime: one thread per core, each with its own poller, listener and scheduler.
//!
//! Connections are assigned to a thread at accept and never move, so everything
//! reachable from a connection is touched by exactly one thread and the data path needs
//! no locks. See `design/002-threading-and-affinity.md`.

#![forbid(unsafe_code)]

/// What `ibex -v` and `show info` call this build, from git at build time (`build.rs`).
pub mod version {
    /// The package version and `git describe` of the last `ibex-*` tag: `0.1.0-rc1`,
    /// `0.1.0-rc1-3-gabcdef12`; the package version alone without git.
    pub const VERSION: &str = env!("IBEX_VERSION");
    /// The short commit; empty without git.
    pub const COMMIT: &str = env!("IBEX_COMMIT");
    /// The commit's date, `2026/10/18`; empty without git.
    pub const DATE: &str = env!("IBEX_DATE");
    /// The `HAProxy` branch Ibex follows (`PRODUCT_BRANCH` in HAProxy's version.h). A
    /// configuration reads it as `HAPROXY_BRANCH` to tell which `HAProxy` syntax it can use, so
    /// it names the `HAProxy` branch whose configuration language Ibex implements, not Ibex's own.
    pub const HAPROXY_BRANCH: &str = "3.5";
}

pub mod applet;
pub mod buf;
pub mod check;
pub mod cli_listener;
pub mod crash;
pub mod check_reply;
pub use ibex_config::cond;
pub mod cookie;
pub mod cpu;
pub mod globalconn;
pub mod dgram;
pub mod engine;
pub mod fdtab;
pub(crate) mod hdrs_bin;
pub mod lb;
pub mod mailbox;
pub mod listener;
pub use ibex_sample::localtime;
pub mod logfmt;
pub mod loghdr;
pub mod logfwd;
pub mod ring;
pub mod syslog;
pub mod poller;
pub mod proxy;
pub mod proxy_state;
pub mod track;
pub mod txn;
pub mod txnlog;
pub mod websocket;
pub mod quic_listener;
pub mod h2_bridge;
pub mod h3_relay;
pub mod raw;
pub mod rule_exprs;
pub mod reuse;
pub mod srv_rt;
pub mod srv_tls;
pub mod stats;
pub mod promex;
mod promex_tables;
pub mod statcnt;
pub mod xprt;
pub mod stats_html;
pub mod stats_post;
pub mod stats_typed;
pub mod systemd;
pub mod lifecycle;
pub mod handover;
pub mod watchdog;

pub use quic_listener::QuicListener;

pub use applet::{AppletArena, AppletContext, CliApplet};
pub use buf::Buf;
pub use check::{CheckEvent, CheckStep, ServerCheckConfig, ServerCheckState, ServerStatus};
pub use engine::{validate_tls, Engine, Proxy, ProxyStats, SessionArena, SessionEntry};
pub use fdtab::{FdState, FdTab, Interest};
pub use ibex_proto::{
    build_synthetic_response, default_body_for_status, format_log_format_string,
    inject_http_header, inject_http_header_with_len, remove_http_header,
    remove_http_header_with_len, status_reason_phrase,
};
pub use listener::Listener;
pub use logfmt::{format_string, LogData, LogFormat, CLF_HTTP_LOG_FORMAT, CLF_TCP_LOG_FORMAT, DEFAULT_HTTPS_LOG_FORMAT, DEFAULT_HTTP_LOG_FORMAT, DEFAULT_TCP_LOG_FORMAT};
pub use syslog::{format_rfc3164, priority, SyslogTarget};
pub use poller::{Event, Poller};
pub use proxy::{find_eoh, Ending, TcpSession, Timeouts, Want, Which};
pub use raw::Io;
pub use rule_exprs::validate_rule_exprs;
pub use xprt::{accept_tls, connect_tls, ClientXprt, ServerXprt, TlsConn};
pub use stats::{
    format_show_info, format_show_stat, format_show_stat_as, format_show_stat_filtered, stats_csv_header, StatRow,
    STAT_FIELDS, STAT_FIELD_COUNT,
};
pub use stats_html::{parse_admin_action, render_stats_html, render_stats_html_for, render_stats_json, AdminAction};
