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

pub mod applet;
pub mod buf;
pub mod check;
pub use ibex_config::cond;
pub mod cookie;
pub mod cpu;
pub mod dgram;
pub mod engine;
pub mod fdtab;
pub mod lb;
pub mod listener;
pub mod localtime;
pub mod logfmt;
pub mod syslog;
pub mod poller;
pub mod proxy;
pub mod proxy_state;
pub mod txn;
pub mod txnlog;
pub mod quic_listener;
pub mod h3_relay;
pub mod raw;
pub mod rule_exprs;
pub mod srv_tls;
pub mod stats;
pub mod xprt;
pub mod stats_html;
pub mod systemd;
pub mod lifecycle;
pub mod handover;

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
pub use logfmt::{format_string, LogData, LogFormat, CLF_HTTP_LOG_FORMAT, CLF_TCP_LOG_FORMAT, DEFAULT_HTTP_LOG_FORMAT, DEFAULT_TCP_LOG_FORMAT};
pub use syslog::{format_rfc3164, priority, SyslogTarget};
pub use poller::{Event, Poller};
pub use proxy::{find_eoh, Ending, TcpSession, Timeouts, Want, Which};
pub use raw::Io;
pub use rule_exprs::validate_rule_exprs;
pub use xprt::{accept_tls, connect_tls, ClientXprt, ServerXprt, TlsConn};
pub use stats::{
    format_show_info, format_show_stat, format_show_stat_filtered, stats_csv_header, StatRow,
    STAT_FIELDS, STAT_FIELD_COUNT,
};
pub use stats_html::{parse_admin_action, render_stats_html, render_stats_json, AdminAction};
