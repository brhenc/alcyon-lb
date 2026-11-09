// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! References to other proxies that `HAProxy` resolves when the configuration loads
//! (`check_config_validity`, `src/cfgparse.c`): `default_backend`, `use_backend` and the
//! table a `track-sc` rule names. A name that matches nothing is an alert and the load fails;
//! left unchecked, Alcyon would send the request to the default backend, or to the proxy itself,
//! as if the rule had not matched (T274 A).

use super::ConfigError;
use crate::ast::{
    BackendSection, FrontendSection, HttpReqAction, HttpReqRule, ListenSection, ProxyKind, TcpReqConnAction, TcpReqConnRule, TcpReqContentAction,
    TcpReqContentRule, TcpReqSessionAction, TcpReqSessionRule, UseBackendRule,
};

/// What the checks read of one proxy, whatever its kind.
struct View<'a> {
    name: &'a str,
    disabled: bool,
    /// A listen or a backend can be the target of `use_backend`.
    is_backend: bool,
    default_backend: Option<&'a str>,
    use_backends: &'a [UseBackendRule],
    /// The `track-sc<N>` rules: the counter and the `table` written, if any.
    tracks: Vec<(u8, Option<&'a str>)>,
    has_table: bool,
}

fn tracks<'a>(
    conn: &'a [TcpReqConnRule],
    session: &'a [TcpReqSessionRule],
    content: &'a [TcpReqContentRule],
    http: &'a [HttpReqRule],
) -> Vec<(u8, Option<&'a str>)> {
    let mut out = Vec::new();
    for r in conn {
        match &r.action {
            TcpReqConnAction::TrackSc0 { table, .. } => out.push((0, table.as_deref())),
            TcpReqConnAction::TrackSc1 { table, .. } => out.push((1, table.as_deref())),
            TcpReqConnAction::TrackSc2 { table, .. } => out.push((2, table.as_deref())),
            _ => {}
        }
    }
    for r in session {
        match &r.action {
            TcpReqSessionAction::TrackSc0 { table, .. } => out.push((0, table.as_deref())),
            TcpReqSessionAction::TrackSc1 { table, .. } => out.push((1, table.as_deref())),
            TcpReqSessionAction::TrackSc2 { table, .. } => out.push((2, table.as_deref())),
            _ => {}
        }
    }
    for r in content {
        match &r.action {
            TcpReqContentAction::TrackSc0 { table, .. } => out.push((0, table.as_deref())),
            TcpReqContentAction::TrackSc1 { table, .. } => out.push((1, table.as_deref())),
            TcpReqContentAction::TrackSc2 { table, .. } => out.push((2, table.as_deref())),
            _ => {}
        }
    }
    for r in http {
        match &r.action {
            HttpReqAction::TrackSc0 { table, .. } => out.push((0, table.as_deref())),
            HttpReqAction::TrackSc1 { table, .. } => out.push((1, table.as_deref())),
            HttpReqAction::TrackSc2 { table, .. } => out.push((2, table.as_deref())),
            _ => {}
        }
    }
    out
}

/// The alerts `HAProxy` prints for the first proxy (in the order of the file) that refers to
/// something that does not exist: its `default_backend`, then each `use_backend` rule, then
/// each `track-sc` table. A disabled proxy is not checked, and `HAProxy` stops at the first
/// proxy in error.
pub(crate) fn validate_references(
    order: &[(ProxyKind, usize)],
    listens: &[ListenSection],
    frontends: &[FrontendSection],
    backends: &[BackendSection],
) -> Result<(), ConfigError> {
    let views: Vec<View<'_>> = order
        .iter()
        .filter_map(|&(kind, i)| {
            Some(match kind {
                ProxyKind::Listen => {
                    let p = listens.get(i)?;
                    View {
                        name: &p.name,
                        disabled: p.disabled,
                        is_backend: true,
                        default_backend: p.default_backend.as_deref(),
                        use_backends: &p.use_backends,
                        tracks: tracks(&p.tcp_req_conn_rules, &p.tcp_req_session_rules, &p.tcp_req_content_rules, &p.http_req_rules),
                        has_table: p.stick_table.is_some(),
                    }
                }
                ProxyKind::Frontend => {
                    let p = frontends.get(i)?;
                    View {
                        name: &p.name,
                        disabled: p.disabled,
                        is_backend: false,
                        default_backend: p.default_backend.as_deref(),
                        use_backends: &p.use_backends,
                        tracks: tracks(&p.tcp_req_conn_rules, &p.tcp_req_session_rules, &p.tcp_req_content_rules, &p.http_req_rules),
                        has_table: p.stick_table.is_some(),
                    }
                }
                ProxyKind::Backend => {
                    let p = backends.get(i)?;
                    View {
                        name: &p.name,
                        disabled: p.disabled,
                        is_backend: true,
                        default_backend: None,
                        use_backends: &[],
                        tracks: tracks(&[], &[], &p.tcp_req_content_rules, &p.http_req_rules),
                        has_table: p.stick_table.is_some(),
                    }
                }
            })
        })
        .collect();
    let backend_exists = |n: &str| views.iter().any(|v| v.is_backend && v.name == n);
    let table_exists = |n: &str| views.iter().any(|v| v.has_table && v.name == n);
    for v in views.iter().filter(|v| !v.disabled) {
        let mut alerts: Vec<(usize, String)> = Vec::new();
        if let Some(d) = v.default_backend.filter(|d| !backend_exists(d)) {
            alerts.push((0, format!("Proxy '{}': unable to find required default_backend: '{d}'.", v.name)));
        }
        for r in v.use_backends.iter().filter(|r| !backend_exists(&r.backend)) {
            alerts.push((0, format!("Proxy '{}': unable to find required use_backend: '{}'.", v.name, r.backend)));
        }
        for &(n, table) in &v.tracks {
            let t = table.unwrap_or(v.name);
            if !table_exists(t) {
                alerts.push((0, format!("Proxy '{}': unable to find table '{t}' referenced by track-sc{n}.", v.name)));
            }
        }
        if !alerts.is_empty() {
            return Err(ConfigError::alerts(alerts));
        }
    }
    Ok(())
}
