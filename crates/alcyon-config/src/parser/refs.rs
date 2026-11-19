// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! References to other proxies that `HAProxy` resolves when the configuration loads
//! (`check_config_validity`, `src/cfgparse.c`): `default_backend`, `use_backend` and the
//! table a `track-sc` rule names. A name that matches nothing is an alert and the load fails;
//! left unchecked, Alcyon would send the request to the default backend, or to the proxy itself,
//! as if the rule had not matched (T274 A).

use super::ConfigError;
use crate::ast::{
    BackendSection, DefaultsSection, FrontendSection, HttpReqAction, HttpReqRule, ListenSection, ProxyKind, TcpReqConnAction, TcpReqConnRule,
    TcpReqContentAction, TcpReqContentRule, TcpReqSessionAction, TcpReqSessionRule, UseBackendRule,
};

/// What the checks read of one proxy, whatever its kind.
struct View<'a> {
    name: &'a str,
    disabled: bool,
    /// A listen or a backend can be the target of `use_backend`.
    is_backend: bool,
    default_backend: Option<&'a str>,
    use_backends: &'a [UseBackendRule],
    /// The `track-sc<N>` rules: the counter, the `table` written if any, and the line.
    tracks: Vec<(u8, Option<&'a str>, Option<u32>)>,
    has_table: bool,
}

fn tracks<'a>(
    conn: &'a [TcpReqConnRule],
    session: &'a [TcpReqSessionRule],
    content: &'a [TcpReqContentRule],
    http: &'a [HttpReqRule],
) -> Vec<(u8, Option<&'a str>, Option<u32>)> {
    // The line tells a rule written here from a copy of one written in a `defaults`, which
    // the `defaults` is answerable for. A `tcp-request connection` or `session` rule keeps
    // no line of its own, and so is never taken for a copy.
    let mut out = Vec::new();
    for r in conn {
        match &r.action {
            TcpReqConnAction::TrackSc0 { table, .. } => out.push((0, table.as_deref(), None)),
            TcpReqConnAction::TrackSc1 { table, .. } => out.push((1, table.as_deref(), None)),
            TcpReqConnAction::TrackSc2 { table, .. } => out.push((2, table.as_deref(), None)),
            _ => {}
        }
    }
    for r in session {
        match &r.action {
            TcpReqSessionAction::TrackSc0 { table, .. } => out.push((0, table.as_deref(), None)),
            TcpReqSessionAction::TrackSc1 { table, .. } => out.push((1, table.as_deref(), None)),
            TcpReqSessionAction::TrackSc2 { table, .. } => out.push((2, table.as_deref(), None)),
            _ => {}
        }
    }
    for r in content {
        match &r.action {
            TcpReqContentAction::TrackSc0 { table, .. } => out.push((0, table.as_deref(), Some(r.line))),
            TcpReqContentAction::TrackSc1 { table, .. } => out.push((1, table.as_deref(), Some(r.line))),
            TcpReqContentAction::TrackSc2 { table, .. } => out.push((2, table.as_deref(), Some(r.line))),
            _ => {}
        }
    }
    for r in http {
        match &r.action {
            HttpReqAction::TrackSc0 { table, .. } => out.push((0, table.as_deref(), Some(r.line))),
            HttpReqAction::TrackSc1 { table, .. } => out.push((1, table.as_deref(), Some(r.line))),
            HttpReqAction::TrackSc2 { table, .. } => out.push((2, table.as_deref(), Some(r.line))),
            _ => {}
        }
    }
    out
}

/// The alerts `HAProxy` prints for the first proxy (in the order of the file) that refers to
/// something that does not exist: its `default_backend`, then each `use_backend` rule, then
/// each `track-sc` table. A disabled proxy is not checked, and `HAProxy` stops at the first
/// proxy in error.
///
/// The `defaults` sections come first, whatever the proxies did: `check_config_validity`
/// walks `defaults_list` before it walks the proxies, and every one of them is answered for
/// -- a `defaults` in error does not stop the others, nor the proxies. `HAProxy` keeps the
/// rules of a `defaults` in the section and has the proxies that inherit it hold a
/// reference to it (`proxy_ref_defaults`), so a rule written in a `defaults` is reported
/// there and never again in the section which inherited a copy of it; `inherited` is what
/// tells the copies apart, by the line each was written on.
pub(crate) fn validate_references(
    order: &[(ProxyKind, usize)],
    listens: &[ListenSection],
    frontends: &[FrontendSection],
    backends: &[BackendSection],
    defaults: &[DefaultsSection],
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

    // The `defaults` sections, in the order they were written. None of them can hold a
    // `stick-table` (`stick-table` is refused in a `defaults`), so a `track-sc` naming no
    // table there names a table that cannot exist; one naming `table <name>` is looked up
    // among the proxies' tables, as everywhere else.
    let mut alerts: Vec<(usize, String)> = Vec::new();
    let mut inherited: Vec<(u32, u8)> = Vec::new();
    for d in defaults {
        // An anonymous `defaults` takes no rule at all, which the parse itself refuses.
        let Some(name) = d.name.as_deref() else { continue };
        // A `defaults` cannot inherit another one that defines rules (the parse refuses it),
        // so every rule seen here was written in this section.
        for (n, table, line) in tracks(&d.tcp_req_conn_rules, &d.tcp_req_session_rules, &d.tcp_req_content_rules, &d.http_req_rules) {
            if let Some(l) = line {
                inherited.push((l, n));
            }
            let missing = match table {
                None => Some(name),
                Some(t) if !table_exists(t) => Some(t),
                Some(_) => None,
            };
            if let Some(t) = missing {
                alerts.push((0, format!("Proxy '{name}': unable to find table '{t}' referenced by track-sc{n}.")));
            }
        }
    }

    for v in views.iter().filter(|v| !v.disabled) {
        let mut proxy_alerts: Vec<(usize, String)> = Vec::new();
        if let Some(d) = v.default_backend.filter(|d| !backend_exists(d)) {
            proxy_alerts.push((0, format!("Proxy '{}': unable to find required default_backend: '{d}'.", v.name)));
        }
        for r in v.use_backends.iter().filter(|r| !r.backend.contains('%') && !backend_exists(&r.backend)) {
            proxy_alerts.push((0, format!("Proxy '{}': unable to find required use_backend: '{}'.", v.name, r.backend)));
        }
        for &(n, table, line) in &v.tracks {
            // Written in a `defaults`, which was answered for above: `HAProxy` holds the
            // rule there, and the proxy only references it.
            if line.is_some_and(|l| inherited.contains(&(l, n))) {
                continue;
            }
            let t = table.unwrap_or(v.name);
            if !table_exists(t) {
                proxy_alerts.push((0, format!("Proxy '{}': unable to find table '{t}' referenced by track-sc{n}.", v.name)));
            }
        }
        if !proxy_alerts.is_empty() {
            alerts.extend(proxy_alerts);
            return Err(ConfigError::alerts(alerts));
        }
    }
    if !alerts.is_empty() {
        return Err(ConfigError::alerts(alerts));
    }
    Ok(())
}
