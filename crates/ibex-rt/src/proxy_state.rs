// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/backend.c (smp_fetch_nbsrv, smp_fetch_srv_is_up,
// smp_fetch_be_conn_free, smp_fetch_srv_conn_free, sample_conv_*), include/haproxy/backend.h
// (be_usable_srv), src/sample.c (smp_resolve_args) and src/stick_table.c
// (sample_conv_in_table). Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors.
// See LICENSE.

//! The proxies' live state, as the sample fetches read it, and the load-time resolution of
//! the backend, server and table arguments those fetches take.
//!
//! [`ProxiesView`] is what [`ibex_sample::SampleContext::proxies`] points at: it reads the
//! server statuses the health checks write, the per-server connection counts, weights and
//! `maxconn`s, and the stick tables, from the worker's own [`Proxy`] list.
//!
//! [`check_expr`] is the load-time half. `HAProxy` resolves a fetch's `<backend>`,
//! `[<backend>/]<server>` and `<table>` arguments when it loads the configuration and
//! refuses one that names nothing; it also refuses here, with `HAProxy`'s wording, what
//! Ibex registers no implementation for ([`ibex_sample::NOT_IMPLEMENTED`]).

use crate::check::ServerStatus;
use crate::engine::Proxy;
use ibex_config::{Config, SectionKind};
use ibex_sample::{not_implemented_message, Expr, ProxyState, Registry, Sample, ServerState};
use ibex_stick_table::StickKey;
use std::sync::atomic::Ordering;

/// The [`ProxyState`] of a worker's proxies.
#[derive(Debug, Clone, Copy)]
pub struct ProxiesView<'a>(pub &'a [Proxy]);

fn status(p: &Proxy, i: usize) -> ServerStatus {
    p.server_statuses.get(i).map_or(ServerStatus::Down, |s| ServerStatus::from(s.load(Ordering::Relaxed)))
}

/// `srv_currently_usable`: running, and with a weight to take traffic (a server drained
/// from the CLI has its weight taken away in `HAProxy`).
fn usable(p: &Proxy, i: usize) -> bool {
    status(p, i) == ServerStatus::Up && p.server_weights.get(i).copied().unwrap_or(1) > 0
}

fn is_backup(p: &Proxy, i: usize) -> bool {
    p.server_backups.get(i).copied().unwrap_or(false)
}

/// `smp_fetch_srv_is_up`: not in maintenance, and not stopped by its check.
fn is_up(p: &Proxy, i: usize) -> bool {
    !matches!(status(p, i), ServerStatus::Down | ServerStatus::Maint)
}

fn cur_sess(p: &Proxy, i: usize) -> u32 {
    p.server_actconn.get(i).map_or(0, |a| a.load(Ordering::Relaxed))
}

/// The usable active servers, and the first usable backup (`lbprm.fbck`: Ibex has no
/// `option allbackups`, so the first one is the one that takes traffic).
fn recount(p: &Proxy) -> (usize, Option<usize>) {
    let n = p.servers.len();
    let act = (0..n).filter(|&i| !is_backup(p, i) && usable(p, i)).count();
    let fbck = (0..n).find(|&i| is_backup(p, i) && usable(p, i));
    (act, fbck)
}

impl<'a> ProxiesView<'a> {
    /// The proxy with a backend named `name` (a `backend` or a `listen`).
    #[must_use]
    pub fn backend(&self, name: &str) -> Option<&'a Proxy> {
        self.0.iter().find(|p| p.has_backend && p.name == name)
    }
}

/// `be_usable_srv`.
#[must_use]
pub fn usable_servers(p: &Proxy) -> i64 {
    match recount(p) {
        (0, Some(_)) => 1,
        (act, _) => i64::try_from(act).unwrap_or(i64::MAX),
    }
}

/// `lbprm.tot_weight`: the usable active servers' weights, or the first usable backup's
/// when there are none (`update_backend_weight`).
#[must_use]
pub fn total_weight(p: &Proxy) -> u32 {
    let weight = |i: usize| p.server_weights.get(i).copied().unwrap_or(1);
    match recount(p) {
        (0, Some(b)) => weight(b),
        (0, None) => 0,
        _ => (0..p.servers.len()).filter(|&i| !is_backup(p, i) && usable(p, i)).map(weight).sum(),
    }
}

impl ProxyState for ProxiesView<'_> {
    fn usable_servers(&self, backend: &str) -> Option<i64> {
        self.backend(backend).map(usable_servers)
    }

    fn backend_conn_free(&self, backend: &str) -> Option<i64> {
        let p = self.backend(backend)?;
        let (act, fbck) = recount(p);
        let mut free = 0i64;
        for i in 0..p.servers.len() {
            if !usable(p, i) || (is_backup(p, i) && (act > 0 || fbck != Some(i))) {
                continue;
            }
            match p.server_maxconn.get(i).copied().flatten() {
                None | Some(0) => return Some(-1),
                Some(mc) => free += i64::from(mc.saturating_sub(cur_sess(p, i))),
            }
        }
        Some(free)
    }

    fn server(&self, backend: &str, server: &str) -> Option<ServerState> {
        let p = self.backend(backend)?;
        let i = p.server_ids.iter().position(|s| s == server)?;
        Some(ServerState {
            is_up: is_up(p, i),
            cur_sess: cur_sess(p, i),
            maxconn: p.server_maxconn.get(i).copied().flatten(),
        })
    }

    fn frontend_exists(&self, name: &str) -> bool {
        self.0.iter().any(|p| p.has_frontend && p.name == name)
    }

    fn table_has_key(&self, table: &str, key: &Sample) -> Option<bool> {
        let t = self.0.iter().find(|p| p.name == table)?.stick_table.as_ref()?;
        let key = sample_stick_key(key.clone());
        t.get_entry(&key).ok().map(|e| e.is_some())
    }
}

/// The stick-table key a sample stands for, as tracking stores it
/// ([`crate::engine::resolve_sample_stick_key`] reads keys the same way).
pub(crate) fn sample_stick_key(smp: Sample) -> StickKey {
    match smp {
        Sample::Ipv4(ip) => StickKey::Ip(std::net::IpAddr::V4(ip)),
        Sample::Ipv6(ip) => StickKey::Ip(std::net::IpAddr::V6(ip)),
        Sample::Sint(i) => StickKey::Integer(i.cast_unsigned()),
        Sample::Str(s) => match s.parse::<std::net::IpAddr>() {
            Ok(ip) => StickKey::Ip(ip),
            Err(_) => StickKey::String(s),
        },
        Sample::Bin(b) => StickKey::Binary(b),
        Sample::Bool(b) => StickKey::Integer(u64::from(b)),
        Sample::Meth(m) => StickKey::String(m.as_str().to_string()),
    }
}

// ---- load time ---------------------------------------------------------------------

/// The section an expression is written in, as the argument resolution needs it.
#[derive(Debug, Clone, Copy)]
pub struct Where<'a> {
    pub section: SectionKind,
    /// `None` for an unnamed `defaults`.
    pub proxy: Option<&'a str>,
}

/// The argument a fetch or converter takes that names something in the configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArgKind {
    /// `[<backend>]`, defaulting to the current proxy (`ARGT_BE`).
    Backend,
    /// `[<backend>/]<server>` (`ARGT_SRV`).
    Server,
    /// `[<table>]`, defaulting to the current proxy (`ARGT_TAB`).
    Table,
}

fn fetch_arg(name: &str) -> Option<ArgKind> {
    match name {
        "nbsrv" | "be_conn_free" => Some(ArgKind::Backend),
        "srv_is_up" | "srv_conn" | "srv_conn_free" => Some(ArgKind::Server),
        _ => None,
    }
}

fn converter_arg(name: &str) -> Option<ArgKind> {
    (name == "in_table").then_some(ArgKind::Table)
}

/// Names Ibex once registered, returning a constant, that `HAProxy` does not have. A
/// configuration that uses one fails on `HAProxy` with "unknown fetch method", and now
/// on Ibex too, wherever it appears.
const NOT_HAPROXY_FETCHES: &[&str] = &["src_trackers", "src_in_table"];

fn has_backend(config: &Config, name: &str) -> bool {
    config.backends.iter().any(|b| b.name == name) || config.listens.iter().any(|l| l.name == name)
}

fn has_proxy(config: &Config, name: &str) -> bool {
    has_backend(config, name) || config.frontends.iter().any(|f| f.name == name)
}

fn has_server(config: &Config, proxy: &str, server: &str) -> bool {
    config.backends.iter().filter(|b| b.name == proxy).any(|b| b.servers.iter().any(|s| s.id == server))
        || config.listens.iter().filter(|l| l.name == proxy).any(|l| l.servers.iter().any(|s| s.id == server))
}

fn has_table(config: &Config, name: &str) -> bool {
    config.backends.iter().any(|b| b.name == name && b.stick_table.is_some())
        || config.listens.iter().any(|l| l.name == name && l.stick_table.is_some())
        || config.frontends.iter().any(|f| f.name == name && f.stick_table.is_some())
}

/// Resolves one argument as `smp_resolve_args` does, with its messages.
fn resolve(config: &Config, at: Where<'_>, kind: ArgKind, arg: Option<&str>, what: &str) -> Result<(), String> {
    // A defaults section is no proxy to default an argument to: `HAProxy` resolves a rule
    // written there in the defaults section itself, and refuses a server without its
    // backend and an omitted table ("backend name must be set"). Its `unique-id-format` and
    // `log-format` are resolved in each proxy that inherits them ([`check_sample_refs`]).
    let cur = match at.section {
        SectionKind::Defaults => None,
        _ => at.proxy,
    };
    let arg = arg.filter(|a| !a.is_empty());
    match kind {
        ArgKind::Backend => match (arg, cur) {
            (Some(be), _) if !has_backend(config, be) => {
                Err(format!("unable to find backend '{be}' referenced in arg 1 of {what}"))
            }
            (None, Some(px)) if !has_backend(config, px) => {
                Err(format!("proxy '{px}', referenced in arg 1 of {what}, has not backend capability"))
            }
            _ => Ok(()),
        },
        ArgKind::Server => {
            let Some(arg) = arg else {
                return Err(format!("missing server name in arg 1 of {what}"));
            };
            let (px, srv) = match arg.split_once('/') {
                Some((px, srv)) => {
                    if !has_proxy(config, px) {
                        return Err(format!("unable to find proxy '{px}' referenced in arg 1 of {what}"));
                    }
                    (px, srv)
                }
                None => match cur {
                    Some(px) => (px, arg),
                    None => return Err(format!("backend name must be set in arg 1 of {what}")),
                },
            };
            if has_server(config, px, srv) {
                Ok(())
            } else {
                Err(format!("unable to find server '{srv}' in proxy '{px}', referenced in arg 1 of {what}"))
            }
        }
        ArgKind::Table => match arg.or(cur) {
            Some(t) if !has_table(config, t) => Err(format!("unable to find table '{t}' referenced in arg 1 of {what}")),
            Some(_) => Ok(()),
            None => Err(format!("table name must be set in arg 1 of {what}")),
        },
    }
}

/// Checks one sample expression written at `at`: no fetch or converter Ibex does not
/// implement, and every backend, server and table argument naming something configured.
///
/// `context` names the place in `HAProxy`'s words ("ACL keyword" for an ACL, "sample fetch
/// keyword" otherwise).
///
/// # Errors
/// The first problem, worded as `HAProxy` words it where it refuses the same thing.
pub fn check_expr(config: &Config, registry: &Registry, at: Where<'_>, expr: &str, acl: bool) -> Result<(), String> {
    // The expression is the first word: an ACL's pattern follows it.
    let word = expr.split_whitespace().next().unwrap_or("");
    let Ok(e) = Expr::parse(word) else { return Ok(()) };
    let in_proxy = at.proxy.map(|p| format!(" in proxy '{p}'")).unwrap_or_default();
    if let Some(msg) = not_implemented_message(&e.fetch_name) {
        return Err(msg);
    }
    if NOT_HAPROXY_FETCHES.contains(&e.fetch_name.as_str()) && registry.get_fetch(&e.fetch_name).is_none() {
        return Err(format!("unknown fetch method '{}'", e.fetch_name));
    }
    for (c, _) in &e.converters {
        if let Some(msg) = not_implemented_message(c) {
            return Err(msg);
        }
    }
    if let Some(kind) = fetch_arg(&e.fetch_name) {
        let what = format!("{} '{}'{in_proxy}", if acl { "ACL keyword" } else { "sample fetch keyword" }, e.fetch_name);
        resolve(config, at, kind, e.fetch_args.first().map(String::as_str), &what)?;
    }
    for (c, args) in &e.converters {
        if let Some(kind) = converter_arg(c) {
            let what = format!("conversion keyword '{c}' for sample fetch keyword '{}'{in_proxy}", e.fetch_name);
            resolve(config, at, kind, args.first().map(String::as_str), &what)?;
        }
    }
    Ok(())
}

/// [`check_expr`] over every ACL and log-format expression the parser recorded
/// ([`Config::sample_refs`]).
///
/// # Errors
/// The first that fails, with its line.
pub fn check_sample_refs(config: &Config, registry: &Registry) -> Result<(), String> {
    for r in &config.sample_refs {
        let in_line = |e: String| format!("parsing [line {}]: {e}", r.line);
        if let (SectionKind::Defaults, "unique-id-format" | "log-format") = (r.section, r.directive.as_str()) {
            // Resolved in each proxy that inherited it, as if written there.
            for (section, name) in format_users(config, &r.directive, &r.expr) {
                check_expr(config, registry, Where { section, proxy: Some(name) }, &r.expr, false).map_err(in_line)?;
            }
            continue;
        }
        let at = Where { section: r.section, proxy: r.proxy.as_deref() };
        check_expr(config, registry, at, &r.expr, r.acl).map_err(in_line)?;
    }
    Ok(())
}

/// The proxies whose `directive` (`unique-id-format`, or `log-format`, which only a proxy
/// with a frontend compiles) contains the expression `expr`.
fn format_users<'c>(config: &'c Config, directive: &str, expr: &str) -> Vec<(SectionKind, &'c str)> {
    let uses = |fmt: &str| ibex_config::parser::log_format_exprs(fmt).contains(&expr);
    let log = directive == "log-format";
    let custom = |spec: &Option<ibex_config::LogFormatSpec>| matches!(spec, Some(ibex_config::LogFormatSpec::Custom(f)) if uses(f));
    let fes = config.frontends.iter().filter(|f| if log { custom(&f.log_format) } else { f.unique_id_format.as_deref().is_some_and(uses) });
    let lis = config.listens.iter().filter(|l| if log { custom(&l.log_format) } else { l.unique_id_format.as_deref().is_some_and(uses) });
    let bes = config.backends.iter().filter(|b| !log && b.unique_id_format.as_deref().is_some_and(uses));
    fes.map(|f| (SectionKind::Frontend, f.name.as_str()))
        .chain(lis.map(|l| (SectionKind::Listen, l.name.as_str())))
        .chain(bes.map(|b| (SectionKind::Backend, b.name.as_str())))
        .collect()
}
