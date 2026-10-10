// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// HAProxy configuration parser, ported to Rust.
// Derived from HAProxy 1.0 - 3.5 by Willy Tarreau <willy@meta-x.org>.

#![allow(clippy::struct_excessive_bools)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

pub mod global;
pub use global::*;

pub mod proxy;
pub use proxy::*;

pub mod server;
pub use server::*;

pub mod rules_tcp;
pub use rules_tcp::*;

pub mod rules_http;
pub use rules_http::*;

pub mod acl;
pub use acl::*;

pub mod stick;
pub use stick::*;

pub mod userlist;
pub use userlist::*;

pub mod forwarded;
pub use forwarded::*;

pub mod logging;
pub use logging::*;

pub mod checks;
pub use checks::*;

pub mod ring;
pub use ring::*;

/// Full `HAProxy` configuration containing one or more proxy sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// Optional global settings.
    pub global: Option<GlobalSection>,
    /// Optional defaults settings.
    pub defaults: Option<DefaultsSection>,
    /// List of proxy listen sections in order of definition (`HAProxy` 1.0 style).
    pub listens: Vec<ListenSection>,
    /// List of frontend sections (`HAProxy` 1.1+ style).
    pub frontends: Vec<FrontendSection>,
    /// List of backend sections (`HAProxy` 1.1+ style).
    pub backends: Vec<BackendSection>,
    /// `ring` sections.
    pub rings: Vec<RingSection>,
    /// `log-forward` sections.
    pub log_forwards: Vec<LogForwardSection>,
    /// Every ACL and log-format sample expression in the proxy and defaults sections, in
    /// the order written. Empty for a configuration not built by the parser.
    pub sample_refs: Vec<SampleRef>,
    /// The `userlist` sections, in the order written.
    pub userlists: Vec<Userlist>,
    /// The proxy sections in the order they were written, as `(kind, index in its list)`.
    /// `HAProxy` numbers proxies in this order; empty for a configuration not built by the
    /// parser, which [`Config::proxy_ids`] then takes as listens, backends, frontends.
    pub proxy_order: Vec<(ProxyKind, usize)>,
    /// The `.warning` and `.notice` lines of the configuration (an `.alert` fails the
    /// parse), for the caller to print as `HAProxy` does while it loads.
    pub directive_messages: Vec<DirectiveMessage>,
    /// Warnings of the proxy sections' keywords (`stats show-desc` without text), printed
    /// by the caller as `HAProxy` prints them while it loads.
    pub proxy_warnings: Vec<crate::ast::global::LoadWarning>,
}

/// A `.warning` or `.notice` directive that was in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectiveMessage {
    /// `true` for `.warning`, `false` for `.notice`.
    pub warning: bool,
    /// 1-based line of the directive in the configuration text.
    pub line: usize,
    /// Its argument: empty when it has none.
    pub text: String,
}

/// Which list of [`Config`] a proxy section is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    /// `Config::listens`.
    Listen,
    /// `Config::frontends`.
    Frontend,
    /// `Config::backends`.
    Backend,
}

/// What [`Config::proxy_ids`] decides for one proxy section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProxyId {
    /// The proxy's numeric id: `iid` in `show stat`, `be_id` in `show servers state`,
    /// what `fe_id` and `be_id` read.
    pub iid: u32,
    /// Its position in the order the sections were written; `show stat` lists proxies in it.
    pub decl: u32,
    /// The section gave the id itself with `id` (`PR_O_FORCED_ID`).
    pub forced: bool,
}

/// The ids of every proxy section, by list and index.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyIds {
    /// `Config::listens`.
    pub listens: Vec<ProxyId>,
    /// `Config::frontends`.
    pub frontends: Vec<ProxyId>,
    /// `Config::backends`.
    pub backends: Vec<ProxyId>,
}

impl Config {
    /// What `HAProxy` warns about once the whole configuration is read, in proxy order
    /// (`proxy_finalize`): a frontend with no `bind`, a proxy missing the timeouts it needs
    /// (`client` for a frontend side; `connect` and `server`, or `tunnel` in `tcp` mode, for a
    /// backend side with servers) and `tcp-check` rules no `option tcp-check` uses. Disabled
    /// proxies and modes other than `tcp` and `http` are skipped.
    #[must_use]
    pub fn check_warnings(&self) -> Vec<String> {
        use crate::ast::server::Mode;
        let order: Vec<(ProxyKind, usize)> = if self.proxy_order.is_empty() {
            (0..self.listens.len())
                .map(|i| (ProxyKind::Listen, i))
                .chain((0..self.backends.len()).map(|i| (ProxyKind::Backend, i)))
                .chain((0..self.frontends.len()).map(|i| (ProxyKind::Frontend, i)))
                .collect()
        } else {
            self.proxy_order.clone()
        };
        let mut out = Vec::new();
        for (kind, i) in order {
            // (type word, name, disabled, mode, has frontend cap, has servers, timeouts, unused tcp-check rules)
            let (word, name, disabled, mode, fe, servers, t, unused_rules) = match kind {
                ProxyKind::Listen => {
                    let l = &self.listens[i];
                    ("proxy", &l.name, l.disabled, l.mode, !l.binds.is_empty(), !l.servers.is_empty(), l.timeouts, !l.tcp_checks.is_empty() && !l.tcp_check)
                }
                ProxyKind::Frontend => {
                    let f = &self.frontends[i];
                    ("frontend", &f.name, f.disabled, f.mode, !f.binds.is_empty(), false, f.timeouts, false)
                }
                ProxyKind::Backend => {
                    let b = &self.backends[i];
                    ("backend", &b.name, b.disabled, b.mode, false, !b.servers.is_empty(), b.timeouts, !b.tcp_checks.is_empty() && !b.tcp_check)
                }
            };
            if disabled {
                continue;
            }
            let has_fe_cap = kind != ProxyKind::Backend;
            let has_be_cap = kind != ProxyKind::Frontend;
            if has_fe_cap && !fe {
                out.push(format!("{word} '{name}' has no 'bind' directive. Please declare it as a backend if this was intended."));
            }
            let set = |d: Option<std::time::Duration>| d.is_some_and(|d| !d.is_zero());
            if matches!(mode, Mode::Tcp | Mode::Http)
                && ((has_fe_cap && !set(t.client))
                    || (has_be_cap && servers && (!set(t.connect) || (!set(t.server) && (mode == Mode::Http || !set(t.tunnel))))))
            {
                out.push(format!(
                    "missing timeouts for {word} '{name}'.\n   | While not properly invalid, you will certainly encounter various problems\n   | with such a configuration. To fix this, please ensure that all following\n   | timeouts are set to a non-zero value: 'client', 'connect', 'server'."
                ));
            }
            if unused_rules {
                out.push(format!("{word} '{name}' uses tcp-check rules without 'option tcp-check', so the rules are ignored."));
            }
        }
        out
    }

    /// Numbers the proxies as `check_config_validity` does (`src/cfgparse.c`): the
    /// explicit `id`s are kept, and each other proxy, in the order written, takes the first
    /// id not in use from a counter that starts at 2 (1 is skipped unless asked for: "an
    /// historical bug" HAProxy keeps) and moves past the id it gave. Disabled proxies
    /// take a number too.
    #[must_use]
    pub fn proxy_ids(&self) -> ProxyIds {
        let total = self.listens.len() + self.frontends.len() + self.backends.len();
        let order: Vec<(ProxyKind, usize)> = if self.proxy_order.len() == total {
            self.proxy_order.clone()
        } else {
            (0..self.listens.len()).map(|i| (ProxyKind::Listen, i))
                .chain((0..self.backends.len()).map(|i| (ProxyKind::Backend, i)))
                .chain((0..self.frontends.len()).map(|i| (ProxyKind::Frontend, i)))
                .collect()
        };
        let explicit = |k: ProxyKind, i: usize| match k {
            ProxyKind::Listen => self.listens[i].id,
            ProxyKind::Frontend => self.frontends[i].id,
            ProxyKind::Backend => self.backends[i].id,
        };
        let mut used: std::collections::HashSet<u32> =
            order.iter().filter_map(|&(k, i)| explicit(k, i)).collect();
        let mut ids = ProxyIds {
            listens: vec![ProxyId::default(); self.listens.len()],
            frontends: vec![ProxyId::default(); self.frontends.len()],
            backends: vec![ProxyId::default(); self.backends.len()],
        };
        let mut next = 2u32;
        for (decl, &(k, i)) in order.iter().enumerate() {
            let forced = explicit(k, i);
            let iid = forced.unwrap_or_else(|| {
                while used.contains(&next) {
                    next += 1;
                }
                used.insert(next);
                let iid = next;
                next += 1;
                iid
            });
            let slot = match k {
                ProxyKind::Listen => &mut ids.listens[i],
                ProxyKind::Frontend => &mut ids.frontends[i],
                ProxyKind::Backend => &mut ids.backends[i],
            };
            *slot = ProxyId { iid, decl: u32::try_from(decl).unwrap_or(u32::MAX), forced: forced.is_some() };
        }
        ids
    }
}

/// The ids of the `count` servers of one backend, in order, as `server_get_next_id` gives
/// them (`src/server.c`): the explicit ones (`explicit`, as `(index, id)`) are kept, and each
/// other server takes the first id not in use after the one the previous such server took,
/// from 1.
#[must_use]
pub fn server_puids(count: usize, explicit: &[(u32, u32)]) -> Vec<u32> {
    let used: std::collections::HashSet<u32> = explicit.iter().map(|e| e.1).collect();
    let mut first_unused = 1u32;
    (0..count)
        .map(|i| {
            if let Some(e) = explicit.iter().find(|e| e.0 as usize == i) {
                return e.1;
            }
            // What it takes is past every id it took before: only the explicit ones are in
            // the way, so the ones given are not kept (a backend can have 60,000 servers).
            while used.contains(&first_unused) {
                first_unused += 1;
            }
            let id = first_unused;
            first_unused += 1;
            id
        })
        .collect()
}

/// The ids of the listeners of one proxy, one per `bind`, in order, as `check_config_validity`
/// gives them (`src/cfgparse.c`) for a single thread: an explicit `id` is kept, and any other
/// listener takes the first id not in use from the one after the previous listener's.
#[must_use]
pub fn listener_ids(binds: &[BindConfig]) -> Vec<u32> {
    let mut used: std::collections::HashSet<u32> = binds.iter().filter_map(|b| b.id).collect();
    let mut ids: Vec<u32> = Vec::with_capacity(binds.len());
    for b in binds {
        let id = b.id.unwrap_or_else(|| {
            let mut next = ids.last().map_or(1, |p| p.saturating_add(1));
            while used.contains(&next) {
                next += 1;
            }
            used.insert(next);
            next
        });
        ids.push(id);
    }
    ids
}

