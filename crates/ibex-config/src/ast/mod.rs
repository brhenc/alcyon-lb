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
    /// Every ACL and log-format sample expression in the proxy and defaults sections, in
    /// the order written. Empty for a configuration not built by the parser.
    pub sample_refs: Vec<SampleRef>,
    /// The `userlist` sections, in the order written.
    pub userlists: Vec<Userlist>,
    /// The proxy sections in the order they were written, as `(kind, index in its list)`.
    /// `HAProxy` numbers proxies in this order; empty for a configuration not built by the
    /// parser, which [`Config::proxy_ids`] then takes as listens, backends, frontends.
    pub proxy_order: Vec<(ProxyKind, usize)>,
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

