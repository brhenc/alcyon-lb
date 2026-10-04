// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `server ... track [<proxy>/]<server>`: a server with no check of its own that takes the
//! state of another (T141).
//!
//! `Proxy::server_statuses` is what every reader (load balancing, `show stat`, `show servers
//! state`) looks at, so a tracker's state is kept there too: [`set_status`] is the one writer
//! of it, and it recomputes every server that tracks the one it changed, chains included.
//! What an operator forced on the tracker itself (`disabled`, `set server ... state`) is kept
//! apart in [`Track::own`], because it must survive the target changing and be given up when
//! the operator says `ready`.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::check::ServerStatus;
use crate::engine::Proxy;

/// What a tracking server follows.
#[derive(Debug)]
pub struct Track {
    /// The tracked server: proxy index and server index.
    pub target: (usize, usize),
    /// `<proxy>/<server>` of the target, as `show stat` prints it (`tracked`, `via`).
    pub label: String,
    /// The state the operator forced on this server: `Up` for none, `Maint` or `Drain`.
    pub own: AtomicU8,
}

/// The state of a tracker whose own forced state is `own` and whose target is `target`.
///
/// Maintenance wins, then a target that is down, then drain; otherwise the server is up.
#[must_use]
pub fn combine(own: ServerStatus, target: ServerStatus) -> ServerStatus {
    if own == ServerStatus::Maint || target == ServerStatus::Maint {
        ServerStatus::Maint
    } else if target == ServerStatus::Down {
        ServerStatus::Down
    } else if own == ServerStatus::Drain || target == ServerStatus::Drain {
        ServerStatus::Drain
    } else {
        ServerStatus::Up
    }
}

fn track_of(proxies: &[Proxy], p: usize, s: usize) -> Option<&Track> {
    proxies.get(p)?.server_track.as_ref()?.get(s)?.as_ref()
}

fn load(proxies: &[Proxy], p: usize, s: usize) -> ServerStatus {
    proxies
        .get(p)
        .and_then(|px| px.server_statuses.get(s))
        .map_or(ServerStatus::Up, |a| ServerStatus::from(a.load(Ordering::Relaxed)))
}

/// Recomputes every server that tracks `(p, s)`, and those that track them. A chain cannot
/// loop: the load refuses it.
fn propagate(proxies: &[Proxy], p: usize, s: usize) {
    let state = load(proxies, p, s);
    for (q, px) in proxies.iter().enumerate() {
        let Some(tracks) = &px.server_track else { continue };
        for (t, tr) in tracks.iter().enumerate() {
            let Some(tr) = tr else { continue };
            if tr.target != (p, s) {
                continue;
            }
            let own = ServerStatus::from(tr.own.load(Ordering::Relaxed));
            px.server_statuses[t].store(combine(own, state) as u8, Ordering::Relaxed);
            propagate(proxies, q, t);
        }
    }
}

/// Sets the state of server `s` of proxy `p`: a check's verdict, or what an operator asked.
/// For a tracker, the state is what the operator forced on it (`Up` for nothing), and the
/// server's own is that combined with its target's.
pub fn set_status(proxies: &[Proxy], p: usize, s: usize, st: ServerStatus) {
    if let Some(tr) = track_of(proxies, p, s) {
        tr.own.store(st as u8, Ordering::Relaxed);
        let (tp, ts) = tr.target;
        let eff = combine(st, load(proxies, tp, ts));
        proxies[p].server_statuses[s].store(eff as u8, Ordering::Relaxed);
    } else if let Some(a) = proxies.get(p).and_then(|px| px.server_statuses.get(s)) {
        a.store(st as u8, Ordering::Relaxed);
    }
    propagate(proxies, p, s);
}

/// Resolves every `track` of the configuration into the proxies, and gives each tracker the
/// state of its target. The load has already refused a target that does not exist.
pub fn attach(proxies: &mut [Proxy], config: &ibex_config::Config) {
    use ibex_config::parser::tracked_target;
    // Nothing to resolve in the common case, and nothing allocated for it: a configuration
    // of sixty thousand backends is held to a memory bound.
    let any = |servers: &[ibex_config::Server]| servers.iter().any(|s| s.track.is_some());
    if !config.listens.iter().any(|l| any(&l.servers)) && !config.backends.iter().any(|b| any(&b.servers)) {
        return;
    }
    let sections: Vec<(&str, &[ibex_config::Server])> = config
        .listens
        .iter()
        .filter(|l| !l.disabled)
        .map(|l| (l.name.as_str(), l.servers.as_slice()))
        .chain(config.backends.iter().filter(|b| !b.disabled).map(|b| (b.name.as_str(), b.servers.as_slice())))
        .collect();
    let find = |px: &str, sv: &str| -> Option<(usize, usize)> {
        let p = proxies.iter().position(|x| x.name == px)?;
        Some((p, proxies[p].server_ids.iter().position(|i| i == sv)?))
    };
    // Section order is proxy order: `build_shared_state` pushes listens, then backends.
    let mut tracks: Vec<Vec<Option<Track>>> = Vec::new();
    for (name, servers) in &sections {
        tracks.push(
            servers
                .iter()
                .map(|server| {
                    let spec = server.track.as_deref()?;
                    let (tpx, tsv) = tracked_target(name, spec);
                    let target = find(tpx, tsv)?;
                    let own = if server.disabled { ServerStatus::Maint } else { ServerStatus::Up };
                    Some(Track { target, label: format!("{tpx}/{tsv}"), own: AtomicU8::new(own as u8) })
                })
                .collect(),
        );
    }
    for (p, t) in tracks.into_iter().enumerate() {
        if t.iter().any(Option::is_some) {
            proxies[p].server_track = Some(std::sync::Arc::new(t));
        }
    }
    // Targets first: a chain's state flows from the server that has a check.
    let roots: Vec<(usize, usize)> = proxies
        .iter()
        .enumerate()
        .flat_map(|(p, px)| (0..px.server_ids.len()).map(move |s| (p, s)))
        .filter(|&(p, s)| track_of(proxies, p, s).is_none())
        .collect();
    for (p, s) in roots {
        propagate(proxies, p, s);
    }
}

/// The `tracked` column of `show stat`: `<proxy>/<server>`, empty for a server that tracks
/// nothing.
#[must_use]
pub fn tracked_label(proxy: &Proxy, s: usize) -> &str {
    proxy.server_track.as_ref().and_then(|t| t.get(s)).and_then(Option::as_ref).map_or("", |t| t.label.as_str())
}

/// Whether the maintenance or drain of server `s` comes from its target and not from the
/// operator (`show stat` prints `MAINT (via <target>)`, `show servers state` sets the `I`
/// admin flags).
#[must_use]
pub fn inherited(proxy: &Proxy, s: usize) -> bool {
    let Some(tr) = proxy.server_track.as_ref().and_then(|t| t.get(s)).and_then(Option::as_ref) else {
        return false;
    };
    let status = proxy.server_statuses.get(s).map_or(ServerStatus::Up, |a| ServerStatus::from(a.load(Ordering::Relaxed)));
    let own = ServerStatus::from(tr.own.load(Ordering::Relaxed));
    matches!(status, ServerStatus::Maint | ServerStatus::Drain) && own != status
}
