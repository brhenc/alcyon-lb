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
    set_raw(proxies, p, s, st as u8);
}

/// [`set_status`] with a `Proxy::server_statuses` value, [`crate::check::DRAIN_DOWN`]
/// included.
pub fn set_raw(proxies: &[Proxy], p: usize, s: usize, raw: u8) {
    let status_of = || proxies.get(p).and_then(|px| px.server_statuses.get(s)).map_or(0, |a| a.load(Ordering::Relaxed));
    let before = status_of();
    set_status_inner(proxies, p, s, raw);
    // `lastchg`, `downtime` and `chkdown` of `show stat` follow the server's state.
    let after = status_of();
    if before != after {
        let px = &proxies[p];
        let down_of = |v: u8| ServerStatus::from(v) == ServerStatus::Down;
        let (was_down, down) = (down_of(before), down_of(after));
        let pc = px.txn_counters();
        if let Some(c) = pc.srv.get(s) {
            c.state_changed(was_down, down);
        }
        // The backend is down when no server of it is up; its own `lastchg`, `downtime` and
        // `chkdown` move when that flips (measured: `disable server` on the only server
        // turns the backend `DOWN`, `chkdown` 1).
        let be_down = !px.server_statuses.iter().any(|a| a.load(Ordering::Relaxed) == ServerStatus::Up as u8);
        let was_be_down = pc.be.down_since.load(Ordering::Relaxed) != 0;
        if be_down != was_be_down {
            pc.be.state_changed(was_be_down, be_down);
        }
    }
}

fn set_status_inner(proxies: &[Proxy], p: usize, s: usize, raw: u8) {
    if let Some(tr) = track_of(proxies, p, s) {
        let st = ServerStatus::from(raw);
        tr.own.store(st as u8, Ordering::Relaxed);
        let (tp, ts) = tr.target;
        let eff = combine(st, load(proxies, tp, ts));
        proxies[p].server_statuses[s].store(eff as u8, Ordering::Relaxed);
    } else if let Some(a) = proxies.get(p).and_then(|px| px.server_statuses.get(s)) {
        a.store(raw, Ordering::Relaxed);
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
    for (p, (name, servers)) in sections.iter().enumerate() {
        tracks.push(
            servers
                .iter()
                .enumerate()
                .map(|(s, server)| {
                    let spec = server.track.as_deref()?;
                    let (tpx, tsv) = tracked_target(name, spec);
                    let target = find(tpx, tsv)?;
                    // A server with no address (`init-addr none`) is in maintenance of its own.
                    let own = if server.disabled || proxies[p].server_rmaint(s) { ServerStatus::Maint } else { ServerStatus::Up };
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

/// The operator sets the admin state of server `s` of proxy `p` to `to` (`Up` for `ready`,
/// `Drain` or `Maint`): `enable`/`disable server`, `set server state`, the stats page's
/// admin form. It moves the admin state only: what the checks found (`cur_state`) is kept,
/// so `ready` does not send traffic to a server they found dead (T274 E1).
pub fn apply_admin(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState], p: usize, s: usize, to: ServerStatus) {
    // A server with no address stays in maintenance (`SRV_ADMF_RMAINT` outlives `enable
    // server` and `set server state ready`: "leaving forced maintenance but remains in
    // maintenance").
    if proxies.get(p).is_some_and(|px| px.server_rmaint(s)) {
        return;
    }
    set_admin(proxies, checks, p, s, to);
}

/// [`apply_admin`] without the `SRV_ADMF_RMAINT` guard: the resolver taking a server into
/// maintenance, or giving it back the admin state it had (`crate::resolvers`).
pub fn set_admin(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState], p: usize, s: usize, to: ServerStatus) {
    let check = checks.iter_mut().find(|c| c.proxy() == p && c.server() == s);
    if track_of(proxies, p, s).is_some() {
        set_status(proxies, p, s, to);
    } else if let Some(c) = check {
        c.set_admin_status(to);
        set_raw(proxies, p, s, c.published());
    } else if let Some(cur) = proxies.get(p).and_then(|px| px.server_statuses.get(s)) {
        set_raw(proxies, p, s, crate::check::admin_transition(cur.load(Ordering::Relaxed), to));
    }
}

/// Whether server `s` of proxy `p` tracks another one.
pub fn is_tracking(proxies: &[Proxy], p: usize, s: usize) -> bool {
    track_of(proxies, p, s).is_some()
}

/// `set server health up|down` on server `s` of proxy `p` (not a tracker: refused before):
/// the operational state moves, the admin state stays.
pub fn apply_health(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState], p: usize, s: usize, up: bool) {
    if let Some(c) = checks.iter_mut().find(|c| c.proxy() == p && c.server() == s) {
        c.set_health(up);
        set_raw(proxies, p, s, c.published());
    } else if let Some(cur) = proxies.get(p).and_then(|px| px.server_statuses.get(s)) {
        set_raw(proxies, p, s, crate::check::health_transition(cur.load(Ordering::Relaxed), up));
    }
}
