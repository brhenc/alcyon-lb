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

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::check::ServerStatus;
use crate::srvlog::{Cause, Kind};
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
            px.fwrr.changed();
            propagate(proxies, q, t);
        }
    }
}

/// Sets the state of server `s` of proxy `p`: a check's verdict, or what an operator asked.
/// For a tracker, the state is what the operator forced on it (`Up` for nothing), and the
/// server's own is that combined with its target's.
pub fn set_status(proxies: &[Proxy], p: usize, s: usize, st: ServerStatus, kind: Kind, cause: Cause<'_>) {
    set_raw(proxies, p, s, st as u8, kind, cause);
}

/// [`set_status`] with a `Proxy::server_statuses` value, [`crate::check::DRAIN_DOWN`]
/// included.
///
/// `kind` and `cause` say what `HAProxy` would write about the change ([`crate::srvlog`]).
pub fn set_raw(proxies: &[Proxy], p: usize, s: usize, raw: u8, kind: Kind, cause: Cause<'_>) {
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
        crate::srvlog::note(proxies, p, s, before, after, kind, cause, be_down && !was_be_down);
    }
}

fn set_status_inner(proxies: &[Proxy], p: usize, s: usize, raw: u8) {
    if let Some(tr) = track_of(proxies, p, s) {
        let st = ServerStatus::from(raw);
        tr.own.store(st as u8, Ordering::Relaxed);
        let (tp, ts) = tr.target;
        let eff = combine(st, load(proxies, tp, ts));
        proxies[p].server_statuses[s].store(eff as u8, Ordering::Relaxed);
        proxies[p].fwrr.changed();
    } else if let Some(a) = proxies.get(p).and_then(|px| px.server_statuses.get(s)) {
        a.store(raw, Ordering::Relaxed);
        proxies[p].fwrr.changed();
    }
    propagate(proxies, p, s);
}

/// Resolves every `track` of the configuration into the proxies, and gives each tracker the
/// state of its target. The load has already refused a target that does not exist.
pub fn attach(proxies: &mut [Proxy], config: &alcyon_config::Config) {
    use alcyon_config::parser::tracked_target;
    // Nothing to resolve in the common case, and nothing allocated for it: a configuration
    // of sixty thousand backends is held to a memory bound.
    let any = |servers: &[alcyon_config::Server]| servers.iter().any(|s| s.track.is_some());
    if !config.listens.iter().any(|l| any(&l.servers)) && !config.backends.iter().any(|b| any(&b.servers)) {
        return;
    }
    let sections: Vec<(&str, &[alcyon_config::Server])> = config
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
pub fn apply_admin(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState], p: usize, s: usize, to: ServerStatus, cause: Cause<'_>) {
    // A server with no address stays in maintenance (`SRV_ADMF_RMAINT` outlives `enable
    // server` and `set server state ready`: "leaving forced maintenance but remains in
    // maintenance").
    // The operator's state is kept under it, taken back when the name resolves again
    // (`SRV_ADMF_FMAINT`/`FDRAIN` beside `RMAINT`; measured on HAProxy 3.5-dev8).
    if let Some(px) = proxies.get(p).filter(|px| px.server_rmaint(s)) {
        let to = if matches!(to, ServerStatus::Maint | ServerStatus::Drain) { to } else { ServerStatus::Up };
        if px.server_rmaint_kept(s) == ServerStatus::Maint && to != ServerStatus::Maint {
            crate::srvlog::line(proxies, p, s, alcyon_config::LogLevel::Notice, "is leaving forced maintenance but remains in maintenance");
        }
        px.set_server_rmaint(s, Some(to));
        return;
    }
    set_admin(proxies, checks, p, s, to, cause);
}

/// [`apply_admin`] without the `SRV_ADMF_RMAINT` guard: the resolver taking a server into
/// maintenance, or giving it back the admin state it had (`crate::resolvers`).
pub fn set_admin(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState], p: usize, s: usize, to: ServerStatus, cause: Cause<'_>) {
    if track_of(proxies, p, s).is_some() {
        set_status(proxies, p, s, to, Kind::Admin, cause);
        return;
    }
    let Some(px) = proxies.get(p) else { return };
    let mut ops = lock_ops(px);
    adopt(&mut ops, p, checks);
    if let Some(c) = checks.iter_mut().find(|c| c.proxy() == p && c.server() == s) {
        c.set_admin_status(to);
        publish_view(px, c);
        set_raw(proxies, p, s, c.published(), Kind::Admin, cause);
    } else if let Some(cur) = px.server_statuses.get(s) {
        queue(&mut ops, px, s, CheckOp::Admin(to));
        set_raw(proxies, p, s, crate::check::admin_transition(cur.load(Ordering::Relaxed), to), Kind::Admin, cause);
    }
}

/// An operator's change to a checked server made on a worker that does not hold its check
/// (the checks run on worker 0; the stats page answers on every worker, T593). The change is
/// applied to `Proxy::server_statuses` and logged where it is made, as `HAProxy` does under
/// the server lock whichever thread runs the applet (`srv_set_stopped`, `srv_adm_set_ready`,
/// `src/server.c`), and queued here for the owner of the check, which takes it into its
/// state before it publishes anything ([`publish_check`]), so its next step does not put
/// its stale state back.
#[derive(Debug, Clone, Copy)]
pub enum CheckOp {
    Admin(ServerStatus),
    Health(bool),
    Enabled(bool),
}

/// The [`CheckOp`]s of one proxy waiting for the owner of the checks, a field of the proxy's
/// counters that every worker shares. Its lock is the server lock of the checked servers of
/// the proxy: whoever changes their state, the owner included, holds it.
#[derive(Debug, Default)]
pub struct CheckOps(std::sync::Mutex<Vec<(u32, CheckOp)>>);

/// The check state of each checked server of one proxy, as the owner of the checks (worker 0)
/// last published it, for the stats pages the other workers serve (T597). A slot is `None`
/// until its check has stepped once. Its lock is taken for a read per server row of a page and
/// for a write per check step, never on the request path.
#[derive(Debug, Default)]
pub struct CheckViews(std::sync::Mutex<Vec<Option<crate::check::CheckView<'static>>>>);

/// The check of server `s` of `px` for a stats page: its own state when this worker holds the
/// checks, else the copy worker 0 published.
pub fn check_view<'a>(px: &Proxy, checks: &'a [crate::check::ServerCheckState], p: usize, s: usize) -> Option<crate::check::CheckView<'a>> {
    if !checks.is_empty() {
        let i = checks.partition_point(|c| (c.proxy(), c.server()) < (p, s));
        return checks.get(i).filter(|c| c.proxy() == p && c.server() == s).map(crate::check::ServerCheckState::view);
    }
    px.server_check_configs.get(s).filter(|c| c.is_some())?;
    let views = px.txn_counters().check_views.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    views.get(s).and_then(Clone::clone)
}

/// Publishes the state of `check` for [`check_view`]; after every change of it.
pub fn publish_view(px: &Proxy, check: &crate::check::ServerCheckState) {
    let s = check.server();
    let mut views = px.txn_counters().check_views.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if views.len() <= s {
        views.resize(px.server_check_configs.len().max(s + 1), None);
    }
    match &mut views[s] {
        Some(v) => v.refresh(check),
        slot @ None => {
            let mut v = check.view().into_owned();
            v.refresh(check);
            *slot = Some(v);
        }
    }
}

/// How many [`CheckOp`]s wait in all proxies.
static OPS_PENDING: AtomicUsize = AtomicUsize::new(0);

fn lock_ops(px: &Proxy) -> std::sync::MutexGuard<'_, Vec<(u32, CheckOp)>> {
    px.txn_counters().check_ops.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Queues `op` for server `s` when it has a check (held by another worker); a server with
/// no check has nothing but `Proxy::server_statuses`.
fn queue(ops: &mut Vec<(u32, CheckOp)>, px: &Proxy, s: usize, op: CheckOp) {
    if px.server_check_configs.get(s).is_some_and(Option::is_some) {
        ops.push((crate::engine::usize_to_u32(s), op));
        OPS_PENDING.fetch_add(1, Ordering::Release);
    }
}

/// Applies to `checks` the queued ops of proxy `p` whose check is there, in order; the
/// others stay queued.
fn adopt(ops: &mut Vec<(u32, CheckOp)>, p: usize, checks: &mut [crate::check::ServerCheckState]) {
    if ops.is_empty() || checks.is_empty() {
        return;
    }
    let before = ops.len();
    ops.retain(|&(s, op)| {
        let Some(c) = checks.iter_mut().find(|c| c.proxy() == p && c.server() == s as usize) else {
            return true;
        };
        match op {
            CheckOp::Admin(to) => c.set_admin_status(to),
            CheckOp::Health(up) => c.set_health(up),
            CheckOp::Enabled(on) => c.enabled = on,
        }
        false
    });
    OPS_PENDING.fetch_sub(before - ops.len(), Ordering::Release);
}

/// The owner of `check` takes the changes made elsewhere before the check runs a step, so
/// that its verdict lands on top of them, as `HAProxy`'s does (measured: a check passing
/// after `hdown` brings a `rise 1` server back up).
pub fn adopt_for(proxies: &[Proxy], check: &mut crate::check::ServerCheckState) {
    if OPS_PENDING.load(Ordering::Acquire) == 0 {
        return;
    }
    if let Some(px) = proxies.get(check.proxy()) {
        adopt(&mut lock_ops(px), check.proxy(), std::slice::from_mut(check));
    }
}

/// The owner of the checks takes the changes the other workers made (once per loop pass,
/// only when some wait), so `show stat` on its CLI reads them before the next check step.
pub fn adopt_pending(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState]) {
    if checks.is_empty() || OPS_PENDING.load(Ordering::Acquire) == 0 {
        return;
    }
    for (p, px) in proxies.iter().enumerate() {
        if px.ids.tc.get().is_some() {
            let mut ops = lock_ops(px);
            let had = !ops.is_empty();
            adopt(&mut ops, p, checks);
            if had {
                for c in checks.iter().filter(|c| c.proxy() == p) {
                    publish_view(px, c);
                }
            }
            // Every check is here: what is left has none (a server added since), nothing
            // will take it, and it must not make every loop pass take the locks.
            OPS_PENDING.fetch_sub(ops.len(), Ordering::Release);
            ops.clear();
        }
    }
}

/// `enable health`/`disable health` (CLI) and the stats page's `ehlth`/`dhlth` on server
/// `s` of proxy `p`; false when it has no check.
pub fn set_check_enabled(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState], p: usize, s: usize, enabled: bool, now: alcyon_sched::Tick) -> bool {
    let Some(px) = proxies.get(p) else { return false };
    let mut ops = lock_ops(px);
    adopt(&mut ops, p, checks);
    if let Some(c) = checks.iter_mut().find(|c| c.proxy() == p && c.server() == s) {
        c.enabled = enabled;
        if enabled {
            c.next_check = now;
        }
        publish_view(px, c);
        true
    } else if px.server_check_configs.get(s).is_some_and(Option::is_some) {
        queue(&mut ops, px, s, CheckOp::Enabled(enabled));
        true
    } else {
        false
    }
}

/// A check's verdict reaches `Proxy::server_statuses`: the owner of the check (worker 0)
/// after each step of it.
pub fn publish_check(proxies: &[Proxy], check: &mut crate::check::ServerCheckState) {
    let (p, s) = (check.proxy(), check.server());
    let Some(px) = proxies.get(p) else { return };
    // Under the lock: a change another worker makes is either taken in first, or made
    // after this publication, on top of it (T593).
    let mut ops = lock_ops(px);
    adopt(&mut ops, p, std::slice::from_mut(check));
    publish_view(px, check);
    if check.enabled && s < px.server_statuses.len() {
        set_raw(proxies, p, s, check.published(), Kind::Op, Cause::Check(check));
    }
}

/// Whether server `s` of proxy `p` tracks another one.
pub fn is_tracking(proxies: &[Proxy], p: usize, s: usize) -> bool {
    track_of(proxies, p, s).is_some()
}

/// `set server health up|down` on server `s` of proxy `p` (not a tracker: refused before):
/// the operational state moves, the admin state stays.
pub fn apply_health(proxies: &[Proxy], checks: &mut [crate::check::ServerCheckState], p: usize, s: usize, up: bool, cause: Cause<'_>) {
    let Some(px) = proxies.get(p) else { return };
    let mut ops = lock_ops(px);
    adopt(&mut ops, p, checks);
    if let Some(c) = checks.iter_mut().find(|c| c.proxy() == p && c.server() == s) {
        c.set_health(up);
        publish_view(px, c);
        set_raw(proxies, p, s, c.published(), Kind::Op, cause);
    } else if let Some(cur) = px.server_statuses.get(s) {
        queue(&mut ops, px, s, CheckOp::Health(up));
        set_raw(proxies, p, s, crate::check::health_transition(cur.load(Ordering::Relaxed), up), Kind::Op, cause);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::ServerCheckState;

    /// Backend `b`: `s1` checked, `s2` a backup; the check of `s1` as worker 0 holds it.
    fn setup() -> (crate::engine::Proxies, ServerCheckState) {
        let c = "defaults\n    mode http\nbackend b\n    server s1 127.0.0.1:1 check inter 200ms fall 1 rise 1\n    server s2 127.0.0.1:1 backup\n";
        let config = alcyon_config::parse_str(c).expect("config");
        let proxies = crate::engine::Engine::build_shared_state(&config).expect("proxies");
        let p = proxies.iter().position(|x| x.name == "b").expect("b");
        let cfg = proxies[p].server_check_configs[0].clone().expect("check");
        let addr = proxies[p].servers.get(0).expect("s1");
        let check = ServerCheckState::new(p, 0, addr, cfg, alcyon_sched::Tick(1));
        (proxies, check)
    }

    fn lines(proxies: &[Proxy]) -> Vec<String> {
        let mut out = Vec::new();
        crate::srvlog::drain(proxies, |_, _, l| out.push(l.to_owned()));
        out
    }

    fn status(proxies: &[Proxy], p: usize) -> u8 {
        proxies[p].server_statuses[0].load(Ordering::Relaxed)
    }

    /// T593: the stats page runs on any worker, the check of the server on worker 0 only. A
    /// change made where the check is not (an empty `checks`) is applied and logged once, and
    /// the owner's next check step keeps it instead of putting its own stale state back.
    #[test]
    fn admin_change_from_a_worker_without_the_check() {
        let (proxies, mut check) = setup();
        let p = check.proxy();
        publish_check(&proxies, &mut check);
        drop(lines(&proxies));

        apply_admin(&proxies, &mut [], p, 0, ServerStatus::Maint, Cause::WebDisable);
        publish_check(&proxies, &mut check);
        assert_eq!(status(&proxies, p), ServerStatus::Maint as u8);
        let l = lines(&proxies);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("Server b/s1 is going DOWN for maintenance ('disable' on stats page)."), "{l:?}");

        apply_admin(&proxies, &mut [], p, 0, ServerStatus::Up, Cause::Web);
        publish_check(&proxies, &mut check);
        assert_eq!(status(&proxies, p), ServerStatus::Up as u8);
        assert_eq!(lines(&proxies), ["Server b/s1 is UP/READY (leaving forced maintenance)."]);
    }

    /// T593, the test's sequence: `hdown` and `hrunn` on the stats page of another worker,
    /// then `set server b/s1 health down` on the CLI (worker 0, the owner).
    #[test]
    fn health_change_from_a_worker_without_the_check() {
        let (proxies, mut check) = setup();
        let p = check.proxy();
        publish_check(&proxies, &mut check);
        drop(lines(&proxies));

        apply_health(&proxies, &mut [], p, 0, false, Cause::Web);
        publish_check(&proxies, &mut check);
        assert_eq!(status(&proxies, p), ServerStatus::Down as u8);
        let l = lines(&proxies);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("Server b/s1 is DOWN, changed from Web interface."), "{l:?}");

        apply_health(&proxies, &mut [], p, 0, true, Cause::Web);
        publish_check(&proxies, &mut check);
        assert_eq!(status(&proxies, p), ServerStatus::Up as u8);
        let l = lines(&proxies);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("Server b/s1 is UP, changed from Web interface."), "{l:?}");

        apply_health(&proxies, std::slice::from_mut(&mut check), p, 0, false, Cause::Cli);
        assert_eq!(status(&proxies, p), ServerStatus::Down as u8);
        let l = lines(&proxies);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("Server b/s1 is DOWN, changed from CLI."), "{l:?}");
    }

    /// A check that passes after an `hdown` made on another worker brings a `rise 1` server
    /// back up (measured on `HAProxy` 3.5-dev8, `nbthread 4`): the owner takes the change in
    /// before the step, and the verdict lands on top of it.
    #[test]
    fn a_check_after_a_change_from_another_worker_lands_on_top() {
        let (proxies, mut check) = setup();
        let p = check.proxy();
        publish_check(&proxies, &mut check);
        apply_health(&proxies, &mut [], p, 0, false, Cause::Web);
        drop(lines(&proxies));
        adopt_for(&proxies, &mut check);
        check.on_success(0);
        publish_check(&proxies, &mut check);
        assert_eq!(status(&proxies, p), ServerStatus::Up as u8);
        let l = lines(&proxies);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].starts_with("Server b/s1 is UP, reason: Layer4 check passed"), "{l:?}");
    }

    /// `ehlth`/`dhlth` on another worker are queued and taken in by the owner in order; an
    /// op for a check that is not in the slice the owner passes stays queued for it.
    #[test]
    fn check_enable_from_a_worker_without_the_check_and_ops_of_other_checks() {
        let c = "defaults\n    mode http\nbackend b\n    server s1 127.0.0.1:1 check\n    server s2 127.0.0.1:1 check\n    server s3 127.0.0.1:1\n";
        let config = alcyon_config::parse_str(c).expect("config");
        let proxies = crate::engine::Engine::build_shared_state(&config).expect("proxies");
        let p = proxies.iter().position(|x| x.name == "b").expect("b");
        let mk = |s: usize| {
            let cfg = proxies[p].server_check_configs[s].clone().expect("check");
            ServerCheckState::new(p, s, proxies[p].servers.get(s).expect("addr"), cfg, alcyon_sched::Tick(1))
        };
        let (mut c1, mut c2) = (mk(0), mk(1));
        assert!(!set_check_enabled(&proxies, &mut [], p, 2, false, alcyon_sched::Tick(1)), "s3 has no check");

        // `hdown` on s2 elsewhere; s1's check step leaves it queued for s2's.
        apply_health(&proxies, &mut [], p, 1, false, Cause::Web);
        publish_check(&proxies, &mut c1);
        assert_eq!(c2.status, ServerStatus::Up);
        adopt_for(&proxies, &mut c2);
        assert_eq!(c2.status, ServerStatus::Down);

        assert!(set_check_enabled(&proxies, &mut [], p, 0, false, alcyon_sched::Tick(1)));
        assert!(c1.enabled);
        adopt_for(&proxies, &mut c1);
        assert!(!c1.enabled);
        // The owner's own `enable health` takes the queue in first, then reschedules.
        assert!(set_check_enabled(&proxies, &mut [], p, 0, false, alcyon_sched::Tick(1)));
        assert!(set_check_enabled(&proxies, std::slice::from_mut(&mut c1), p, 0, true, alcyon_sched::Tick(7)));
        assert!(c1.enabled);
        assert_eq!(c1.next_check, alcyon_sched::Tick(7));
        drop(lines(&proxies));
    }
}
