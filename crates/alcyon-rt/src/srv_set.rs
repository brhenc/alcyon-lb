// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The servers of one backend, read through one door (T637, slice S1a).
//!
//! A server is a position in about 25 parallel arrays on [`Proxy`]. Every reader that walks
//! them or looks a server up by name has to remember what a missing server looks like; when the
//! set of servers can change at run time (`docs/design/runtime-server-set-2026-11-16.md`), the
//! one that forgets reads a deleted server. This module is the first step: the cold readers go
//! through [`ServerSet`] and [`Srv`], so that when the arrays are made private (S1b) and given
//! slots that can be empty, there is one place that knows.
//!
//! Today the set is a *view* of the proxy's arrays: nothing is copied and nothing changes
//! behaviour. A slot is empty when its name is empty (a configured server always has one), and
//! [`ServerSet::at`], [`ServerSet::find`], [`ServerSet::by_puid`] and [`ServerSet::live`] do
//! not return an empty slot.
//!
//! `harness/server_set_census.py` counts the places outside this file that still name an array.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use crate::check::{ServerCheckConfig, ServerStatus};
use crate::engine::{Proxy, RateCtr};
use crate::track::Track;

/// The servers of a proxy.
#[derive(Clone, Copy)]
pub struct ServerSet<'a>(&'a Proxy);

/// One server of a [`ServerSet`]. Only the set makes one.
#[derive(Clone, Copy)]
pub struct Srv<'a> {
    px: &'a Proxy,
    i: usize,
}

impl Proxy {
    /// This proxy's servers.
    #[must_use]
    pub fn srv_set(&self) -> ServerSet<'_> {
        ServerSet(self)
    }

    /// Server `idx`'s configured weight, whatever it is now.
    #[must_use]
    pub fn initial_weight(&self, idx: usize) -> u32 {
        self.srv_set().at(idx).and_then(|s| s.initial_weight()).unwrap_or(1)
    }

    /// Changes server `idx`'s current weight, keeping the configured one for
    /// [`Self::initial_weight`]. The weights are shared: every worker's next balancing
    /// decision sees it.
    pub fn set_weight(&self, idx: usize, weight: u32) {
        if let Some(s) = self.srv_set().at(idx) {
            s.set_weight(weight);
        }
        self.fwrr.changed();
    }

    /// The places where the load writes into the set (the proxy is not shared yet).
    pub fn srv_set_mut(&mut self) -> ServerSetMut<'_> {
        ServerSetMut(self)
    }
}

impl<'a> ServerSet<'a> {
    /// Number of slots, empty ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.server_ids.len()
    }

    /// No slot at all (a frontend, or a backend without servers).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.servers.is_empty()
    }

    /// The server in slot `i`; `None` when there is no such slot or it is empty.
    #[must_use]
    pub fn at(&self, i: usize) -> Option<Srv<'a>> {
        self.0.server_ids.get(i).filter(|n| !n.is_empty()).map(|_| Srv { px: self.0, i })
    }

    /// The server called `name`.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Srv<'a>> {
        self.live().find(|s| s.name() == name)
    }

    /// The server whose `puid` is `id`.
    #[must_use]
    pub fn by_puid(&self, id: u32) -> Option<Srv<'a>> {
        self.live().find(|s| s.puid() == id)
    }

    /// The servers that exist, in the order they are listed.
    pub fn live(&self) -> impl Iterator<Item = Srv<'a>> + 'a {
        let px = self.0;
        (0..px.server_ids.len()).filter_map(move |i| px.srv_set().at(i))
    }

    /// Whether any server is up (`Up` itself: a draining server is not).
    #[must_use]
    pub fn any_up(&self) -> bool {
        self.0.server_statuses.iter().any(|a| a.load(Ordering::Relaxed) == ServerStatus::Up as u8)
    }

    /// `(slot, status)` of every status cell, for the page that totals them.
    pub fn raw_statuses(&self) -> impl Iterator<Item = u8> + 'a {
        self.0.server_statuses.iter().map(|a| a.load(Ordering::Relaxed))
    }

    /// Whether slot `i` has a health-check configuration.
    #[must_use]
    pub fn checked(&self, i: usize) -> bool {
        self.0.server_check_configs.get(i).is_some_and(Option::is_some)
    }

    /// How many slots have a check configuration vector (the length views are sized to).
    #[must_use]
    pub fn check_slots(&self) -> usize {
        self.0.server_check_configs.len()
    }

    /// Slot `i`'s check configuration.
    #[must_use]
    pub fn check_config(&self, i: usize) -> Option<&'a Arc<ServerCheckConfig>> {
        self.0.server_check_configs.get(i).and_then(Option::as_ref)
    }

    /// Slot `i`'s tracking, `None` when it tracks nothing.
    #[must_use]
    pub fn track(&self, i: usize) -> Option<&'a Track> {
        self.0.server_track.as_ref()?.get(i)?.as_ref()
    }

    /// What each slot tracks, `None` when no server tracks anything.
    #[must_use]
    pub fn tracks(&self) -> Option<&'a [Option<Track>]> {
        self.0.server_track.as_ref().map(|t| t.as_slice())
    }

    /// The `(wretr, wredis, econ)` of slot `i`.
    #[must_use]
    pub fn retr(&self, i: usize) -> (u64, u64, u64) {
        self.0.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&i).copied().unwrap_or_default()
    }
}

impl<'a> Srv<'a> {
    /// The slot, which streams, checks and messages hold.
    #[must_use]
    pub fn index(&self) -> usize {
        self.i
    }

    /// Its name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.px.server_ids.get(self.i).unwrap_or("")
    }

    /// Renames it (the CLI; allocates).
    pub fn rename(&self, new: &str) {
        self.px.server_ids.set(self.i, new);
    }

    /// Its numeric id in the backend.
    #[must_use]
    pub fn puid(&self) -> u32 {
        self.px.server_puid(self.i)
    }

    /// Its address; `None` when the address array has no such slot.
    #[must_use]
    pub fn addr(&self) -> Option<SocketAddr> {
        self.px.servers.get(self.i)
    }

    /// Changes its address, in place for every worker.
    pub fn set_addr(&self, a: SocketAddr) {
        self.px.servers.set(self.i, a);
    }

    /// The cell holding its status.
    #[must_use]
    pub fn status_cell(&self) -> Option<&'a AtomicU8> {
        self.px.server_statuses.get(self.i)
    }

    /// Its status as stored.
    #[must_use]
    pub fn raw_status(&self) -> Option<u8> {
        self.status_cell().map(|a| a.load(Ordering::Relaxed))
    }

    /// Stores its status and returns the one it had.
    #[must_use]
    pub fn swap_status(&self, v: u8) -> Option<u8> {
        self.status_cell().map(|a| a.swap(v, Ordering::Relaxed))
    }

    /// Stores its status.
    pub fn store_status(&self, v: u8) {
        if let Some(a) = self.status_cell() {
            a.store(v, Ordering::Relaxed);
        }
    }

    /// Its current weight.
    #[must_use]
    pub fn weight(&self) -> Option<u32> {
        self.px.server_weights.get(self.i)
    }

    /// Its configured weight.
    #[must_use]
    pub fn initial_weight(&self) -> Option<u32> {
        self.px.server_weights.initial(self.i)
    }

    /// Sets its current weight, keeping the configured one.
    pub fn set_weight(&self, w: u32) {
        self.px.server_weights.set(self.i, w);
    }

    /// Its `maxconn`, `None` when it has none.
    #[must_use]
    pub fn maxconn(&self) -> Option<u32> {
        self.px.server_maxconn.get(self.i)
    }

    /// Streams on it now.
    #[must_use]
    pub fn actconn(&self) -> u32 {
        self.px.server_actconn.get(self.i).map_or(0, |a| a.load(Ordering::Relaxed))
    }

    /// Its session-rate counter.
    #[must_use]
    pub fn sess_rate(&self) -> Option<&'a RateCtr> {
        self.px.server_sess_rates.get(self.i)
    }

    /// Whether it is a `backup` server.
    #[must_use]
    pub fn backup(&self) -> bool {
        self.px.server_backups.get(self.i).copied().unwrap_or(false)
    }

    /// Whether it has TLS (`ssl`).
    #[must_use]
    pub fn has_tls(&self) -> bool {
        self.px.server_tls.get(self.i).is_some_and(Option::is_some)
    }

    /// Whether a sample fetch names it, so it cannot be renamed.
    #[must_use]
    pub fn name_refd(&self) -> bool {
        self.px.server_name_refd.get(self.i).copied().unwrap_or(false)
    }

    /// Its check configuration.
    #[must_use]
    pub fn check_config(&self) -> Option<&'a Arc<ServerCheckConfig>> {
        self.px.srv_set().check_config(self.i)
    }

    /// Whether it has no address (`SRV_ADMF_RMAINT`).
    #[must_use]
    pub fn rmaint(&self) -> bool {
        self.px.server_rmaint(self.i)
    }
}

/// What the load writes into a proxy's server arrays while it still owns the proxy.
pub struct ServerSetMut<'a>(&'a mut Proxy);

impl ServerSetMut<'_> {
    /// Gives each server what it tracks.
    pub fn set_tracks(&mut self, t: Vec<Option<Track>>) {
        self.0.server_track = Some(Arc::new(t));
    }

    /// What `show servers state` prints as slot `i`'s health when it has no check.
    pub fn set_init_health(&mut self, i: usize, health: u32) {
        let n = self.0.servers.len();
        let h = &mut self.0.ids.server_init_health;
        if h.len() < n {
            h.resize(n, 0);
        }
        h[i] = health;
    }

    /// What the server-state file gave slot `i`.
    pub fn set_restored(&mut self, i: usize, r: crate::server_state::Restored) {
        let n = self.0.servers.len();
        let slots = &mut self.0.ids.server_restored;
        if slots.len() < n {
            slots.resize(n, None);
        }
        slots[i] = Some(r);
    }

    /// Points slot `i`'s checks at `port`, when it has a check.
    pub fn set_check_port(&mut self, i: usize, port: u16) {
        if let Some(slot) = self.0.server_check_configs.get_mut(i) {
            if let Some(cfg) = slot.as_deref() {
                *slot = Some(Arc::new(ServerCheckConfig { check_port: Some(port), ..cfg.clone() }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies() -> crate::engine::Proxies {
        let c = "defaults\n    mode http\nbackend b\n    server s1 127.0.0.1:1 id 7\n    server s2 127.0.0.1:2 backup\n    server s3 127.0.0.1:3\nfrontend f\n    bind 127.0.0.1:0\n";
        let config = alcyon_config::parse_str(c).expect("config");
        crate::engine::Engine::build_shared_state(&config).expect("proxies")
    }

    fn backend(proxies: &crate::engine::Proxies) -> &Proxy {
        proxies.iter().find(|p| p.name == "b").expect("b")
    }

    #[test]
    fn a_check_port_reaches_the_check_of_a_checked_server_only() {
        let c = "defaults\n    mode http\nbackend b\n    server s1 127.0.0.1:1 check\n    server s2 127.0.0.1:2\nfrontend f\n    bind 127.0.0.1:0\n";
        let config = alcyon_config::parse_str(c).expect("config");
        let mut all = crate::engine::Engine::build_shared_state(&config).expect("proxies").into_vec();
        let p = all.iter_mut().find(|p| p.name == "b").expect("b");
        p.srv_set_mut().set_check_port(0, 9999);
        p.srv_set_mut().set_check_port(1, 9999);
        assert_eq!(p.srv_set().check_config(0).and_then(|c| c.check_port), Some(9999));
        assert!(p.srv_set().check_config(1).is_none());
    }

    #[test]
    fn a_server_is_found_by_name_by_slot_and_by_id() {
        let all = proxies();
        let p = backend(&all);
        let set = p.srv_set();
        assert_eq!(set.len(), 3);
        assert_eq!(set.find("s2").map(|s| s.index()), Some(1));
        assert!(set.find("nobody").is_none());
        assert_eq!(set.at(2).map(|s| s.name()), Some("s3"));
        assert!(set.at(3).is_none());
        assert_eq!(set.by_puid(7).map(|s| s.name()), Some("s1"));
        assert!(set.by_puid(99).is_none());
        assert!(set.at(1).expect("s2").backup());
        assert!(!set.at(0).expect("s1").backup());
    }

    #[test]
    fn live_skips_an_empty_slot_and_so_do_the_lookups() {
        let all = proxies();
        let p = backend(&all);
        p.srv_set().at(1).expect("s2").rename("");
        let set = p.srv_set();
        assert_eq!(set.len(), 3, "the slot is still there");
        assert_eq!(set.live().map(|s| s.name()).collect::<Vec<_>>(), ["s1", "s3"]);
        assert!(set.at(1).is_none());
        assert!(set.find("").is_none());
        assert_eq!(set.live().map(|s| s.index()).collect::<Vec<_>>(), [0, 2]);
    }

    #[test]
    fn a_rename_and_an_address_are_seen_through_the_set() {
        let all = proxies();
        let p = backend(&all);
        let s = p.srv_set().find("s3").expect("s3");
        s.rename("three");
        assert!(p.srv_set().find("s3").is_none());
        let s = p.srv_set().find("three").expect("three");
        let a: SocketAddr = "10.0.0.1:80".parse().expect("addr");
        s.set_addr(a);
        assert_eq!(p.srv_set().at(2).and_then(|s| s.addr()), Some(a));
        s.set_weight(5);
        assert_eq!((s.weight(), p.initial_weight(2)), (Some(5), 1));
        assert_eq!(s.actconn(), 0);
        assert_eq!(s.maxconn(), None);
    }
}
