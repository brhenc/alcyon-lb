// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The backends of the process: the published [`Table`] (T637, slice S2).
//!
//! `docs/design/runtime-server-set-2026-11-16.md` section 3.1. A backend is a *slot* of the table
//! for its whole life: [`Table::get`] by slot is a chunk pointer and an `Arc` pointer. The table
//! is immutable. A change builds a new one that shares every chunk it did not touch
//! ([`Table::replace`]), posts it to every worker ([`publish`], [`crate::mailbox::Msg::Table`])
//! and each worker swaps at the top of its loop, between two events, and replies with the epoch
//! it now reads. Nothing is freed under a reader: an old table goes when the last worker drops
//! its pointer.
//!
//! The request path compares no backend name. A `use_backend` rule and the `default_backend` of a
//! frontend are resolved to a slot when the table is built ([`Table::new`]), and
//! [`Table::route`] is the one place that turns a rule into a backend: a slot, a backend the
//! configuration disabled, or (later, for backends added at run time) a name looked up in
//! `by_name`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::engine::{Proxy, SharedFlag};
use crate::mailbox::{Gather, Mailboxes, Msg};
use alcyon_sched::task::TaskRef;

/// Slots per chunk. A change copies one chunk (1,024 pointers), never the whole table.
const CHUNK_SHIFT: usize = 10;
const CHUNK: usize = 1 << CHUNK_SHIFT;
/// Chunks a table can address: 131,072 slots. The top level is an inline array of this many
/// pointers, indexed with a mask, so reading a slot has no bounds check to make (the request path
/// reads the table about 90 times a request; with a `Box<[_]>` of chunks it cost 0.9% of ins/req).
const MAX_CHUNKS: usize = 128;
type Chunk = [Arc<Proxy>; CHUNK];

thread_local! {
    static BACKEND_NAME_COMPARISONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many backend-name lookups this thread has made on the request path (debug builds only;
/// always 0 in release): a test reads it around requests to show that `use_backend` and
/// `default_backend` targets are resolved at load.
#[must_use]
pub fn backend_name_comparisons_on_this_thread() -> u64 {
    BACKEND_NAME_COMPARISONS.with(std::cell::Cell::get)
}

/// What a `use_backend` rule or a `default_backend` names, resolved when the table is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The backend at this slot.
    Slot(u32),
    /// A backend the configuration disabled: `force-be-switch` sends the request to it, which
    /// has no server to give.
    Disabled,
    /// A name that is no backend of the table when it was built: looked up by name per request.
    Name,
}

/// The targets of one frontend's routing rules, in the order of its `use_backend` rules.
#[derive(Debug, Clone, Default)]
pub struct Routes {
    rules: Box<[Target]>,
    default: Option<Target>,
}

/// What [`Table::route`] found for one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routed {
    /// The request goes to the backend at this slot.
    Backend(usize),
    /// The rule names a backend `unpublish backend` took out of the switching rules: the
    /// rule is skipped, as one naming a backend the configuration disabled.
    Unpublished(usize),
    /// The rule names a backend `del backend` is deleting: no path enters it, `force-be-switch`
    /// included. The rule is skipped.
    Retiring,
    /// The rule names a backend the configuration disabled.
    Disabled,
    /// The rule names no backend: the next rule is tried.
    Miss,
}

/// The backends, published as one immutable value.
#[derive(Debug)]
pub struct Table {
    epoch: u64,
    len: usize,
    /// Fixed-size chunks: an index is `chunks[slot >> 10][slot & 1023]` with the second bounds
    /// check gone at compile time (T637 S2: the request path indexes the table ~100 times).
    /// A slot at or past `len` holds the empty proxy `filler`: a stale number reads nothing.
    chunks: [Arc<Chunk>; MAX_CHUNKS],
    /// Live backends by name; the first of two proxies with one name (a frontend and a
    /// backend) wins, as the scan it replaces did.
    by_name: Arc<HashMap<Box<str>, u32>>,
    /// The live slots in listing order.
    live: Arc<[u32]>,
}

impl Table {
    fn build(epoch: u64, len: usize, items: &[Arc<Proxy>], filler: &Arc<Proxy>, by_name: Arc<HashMap<Box<str>, u32>>, live: Arc<[u32]>) -> Self {
        let empty: Arc<Chunk> = Arc::new(std::array::from_fn(|_| Arc::clone(filler)));
        let mut real = items.chunks(CHUNK).map(|c| Arc::new(std::array::from_fn(|i| Arc::clone(c.get(i).unwrap_or(filler)))));
        let chunks = std::array::from_fn(|_| real.next().unwrap_or_else(|| Arc::clone(&empty)));
        Self { epoch, len, chunks, by_name, live }
    }
}

impl Table {
    /// The table of `proxies`, epoch 1: slot = position. Resolves every frontend's
    /// `use_backend` and `default_backend` to a slot.
    ///
    /// # Panics
    /// With more than `u32::MAX` proxies.
    #[must_use]
    pub fn new(mut proxies: Vec<Proxy>) -> Self {
        let len = proxies.len();
        let mut by_name: HashMap<Box<str>, u32> = HashMap::with_capacity(len);
        for (i, p) in proxies.iter().enumerate() {
            by_name.entry(p.name.as_str().into()).or_insert_with(|| u32::try_from(i).expect("fewer than 2^32 proxies"));
        }
        for p in &mut proxies {
            resolve_routes(p, &by_name);
        }
        assert!(len <= MAX_CHUNKS * CHUNK, "at most {} proxies", MAX_CHUNKS * CHUNK);
        let items: Vec<Arc<Proxy>> = proxies.into_iter().map(Arc::new).collect();
        let live = (0..u32::try_from(len).expect("fewer than 2^32 proxies")).collect();
        Self::build(1, len, &items, &Arc::new(crate::engine::empty_proxy()), Arc::new(by_name), live)
    }

    /// The next table, with the proxy at `slot` replaced by `proxy` (same name). Every chunk but
    /// the one of `slot` is shared with `self`; so are the name map and the listing.
    ///
    /// # Panics
    /// If `slot` is out of range or `proxy` has another name than the one it replaces.
    #[must_use]
    pub fn replace(&self, slot: usize, mut proxy: Proxy) -> Self {
        assert_eq!(self[slot].name, proxy.name, "a replaced backend keeps its name");
        resolve_routes(&mut proxy, &self.by_name);
        let (c, i) = (slot >> CHUNK_SHIFT, slot & (CHUNK - 1));
        let mut chunks = self.chunks.clone();
        let mut one: Chunk = (*self.chunks[c]).clone();
        one[i] = Arc::new(proxy);
        chunks[c] = Arc::new(one);
        Self { epoch: self.epoch + 1, len: self.len, chunks, by_name: Arc::clone(&self.by_name), live: Arc::clone(&self.live) }
    }

    /// The next table, with the backend at `slot` deleted (T637 S6a, `del backend`). The slot
    /// keeps its place and is never given to another backend (the LB snapshot cache of every
    /// worker is keyed by it): it holds an inert tombstone that has no name, no frontend, no
    /// backend and no server, and keeps the deleted proxy's declaration links so `show stat`'s
    /// walk goes on through it. The name map and the listing lose the slot; every other chunk
    /// is shared with `self`.
    ///
    /// # Panics
    /// If `slot` is out of range.
    #[must_use]
    pub fn remove(&self, slot: usize) -> Self {
        let gone = &self[slot];
        let slot32 = u32::try_from(slot).expect("fewer than 2^32 proxies");
        let tomb = crate::engine::tombstone_proxy(slot, gone);
        let mut by_name = (*self.by_name).clone();
        if by_name.get(gone.name.as_str()) == Some(&slot32) {
            by_name.remove(gone.name.as_str());
            // A frontend and a backend may share a name; the first still live one answers.
            if let Some(i) = self.live.iter().copied().find(|&i| i != slot32 && self[i as usize].name == gone.name) {
                by_name.insert(gone.name.as_str().into(), i);
            }
        }
        let live: Arc<[u32]> = self.live.iter().copied().filter(|&i| i != slot32).collect();
        let (c, i) = (slot >> CHUNK_SHIFT, slot & (CHUNK - 1));
        let mut chunks = self.chunks.clone();
        let mut one: Chunk = (*self.chunks[c]).clone();
        one[i] = Arc::new(tomb);
        chunks[c] = Arc::new(one);
        Self { epoch: self.epoch + 1, len: self.len, chunks, by_name: Arc::new(by_name), live }
    }

    /// Which table this is: 1 at load, one more for every [`Table::replace`] of a chain.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of slots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The proxy at `slot`.
    #[must_use]
    pub fn get(&self, slot: usize) -> Option<&Proxy> {
        (slot < self.len).then(|| &self[slot])
    }

    /// Every proxy, in slot order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter { table: self, next: 0, end: self.len }
    }

    /// The live slots, in listing order.
    #[must_use]
    pub fn live(&self) -> &[u32] {
        &self.live
    }

    /// The slot of the live proxy called `name`: one hash lookup (counted in debug builds).
    #[must_use]
    pub fn slot_by_name(&self, name: &str) -> Option<usize> {
        #[cfg(debug_assertions)]
        BACKEND_NAME_COMPARISONS.with(|c| c.set(c.get() + 1));
        self.by_name.get(name).map(|&s| s as usize)
    }

    /// What rule `rule` of `fe` (`None`: its `default_backend`) names. The only reader of a
    /// [`Target`] and of the backend's `unpublished` flag on the request path:
    /// `resolve_backend` calls it for every rule it evaluates. A rule whose backend
    /// `unpublish backend` took out of the switching rules is skipped, and the evaluation
    /// goes on to the next rule, then to the `default_backend`.
    #[must_use]
    pub fn route(&self, fe: &Proxy, rule: Option<usize>) -> Routed {
        let (target, name) = match rule {
            Some(i) => (fe.routes.as_deref().and_then(|r| r.rules.get(i)), fe.use_backends.get(i).map(|u| u.backend.as_str())),
            None => (fe.routes.as_deref().and_then(|r| r.default.as_ref()), fe.default_backend.as_deref()),
        };
        // The backend of a found slot: published, or unpublished (this function is the flag's
        // only reader on the request path).
        let found = |s: usize| -> Routed {
            match self[s].unpublished.state() {
                SharedFlag::PUBLISHED => Routed::Backend(s),
                SharedFlag::UNPUBLISHED => Routed::Unpublished(s),
                _ => Routed::Retiring,
            }
        };
        match target.copied().unwrap_or(Target::Name) {
            Target::Slot(s) => found(s as usize),
            Target::Disabled => Routed::Disabled,
            Target::Name => match name.and_then(|n| self.slot_by_name(n).map(|s| (s, n))) {
                Some((s, _)) => found(s),
                None => Routed::Miss,
            },
        }
    }

    /// What a `use_backend` rule with a log-format name names, with the name the rule built
    /// per request (`process_switching_rules` builds it from the rule's expression): one
    /// lookup of the name map, backends only -- a frontend that holds the name is no target,
    /// as `proxy_be_by_name` finds no frontend -- with the same unpublished check as
    /// [`Table::route`]. A name the configuration `disabled` is no backend of the table (it
    /// is not built): `fe`'s list of disabled names answers it as a disabled target, as the
    /// static rule `resolve_routes` resolved to [`Target::Disabled`].
    #[must_use]
    pub fn route_dyn(&self, fe: &Proxy, name: &str) -> Routed {
        let Some(s) = self.slot_by_name(name) else {
            return if fe.disabled_backends.iter().any(|n| n == name) {
                Routed::Disabled
            } else {
                Routed::Miss
            };
        };
        if !self[s].has_backend {
            return Routed::Miss;
        }
        match self[s].unpublished.state() {
            SharedFlag::PUBLISHED => Routed::Backend(s),
            SharedFlag::UNPUBLISHED => Routed::Unpublished(s),
            _ => Routed::Retiring,
        }
    }

    /// The proxies back, for a unit test that writes into them as the load does.
    #[cfg(test)]
    pub(crate) fn into_vec(self) -> Vec<Proxy> {
        self.iter().cloned().collect()
    }
}

/// The proxies of a [`Table`] in slot order. A named type with no `Drop`, so a borrow of the
/// table ends where the last use of the iterator does.
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    table: &'a Table,
    next: usize,
    end: usize,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Proxy;
    fn next(&mut self) -> Option<&'a Proxy> {
        (self.next < self.end).then(|| {
            self.next += 1;
            &self.table[self.next - 1]
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.end - self.next, Some(self.end - self.next))
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        (self.next < self.end).then(|| {
            self.end -= 1;
            &self.table[self.end]
        })
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a Table {
    type Item = &'a Proxy;
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl std::ops::Index<usize> for Table {
    type Output = Proxy;
    #[inline(always)]
    fn index(&self, slot: usize) -> &Proxy {
        debug_assert!(slot < self.len, "slot {slot} of {}", self.len);
        &self.chunks[(slot >> CHUNK_SHIFT) & (MAX_CHUNKS - 1)][slot & (CHUNK - 1)]
    }
}

/// What the code shared by the load (a `Vec<Proxy>` still being built) and the request path (a
/// [`Table`]) reads: the proxies by position.
#[allow(clippy::len_without_is_empty)] // the callers count, they never ask for emptiness
pub trait ProxyList: std::ops::Index<usize, Output = Proxy> {
    /// The proxy at `i`, if there is one.
    fn get(&self, i: usize) -> Option<&Proxy>;
    /// How many proxies.
    fn len(&self) -> usize;
    /// Every proxy, in order.
    fn iter(&self) -> impl Iterator<Item = &Proxy>;
}

impl ProxyList for [Proxy] {
    fn get(&self, i: usize) -> Option<&Proxy> {
        <[Proxy]>::get(self, i)
    }
    fn len(&self) -> usize {
        <[Proxy]>::len(self)
    }
    fn iter(&self) -> impl Iterator<Item = &Proxy> {
        <[Proxy]>::iter(self)
    }
}

impl ProxyList for Table {
    fn get(&self, i: usize) -> Option<&Proxy> {
        Table::get(self, i)
    }
    fn len(&self) -> usize {
        self.len
    }
    fn iter(&self) -> impl Iterator<Item = &Proxy> {
        Table::iter(self)
    }
}

impl std::ops::Index<usize> for crate::engine::Proxies {
    type Output = Proxy;
    fn index(&self, slot: usize) -> &Proxy {
        &(**self)[slot]
    }
}

impl ProxyList for crate::engine::Proxies {
    fn get(&self, i: usize) -> Option<&Proxy> {
        Table::get(self, i)
    }
    fn len(&self) -> usize {
        Table::len(self)
    }
    fn iter(&self) -> impl Iterator<Item = &Proxy> {
        Table::iter(self)
    }
}

/// `proxy`'s routing rules, resolved against `by_name`.
fn resolve_routes(proxy: &mut Proxy, by_name: &HashMap<Box<str>, u32>) {
    if proxy.use_backends.is_empty() && proxy.default_backend.is_none() {
        proxy.routes = None;
        return;
    }
    let one = |name: &str| match by_name.get(name) {
        Some(&s) => Target::Slot(s),
        None if proxy.disabled_backends.iter().any(|d| d == name) => Target::Disabled,
        None => Target::Name,
    };
    let routes = Routes { rules: proxy.use_backends.iter().map(|u| one(&u.backend)).collect(), default: proxy.default_backend.as_deref().map(one) };
    proxy.routes = Some(Box::new(routes));
}

/// Posts `table` to every worker of `boxes`. Each swaps at the top of its next loop pass and
/// replies with the epoch it now reads; the gather is complete when the last has. `task` of
/// worker `wid` is woken then.
#[must_use]
pub fn publish(boxes: &Arc<Mailboxes>, table: &Arc<Table>, wid: usize, task: TaskRef) -> Arc<Gather<u64>> {
    let g = Gather::new(boxes, wid, task);
    boxes.broadcast(|| Msg::Table(Arc::clone(table), Arc::clone(&g)));
    g
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use std::fmt::Write as _;

    /// The proxies of `text` as the load builds them: listens, backends, frontends.
    fn load(text: &str) -> Vec<Proxy> {
        Engine::build_shared_state(&alcyon_config::parse_str(text).expect("parse")).expect("build_shared_state").into_vec()
    }

    fn big() -> String {
        let mut cfg = String::from("defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nbackend b\n  server s 127.0.0.1:1\n");
        for i in 0..1_100 {
            let _ = writeln!(cfg, "backend x{i}\n  server s 127.0.0.1:1");
        }
        cfg.push_str("backend d\n  disabled\n  server s 127.0.0.1:1\nfrontend f\n  bind 127.0.0.1:0\n  use_backend d if TRUE\n  use_backend x7 if TRUE\n  default_backend b\n");
        cfg
    }

    #[test]
    fn a_replaced_slot_shares_every_other_chunk_and_the_name_map() {
        let proxies = load(&big());
        let replacement = proxies[3].clone();
        let t1 = Table::new(proxies);
        assert_eq!((t1.epoch(), t1.len(), t1.chunks.len(), t1.is_empty()), (1, 1_102, MAX_CHUNKS, false), "b, 1100 x, f: the disabled d has no proxy");
        let t2 = t1.replace(3, replacement);
        assert_eq!(t2.epoch(), 2);
        assert!(!Arc::ptr_eq(&t1.chunks[0], &t2.chunks[0]), "the chunk of the slot is copied");
        assert!(Arc::ptr_eq(&t1.chunks[1], &t2.chunks[1]), "the other chunk is shared");
        assert!(Arc::ptr_eq(&t1.chunks[0][4], &t2.chunks[0][4]), "so is every other proxy of the copied chunk");
        assert!(!std::ptr::eq(&raw const t1[3], &raw const t2[3]));
        assert!(Arc::ptr_eq(&t1.by_name, &t2.by_name) && Arc::ptr_eq(&t1.live, &t2.live));
        assert_eq!(t2.live().len(), 1_102);
        assert_eq!(t2.slot_by_name("x7"), Some(8));
        assert_eq!(t2.slot_by_name("nope"), None);
        assert_eq!(t2.get(1_102).map(|p| &*p.name), None);
        assert!(Arc::ptr_eq(&t2.chunks[2], &t2.chunks[3]), "the chunks past the last proxy are one shared, empty chunk");
        assert_eq!(&*t2.chunks[1][1_102 - CHUNK].name, "", "the unused slots of the last chunk read an empty proxy");
        assert_eq!(t2.get(1_101).map(|p| &*p.name), Some("f"));
        let names: Vec<&str> = t2.iter().map(|p| p.name.as_str()).collect();
        assert_eq!((names.len(), names[0], names[1_101], t2.iter().len()), (1_102, "b", "f", 1_102));
        assert_eq!(t2.iter().next_back().map(|p| &*p.name), Some("f"));
        assert_eq!((&t2).into_iter().count(), 1_102);
    }

    #[test]
    #[should_panic(expected = "keeps its name")]
    fn a_replaced_backend_keeps_its_name() {
        let proxies = load(&big());
        let other = proxies[2].clone();
        let _ = Table::new(proxies).replace(1, other);
    }

    #[test]
    fn route_resolves_rules_at_load_and_looks_up_no_name_for_resolved_ones() {
        let t = Table::new(load(&big()));
        let fe = &t[t.slot_by_name("f").expect("f")];
        let before = backend_name_comparisons_on_this_thread();
        assert_eq!(t.route(fe, Some(0)), Routed::Disabled);
        assert_eq!(t.route(fe, Some(1)), Routed::Backend(8));
        assert_eq!(t.route(fe, None), Routed::Backend(0));
        assert_eq!(t.route(fe, Some(2)), Routed::Miss, "no such rule");
        #[cfg(debug_assertions)]
        assert_eq!(backend_name_comparisons_on_this_thread() - before, 0, "resolved rules look no name up");
        // A frontend whose routes were not resolved (a test's hand-made proxy) looks names up.
        let mut bare = fe.clone();
        bare.routes = None;
        assert_eq!(t.route(&bare, Some(1)), Routed::Backend(8));
        assert_eq!(t.route(&bare, None), Routed::Backend(0));
        bare.default_backend = Some("ghost".into());
        assert_eq!(t.route(&bare, None), Routed::Miss);
    }

    #[test]
    fn a_name_the_table_lacks_is_resolved_by_name_and_a_proxy_without_rules_has_no_routes() {
        let mut v = load(&big());
        let b = v.remove(0);
        assert_eq!(b.name, "b");
        let t = Table::new(v);
        let fe = &t[t.slot_by_name("f").expect("f")];
        assert!(fe.routes.is_some() && t[0].routes.is_none());
        assert_eq!(t.route(fe, None), Routed::Miss, "`b` is not in this table");
        let t2 = t.replace(0, t[0].clone());
        assert_eq!(t2.route(fe, Some(1)), Routed::Backend(7));
    }

    #[test]
    fn proxy_list_reads_a_slice_and_a_table_alike() {
        fn names(p: &(impl ProxyList + ?Sized)) -> (usize, Option<String>, Vec<String>) {
            (p.len(), p.get(0).map(|x| x.name.clone()), p.iter().take(2).map(|x| x.name.clone()).collect())
        }
        let v = load(&big());
        let want = names(&v[..]);
        let proxies = crate::engine::Proxies::new(v);
        assert_eq!(names(&proxies), want);
        assert_eq!(names(&**proxies.table()), want);
        assert_eq!(proxies[0].name, "b");
    }

    #[test]
    fn a_removed_slot_is_a_tombstone_that_keeps_the_listing_order() {
        let t1 = Table::new(load(&big()));
        let t2 = t1.remove(3);
        assert_eq!((t2.epoch(), t2.len()), (2, 1_102));
        let gone = &t2[3];
        assert_eq!((&*gone.name, gone.has_frontend, gone.has_backend, gone.srv_set().len(), gone.id), ("", false, false, 0, 3));
        assert_eq!((gone.ids.decl, gone.ids.next_decl), (t1[3].ids.decl, t1[3].ids.next_decl), "the declaration walk goes on through the hole");
        assert_eq!(gone.unpublished.state(), SharedFlag::RETIRING);
        assert_eq!((t2.slot_by_name(&t1[3].name), t2.slot_by_name(&t1[4].name)), (None, Some(4)));
        assert_eq!((t2.live().len(), t2.live().contains(&3)), (1_101, false));
        assert!(Arc::ptr_eq(&t1.chunks[1], &t2.chunks[1]) && !Arc::ptr_eq(&t1.chunks[0], &t2.chunks[0]));
        assert!(Arc::ptr_eq(&t1.chunks[0][4], &t2.chunks[0][4]), "the other proxies of the chunk are shared");
        assert!(t1[3].has_backend && t1.slot_by_name(&t1[3].name) == Some(3), "the table it came from is unchanged");
    }

    /// Two proxies with one name (a frontend and a backend): the name map follows the live one.
    #[test]
    fn removing_one_of_two_proxies_with_a_name_keeps_the_other_by_name() {
        let mut proxies = load(&big());
        proxies[3].name = proxies[2].name.clone();
        let t1 = Table::new(proxies);
        let name = t1[2].name.clone();
        assert_eq!(t1.slot_by_name(&name), Some(2), "the first wins");
        assert_eq!(t1.remove(2).slot_by_name(&name), Some(3), "the next one answers");
        assert_eq!(t1.remove(3).slot_by_name(&name), Some(2), "the first stays");
    }

    /// A retiring backend is entered by no rule, and a deleted one is a miss.
    #[test]
    fn a_retiring_backend_is_routed_to_by_nothing() {
        let t = Table::new(load(&big()));
        let f = &t[t.len() - 1];
        assert!(matches!(t.route(f, Some(1)), Routed::Backend(8)));
        assert!(t[8].unpublished.transition(SharedFlag::PUBLISHED, SharedFlag::RETIRING));
        assert!(matches!(t.route(f, Some(1)), Routed::Retiring), "a rule naming it");
        assert!(matches!(t.route_dyn(f, "x7"), Routed::Retiring), "a rule built from a name");
        t[8].unpublished.set(false);
        assert!(matches!(t.route(f, Some(1)), Routed::Retiring), "publish does not revive it");
        let gone = t.remove(8);
        assert!(matches!(gone.route_dyn(f, "x7"), Routed::Miss));
    }
}
