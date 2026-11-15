// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Values of a proxy that the CLI and the stats page change at run time (T177).
//!
//! The workers share one copy of the proxies (`engine::Proxies`). A runtime write must
//! change that copy in place, so every worker sees it on its next connection: these types
//! hold the values in atomics behind an `Arc`, and cloning one shares it, as the counters
//! of a `Proxy` already are.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// A frontend's connection limit and the connections it holds, shared by every worker and
/// listener of the proxy: `maxconn N` is a total over all threads (`feconn` against
/// `maxconn` in `HAProxy`), and `set maxconn frontend` changes it for all of them.
#[derive(Debug, Clone, Default)]
pub struct ConnLimit(Arc<(AtomicU32, AtomicU32)>);

impl ConnLimit {
    #[must_use]
    pub fn get(&self) -> u32 {
        self.0 .0.load(Ordering::Relaxed)
    }

    pub fn set(&self, v: u32) {
        self.0 .0.store(v, Ordering::Relaxed);
    }

    /// Connections currently counted against the limit, over all workers.
    #[must_use]
    pub fn conns(&self) -> u32 {
        self.0 .1.load(Ordering::Relaxed)
    }

    pub fn inc(&self) {
        self.0 .1.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes a slot if there is one, atomically (workers racing on a check then an `inc`
    /// would overshoot the limit by one each).
    pub fn try_inc(&self) -> bool {
        let max = self.get();
        self.0 .1.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| (max == 0 || c < max).then_some(c + 1)).is_ok()
    }

    pub fn dec(&self) {
        let _ = self.0 .1.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(1)));
    }

    /// True when the limit is set (non-zero) and reached.
    #[must_use]
    pub fn is_full(&self) -> bool {
        let max = self.get();
        max != 0 && self.conns() >= max
    }
}

impl std::fmt::Display for ConnLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

impl From<u32> for ConnLimit {
    fn from(v: u32) -> Self {
        let l = Self::default();
        l.set(v);
        l
    }
}

/// One `u32` shared by every worker: a proxy's `maxconn`, which its listeners read too.
#[derive(Debug, Clone, Default)]
pub struct SharedU32(Arc<AtomicU32>);

impl SharedU32 {
    #[must_use]
    pub fn new(v: u32) -> Self {
        Self(Arc::new(AtomicU32::new(v)))
    }

    #[must_use]
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    pub fn set(&self, v: u32) {
        self.0.store(v, Ordering::Relaxed);
    }
}

impl std::fmt::Display for SharedU32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

impl From<u32> for SharedU32 {
    fn from(v: u32) -> Self {
        Self::new(v)
    }
}

/// One `u32` per server, shared by every worker: the current weights.
#[derive(Debug, Clone)]
pub struct ServerU32s(Arc<[AtomicU32]>);

impl ServerU32s {
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<u32> {
        self.0.get(idx).map(|a| a.load(Ordering::Relaxed))
    }

    /// Stores `v` for server `idx`; false when there is no such server.
    pub fn set(&self, idx: usize, v: u32) -> bool {
        self.0.get(idx).map(|a| a.store(v, Ordering::Relaxed)).is_some()
    }
}

impl FromIterator<u32> for ServerU32s {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        Self(iter.into_iter().map(AtomicU32::new).collect())
    }
}

/// Each server's weight, shared by every worker: the current one (`set weight`) and the
/// configured one it is a share of (`iweight`, the `initial` of `get weight`), packed in
/// one word as `initial << 16 | current`. A weight is at most 256.
#[derive(Debug, Clone)]
pub struct ServerWeights(ServerU32s);

impl ServerWeights {
    /// Server `idx`'s current weight.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<u32> {
        self.0.get(idx).map(|w| w & 0xffff)
    }

    /// Server `idx`'s configured weight.
    #[must_use]
    pub fn initial(&self, idx: usize) -> Option<u32> {
        self.0.get(idx).map(|w| w >> 16)
    }

    /// Changes server `idx`'s current weight; false when there is no such server.
    pub fn set(&self, idx: usize, w: u32) -> bool {
        let Some(a) = self.0 .0.get(idx) else { return false };
        let w = w.min(0xffff);
        let _ = a.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| Some(old & 0xffff_0000 | w));
        true
    }
}

impl FromIterator<u32> for ServerWeights {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        Self(iter.into_iter().map(|w| w.min(0xffff) << 16 | w.min(0xffff)).collect())
    }
}

/// A server's `maxconn` per server, shared by every worker. `None` (no limit) is kept as
/// `u32::MAX`, a limit no worker can reach anyway.
#[derive(Debug, Clone)]
pub struct ServerMaxconns(ServerU32s);

impl ServerMaxconns {
    const NONE: u32 = u32::MAX;

    /// Server `idx`'s limit, `None` when it has none (or there is no such server).
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<u32> {
        self.0.get(idx).filter(|&v| v != Self::NONE)
    }

    /// Sets server `idx`'s limit; false when there is no such server.
    pub fn set(&self, idx: usize, v: Option<u32>) -> bool {
        self.0.set(idx, v.unwrap_or(Self::NONE))
    }
}

impl FromIterator<Option<u32>> for ServerMaxconns {
    fn from_iter<I: IntoIterator<Item = Option<u32>>>(iter: I) -> Self {
        Self(iter.into_iter().map(|v| v.unwrap_or(Self::NONE)).collect())
    }
}

/// A socket address readable and writable from any thread without a lock: a sequence
/// lock over four atomic words. A reader that overlaps a write reads again, so it never
/// sees half of an old address and half of a new one; writes are rare (`set server
/// addr`), reads are one per connection.
#[derive(Debug)]
struct SeqAddr {
    seq: AtomicU32,
    w: [AtomicU64; 4],
}

fn encode(a: SocketAddr) -> [u64; 4] {
    match a {
        SocketAddr::V4(v) => [0, u64::from(v.ip().to_bits()), u64::from(v.port()), 0],
        SocketAddr::V6(v) => {
            let ip = v.ip().to_bits();
            [
                (ip >> 64) as u64,
                ip as u64,
                u64::from(v.port()) | 1 << 16 | u64::from(v.flowinfo()) << 32,
                u64::from(v.scope_id()),
            ]
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
fn decode(w: [u64; 4]) -> SocketAddr {
    let port = (w[2] & 0xffff) as u16;
    if w[2] & 1 << 16 == 0 {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_bits(w[1] as u32), port))
    } else {
        let ip = u128::from(w[0]) << 64 | u128::from(w[1]);
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_bits(ip), port, (w[2] >> 32) as u32, w[3] as u32))
    }
}

impl SeqAddr {
    fn new(a: SocketAddr) -> Self {
        Self { seq: AtomicU32::new(0), w: encode(a).map(AtomicU64::new) }
    }

    fn load(&self) -> SocketAddr {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 == 0 {
                let w = [0, 1, 2, 3].map(|i| self.w[i].load(Ordering::Relaxed));
                fence(Ordering::Acquire);
                if self.seq.load(Ordering::Relaxed) == s1 {
                    return decode(w);
                }
            }
            std::hint::spin_loop();
        }
    }

    fn store(&self, a: SocketAddr) {
        // Writers take the sequence to odd one at a time.
        let mut s = self.seq.load(Ordering::Relaxed);
        loop {
            if s & 1 == 1 {
                std::hint::spin_loop();
                s = self.seq.load(Ordering::Relaxed);
                continue;
            }
            match self.seq.compare_exchange_weak(s, s.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => break,
                Err(cur) => s = cur,
            }
        }
        fence(Ordering::Release);
        for (slot, v) in self.w.iter().zip(encode(a)) {
            slot.store(v, Ordering::Relaxed);
        }
        self.seq.store(s.wrapping_add(2), Ordering::Release);
    }
}

/// The addresses of a backend's servers, shared by every worker: `set server addr`
/// changes where every worker's next connection to the server goes.
#[derive(Debug, Clone)]
pub struct ServerAddrs(Arc<[SeqAddr]>);

impl ServerAddrs {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn get(&self, idx: usize) -> Option<SocketAddr> {
        self.0.get(idx).map(SeqAddr::load)
    }

    /// Server `idx`'s address.
    ///
    /// # Panics
    /// When there is no server `idx`, as indexing a slice does.
    #[must_use]
    pub fn at(&self, idx: usize) -> SocketAddr {
        self.0[idx].load()
    }

    /// Changes server `idx`'s address; false when there is no such server.
    pub fn set(&self, idx: usize, a: SocketAddr) -> bool {
        self.0.get(idx).map(|s| s.store(a)).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.0.iter().map(SeqAddr::load)
    }

    /// The first server at `a`.
    #[must_use]
    pub fn position(&self, a: SocketAddr) -> Option<usize> {
        self.iter().position(|s| s == a)
    }
}

impl FromIterator<SocketAddr> for ServerAddrs {
    fn from_iter<I: IntoIterator<Item = SocketAddr>>(iter: I) -> Self {
        Self(iter.into_iter().map(SeqAddr::new).collect())
    }
}

impl From<Vec<SocketAddr>> for ServerAddrs {
    fn from(v: Vec<SocketAddr>) -> Self {
        v.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip() {
        for s in ["127.0.0.1:80", "[::1]:443", "[fe80::1%2]:8080", "10.1.2.3:0", "[2001:db8::5]:65535"] {
            let a: SocketAddr = s.parse().expect("addr");
            let addrs: ServerAddrs = vec![a].into();
            assert_eq!(addrs.at(0), a);
            let b: SocketAddr = "192.0.2.9:9".parse().expect("addr");
            assert!(addrs.set(0, b));
            assert_eq!(addrs.get(0), Some(b));
            assert!(addrs.set(0, a));
            assert_eq!(addrs.at(0), a);
        }
    }

    #[test]
    fn a_shared_clone_sees_the_write() {
        let addrs: ServerAddrs = vec!["127.0.0.1:1".parse().expect("addr")].into();
        let w: ServerWeights = [1, 2].into_iter().collect();
        let m: ServerMaxconns = [None, Some(3)].into_iter().collect();
        let (addrs2, w2, m2) = (addrs.clone(), w.clone(), m.clone());
        addrs.set(0, "127.0.0.1:2".parse().expect("addr"));
        w.set(0, 0);
        m.set(0, Some(1));
        m.set(1, None);
        assert_eq!(addrs2.at(0).port(), 2);
        assert_eq!((w2.get(0), w2.get(1)), (Some(0), Some(2)));
        assert_eq!((w2.initial(0), w2.initial(1)), (Some(1), Some(2)));
        assert_eq!((m2.get(0), m2.get(1)), (Some(1), None));
    }

    #[test]
    fn readers_never_see_a_torn_address() {
        let a: SocketAddr = "[2001:db8::1]:1111".parse().expect("addr");
        let b: SocketAddr = "10.0.0.2:2222".parse().expect("addr");
        let addrs: ServerAddrs = vec![a].into();
        let r = addrs.clone();
        let reader = std::thread::spawn(move || {
            for _ in 0..200_000 {
                let got = r.at(0);
                assert!(got == a || got == b, "torn read {got}");
            }
        });
        for i in 0..200_000 {
            addrs.set(0, if i % 2 == 0 { b } else { a });
        }
        reader.join().expect("reader");
    }

    #[test]
    fn concurrent_writers_take_turns() {
        let a: SocketAddr = "[2001:db8::1]:1111".parse().expect("addr");
        let b: SocketAddr = "10.0.0.2:2222".parse().expect("addr");
        let addrs: ServerAddrs = vec![a].into();
        let writers: Vec<_> = [a, b]
            .into_iter()
            .map(|x| {
                let w = addrs.clone();
                std::thread::spawn(move || {
                    for _ in 0..200_000 {
                        w.set(0, x);
                    }
                })
            })
            .collect();
        for _ in 0..200_000 {
            let got = addrs.at(0);
            assert!(got == a || got == b, "torn read {got}");
        }
        for w in writers {
            w.join().expect("writer");
        }
        assert_eq!(addrs.0[0].seq.load(Ordering::Relaxed), 800_000, "every write took the sequence twice");
    }
}

/// One name of a server. `next` is empty while this is the server's current name; a rename
/// fills it, once, with the slot that holds the name after this one.
#[derive(Debug)]
struct NameSlot {
    name: &'static str,
    next: OnceLock<&'static NameSlot>,
}

impl NameSlot {
    fn new(name: String) -> Self {
        Self { name: Box::leak(name.into_boxed_str()), next: OnceLock::new() }
    }

    /// The slot that holds the current name: the end of the chain that starts here.
    /// `OnceLock::get` is one Acquire load and writes nothing, so a reader on the request
    /// path touches no memory another thread has to read back (AGENTS.md rule 8). It must
    /// stay that way: no lock, no counter, no "last read" here.
    fn tail(&self) -> &NameSlot {
        let mut slot = self;
        while let Some(next) = slot.next.get() {
            slot = next;
        }
        slot
    }
}

/// Each server's name, shared by every worker: `set server ... name` renames in place.
///
/// A server's first name is a slot inside the shared array (no allocation per server beyond
/// the name itself: 60,000 servers are counted, `request_allocations.rs`). A rename appends
/// a leaked slot to that server's chain and never changes or frees an older one, so a reader
/// needs no lock and a `&str` it holds never dangles. The leak is one slot and one name per
/// rename, an operator's action (tradeoff.md 6.35); a read walks one hop per rename the
/// server has had since startup.
#[derive(Debug, Clone, Default)]
pub struct ServerNames(Arc<[NameSlot]>);

impl ServerNames {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn get(&self, i: usize) -> Option<&'static str> {
        self.0.get(i).map(|first| first.tail().name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.iter().map(|first| first.tail().name)
    }

    /// The server at `i` is called `name` from now on. Allocates and leaks: for the CLI, not
    /// for a request.
    pub fn set(&self, i: usize, name: &str) {
        let Some(first) = self.0.get(i) else { return };
        let new: &'static NameSlot = Box::leak(Box::new(NameSlot::new(name.to_owned())));
        let mut tail = first.tail();
        // Another rename of the same server got there first: ours goes after it.
        while tail.next.set(new).is_err() {
            tail = tail.tail();
        }
    }
}

impl std::ops::Index<usize> for ServerNames {
    type Output = str;
    fn index(&self, i: usize) -> &str {
        self.get(i).expect("server index in range")
    }
}

impl FromIterator<String> for ServerNames {
    fn from_iter<I: IntoIterator<Item = String>>(it: I) -> Self {
        Self(it.into_iter().map(NameSlot::new).collect())
    }
}

#[cfg(test)]
mod name_tests {
    use super::*;

    fn names(v: &[&str]) -> ServerNames {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn names_read_back_as_configured() {
        let n = names(&["a", "b", "c"]);
        assert_eq!(n.len(), 3);
        assert_eq!(n.get(0), Some("a"));
        assert_eq!(n.get(2), Some("c"));
        assert_eq!(n.get(3), None);
        assert_eq!(&n[1], "b");
        assert_eq!(n.iter().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(ServerNames::default().len(), 0);
        assert_eq!(ServerNames::default().get(0), None);
    }

    #[test]
    fn a_rename_is_seen_by_every_clone_and_leaves_the_others_alone() {
        let n = names(&["a", "b", "c"]);
        let other = n.clone();
        n.set(1, "bee");
        assert_eq!(other.get(1), Some("bee"));
        assert_eq!(other.iter().collect::<Vec<_>>(), ["a", "bee", "c"]);
        // Out of range: nothing to rename, nothing changes.
        n.set(3, "nobody");
        assert_eq!(n.iter().collect::<Vec<_>>(), ["a", "bee", "c"]);
    }

    #[test]
    fn a_chain_of_renames_reads_the_last_one() {
        let n = names(&["s0", "s1"]);
        let first = n.get(0).expect("name");
        for i in 0..50 {
            n.set(0, &format!("renamed{i}"));
            assert_eq!(n.get(0), Some(format!("renamed{i}").as_str()));
        }
        // Back to a name it had before: the latest still wins.
        n.set(0, "s0");
        assert_eq!(n.get(0), Some("s0"));
        assert_eq!(n.get(1), Some("s1"));
        // A name read before the renames is still the old name, not freed memory.
        assert_eq!(first, "s0");
    }

    /// The 60,000-server memory bound (`request_allocations.rs`) has 0.4 MB of headroom: a
    /// slot is two words of name and two of link, and a third field would not fit.
    #[test]
    fn a_slot_is_four_words() {
        assert_eq!(std::mem::size_of::<NameSlot>(), 32);
    }

    /// Readers against renamers, as `readers_never_see_a_torn_address` does for addresses:
    /// every read is a name that was set, whole, and one reader never goes back to an older
    /// name of a single renamer.
    #[test]
    fn readers_never_see_a_name_that_was_not_set() {
        const RENAMES: usize = 2_000;
        let n = names(&["w0-0", "other"]);
        let writers: Vec<_> = (0..4)
            .map(|w| {
                let n = n.clone();
                std::thread::spawn(move || {
                    for i in 1..=RENAMES {
                        n.set(0, &format!("w{w}-{i}"));
                    }
                })
            })
            .collect();
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let n = n.clone();
                std::thread::spawn(move || {
                    let mut last = [0usize; 4];
                    for _ in 0..20_000 {
                        let got = n.get(0).expect("name");
                        let (w, i) = got.strip_prefix('w').and_then(|r| r.split_once('-')).expect(got);
                        let (w, i): (usize, usize) = (w.parse().expect(got), i.parse().expect(got));
                        assert!(w < 4 && i <= RENAMES, "a name nobody set: {got}");
                        assert!(i >= last[w], "went back from w{w}-{} to {got}", last[w]);
                        last[w] = i;
                        assert_eq!(n.get(1), Some("other"));
                    }
                })
            })
            .collect();
        for t in writers.into_iter().chain(readers) {
            t.join().expect("thread");
        }
        let last = n.get(0).expect("name");
        assert!(last.ends_with(&format!("-{RENAMES}")), "the last rename of some writer wins: {last}");
        // No rename was lost to another: the chain holds every one of them.
        let mut renames = 0;
        let mut slot = &n.0[0];
        while let Some(next) = slot.next.get() {
            renames += 1;
            slot = next;
        }
        assert_eq!(renames, 4 * RENAMES);
    }
}
