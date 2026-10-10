// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/pattern.c (`pat_idx_*`, `pat_match_*`, `pat_ref_*`).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The entries of one pattern file, indexed for the ways they are matched.
//!
//! `HAProxy` indexes a pattern file by its match method: an ebtree of strings for `str`
//! and `beg`, an ip tree (longest prefix) for `ip`, a list walked in file order for `end`,
//! `sub`, `dir`, `dom`, `int` and `reg`; and the runtime CLI adds, changes and deletes one
//! entry at a time. This table keeps:
//!
//! * the entries by id, which is their order in the file (ids only grow);
//! * a hash of the keys (`str`, and `beg`/`end` by trying the key lengths that exist);
//! * an ip index by prefix length (longest prefix first);
//! * a regex per entry, compiled the first time a `reg` lookup reaches it, so that a map
//!   read only as `str` compiles none;
//! * the compiled patterns of every ACL reader of the file, kept up to date entry by entry.
//!
//! Every change costs one entry, never the whole file.

use crate::matcher::Matcher;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::OnceLock;

/// One entry of a pattern file.
#[derive(Debug)]
pub struct Entry {
    pub key: Box<str>,
    pub val: Box<str>,
    /// The key as an integer or a `<low>-<high>` range, for `map_int`.
    int: Option<(i64, i64)>,
    /// The key as a regex, compiled when a `reg` lookup first reaches it.
    regex: OnceLock<Option<Box<ibex_regex::UserRegex>>>,
}

impl Entry {
    fn regex(&self) -> Option<&ibex_regex::UserRegex> {
        self.regex.get_or_init(|| ibex_regex::UserRegex::new(&self.key).ok().map(Box::new)).as_deref()
    }
}

/// The key of an ip entry: the network, masked, and its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum IpKey {
    V4(u8, u32),
    V6(u8, u128),
}

fn mask4(addr: u32, len: u8) -> u32 {
    if len == 0 { 0 } else { addr & (u32::MAX << (32 - u32::from(len))) }
}

fn mask6(addr: u128, len: u8) -> u128 {
    if len == 0 { 0 } else { addr & (u128::MAX << (128 - u32::from(len))) }
}

/// `<addr>` or `<addr>/<prefix length>`.
fn ip_key(key: &str) -> Option<IpKey> {
    let (net, len) = match key.split_once('/') {
        Some((n, l)) => (n, Some(l.parse::<u8>().ok()?)),
        None => (key, None),
    };
    match net.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => {
            let len = len.unwrap_or(32);
            (len <= 32).then(|| IpKey::V4(len, mask4(u32::from(a), len)))
        }
        IpAddr::V6(a) => {
            let len = len.unwrap_or(128);
            (len <= 128).then(|| IpKey::V6(len, mask6(u128::from(a), len)))
        }
    }
}

/// An integer key, or a `<low>-<high>` range (bounds included).
fn int_key(key: &str) -> Option<(i64, i64)> {
    if let Ok(n) = key.parse::<i64>() {
        return Some((n, n));
    }
    let (lo, hi) = key.split_once('-')?;
    Some((lo.parse().ok()?, hi.parse().ok()?))
}

/// The patterns of one ACL reader (`<method>`, case-insensitive or not), compiled.
#[derive(Debug)]
struct Reader {
    method: String,
    case_insensitive: bool,
    compiled: BTreeMap<u64, Matcher>,
}

/// The entries of a pattern file and their indexes.
#[derive(Debug, Default)]
pub struct PatTable {
    entries: BTreeMap<u64, Entry>,
    /// The ids of the entries of each key, in file order.
    by_key: HashMap<Box<str>, Vec<u64>>,
    /// How many different keys have each length.
    key_lens: BTreeMap<usize, usize>,
    /// The ids of the ip entries of each network, in file order.
    by_ip: HashMap<IpKey, Vec<u64>>,
    /// How many different networks have each prefix length (v4, v6).
    v4_lens: BTreeMap<u8, usize>,
    v6_lens: BTreeMap<u8, usize>,
    readers: Vec<Reader>,
}

impl PatTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `(id, entry)` in file order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &Entry)> {
        self.entries.iter().map(|(id, e)| (*id, e))
    }

    /// Adds an entry with id `id`, which must be larger than every id in the table.
    pub fn insert(&mut self, id: u64, key: &str, val: &str) {
        let ids = self.by_key.entry(key.into()).or_default();
        if ids.is_empty() {
            *self.key_lens.entry(key.len()).or_default() += 1;
        }
        ids.push(id);
        if let Some(ip) = ip_key(key) {
            let ids = self.by_ip.entry(ip).or_default();
            if ids.is_empty() {
                match ip {
                    IpKey::V4(l, _) => *self.v4_lens.entry(l).or_default() += 1,
                    IpKey::V6(l, _) => *self.v6_lens.entry(l).or_default() += 1,
                }
            }
            ids.push(id);
        }
        for r in &mut self.readers {
            if let Ok(m) = Matcher::compile_with_flags(&r.method, key, r.case_insensitive) {
                r.compiled.insert(id, m);
            }
        }
        self.entries.insert(id, Entry { key: key.into(), val: val.into(), int: int_key(key), regex: OnceLock::new() });
    }

    /// Removes entry `id`; whether there was one.
    pub fn remove(&mut self, id: u64) -> bool {
        let Some(e) = self.entries.remove(&id) else { return false };
        // Every entry is in `by_key`, and an ip one in `by_ip` (`insert`).
        if take_id(&mut self.by_key, &e.key, id) {
            dec(&mut self.key_lens, &e.key.len());
        }
        if let Some(ip) = ip_key(&e.key) {
            if take_id(&mut self.by_ip, &ip, id) {
                match ip {
                    IpKey::V4(l, _) => dec(&mut self.v4_lens, &l),
                    IpKey::V6(l, _) => dec(&mut self.v6_lens, &l),
                }
            }
        }
        for r in &mut self.readers {
            r.compiled.remove(&id);
        }
        true
    }

    /// Removes every entry; the readers stay registered.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_key.clear();
        self.key_lens.clear();
        self.by_ip.clear();
        self.v4_lens.clear();
        self.v6_lens.clear();
        for r in &mut self.readers {
            r.compiled.clear();
        }
    }

    /// The ids of the entries whose key is `key`, or the entry whose id is `#<hex id>`.
    #[must_use]
    pub fn ids(&self, key: &str) -> Vec<u64> {
        if let Some(hex) = key.strip_prefix('#') {
            return u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                .ok()
                .filter(|id| self.entries.contains_key(id))
                .into_iter()
                .collect();
        }
        self.by_key.get(key).cloned().unwrap_or_default()
    }

    /// Changes the value of entry `id`.
    pub fn set_val(&mut self, id: u64, val: &str) {
        if let Some(e) = self.entries.get_mut(&id) {
            e.val = val.into();
        }
    }

    fn hit(&self, id: u64) -> Option<(String, String)> {
        self.entries.get(&id).map(|e| (e.val.to_string(), e.key.to_string()))
    }

    fn first_of(&self, key: &str) -> Option<u64> {
        self.by_key.get(key).and_then(|ids| ids.first().copied())
    }

    /// The first walk hit, in file order.
    fn walk(&self, mut pred: impl FnMut(&Entry) -> bool) -> Option<(String, String)> {
        self.entries.values().find(|e| pred(e)).map(|e| (e.val.to_string(), e.key.to_string()))
    }

    /// `str`: the first entry whose key is `input`. Answers `(value, key)`.
    #[must_use]
    pub fn match_str(&self, input: &str) -> Option<(String, String)> {
        self.hit(self.first_of(input)?)
    }

    /// `beg`: the entry with the longest key that `input` starts with.
    #[must_use]
    pub fn match_beg(&self, input: &str) -> Option<(String, String)> {
        let id = self
            .key_lens
            .range(..=input.len())
            .rev()
            .find_map(|(&len, _)| input.is_char_boundary(len).then(|| self.first_of(&input[..len])).flatten())?;
        self.hit(id)
    }

    /// `end`: the first entry, in file order, whose key `input` ends with.
    #[must_use]
    pub fn match_end(&self, input: &str) -> Option<(String, String)> {
        let id = self
            .key_lens
            .range(..=input.len())
            .filter_map(|(&len, _)| {
                let at = input.len() - len;
                input.is_char_boundary(at).then(|| self.first_of(&input[at..])).flatten()
            })
            .min()?;
        self.hit(id)
    }

    /// `sub`: the first entry whose key `input` contains.
    #[must_use]
    pub fn match_sub(&self, input: &str) -> Option<(String, String)> {
        self.walk(|e| input.contains(&*e.key))
    }

    /// `dir`: the first entry whose key, its own leading and trailing `/` left out, is a
    /// whole `/`-delimited word of `input`, anywhere in it (`HAProxy` `pat_match_dir`).
    #[must_use]
    pub fn match_dir(&self, input: &str) -> Option<(String, String)> {
        self.walk(|e| crate::matcher::match_word(input.as_bytes(), e.key.as_bytes(), b"/", false))
    }

    /// `dom`: the same with `.` as the delimiter (`HAProxy` `pat_match_dom`).
    #[must_use]
    pub fn match_dom(&self, input: &str) -> Option<(String, String)> {
        self.walk(|e| crate::matcher::match_word(input.as_bytes(), e.key.as_bytes(), b".", false))
    }

    /// `int`: the first entry whose integer or range holds `input`.
    #[must_use]
    pub fn match_int(&self, input: &str) -> Option<(String, String)> {
        let n = input.parse::<i64>().ok()?;
        self.walk(|e| e.int.is_some_and(|(lo, hi)| lo <= n && n <= hi))
    }

    /// `ip`: the entry with the longest network holding `input`.
    #[must_use]
    pub fn match_ip(&self, input: &str) -> Option<(String, String)> {
        let id = match input.parse::<IpAddr>().ok()? {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4_lens.keys().rev().find_map(|&l| self.by_ip.get(&IpKey::V4(l, mask4(a, l))).and_then(|v| v.first().copied()))
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6_lens.keys().rev().find_map(|&l| self.by_ip.get(&IpKey::V6(l, mask6(a, l))).and_then(|v| v.first().copied()))
            }
        }?;
        self.hit(id)
    }

    /// `reg`: the first entry whose regex matches `input`.
    #[must_use]
    pub fn match_reg(&self, input: &str) -> Option<(String, String)> {
        self.walk(|e| e.regex().is_some_and(|re| re.is_match(input)))
    }

    /// `regm`: as `reg`, the value with `\<n>` replaced by the regex's groups.
    #[must_use]
    pub fn match_regm(&self, input: &str) -> Option<(String, String)> {
        self.entries.values().find_map(|e| {
            let caps = e.regex()?.captures(input)?;
            let mut result = e.val.to_string();
            for i in 1..caps.len() {
                result = result.replace(&format!("\\{i}"), caps.get(i).unwrap_or(""));
            }
            Some((result, e.key.to_string()))
        })
    }

    /// The index of the ACL reader `(method, case_insensitive)`, registered (and its
    /// patterns compiled) on first use.
    ///
    /// # Errors
    /// A pattern of the table does not compile with `method`.
    pub fn reader(&mut self, method: &str, case_insensitive: bool) -> Result<usize, String> {
        if let Some(i) = self.readers.iter().position(|r| r.method == method && r.case_insensitive == case_insensitive) {
            return Ok(i);
        }
        let mut compiled = BTreeMap::new();
        for (id, e) in &self.entries {
            compiled.insert(*id, Matcher::compile_with_flags(method, &e.key, case_insensitive)?);
        }
        self.readers.push(Reader { method: method.to_string(), case_insensitive, compiled });
        Ok(self.readers.len() - 1)
    }

    /// The `(method, case_insensitive)` of every ACL reader.
    #[must_use]
    pub fn reader_methods(&self) -> Vec<(String, bool)> {
        self.readers.iter().map(|r| (r.method.clone(), r.case_insensitive)).collect()
    }

    /// The compiled patterns of reader `i`, in file order.
    pub fn compiled(&self, i: usize) -> impl Iterator<Item = &Matcher> {
        self.readers.get(i).into_iter().flat_map(|r| r.compiled.values())
    }
}

/// Takes `id` out of the ids under `k`, and `k` out of `m` once it has none left; whether
/// it went.
fn take_id<K: Eq + std::hash::Hash>(m: &mut HashMap<K, Vec<u64>>, k: &K, id: u64) -> bool {
    let emptied = m.get_mut(k).is_some_and(|ids| {
        ids.retain(|x| *x != id);
        ids.is_empty()
    });
    emptied && m.remove(k).is_some()
}

fn dec<K: Ord>(m: &mut BTreeMap<K, usize>, k: &K) {
    if let Some(n) = m.get_mut(k) {
        *n -= 1;
        if *n == 0 {
            m.remove(k);
        }
    }
}
