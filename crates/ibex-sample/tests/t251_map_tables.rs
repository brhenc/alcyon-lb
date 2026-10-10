// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Map and ACL files cost what their match type costs (T251 items 1 to 3).
//!
//! `HAProxy` indexes a map by how it is matched (`pat_parse_*` / `pat_idx_*`: an ebtree for
//! `str` and `beg`, an ip tree for `ip`, a list for the others) and the runtime CLI adds,
//! changes and removes one entry at a time. Ibex compiled every key of every map as a regex
//! (a 200k-line `str` map took 1.46 GB, `HAProxy` 152 MB) and rebuilt the whole table on
//! every `add map` (200 adds: 27 s; `HAProxy` 2000 adds in 0.08 s), and every ACL `-f` file
//! was compiled again by every reader after each `add acl`.
//!
//! The match results were measured on `HAProxy 3.5-dev8-885761-29` (2026-10-10):
//! `map_end` and `map_int` take the first entry of the file that matches (a list walk),
//! `map_ip` the longest prefix (`10.0.0.0/8`, `10.1.0.0/16`, `10.1.2.3` → `10.1.2.3` for
//! 10.1.2.3, the /16 for 10.1.9.9), `map_beg` the longest prefix.

use ibex_sample::patref::{self, RefKind};
use ibex_sample::registry::{match_map, MapMatchType};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

fn tmp(name: &str, text: &str) -> String {
    let p = std::env::temp_dir().join(format!("ibex-t251-{}-{name}", std::process::id()));
    std::fs::write(&p, text).expect("write");
    p.display().to_string()
}

fn big_map(name: &str, n: usize) -> String {
    let mut text = String::with_capacity(n * 24);
    for i in 0..n {
        let _ = writeln!(text, "key{i:07} value{i:07}");
    }
    tmp(name, &text)
}

fn val(path: &str, input: &str, t: MapMatchType) -> Option<String> {
    match_map(path, input, t).map(|(v, _)| v)
}

/// Runs `step` `n` times, failing as soon as the whole run takes longer than `budget`.
fn within(budget: Duration, n: usize, mut step: impl FnMut(usize)) {
    let start = Instant::now();
    for i in 0..n {
        step(i);
        assert!(start.elapsed() < budget, "{} of {n} steps took {:?} (budget {budget:?})", i + 1, start.elapsed());
    }
}

#[test]
fn a_str_map_compiles_no_regex() {
    let path = big_map("str.map", 50_000);
    let before = ibex_regex::compiles_on_this_thread();
    let start = Instant::now();
    assert_eq!(val(&path, "key0025000", MapMatchType::Str).as_deref(), Some("value0025000"));
    let took = start.elapsed();
    assert_eq!(ibex_regex::compiles_on_this_thread() - before, 0, "regexes compiled for a str map");
    assert!(took < Duration::from_secs(5), "50k-line str map loaded in {took:?}");
    assert_eq!(val(&path, "key0025000x", MapMatchType::Str), None);
    assert_eq!(val(&path, "key0049999", MapMatchType::Beg).as_deref(), Some("value0049999"));
    assert_eq!(ibex_regex::compiles_on_this_thread() - before, 0, "regexes compiled for a beg lookup");
}

#[test]
fn a_reg_map_still_matches() {
    let path = tmp("reg.map", "^/api/(v[0-9]+)/ api-\\1\n^/static/ static\n");
    assert_eq!(val(&path, "/static/x", MapMatchType::Reg).as_deref(), Some("static"));
    assert_eq!(val(&path, "/api/v2/x", MapMatchType::Regm).as_deref(), Some("api-v2"));
    assert_eq!(val(&path, "/other", MapMatchType::Reg), None);
}

#[test]
fn add_map_is_incremental() {
    let path = big_map("add.map", 50_000);
    assert_eq!(val(&path, "key0000001", MapMatchType::Str).as_deref(), Some("value0000001"));
    // Each add is followed by a lookup, so that a table rebuilt lazily is rebuilt each time.
    within(Duration::from_secs(5), 2000, |i| {
        let (k, v) = (format!("new{i}"), format!("v{i}"));
        assert_eq!(patref::command("add", RefKind::Map, &[&path, &k, &v], None), "");
        assert_eq!(val(&path, &k, MapMatchType::Str), Some(v));
    });
    let body = (0..300).fold(String::new(), |mut b, i| {
        let _ = writeln!(b, "pay{i} pv{i}");
        b
    });
    within(Duration::from_secs(2), 1, |_| {
        assert_eq!(patref::command("add", RefKind::Map, &[&path], Some(&body)), "");
    });
    assert_eq!(val(&path, "pay299", MapMatchType::Str).as_deref(), Some("pv299"));
}

#[test]
fn set_and_del_map_are_incremental() {
    let path = big_map("setdel.map", 50_000);
    assert_eq!(val(&path, "key0000001", MapMatchType::Str).as_deref(), Some("value0000001"));
    within(Duration::from_secs(5), 1000, |i| {
        let k = format!("key{:07}", i * 7);
        assert_eq!(patref::command("set", RefKind::Map, &[&path, &k, "changed"], None), "");
        assert_eq!(val(&path, &k, MapMatchType::Str).as_deref(), Some("changed"));
        let d = format!("key{:07}", i * 7 + 3);
        assert_eq!(patref::command("del", RefKind::Map, &[&path, &d], None), "");
        assert_eq!(val(&path, &d, MapMatchType::Str), None);
    });
    let show = patref::command("show", RefKind::Map, &[&path], None);
    assert_eq!(show.lines().count(), 49_000);
    // `del` by id removes that entry only.
    let first = show.lines().next().expect("an entry").split(' ').next().expect("id").to_string();
    assert_eq!(patref::command("del", RefKind::Map, &[&path, &format!("#{first}")], None), "");
    assert_eq!(patref::command("show", RefKind::Map, &[&path], None).lines().count(), 48_999);
    assert_eq!(patref::command("clear", RefKind::Map, &[&path], None), "");
    assert_eq!(val(&path, "key0000002", MapMatchType::Str), None);
}

#[test]
fn duplicate_keys_answer_the_first_until_it_is_deleted() {
    let path = tmp("dup.map", "/a a1\n/a/b ab\n/a b2\n");
    assert_eq!(val(&path, "/a", MapMatchType::Str).as_deref(), Some("a1"));
    let show = patref::command("show", RefKind::Map, &[&path], None);
    let first = show.lines().next().expect("an entry").split(' ').next().expect("id").to_string();
    assert_eq!(patref::command("del", RefKind::Map, &[&path, &format!("#{first}")], None), "");
    assert_eq!(val(&path, "/a", MapMatchType::Str).as_deref(), Some("b2"));
    assert_eq!(val(&path, "/a/b/c", MapMatchType::Beg).as_deref(), Some("ab"));
    assert_eq!(val(&path, "/a/x", MapMatchType::Beg).as_deref(), Some("b2"));
}

#[test]
fn map_end_takes_the_first_entry_that_matches() {
    let path = tmp("end.map", "b ends_b\nab ends_ab\n");
    assert_eq!(val(&path, "/xab", MapMatchType::End).as_deref(), Some("ends_b"));
    assert_eq!(val(&path, "/xab", MapMatchType::Sub).as_deref(), Some("ends_b"));
}

#[test]
fn map_int_takes_the_first_entry_that_matches() {
    let path = tmp("int.map", "1-10 range\n5 five\n");
    assert_eq!(val(&path, "5", MapMatchType::Int).as_deref(), Some("range"));
    assert_eq!(val(&path, "11", MapMatchType::Int), None);
    let path = tmp("int2.map", "5 five\n1-10 range\n");
    assert_eq!(val(&path, "5", MapMatchType::Int).as_deref(), Some("five"));
    assert_eq!(val(&path, "7", MapMatchType::Int).as_deref(), Some("range"));
}

#[test]
fn map_ip_takes_the_longest_prefix() {
    let path = tmp("ip.map", "10.0.0.0/8 eight\n10.1.0.0/16 sixteen\n10.1.2.3 exact\n2001:db8::/32 v6\n2001:db8:1::/48 v6-48\n");
    assert_eq!(val(&path, "10.1.2.3", MapMatchType::Ip).as_deref(), Some("exact"));
    assert_eq!(val(&path, "10.1.9.9", MapMatchType::Ip).as_deref(), Some("sixteen"));
    assert_eq!(val(&path, "10.9.9.9", MapMatchType::Ip).as_deref(), Some("eight"));
    assert_eq!(val(&path, "11.0.0.1", MapMatchType::Ip), None);
    assert_eq!(val(&path, "2001:db8:1::5", MapMatchType::Ip).as_deref(), Some("v6-48"));
    assert_eq!(val(&path, "2001:db8:2::5", MapMatchType::Ip).as_deref(), Some("v6"));
    assert_eq!(patref::command("del", RefKind::Map, &[&path, "10.1.0.0/16"], None), "");
    assert_eq!(val(&path, "10.1.9.9", MapMatchType::Ip).as_deref(), Some("eight"));
}

#[test]
fn add_acl_compiles_the_new_pattern_once_for_every_reader() {
    let text = (0..20_000).fold(String::new(), |mut b, i| {
        let _ = writeln!(b, "^/p{i}/");
        b
    });
    let path = tmp("reg.acl", &text);
    let pat = patref::acl_file(&path).expect("acl file");
    // Two readers, as two worker threads each build the ACL from the configuration.
    let a = patref::FileMatcher::new(std::sync::Arc::clone(&pat), "reg", false).expect("reader a");
    let b = patref::FileMatcher::new(std::sync::Arc::clone(&pat), "reg", false).expect("reader b");
    let smp = ibex_sample::Sample::Str("/new/x".to_string());
    assert!(!a.matches(&smp) && !b.matches(&smp));
    let before = ibex_regex::compiles_on_this_thread();
    within(Duration::from_secs(5), 1, |_| {
        assert_eq!(patref::command("add", RefKind::Acl, &[&path, "^/new/"], None), "");
        assert!(a.matches(&smp), "reader a sees the added pattern");
        assert!(b.matches(&smp), "reader b sees the added pattern");
    });
    let compiled = ibex_regex::compiles_on_this_thread() - before;
    assert!(compiled <= 2, "{compiled} regexes compiled for one added pattern");
    assert_eq!(patref::command("del", RefKind::Acl, &[&path, "^/new/"], None), "");
    assert!(!a.matches(&smp) && !b.matches(&smp), "the deleted pattern is gone");
    assert!(a.matches(&ibex_sample::Sample::Str("/p19999/".to_string())));
}

/// `map_dir` and `map_dom` find the key as a whole `/`- or `.`-delimited word anywhere in
/// the input, the key's own leading and trailing delimiters left out (`match_word`), as
/// measured on `HAProxy` 3.5-dev8 with `http-request return ... %[req.hdr(x-in),map_dir(...)]`.
#[test]
fn map_dir_and_map_dom_match_a_delimited_word_anywhere() {
    let dir = tmp("dir.map", "/a/b ab\n/c/ c_slash\nx x\n");
    let dom = tmp("dom.map", "example.com ex\n.org dotorg\nfoo foo\n");
    let dirs = [
        ("/a/b", Some("ab")),
        ("/a/b/c", Some("ab")),
        ("/a/bc", None),
        ("/y/a/b/z", Some("ab")),
        ("/c/d", Some("c_slash")),
        ("/c", Some("c_slash")),
        ("/q/x/r", Some("x")),
        ("x", Some("x")),
        ("/xx", None),
    ];
    for (input, want) in dirs {
        assert_eq!(val(&dir, input, MapMatchType::Dir).as_deref(), want, "map_dir {input}");
    }
    let doms = [
        ("a.example.com", Some("ex")),
        ("example.com.au", Some("ex")),
        ("www.example.com", Some("ex")),
        ("example.comx", None),
        ("myexample.com", None),
        ("a.org", Some("dotorg")),
        ("org", Some("dotorg")),
        ("b.foo.c", Some("foo")),
        ("foo", Some("foo")),
    ];
    for (input, want) in doms {
        assert_eq!(val(&dom, input, MapMatchType::Dom).as_deref(), want, "map_dom {input}");
    }
}

/// Entries that share a network or a key length are taken out one at a time; the others
/// still answer (v4 and v6).
#[test]
fn deleting_one_of_two_entries_of_a_network_keeps_the_other() {
    let path = tmp("ipdup.map", "10.0.0.0/8 first\n10.0.0.0/8 second\n11.0.0.0/8 other\n2001:db8::/32 v6\n");
    assert_eq!(val(&path, "10.1.2.3", MapMatchType::Ip).as_deref(), Some("first"));
    let show = patref::command("show", RefKind::Map, &[&path], None);
    let first = show.lines().next().expect("an entry").split(' ').next().expect("id").to_string();
    assert_eq!(patref::command("del", RefKind::Map, &[&path, &format!("#{first}")], None), "");
    assert_eq!(val(&path, "10.1.2.3", MapMatchType::Ip).as_deref(), Some("second"));
    assert_eq!(patref::command("del", RefKind::Map, &[&path, "11.0.0.0/8"], None), "");
    assert_eq!(val(&path, "11.1.2.3", MapMatchType::Ip), None);
    assert_eq!(val(&path, "10.1.2.3", MapMatchType::Ip).as_deref(), Some("second"));
    assert_eq!(patref::command("del", RefKind::Map, &[&path, "2001:db8::/32"], None), "");
    assert_eq!(val(&path, "2001:db8::1", MapMatchType::Ip), None);
}
