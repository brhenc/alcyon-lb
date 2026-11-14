// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `track-sc` written in a `defaults` section names that section's table, and a
//! `defaults` section can hold no `stick-table` at all -- so the rule points at a table
//! that cannot exist. `haproxy` (3.5-dev8-885761-29, `check_trk_action()` in
//! `src/action.c`, run over every section of `defaults_list` by `check_config_validity()`
//! in `src/cfgparse.c` before the proxies are looked at) refuses it:
//!
//! ```text
//! [ALERT] (..) : Proxy 'invalid': unable to find table 'invalid' referenced by track-sc0.
//! ```
//!
//! Alcyon only checked the real proxies, so `reg-tests/startup/default_rules.vtc`'s `h16`
//! was accepted. What the oracle does, measured case by case:
//!
//! * the section named in the alert is the `defaults` section, never a proxy inheriting
//!   the rule, and the copy inherited by a proxy is not reported a second time;
//! * an explicit `table <name>` is looked up among the tables of the real proxies, so
//!   `track-sc0 src table be` in a `defaults` loads (`h17`), while a name that holds no
//!   table is refused, naming the `defaults` section as the referring proxy;
//! * every `defaults` section is checked, in the order written, and a `defaults` in error
//!   does not stop the check of the proxies -- but the first proxy in error does.

use alcyon_config::parse_str;

/// The reference checks as `alcyon -c` reports them: the alert lines, in order.
fn refs(cfg: &str) -> Result<(), Vec<String>> {
    let config = parse_str(cfg).map_err(|e| vec![format!("parsing failed: {}", e.message)])?;
    config.check_references().map_err(|e| e.alerts.iter().map(|(_, text)| text.clone()).collect())
}

/// `alert("table", "name", n)` as the oracle words it.
fn alert(proxy: &str, table: &str, n: u8) -> String {
    format!("Proxy '{proxy}': unable to find table '{table}' referenced by track-sc{n}.")
}

const TABLE: &str = "stick-table type ip size 100k expire 30s store http_req_rate(10s)";

/// `h16` of `startup/default_rules.vtc`: the rule names no table, and the section it is
/// written in has none. The table of the backend, written below, is not its table.
#[test]
fn track_sc_in_defaults_without_a_table_is_refused() {
    let cfg = "global
defaults invalid
    mode http
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 20 }

backend be
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    server www 127.0.0.1:80
";
    assert_eq!(refs(cfg), Err(vec![alert("invalid", "invalid", 0)]));
}

/// The counter of the rule is the one named in it, not always 0.
#[test]
fn track_sc_in_defaults_names_its_own_counter() {
    let cfg = &format!("global\ndefaults d\n    mode http\n    http-request track-sc2 src\nbackend be\n    {TABLE}\n    server www 127.0.0.1:80\n");
    assert_eq!(refs(cfg), Err(vec![alert("d", "d", 2)]));
}

/// A backend inheriting the defaults does not make the rule point at its table: the
/// oracle still refuses, naming the `defaults` section alone.
#[test]
fn a_child_with_a_table_does_not_rescue_the_rule_of_the_defaults() {
    let cfg = &format!("global\ndefaults invalid\n    mode http\n    http-request track-sc0 src\nbackend be from invalid\n    {TABLE}\n    server www 127.0.0.1:80\n");
    assert_eq!(refs(cfg), Err(vec![alert("invalid", "invalid", 0)]));
}

/// The same for a `tcp-request content` rule, and the proxy which inherits a copy of it
/// is not reported again: the rule was written in the `defaults`, and the oracle names
/// that section only.
#[test]
fn tcp_request_content_track_sc_in_defaults_is_refused_once() {
    let cfg = "global
defaults d
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content track-sc0 src
backend be
    server www 127.0.0.1:80
";
    assert_eq!(refs(cfg), Err(vec![alert("d", "d", 0)]));
}

/// An explicit `table` is looked up by name; a name holding no table is refused, and the
/// referring proxy stays the `defaults` section the rule was written in.
#[test]
fn track_sc_in_defaults_naming_a_table_that_holds_none_is_refused() {
    let cfg = &format!("global\ndefaults def_back\n    mode http\n    http-request track-sc0 src table nosuch\nbackend be from def_back\n    {TABLE}\n    server www 127.0.0.1:80\n");
    assert_eq!(refs(cfg), Err(vec![alert("def_back", "nosuch", 0)]));
}

/// Every `defaults` section is checked, in the order they were written.
#[test]
fn every_defaults_section_is_checked_in_order() {
    let cfg = "global
defaults d1
    mode http
    http-request track-sc0 src
defaults d2
    mode http
    http-request track-sc1 src
backend be
    mode http
    server www 127.0.0.1:80
";
    assert_eq!(refs(cfg), Err(vec![alert("d1", "d1", 0), alert("d2", "d2", 1)]));
}

/// A `defaults` in error does not stop the check of the proxies, and its alert comes
/// first: the oracle reports both, the section checked first.
#[test]
fn a_bad_defaults_does_not_hide_a_bad_proxy() {
    let cfg = "global
defaults base
    mode http
frontend fe
    bind 127.0.0.1:8081
    http-request track-sc0 src
defaults d
    mode http
    http-request track-sc1 src
backend be from d
    server www 127.0.0.1:80
";
    assert_eq!(refs(cfg), Err(vec![alert("d", "d", 1), alert("fe", "fe", 0)]));
}

// ---------------------------------------------------------------------------
// What must keep working.

/// `h17` of the same reg-test: a `defaults` naming the table of a proxy that has one.
#[test]
fn track_sc_in_defaults_naming_an_existing_table_is_accepted() {
    let cfg = &format!("global\ndefaults def_back\n    mode http\n    http-request track-sc0 src table be\n    http-request deny deny_status 429 if {{ sc_http_req_rate(0,be) gt 20 }}\nbackend be from def_back\n    {TABLE}\n    server www 127.0.0.1:80\n");
    assert_eq!(refs(cfg), Ok(()));
}

/// A rule in a proxy that owns a stick-table points at its own table.
#[test]
fn track_sc_in_a_proxy_with_its_own_table_is_accepted() {
    let cfg = &format!("global\ndefaults t\n    mode http\nbackend be\n    {TABLE}\n    http-request track-sc0 src\n    server www 127.0.0.1:80\n");
    assert_eq!(refs(cfg), Ok(()));
}

/// A rule in a proxy naming the table of another one, declared after it.
#[test]
fn track_sc_naming_another_proxies_table_is_accepted() {
    let cfg = &format!("global\ndefaults t\n    mode http\nbackend be\n    http-request track-sc0 src table tb\n    server www 127.0.0.1:80\nbackend tb\n    {TABLE}\n    server other 127.0.0.1:81\n");
    assert_eq!(refs(cfg), Ok(()));
}

/// A `listen` with its own table, the same rule.
#[test]
fn track_sc_in_a_listen_with_its_own_table_is_accepted() {
    let cfg = &format!("global\ndefaults t\n    mode http\nlisten li\n    bind 127.0.0.1:8081\n    {TABLE}\n    http-request track-sc0 src\n    server www 127.0.0.1:80\n");
    assert_eq!(refs(cfg), Ok(()));
}

/// A `defaults` naming the table of a `listen`, and of a backend declared before it.
#[test]
fn track_sc_in_defaults_naming_a_table_declared_before_it_is_accepted() {
    let cfg = &format!("global\nlisten li\n    bind 127.0.0.1:8081\n    {TABLE}\ndefaults d\n    mode http\n    http-request track-sc0 src table li\nbackend be from d\n    server www 127.0.0.1:80\n");
    assert_eq!(refs(cfg), Ok(()));
}
