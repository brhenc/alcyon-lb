// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T612a (ALCYON-STATS-HTML-XSS-001): a stick-table key is client-controlled text; the HTML
//! stats page must print it as text, never as markup. (HAProxy's own HTML stats page has no
//! stick-table section, so there is no oracle row to match; the rule is plain HTML escaping.)

use alcyon_rt::{render_stats_html, Engine};
use alcyon_stick_table::StickKey;

#[test]
fn a_stick_table_key_is_escaped_in_the_stats_page() {
    let addr = crate::common::reserve_addr();
    let cfg = format!(
        "defaults\n    mode http\nfrontend fe\n    bind {addr}\n    stats enable\n    stats uri /s\nbackend t1\n    stick-table type string len 64 size 100 store http_req_cnt\nbackend t2\n    stick-table type ip size 10\nbackend t3\n    stick-table type integer size 10\nbackend t4\n    stick-table type binary len 2 size 10\n"
    );
    let engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("config"), 64).expect("engine");
    let table = engine.proxies.iter().find_map(|p| p.stick_table.as_ref().filter(|_| p.name == "t1")).expect("t1");
    for k in ["<script>alert(1)</script>", "a&b", "q\"'x", "plain"] {
        table.update_entry(&StickKey::String(k.into()), |d| d.http_req_cnt += 1).unwrap();
    }
    let html = render_stats_html(&engine.proxies, &engine.checks, 1);
    assert!(!html.contains("<script>alert"), "key printed as markup");
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("a&amp;b"));
    assert!(html.contains("q&quot;&#39;x"));
    assert!(html.contains(">plain<"));
}

/// The other key types are printed as `show table` does: address, number, hex.
#[test]
fn the_other_key_types_print_as_text() {
    let addr = crate::common::reserve_addr();
    let cfg = format!(
        "defaults\n    mode http\nfrontend fe\n    bind {addr}\n    stats enable\n    stats uri /s\nbackend t2\n    stick-table type ip size 10\nbackend t3\n    stick-table type integer size 10\nbackend t4\n    stick-table type binary len 2 size 10\n"
    );
    let engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("config"), 64).expect("engine");
    let table = |n: &str| engine.proxies.iter().find_map(|p| p.stick_table.as_ref().filter(|_| p.name == n)).expect("table");
    table("t2").update_entry(&StickKey::Ip("10.1.2.3".parse().unwrap()), |d| d.http_req_cnt += 1).unwrap();
    table("t3").update_entry(&StickKey::Integer(77), |d| d.http_req_cnt += 1).unwrap();
    table("t4").update_entry(&StickKey::Binary(vec![0xab, 0x01]), |d| d.http_req_cnt += 1).unwrap();
    let html = render_stats_html(&engine.proxies, &engine.checks, 1);
    for key in ["10.1.2.3", "77", "ab01"] {
        assert!(html.contains(&format!("<td class=\"mono\">{key}</td>")), "{key}");
    }
}
