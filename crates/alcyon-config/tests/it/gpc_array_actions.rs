// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `sc-inc-gpc(<idx>,<sc>)`, `sc-add-gpc(<idx>,<sc>) <value>` and `sc-set-gpt(<idx>,<sc>) <value>`
//! in `http-request`, `tcp-request session` and `tcp-request content` (T139).
//!
//! Every message below is what `HAProxy` 3.5-dev8-885761-29 printed for the same line on
//! 2026-10-04 (`haproxy -c`, rule inside a frontend). The three rule sets word them alike. A
//! missing value is accepted: `strtol` reads nothing, and the value is 0.

use alcyon_config::{parse_config, HttpReqAction, TcpReqContentAction, TcpReqSessionAction};

const RULE_SETS: &[&str] = &["http-request", "tcp-request session", "tcp-request content"];

fn load(rule_set: &str, action: &str) -> Result<alcyon_config::Config, String> {
    parse_config(&format!("frontend fe\n  mode http\n  bind 127.0.0.1:1\n  {rule_set} {action}\n")).map_err(|e| e.to_string())
}

#[test]
fn bad_array_actions_are_refused_with_haproxy_s_words() {
    let cases: &[(&str, &str)] = &[
        ("sc-inc-gpc", "invalid gpc ID 'sc-inc-gpc'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)"),
        ("sc-inc-gpc2", "invalid gpc ID 'sc-inc-gpc2'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)"),
        ("sc-inc-gpc(0)", "Missing gpc ID 'sc-inc-gpc(0)'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)"),
        ("sc-inc-gpc(x,1)", "Missing gpc ID 'sc-inc-gpc(x,1)'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)"),
        ("sc-inc-gpc(0,x)", "invalid stick table track ID 'sc-inc-gpc(0,x)'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)"),
        ("sc-inc-gpc(0,3)", "invalid stick table track ID 'sc-inc-gpc(0,3)'. The max allowed ID is 2 (tune.stick-counters)"),
        ("sc-add-gpc", "Missing or invalid arguments for 'sc-add-gpc'. Expects sc-add-gpc(<GPC ID>,<Track ID>)"),
        ("sc-add-gpc(0)", "Missing gpc ID. Expects sc-add-gpc(0)(<GPC ID>,<Track ID>)"),
        ("sc-add-gpc(0,3) 1", "invalid stick table track ID 'sc-add-gpc(0,3)'. The max allowed ID is 2 (tune.stick-counters)"),
        ("sc-set-gpt", "invalid gpt ID 'sc-set-gpt'. Expects sc-set-gpt(<GPT ID>,<Track ID>)"),
        ("sc-set-gpt(0)", "Missing gpt ID 'sc-set-gpt(0)'. Expects sc-set-gpt(<GPT ID>,<Track ID>)"),
        ("sc-set-gpt(0,x) 1", "invalid stick table track ID 'sc-set-gpt(0,x)'. Expects sc-set-gpt(<GPT ID>,<Track ID>)"),
        ("sc-set-gpt(0,3) 1", "invalid stick table track ID 'sc-set-gpt(0,3)'. The max allowed ID is 2"),
    ];
    let mut wrong = Vec::new();
    for rs in RULE_SETS {
        for (action, want) in cases {
            match load(rs, action) {
                Ok(_) => wrong.push(format!("{rs} {action}: loaded")),
                Err(e) if e.contains(want) => {}
                Err(e) => wrong.push(format!("{rs} {action}: {e:?} lacks {want:?}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn array_actions_parse_with_their_index_counter_and_value() {
    for (action, idx, sc, value) in [("sc-add-gpc(2,1) 5", 2, 1, Some("5")), ("sc-add-gpc(0,2)", 0, 2, Some("0")), ("sc-set-gpt(3,0) 7", 3, 0, Some("7")), ("sc-set-gpt(1,1)", 1, 1, Some("0")), ("sc-inc-gpc(4,2)", 4, 2, None)] {
        let cfg = load("http-request", action).expect("http-request");
        let got = &cfg.frontends[0].http_req_rules[0].action;
        let ok = match (got, value, action.split('(').next().unwrap()) {
            (HttpReqAction::ScAddGpc { idx: i, sc: s, expr }, Some(v), "sc-add-gpc") => (*i, *s, expr.as_str()) == (idx, sc, v),
            (HttpReqAction::ScSetGpt { idx: i, sc: s, expr }, Some(v), "sc-set-gpt") => (*i, *s, expr.as_str()) == (idx, sc, v),
            (HttpReqAction::ScIncGpc { idx: i, sc: s }, None, "sc-inc-gpc") => (*i, *s) == (idx, sc),
            _ => false,
        };
        assert!(ok, "http-request {action}: {got:?}");

        let cfg = load("tcp-request session", action).expect("session");
        let got = &cfg.frontends[0].tcp_req_session_rules[0].action;
        let ok = match (got, value) {
            (TcpReqSessionAction::ScAddGpc { idx: i, sc: s, expr }, Some(v)) => (*i, *s, expr.as_str()) == (idx, sc, v),
            (TcpReqSessionAction::ScSetGpt { idx: i, sc: s, expr }, Some(v)) => (*i, *s, expr.as_str()) == (idx, sc, v),
            (TcpReqSessionAction::ScIncGpc { idx: i, sc: s }, None) => (*i, *s) == (idx, sc),
            _ => false,
        };
        assert!(ok, "tcp-request session {action}: {got:?}");

        let cfg = load("tcp-request content", action).expect("content");
        let got = &cfg.frontends[0].tcp_req_content_rules[0].action;
        let ok = match (got, value) {
            (TcpReqContentAction::ScAddGpc { idx: i, sc: s, expr }, Some(v)) => (*i, *s, expr.as_str()) == (idx, sc, v),
            (TcpReqContentAction::ScSetGpt { idx: i, sc: s, expr }, Some(v)) => (*i, *s, expr.as_str()) == (idx, sc, v),
            (TcpReqContentAction::ScIncGpc { idx: i, sc: s }, None) => (*i, *s) == (idx, sc),
            _ => false,
        };
        assert!(ok, "tcp-request content {action}: {got:?}");
    }
}

/// `gpc_rate(<n>,<period>)` is one field of a `store` list, not two.
#[test]
fn a_store_field_with_a_comma_in_its_parentheses_is_one_field() {
    let cfg = parse_config("backend t\n  stick-table type ip size 10 store gpc(3),gpc_rate(3,10s),gpt(3),conn_cnt\n").expect("loads");
    let t = cfg.backends[0].stick_table.as_ref().expect("table");
    assert_eq!(t.store_fields, ["gpc(3)", "gpc_rate(3,10s)", "gpt(3)", "conn_cnt"]);
}

/// What `haproxy -c` says of a `store` list (3.5-dev8-885761-29, 2026-10-04): the unknown or
/// half-written types and the legacy names beside the array ones are refused; they used to be
/// dropped without a word.
#[test]
fn a_store_list_is_checked_as_haproxy_checks_it() {
    let refused: &[(&str, &str)] = &[
        ("gpc(2),gpc0", "stick-table: simultaneous usage of 'gpc' and 'gpc[0/1]' in a same table is not permitted as 'gpc' overrides 'gpc[0/1]'."),
        ("gpc(2),gpc1", "simultaneous usage of 'gpc' and 'gpc[0/1]'"),
        ("gpc_rate(2,10s),gpc0_rate(10s)", "stick-table: simultaneous usage of 'gpc_rate' and 'gpc[0/1]_rate' in a same table is not permitted as 'gpc_rate' overrides 'gpc[0/1]_rate'."),
        ("gpc_rate(2,10s),gpc1_rate(10s)", "simultaneous usage of 'gpc_rate' and 'gpc[0/1]_rate'"),
        ("gpt(2),gpt0", "stick-table: simultaneous usage of 'gpt' and 'gpt0' in a same table is not permitted as 'gpt' overrides 'gpt0'."),
        ("bogus", "stick-table: unknown store option 'bogus'."),
        ("gpc(0)", "stick-table: array size is out of allowed range (1-100) for store option 'gpc'."),
        ("gpc(101)", "array size is out of allowed range (1-100) for store option 'gpc'"),
        ("gpc_rate(2)", "stick-table: missing argument to store option 'gpc_rate'."),
        ("conn_rate", "stick-table: missing argument to store option 'conn_rate'."),
        ("gpc", "missing argument to store option 'gpc'"),
    ];
    for (store, want) in refused {
        let e = parse_config(&format!("backend b\n  mode http\n  stick-table type ip size 10 store {store}\n"))
            .expect_err(store)
            .to_string();
        assert!(e.contains(want), "{store}: {e:?} lacks {want:?}");
    }
    for ok in ["gpc0,gpc0", "gpc(2),gpc_rate(2,10s),gpt(2)", "gpc0,gpc1,gpt0,gpc0_rate(10s),conn_rate(1m),server_id", "glitch_cnt,glitch_rate(10s),bytes_in_rate(1s)"] {
        parse_config(&format!("backend b\n  mode http\n  stick-table type ip size 10 store {ok}\n")).expect(ok);
    }
}
