// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `do-log`, `set-log-level` and `set-nice` actions at load: what `HAProxy`
//! 3.5-dev11 accepts and refuses for them, as its `stream_parse_set_log_level` and
//! `stream_parse_set_nice` (`src/stream.c`) do.
//!
//! `set-log-level` takes exactly one argument, `silent` or one of the eight syslog level
//! names (case-sensitive, `strcmp` against `log_levels` in `src/log.c`); `HAProxy` stores
//! `-1` for `silent` and the level's syslog number plus one for a name. `set-nice` takes
//! exactly one argument, read with `atoi` (leading whitespace and a sign, digits, the rest
//! ignored, no digits is 0) and clamped to `-1024..=1024`.
//!
//! `set-log-level` and `set-nice` are actions of `http-request` and `http-response`;
//! `http-after-response` lists only `set-log-level`, so it refuses `set-nice`.

use alcyon_config::{parse_config, HttpAfterResAction, HttpReqAction, HttpResAction};

fn cfg(section: &str, rules: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         {section} fe\n    bind 127.0.0.1:8080\n    {rules}\n    default_backend be\n\nbackend be\n    server s 127.0.0.1:9\n"
    )
}

#[test]
fn set_log_level_maps_the_level_names_to_haproxys_override_values() {
    // `silent` is -1; a level name is its syslog number plus one, the value `HAProxy`
    // stores in `s->logs.level` (emerg 1 .. debug 8).
    for (arg, want) in [
        ("silent", -1i8),
        ("emerg", 1),
        ("alert", 2),
        ("crit", 3),
        ("err", 4),
        ("warning", 5),
        ("notice", 6),
        ("info", 7),
        ("debug", 8),
    ] {
        let c = parse_config(&cfg("frontend", &format!("http-request set-log-level {arg}"))).expect(arg);
        assert!(
            matches!(&c.frontends[0].http_req_rules[0].action, HttpReqAction::SetLogLevel(l) if *l == want),
            "{arg}"
        );
    }
}

#[test]
fn set_log_level_parses_under_http_response() {
    let c = parse_config(&cfg("frontend", "http-response set-log-level err if TRUE")).expect("accepted");
    let rule = &c.frontends[0].http_res_rules[0];
    assert!(matches!(&rule.action, HttpResAction::SetLogLevel(l) if *l == 4));
    assert!(rule.cond.is_some());
    let c = parse_config(&cfg("frontend", "http-response set-log-level silent")).expect("accepted");
    assert!(matches!(&c.frontends[0].http_res_rules[0].action, HttpResAction::SetLogLevel(l) if *l == -1));
}

#[test]
fn set_log_level_parses_under_http_after_response() {
    let c = parse_config(&cfg("frontend", "http-after-response set-log-level warning")).expect("accepted");
    assert!(
        matches!(&c.frontends[0].http_after_res_rules[0].action, HttpAfterResAction::SetLogLevel(l) if *l == 5)
    );
}

#[test]
fn the_set_log_level_lines_haproxy_refuses_are_refused() {
    for (line, want) in [
        ("http-request set-log-level", "expects exactly 1 argument (log level name or 'silent')"),
        ("http-request set-log-level bogus", "expects exactly 1 argument (log level name or 'silent')"),
        ("http-request set-log-level ERR", "expects exactly 1 argument (log level name or 'silent')"),
        ("http-response set-log-level", "expects exactly 1 argument (log level name or 'silent')"),
        ("http-after-response set-log-level bogus", "expects exactly 1 argument (log level name or 'silent')"),
    ] {
        let err = parse_config(&cfg("frontend", line)).expect_err(line).to_string();
        assert!(err.contains(want), "{line}: {err}");
    }
}

#[test]
fn set_nice_reads_its_number_the_way_atoi_does() {
    // `atoi`: leading whitespace (a quoted argument keeps it), a sign, digits; the rest of
    // the word is ignored and a word with no digits is 0; the value is clamped to
    // -1024..=1024 (`stream_parse_set_nice`).
    for (arg, want) in [
        ("5", 5i16),
        ("-3", -3),
        ("+7", 7),
        ("0", 0),
        ("5foo", 5),
        ("foo", 0),
        ("' 5'", 5),
        ("99999", 1024),
        ("-99999", -1024),
    ] {
        let c = parse_config(&cfg("frontend", &format!("http-request set-nice {arg}"))).expect(arg);
        assert!(
            matches!(&c.frontends[0].http_req_rules[0].action, HttpReqAction::SetNice(n) if *n == want),
            "{arg}"
        );
    }
}

#[test]
fn set_nice_parses_under_http_response_and_not_under_http_after_response() {
    let c = parse_config(&cfg("frontend", "http-response set-nice -9 if TRUE")).expect("accepted");
    let rule = &c.frontends[0].http_res_rules[0];
    assert!(matches!(&rule.action, HttpResAction::SetNice(n) if *n == -9));
    assert!(rule.cond.is_some());
    // `http-after-response` lists `set-log-level` only.
    let err = parse_config(&cfg("frontend", "http-after-response set-nice 5"))
        .expect_err("refused")
        .to_string();
    assert!(err.contains("set-nice"), "{err}");
}

#[test]
fn the_set_nice_lines_haproxy_refuses_are_refused() {
    for (line, want) in [
        ("http-request set-nice", "expects exactly 1 argument (integer value)"),
        ("http-response set-nice", "expects exactly 1 argument (integer value)"),
    ] {
        let err = parse_config(&cfg("frontend", line)).expect_err(line).to_string();
        assert!(err.contains(want), "{line}: {err}");
    }
}
