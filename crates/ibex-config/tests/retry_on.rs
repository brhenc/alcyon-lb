// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `retry-on` (T131 item 8). Messages and acceptance measured on `HAProxy` 3.5-dev8-885761-29
//! with `haproxy -c`.

use ibex_config::{parse_str, RE_CONN_FAILED, RE_DISCONNECTED, RE_TIMEOUT};

fn backend(line: &str) -> Result<u32, String> {
    let cfg = parse_str(&format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         backend b\n  {line}\n  server s 127.0.0.1:2\n"
    ))
    .map_err(|e| e.message)?;
    Ok(cfg.backends[0].retry_on)
}

#[test]
fn the_default_is_conn_failure_and_a_list_replaces_it() {
    assert_eq!(backend("retries 3"), Ok(RE_CONN_FAILED));
    assert_eq!(backend("retry-on none"), Ok(0));
    assert_eq!(backend("retry-on empty-response response-timeout"), Ok(RE_DISCONNECTED | RE_TIMEOUT));
    assert_eq!(backend("retry-on 503"), Ok(0x2000));
    assert_eq!(backend("retry-on 503 504\n  retry-on conn-failure"), Ok(RE_CONN_FAILED));
    let all = backend("retry-on all-retryable-errors").expect("accepted");
    assert_eq!(all & 0x7ff8, 0x0400 | 0x1000 | 0x2000 | 0x4000, "500 502 503 504");
}

#[test]
fn what_haproxy_refuses_is_refused_with_its_words() {
    assert_eq!(backend("retry-on"), Err("'retry-on' needs at least one keyword to specify when to retry".to_string()));
    assert_eq!(backend("retry-on foo"), Err("'retry-on': unknown keyword 'foo'".to_string()));
    assert_eq!(backend("retry-on 410"), Err("'retry-on': unknown keyword '410'".to_string()));
    assert_eq!(backend("retry-on 503 none"), Err("'retry-on' 'none' keyword only usable alone".to_string()));
}

#[test]
fn defaults_and_listen_take_it_and_a_frontend_does_not() {
    let cfg = parse_str(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n  retry-on 503\n\
         backend b\n  server s 127.0.0.1:2\n\
         backend c\n  retry-on none\n  server s 127.0.0.1:2\n\
         listen l\n  bind 127.0.0.1:0\n  server s 127.0.0.1:2\n",
    )
    .expect("parses");
    assert_eq!((cfg.backends[0].retry_on, cfg.backends[1].retry_on, cfg.listens[0].retry_on), (0x2000, 0, 0x2000));
    let err = parse_str(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         frontend f\n  bind 127.0.0.1:0\n  retry-on 503\n  default_backend b\nbackend b\n  server s 127.0.0.1:2\n",
    )
    .expect_err("refused");
    assert_eq!(err.message, "'retry-on' only available in backend or listen section");
}

/// Measured with `haproxy -c`: a switch-off option with an argument is refused, and
/// `http-request disable-l7-retry if <cond>` is accepted (the condition is kept).
#[test]
fn switch_off_options_refuse_an_argument() {
    for kw in ["noepoll", "nopoll", "nosplice", "noreuseport"] {
        let err = parse_str(&format!("global\n  {kw} foo\n")).expect_err("refused");
        assert_eq!(err.message, format!("'{kw}' cannot handle unexpected argument 'foo'."));
    }
    assert!(parse_str("global\n  noepoll\n").is_ok());
}

#[test]
fn disable_l7_retry_takes_a_condition() {
    let cfg = parse_str(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         frontend f\n  bind 127.0.0.1:0\n  http-request disable-l7-retry if { path /x }\n  http-request disable-l7-retry\n  default_backend b\n\
         backend b\n  server s 127.0.0.1:2\n",
    )
    .expect("accepted");
    let rules = &cfg.frontends[0].http_req_rules;
    assert_eq!(rules.len(), 2);
    assert!(rules[0].cond.is_some() && rules[1].cond.is_none());
}
