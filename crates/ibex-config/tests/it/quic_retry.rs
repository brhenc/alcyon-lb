// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `quic-force-retry` (bind) and `tune.quic.fe.sec.retry-threshold` (global), T492.
//!
//! Measured on the QUIC oracle, `HAProxy` 3.5-dev7 (`haproxy -c`, `cfg_parse_quic_tune_setting`
//! in src/cfgparse-quic.c, an `atoi` into an `unsigned int` that must be at least 1):
//! `7` loads; `-1` loads (it is 4294967295); `5x` loads (5); `4294967297` loads (1);
//! no argument, `0`, `abc` and `4294967296` fail with "'tune.quic.fe.sec.retry-threshold'
//! expects a positive integer."; `7 8` fails with "cannot handle unexpected argument '8'.".
//! `quic-force-retry` loads on a QUIC bind and, doing nothing there, on a TCP one.

use ibex_config::parse_str;

fn threshold(v: &str) -> Result<Option<u64>, String> {
    parse_str(&format!("global\n  tune.quic.fe.sec.retry-threshold {v}\ndefaults\n  mode http\n"))
        .map(|c| c.global.and_then(|g| g.quic_retry_threshold))
        .map_err(|e| e.to_string())
}

#[test]
fn retry_threshold_reads_as_atoi_into_an_unsigned_int() {
    assert_eq!(threshold("7"), Ok(Some(7)));
    assert_eq!(threshold("-1"), Ok(Some(4_294_967_295)));
    assert_eq!(threshold("5x"), Ok(Some(5)));
    assert_eq!(threshold("4294967297"), Ok(Some(1)));
}

#[test]
fn retry_threshold_refuses_zero_and_what_is_not_a_number() {
    for v in ["", "0", "abc", "4294967296"] {
        let e = threshold(v).unwrap_err();
        assert!(e.contains("'tune.quic.fe.sec.retry-threshold' expects a positive integer."), "{v:?}: {e}");
    }
    let e = threshold("7 8").unwrap_err();
    assert!(e.contains("'tune.quic.fe.sec.retry-threshold' cannot handle unexpected argument '8'."), "{e}");
}

#[test]
fn retry_threshold_is_unset_by_default() {
    let c = parse_str("global\n  maxconn 10\ndefaults\n  mode http\n").expect("parse");
    assert_eq!(c.global.and_then(|g| g.quic_retry_threshold), None);
}

#[test]
fn quic_force_retry_is_a_bind_option() {
    let c = parse_str(
        "frontend f\n  mode http\n  bind quic4@127.0.0.1:8443 ssl crt /tmp/c.pem alpn h3 quic-force-retry\n  \
         bind quic4@127.0.0.1:8444 ssl crt /tmp/c.pem alpn h3\n  bind 127.0.0.1:8080 quic-force-retry\n",
    )
    .expect("parse");
    let binds = &c.frontends[0].binds;
    let forced = |i: usize| binds[i].sock.as_ref().is_some_and(|s| s.quic_force_retry);
    assert!(forced(0));
    assert!(!forced(1));
    assert!(forced(2), "accepted on a TCP bind, as HAProxy does, where it does nothing");
}
