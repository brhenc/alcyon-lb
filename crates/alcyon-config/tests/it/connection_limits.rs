// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `maxsslconn` (global) reaches no data path in Alcyon: there is no count of TLS
//! connections to cap. It was accepted and dropped (T240 item 4); a limit is now refused,
//! and 0 -- HAProxy's "no limit" (`atol`, so also a word) -- is accepted, since that is
//! what Alcyon does. The syntax errors are HAProxy's (3.5-dev8, `haproxy -c`).
//!
//! `maxqueue` (server) reaches the data path: the queue a request the balancing assigned
//! to the server takes when it is at its `maxconn` (`alcyon-rt`'s `pendconn_add`) is
//! bounded by it, `SRV_STATUS_FULL` otherwise. The value, and 0 for unlimited, load.

use alcyon_config::parse_str;

fn refusal(cfg: &str) -> String {
    match parse_str(cfg) {
        Ok(_) => panic!("accepted:\n{cfg}"),
        Err(e) => e.message,
    }
}

#[test]
fn maxsslconn_with_a_limit_is_refused() {
    assert_eq!(
        refusal("global\n maxsslconn 100\n"),
        "'maxsslconn' is not implemented in Alcyon: TLS connections are limited by 'maxconn' only"
    );
}

#[test]
fn maxsslconn_zero_is_no_limit_and_loads() {
    assert!(parse_str("global\n maxsslconn 0\n").is_ok());
    assert!(parse_str("global\n maxsslconn abc\n").is_ok(), "atol: 0");
}

#[test]
fn maxsslconn_syntax_errors_are_haproxys() {
    assert_eq!(refusal("global\n maxsslconn\n"), "'maxsslconn' expects an integer argument.");
    assert_eq!(refusal("global\n maxsslconn -1\n"), "'maxsslconn' expects a positive numeric value.");
    assert_eq!(refusal("global\n maxsslconn 100 x\n"), "'maxsslconn' cannot handle unexpected argument 'x'.");
}

#[test]
fn a_server_maxqueue_limit_loads_and_reaches_the_ast() {
    let cfg = parse_str("backend b\n server s 127.0.0.1:1 maxconn 1 maxqueue 10\n").unwrap();
    assert_eq!(cfg.backends[0].server_extras.maxqueue(0), 10);
    // 0 (unlimited) loads and stays 0.
    let cfg = parse_str("backend b\n server s 127.0.0.1:1 maxqueue 0\n").unwrap();
    assert_eq!(cfg.backends[0].server_extras.maxqueue(0), 0);
    assert!(parse_str("backend b\n default-server maxqueue 0\n server s 127.0.0.1:1\n").is_ok());
    // `atol` takes a leading `+`: `+5` is a limit of 5.
    let cfg = parse_str("backend b\n server s 127.0.0.1:1 maxqueue +5\n").unwrap();
    assert_eq!(cfg.backends[0].server_extras.maxqueue(0), 5);
    // `default-server` sets it for the servers that follow.
    let cfg = parse_str("backend b\n default-server maxqueue 5\n server s 127.0.0.1:1\n").unwrap();
    assert_eq!(cfg.backends[0].server_extras.maxqueue(0), 5);
    // The same integer as `maxconn`: a non-numeric value is refused.
    assert_eq!(
        refusal("backend b\n server s 127.0.0.1:1 maxqueue abc\n"),
        "<maxqueue> expects an integer argument."
    );
    // No argument at all: refused, as in `HAProxy` (`expect_integer`).
    assert_eq!(
        refusal("backend b\n server s 127.0.0.1:1 maxqueue\n"),
        "'server s' : 'maxqueue' expects an integer argument."
    );
    assert_eq!(
        refusal("backend b\n default-server maxqueue\n"),
        "'maxqueue' expects an integer argument."
    );
}
