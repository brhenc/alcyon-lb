// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `maxsslconn` (global) and `maxqueue` (server) reach no data path in Ibex: there is no
//! count of TLS connections to cap, and no per-server queue (a request waits in its
//! backend's queue). Both were accepted and dropped (T240 item 4); a limit is now
//! refused, and 0 -- HAProxy's "no limit" (`atol`, so also a word) -- is accepted, since
//! that is what Ibex does. The syntax errors are HAProxy's (3.5-dev8, `haproxy -c`).

use ibex_config::parse_str;

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
        "'maxsslconn' is not implemented in Ibex: TLS connections are limited by 'maxconn' only"
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
fn a_server_maxqueue_limit_is_refused_and_zero_loads() {
    let m = refusal("backend b\n server s 127.0.0.1:1 maxqueue 10\n");
    assert!(m.contains("'maxqueue' is not supported: Ibex has no per-server queue"), "{m}");
    assert!(parse_str("backend b\n server s 127.0.0.1:1 maxqueue 0\n").is_ok());
    assert!(parse_str("backend b\n default-server maxqueue 0\n server s 127.0.0.1:1\n").is_ok());
    let m = refusal("backend b\n default-server maxqueue 5\n server s 127.0.0.1:1\n");
    assert!(m.contains("'maxqueue' is not supported"), "{m}");
}
