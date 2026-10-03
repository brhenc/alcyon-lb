// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-response deny` takes a status and nothing Ibex does not act on.
//!
//! `HAProxy` 3.5 accepts the same body arguments as `http-request deny` (`content-type`,
//! `string`, `hdr`, `errorfile`, ...). Ibex's response deny sends the error page for the
//! status and has no use for them, and the parser used to skip every word it did not
//! know -- a line that asked for a body was accepted and the body never sent (AGENTS.md
//! rule 5). Until the body arguments are implemented they are refused; a word `HAProxy`
//! does not know either is refused by both (`tests/corpus/56_*.cfg`).

use ibex_config::parse_config;

fn cfg(line: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         frontend fe\n    bind 127.0.0.1:8080\n    default_backend be\n\nbackend be\n    {line}\n"
    )
}

#[test]
fn a_status_is_accepted() {
    for line in [
        "http-response deny",
        "http-response deny deny_status 503",
        "http-response deny status 503 if { status 500 }",
    ] {
        assert!(parse_config(&cfg(line)).is_ok(), "{line}: {:?}", parse_config(&cfg(line)));
    }
}

#[test]
fn a_body_argument_is_refused_rather_than_dropped() {
    for line in [
        "http-response deny content-type text/plain string nope",
        "http-response deny deny_status 503 hdr X-A b",
        "http-response deny errorfile /dev/null",
    ] {
        let err = parse_config(&cfg(line)).expect_err(line).to_string();
        assert!(err.contains("http-response deny"), "{line}: {err}");
    }
}
