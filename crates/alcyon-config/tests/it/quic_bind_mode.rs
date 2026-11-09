// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `quic` bind needs an HTTP frontend (T494). Measured with the QUIC build of HAProxy
//! (3.5-dev7), `mode tcp` frontend with `bind quic4@127.0.0.1:61070 ssl crt c.pem alpn h3`:
//! `[ALERT] frontend 'fe' : MUX protocol 'quic' is not usable for 'bind quic4@127.0.0.1:61070'
//! at [file:7].` and the configuration is refused.

use alcyon_config::parse_str;

fn cfg(mode: &str, bind: &str) -> String {
    format!(
        "defaults\n  mode {mode}\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         frontend fe\n  {bind}\n  default_backend be\nbackend be\n  server s1 127.0.0.1:1\n"
    )
}

#[test]
fn quic_bind_in_a_tcp_frontend_is_refused() {
    let err = parse_str(&cfg("tcp", "bind quic4@127.0.0.1:61070 ssl crt /tmp/c.pem alpn h3")).unwrap_err();
    let text = format!("{err:?} {err}");
    assert!(
        text.contains("frontend 'fe' : MUX protocol 'quic' is not usable for 'bind quic4@127.0.0.1:61070'"),
        "{text}"
    );
}

#[test]
fn quic6_bind_names_its_address_form() {
    let err = parse_str(&cfg("tcp", "bind quic6@[::1]:61070 ssl crt /tmp/c.pem alpn h3")).unwrap_err();
    let text = format!("{err:?} {err}");
    assert!(text.contains("MUX protocol 'quic' is not usable for 'bind quic6@[::1]:61070'"), "{text}");
}

#[test]
fn quic_bind_in_an_http_frontend_is_accepted() {
    parse_str(&cfg("http", "bind quic4@127.0.0.1:61070 ssl crt /tmp/c.pem alpn h3")).expect("http mode");
}

#[test]
fn quic_bind_without_alpn_stays_accepted() {
    parse_str(&cfg("http", "bind quic4@127.0.0.1:61070 ssl crt /tmp/c.pem")).expect("no alpn");
}

#[test]
fn a_tcp_frontend_without_quic_is_accepted() {
    parse_str(&cfg("tcp", "bind 127.0.0.1:61070")).expect("plain tcp bind");
}
