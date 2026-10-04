// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `bind` keywords in `listen` and `frontend` sections (T110).
//!
//! Both sections' bind loops ended in `_ => {}`, and `listen` kept only `accept-proxy`:
//! `bind :443 ssl crt c.pem` in a `listen` served plaintext. Measured with `haproxy -c`
//! 3.5-dev8-885761-29:
//!
//! * `bind 127.0.0.1:1 foo` is `unknown keyword 'foo'`, in `listen` and in `frontend`;
//! * `crt`, `alpn`... with no argument are alerts (`'crt' : missing certificate location`);
//! * `bind 127.0.0.1:1 ssl` with no `crt` loads (the failure comes at start).
//!
//! `haproxy -dKall` lists the other keywords; Ibex refuses those it does not implement
//! when running without them would change security or who may connect, and ignores the
//! rest with a warning.

use ibex_config::{parse_str, Config, ConfigError};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn in_listen(bind: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{DEFAULTS}listen x\n  {bind}\n"))
}

fn in_frontend(bind: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{DEFAULTS}frontend x\n  {bind}\n"))
}

#[test]
fn listen_keeps_ssl_crt_alpn_and_proto() {
    let cfg = in_listen("bind 127.0.0.1:8443 ssl crt /tmp/c.pem alpn h2,http/1.1 proto h2").unwrap();
    let b = &cfg.listens[0].binds[0];
    assert!(b.ssl);
    assert_eq!(b.crt, vec!["/tmp/c.pem".to_string()]);
    assert_eq!(b.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    assert_eq!(b.proto.as_deref(), Some("h2"));
}

#[test]
fn listen_keeps_every_bind_line() {
    let cfg = parse_str(&format!(
        "{DEFAULTS}listen x\n  bind 127.0.0.1:8080\n  bind 127.0.0.1:8443 ssl crt /tmp/c.pem\n  bind 127.0.0.1:9000 accept-proxy\n"
    ))
    .unwrap();
    let l = &cfg.listens[0];
    let ports: Vec<u16> = l.binds.iter().map(|b| b.addr.port()).collect();
    assert_eq!(ports, vec![8080, 8443, 9000]);
    assert!(!l.binds[0].ssl && l.binds[1].ssl);
    assert!(l.binds[2].accept_proxy && l.accept_proxy);
    assert_eq!(l.addr.port(), 8080, "the first bind stays the section's address");
}

#[test]
fn listen_accept_proxy_v2_is_kept() {
    let cfg = in_listen("bind 127.0.0.1:8080 accept-proxy-v2").unwrap();
    assert!(cfg.listens[0].accept_proxy && cfg.listens[0].accept_proxy_v2);
    assert!(cfg.listens[0].binds[0].accept_proxy_v2);
}

#[test]
fn listen_refuses_quic() {
    let err = in_listen("bind quic4@127.0.0.1:8443 ssl crt /tmp/c.pem").unwrap_err();
    assert!(err.to_string().contains("QUIC"), "{err}");
}

#[test]
fn unknown_bind_keyword_is_refused_in_both_sections() {
    for f in [in_listen, in_frontend] {
        let err = f("bind 127.0.0.1:8080 foo").unwrap_err().to_string();
        assert!(err.contains("unknown keyword 'foo'"), "{err}");
    }
}

#[test]
fn bind_keywords_missing_their_argument_are_refused() {
    for kw in ["crt", "alpn", "proto", "verify", "name"] {
        for f in [in_listen, in_frontend] {
            let err = f(&format!("bind 127.0.0.1:8080 {kw}")).unwrap_err().to_string();
            assert!(err.contains(&format!("'{kw}'")), "{kw}: {err}");
        }
    }
}

#[test]
fn unimplemented_security_keywords_are_refused_in_both_sections() {
    let refused = [
        "ssl verify required ca-file /tmp/ca.pem",
        "ssl crt /tmp/c.pem ca-file /tmp/ca.pem",
        "ssl crt /tmp/c.pem strict-sni",
        "ssl crt /tmp/c.pem ciphers HIGH",
        "ssl crt-list /tmp/l",
        "maxconn 5",
        "transparent",
        "user nobody",
        "accept-netscaler-cip 1",
    ];
    for b in refused {
        for f in [in_listen, in_frontend] {
            let err = f(&format!("bind 127.0.0.1:8080 {b}")).expect_err(b).to_string();
            let named = b.split_whitespace().any(|w| err.contains(&format!("'{w}'")));
            assert!(named && err.contains("not supported"), "{b}: {err}");
        }
    }
}

#[test]
fn tuning_keywords_are_accepted_and_their_argument_is_skipped() {
    // `name` and `backlog` take an argument: `ssl` after it must still be read.
    for f in [in_listen, in_frontend] {
        let cfg = f("bind 127.0.0.1:8080 name web backlog 100 tfo defer-accept ssl crt /tmp/c.pem").unwrap();
        let b = match (cfg.listens.first(), cfg.frontends.first()) {
            (Some(l), _) => l.binds[0].clone(),
            (_, Some(fe)) => fe.binds[0].clone(),
            _ => unreachable!(),
        };
        assert!(b.ssl, "'ssl' after an ignored keyword's argument must still be parsed");
        assert_eq!(b.crt, vec!["/tmp/c.pem".to_string()]);
    }
}

#[test]
fn frontend_quic_bind_defaults_its_alpn_to_h3() {
    let cfg = in_frontend("bind quic4@127.0.0.1:8443 ssl crt /tmp/c.pem").unwrap();
    assert_eq!(cfg.frontends[0].binds[0].alpn, vec!["h3".to_string()]);
}
