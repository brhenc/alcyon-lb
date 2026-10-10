// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TLS version bounds on `bind` lines and in `ssl-default-bind-options` /
//! `ssl-default-server-options` (T153).
//!
//! Ibex served TLS 1.3 only and refused every version keyword on a `bind`. With TLS 1.2
//! built in, the keywords reach the handshake (`ssl-min-ver`, `ssl-max-ver`, `force-tlsvN`,
//! `no-tlsvN`), on the bind and, through the global defaults, on the servers too. Measured
//! with `haproxy -c` 3.5-dev8-885761-29:
//!
//! * `bind ... ssl-min-ver TLSv1.4` is "'TLSv1.4' : unknown ssl/tls version";
//! * `ssl-min-ver` with no value is "'ssl-min-ver' : missing the ssl/tls version";
//! * `ssl-min-ver TLSv1.3` in `ssl-default-bind-options` with `ssl-max-ver TLSv1.2` on the
//!   bind: "all SSL/TLS versions are disabled for bind '127.0.0.1:18455'";
//! * the global options are what a bind or server says nothing about: the bind's own
//!   `ssl-min-ver` wins over the default's.
//!
//! `TLSv1.0`, `TLSv1.1` and `SSLv3` HAProxy accepts. rustls speaks neither, so Ibex
//! refuses them rather than serve a range it cannot.

use ibex_config::{parse_str, Config, ConfigError, TlsVersion};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn frontend(global: &str, bind: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{global}{DEFAULTS}frontend x\n  bind 127.0.0.1:8443 ssl crt /tmp/c.pem {bind}\n"))
}

fn range(global: &str, bind: &str) -> (Option<TlsVersion>, Option<TlsVersion>) {
    let cfg = frontend(global, bind).unwrap_or_else(|e| panic!("{global} / {bind}: {e}"));
    let b = &cfg.frontends[0].binds[0];
    (b.min_ver, b.max_ver)
}

#[test]
fn bind_version_keywords_are_kept() {
    use TlsVersion::{Tls12, Tls13};
    assert_eq!(range("", ""), (None, None));
    assert_eq!(range("", "ssl-min-ver TLSv1.3"), (Some(Tls13), None));
    assert_eq!(range("", "ssl-max-ver TLSv1.2"), (None, Some(Tls12)));
    assert_eq!(range("", "ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3"), (Some(Tls12), Some(Tls13)));
    assert_eq!(range("", "force-tlsv12"), (Some(Tls12), Some(Tls12)));
    assert_eq!(range("", "force-tlsv13"), (Some(Tls13), Some(Tls13)));
    assert_eq!(range("", "no-tlsv12"), (Some(Tls13), None));
    assert_eq!(range("", "no-tlsv13"), (None, Some(Tls12)));
    // What rustls never offers: asking for it to be off is already the case.
    assert_eq!(range("", "no-sslv3 no-tlsv10 no-tlsv11"), (None, None));
}

#[test]
fn bind_versions_rustls_cannot_speak_are_refused() {
    for kw in ["ssl-min-ver TLSv1.0", "ssl-min-ver TLSv1.1", "ssl-min-ver SSLv3", "ssl-max-ver TLSv1.1", "force-tlsv10", "force-tlsv11", "force-sslv3"] {
        let err = frontend("", kw).expect_err(kw).to_string();
        assert!(err.contains("not supported") && err.contains("TLS 1.2 and 1.3 only"), "{kw}: {err}");
    }
}

#[test]
fn bind_version_errors_are_haproxys() {
    let err = frontend("", "ssl-min-ver TLSv1.4").unwrap_err().to_string();
    assert!(err.contains("'TLSv1.4' : unknown ssl/tls version"), "{err}");
    let err = frontend("", "ssl-min-ver").unwrap_err().to_string();
    assert!(err.contains("'ssl-min-ver' : missing the ssl/tls version"), "{err}");
    let err = frontend("", "ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.2").unwrap_err().to_string();
    assert!(err.contains("all SSL/TLS versions are disabled for bind '127.0.0.1:8443'"), "{err}");
    let err = frontend("", "no-tlsv12 no-tlsv13").unwrap_err().to_string();
    assert!(err.contains("all SSL/TLS versions are disabled"), "{err}");
}

#[test]
fn listen_binds_keep_them_too() {
    let cfg = parse_str(&format!("{DEFAULTS}listen x\n  bind 127.0.0.1:8443 ssl crt /tmp/c.pem ssl-max-ver TLSv1.2\n")).unwrap();
    assert_eq!(cfg.listens[0].binds[0].max_ver, Some(TlsVersion::Tls12));
}

#[test]
fn global_bind_options_fill_in_what_the_bind_leaves_open() {
    use TlsVersion::{Tls12, Tls13};
    let g = "global\n  ssl-default-bind-options ssl-min-ver TLSv1.3\n";
    assert_eq!(range(g, ""), (Some(Tls13), None));
    // The bind's own bound wins; the other bound still comes from the default.
    let g2 = "global\n  ssl-default-bind-options ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3\n";
    assert_eq!(range(g2, "ssl-min-ver TLSv1.2"), (Some(Tls12), Some(Tls13)));
    assert_eq!(range("global\n  ssl-default-bind-options force-tlsv12\n", ""), (Some(Tls12), Some(Tls12)));
    assert_eq!(range("global\n  ssl-default-bind-options no-tlsv12\n", ""), (Some(Tls13), None));
    // A default that contradicts the bind's bound leaves nothing: HAProxy's alert.
    let err = frontend(g, "ssl-max-ver TLSv1.2").unwrap_err().to_string();
    assert!(err.contains("all SSL/TLS versions are disabled for bind"), "{err}");
    // Options that are not versions are kept as before.
    assert_eq!(range("global\n  ssl-default-bind-options prefer-client-ciphers no-tls-tickets\n", ""), (None, None));
}

#[test]
fn global_server_options_fill_in_servers() {
    let g = |opts: &str| {
        parse_str(&format!(
            "global\n  ssl-default-server-options {opts}\n{DEFAULTS}backend b\n  server s 127.0.0.1:1 ssl verify none\n  server t 127.0.0.1:2 ssl verify none ssl-max-ver TLSv1.3\n"
        ))
    };
    let cfg = g("ssl-min-ver TLSv1.3").unwrap();
    let ssl = |i: usize| cfg.backends[0].servers[i].ssl.clone().unwrap();
    assert_eq!(ssl(0).min_ver, Some(TlsVersion::Tls13));
    assert_eq!((ssl(1).min_ver, ssl(1).max_ver), (Some(TlsVersion::Tls13), Some(TlsVersion::Tls13)));
    let cfg = g("force-tlsv12").unwrap();
    assert_eq!(cfg.backends[0].servers[0].ssl.clone().unwrap().max_ver, Some(TlsVersion::Tls12));
    // The server's own `ssl-max-ver` wins over the default's.
    assert_eq!(cfg.backends[0].servers[1].ssl.clone().unwrap().max_ver, Some(TlsVersion::Tls13));
}

#[test]
fn global_options_naming_versions_rustls_cannot_speak_are_refused() {
    for (kw, opt) in [("ssl-default-bind-options", "ssl-min-ver TLSv1.0"), ("ssl-default-server-options", "force-tlsv11"), ("ssl-default-bind-options", "ssl-max-ver TLSv1.4")] {
        let err = parse_str(&format!("global\n  {kw} {opt}\n{DEFAULTS}")).expect_err(opt).to_string();
        assert!(err.contains("TLS 1.2 and 1.3 only") || err.contains("unknown ssl/tls version"), "{opt}: {err}");
    }
}
