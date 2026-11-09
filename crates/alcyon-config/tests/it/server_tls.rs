// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The TLS keywords of a `server` / `default-server` line (T113): what they parse to, and
//! what `HAProxy` refuses at load time.
//!
//! Measured with `haproxy -c` (3.5-dev8-885761-29) on 2026-10-03, one line per run:
//!
//! * `ssl`, `ssl verify required`, `check-ssl`: "verify is enabled by default but no CA
//!   file specified. If you're running on a LAN where you're certain to trust the server's
//!   certificate, please set an explicit 'verify none' statement on the 'server' line, or
//!   use 'ssl-server-verify none' in the global section to disable server-side
//!   verifications by default." (exit 1);
//! * `ssl verify none`, `ssl ca-file <existing>`, `ssl verify none sni str(foo)`,
//!   `ssl verify none alpn h2,http/1.1`, `ssl verify none ssl-min-ver TLSv1.2`,
//!   `check check-sni foo`, `check-alpn h2`, and `verify none` / `sni str(foo)` /
//!   `alpn h2` / `verifyhost foo` without `ssl`: valid;
//! * `ssl verify none ssl-min-ver TLSv1.4`: "'TLSv1.4' : unknown ssl/tls version.";
//! * `ssl verify none sni bogus(`: "error detected while parsing sni or pool-conn-name
//!   expressions : unknown fetch method 'bogus'." -- Alcyon reports that from the sample
//!   registry at load (`alcyon -c`), not from the parser.
//!
//! rustls speaks TLS 1.2 and 1.3 only, so `ssl-min-ver TLSv1.0` and friends, which
//! `HAProxy` accepts, are refused: a server that only speaks TLS 1.0 would never be
//! reached and the operator should know why.

use alcyon_config::{parse_str, Config, ConfigError, ServerSsl, SslVerify, TlsVersion};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn server_line(rest: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{DEFAULTS}backend b\n  server s1 127.0.0.1:8080 {rest}\n"))
}

/// The parsed `ServerSsl` of `server s1 ... {rest}`. A plaintext server line has none,
/// so the default stands in; every assertion here is on a line that sets a TLS keyword.
fn first_server(rest: &str) -> ServerSsl {
    let cfg = server_line(rest).unwrap_or_else(|e| panic!("`{rest}` must load: {}", e.message));
    cfg.backends[0].servers[0].ssl.as_deref().cloned().unwrap_or_default()
}

#[test]
fn ssl_turns_tls_on_and_verify_none_is_the_only_way_without_a_ca() {
    let s = first_server("ssl verify none");
    assert!(s.ssl, "`ssl` must mark the server as TLS");
    assert_eq!(s.verify, Some(SslVerify::None));
    assert!(s.ca_file.is_none());

    for line in ["ssl", "ssl verify required", "check-ssl", "check check-ssl", "ssl verifyhost foo.com"] {
        let err = server_line(line).expect_err(line);
        assert!(
            err.message.contains("verify is enabled by default but no CA file specified"),
            "`{line}`: HAProxy's alert, got: {}",
            err.message
        );
        assert!(err.message.contains("'verify none'"), "{}", err.message);
    }
}

#[test]
fn ca_file_implies_verify_required_and_is_kept() {
    let s = first_server("ssl ca-file /etc/ssl/ca.pem");
    assert!(s.ssl);
    assert_eq!(s.verify, None, "no explicit verify: HAProxy's default (required) applies at load");
    assert_eq!(s.ca_file.as_deref(), Some("/etc/ssl/ca.pem"));
    let s = first_server("ssl verify required ca-file /etc/ssl/ca.pem crl-file /etc/ssl/crl.pem crt /etc/ssl/client.pem");
    assert_eq!(s.verify, Some(SslVerify::Required));
    assert_eq!(s.crl_file.as_deref(), Some("/etc/ssl/crl.pem"));
    assert_eq!(s.crt.as_deref(), Some("/etc/ssl/client.pem"));
}

#[test]
fn sni_alpn_verifyhost_are_kept_with_or_without_ssl() {
    let s = first_server("ssl verify none sni str(record1.bug940.domain.tld) alpn h2,http/1.1 verifyhost www.test1.com");
    assert_eq!(s.sni.as_deref(), Some("str(record1.bug940.domain.tld)"));
    assert_eq!(s.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    assert_eq!(s.verifyhost.as_deref(), Some("www.test1.com"));
    // Without `ssl` HAProxy accepts them and they do nothing until `ssl` or `check-ssl`.
    let s = first_server("verify none sni str(foo) alpn h2 verifyhost foo ca-file /x.pem");
    assert!(!s.ssl);
    assert_eq!(s.sni.as_deref(), Some("str(foo)"));
    assert_eq!(s.verify, Some(SslVerify::None));
}

#[test]
fn sni_auto_can_be_switched_off() {
    assert!(!first_server("ssl verify none").no_sni_auto);
    assert!(first_server("ssl verify none no-sni-auto").no_sni_auto);
    assert!(!first_server("ssl verify none no-sni-auto sni-auto").no_sni_auto);
    assert!(first_server("check check-ssl verify none no-check-sni-auto").no_check_sni_auto);
}

#[test]
fn check_tls_keywords_are_kept() {
    let s = first_server("check check-ssl verify none check-sni chk.example check-alpn http/1.1");
    assert_eq!(s.check_ssl, Some(true));
    assert_eq!(s.check_sni.as_deref(), Some("chk.example"));
    assert_eq!(s.check_alpn, vec!["http/1.1".to_string()]);
    assert!(!s.ssl, "`check-ssl` encrypts the checks only");
    let s = first_server("ssl verify none check no-check-ssl");
    assert_eq!(s.check_ssl, Some(false));
    assert_eq!(first_server("ssl verify none check").check_ssl, None, "inherited from `ssl` at load");
}

#[test]
fn tls_versions_rustls_speaks_are_accepted_and_the_others_refused() {
    let s = first_server("ssl verify none ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3");
    assert_eq!(s.min_ver, Some(TlsVersion::Tls12));
    assert_eq!(s.max_ver, Some(TlsVersion::Tls13));
    let s = first_server("ssl verify none force-tlsv13");
    assert_eq!((s.min_ver, s.max_ver), (Some(TlsVersion::Tls13), Some(TlsVersion::Tls13)));
    let s = first_server("ssl verify none no-tlsv13");
    assert_eq!((s.min_ver, s.max_ver), (None, Some(TlsVersion::Tls12)));
    let s = first_server("ssl verify none no-tlsv12");
    assert_eq!((s.min_ver, s.max_ver), (Some(TlsVersion::Tls13), None));
    // rustls never offers these, so disabling them changes nothing.
    assert!(server_line("ssl verify none no-tlsv10 no-tlsv11 no-sslv3").is_ok());

    for line in ["ssl verify none ssl-min-ver TLSv1.0", "ssl verify none ssl-max-ver TLSv1.1", "ssl verify none ssl-min-ver SSLv3", "ssl verify none force-tlsv12 force-tlsv10"] {
        let err = server_line(line).expect_err(line);
        assert!(err.message.contains("rustls"), "`{line}` must say why: {}", err.message);
    }
    let err = server_line("ssl verify none ssl-min-ver TLSv1.4").expect_err("unknown version");
    assert!(err.message.contains("'TLSv1.4' : unknown ssl/tls version."), "{}", err.message);
    let err = server_line("ssl verify none no-tlsv13 no-tlsv12").expect_err("nothing left");
    assert!(err.message.contains("no TLS version"), "{}", err.message);
}

#[test]
fn session_reuse_can_be_switched_off() {
    assert!(!first_server("ssl verify none").no_reuse);
    assert!(first_server("ssl verify none no-ssl-reuse").no_reuse);
    assert!(!first_server("ssl verify none no-ssl-reuse ssl-reuse").no_reuse);
}

#[test]
fn default_server_tls_is_inherited_and_no_ssl_undoes_it() {
    let cfg = parse_str(&format!(
        "{DEFAULTS}backend b\n  default-server ssl verify none alpn h2 check-ssl\n  server s1 127.0.0.1:8080\n  server s2 127.0.0.1:8081 no-ssl no-check-ssl\n"
    ))
    .expect("loads");
    let s1 = cfg.backends[0].servers[0].ssl.as_deref().expect("s1 inherited TLS");
    assert!(s1.ssl);
    assert_eq!(s1.alpn, vec!["h2".to_string()]);
    assert_eq!(s1.check_ssl, Some(true));
    let s2 = cfg.backends[0].servers[1].ssl.as_deref().expect("s2 still carries the turned-off flags");
    assert!(!s2.ssl, "`no-ssl` turns the inherited `ssl` off");
    assert_eq!(s2.check_ssl, Some(false));
}

#[test]
fn a_missing_argument_is_reported_as_haproxy_does() {
    for kw in ["sni", "alpn", "ca-file", "verifyhost", "check-sni", "check-alpn", "crt", "crl-file", "ssl-min-ver", "ssl-max-ver", "verify"] {
        let err = server_line(kw).expect_err(kw);
        assert!(err.message.contains(&format!("'{kw}'")), "`{kw}`: {}", err.message);
    }
    let err = server_line("ssl verify maybe").expect_err("bad verify");
    assert!(err.message.contains("'verify'") && err.message.contains("maybe"), "{}", err.message);
}

#[test]
fn the_openssl_only_keywords_stay_refused() {
    for line in [
        "ssl verify none ciphers ECDHE-RSA-AES128-GCM-SHA256",
        "ssl verify none ciphersuites TLS_AES_128_GCM_SHA256",
        "ssl verify none curves X25519",
        "ssl verify none sigalgs RSA-PSS+SHA256",
        "ssl verify none client-sigalgs RSA-PSS+SHA256",
        "ssl verify none npn h2",
        "ssl verify none allow-0rtt",
        "ssl verify none ktls on",
        "ssl verify none renegotiate",
        "ssl verify none no-renegotiate",
        "ssl verify none tls-tickets",
        "ssl verify none no-tls-tickets",
        "ssl verify none send-proxy-v2-ssl",
        "ssl verify none send-proxy-v2-ssl-cn",
        "ssl verify none force-sslv3",
        "ssl verify none force-tlsv10",
        "ssl verify none force-tlsv11",
    ] {
        let err = server_line(line).expect_err(line);
        let kw = line.split_whitespace().nth(3).unwrap();
        assert!(err.message.contains(&format!("'{kw}'")), "`{line}`: {}", err.message);
    }
}

/// `proto h2` and `check-proto h2` used to be a warning, then refused (T113). Since T540 both
/// speak h2 to the server.
#[test]
fn h2_towards_a_server_and_its_checks_is_accepted() {
    for line in ["proto h2", "check-proto h2", "check check-proto h2", "proto h1 check-proto h1"] {
        assert!(server_line(line).is_ok(), "{line}");
    }
}

/// The `sni` expression is recorded for the load-time check of its fetch name, as ACL
/// and log-format expressions are.
#[test]
fn the_sni_expression_is_recorded_for_the_load_time_check() {
    let cfg = server_line("ssl verify none sni req.hdr(host),field(1,:)").expect("loads");
    assert!(
        cfg.sample_refs.iter().any(|r| r.directive == "server" && r.expr == "req.hdr(host),field(1,:)" && !r.acl),
        "sample_refs: {:?}",
        cfg.sample_refs
    );
}
