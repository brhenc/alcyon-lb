// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Every `server` and `default-server` keyword the reference `HAProxy` knows, and what Ibex
//! does with it (T94).
//!
//! Until T94 both keyword loops ended in `_ => {}`: any keyword was accepted and dropped,
//! and a keyword's argument was then read as the next keyword. `server s1 10.0.0.1:443 ssl
//! verify required ca-file ca.pem` loaded and connected in plaintext; `server a ... cookie
//! backup` made `a` a backup server.
//!
//! The keyword list is `srv_kws` in `src/server.c`, `src/check.c`, `src/cfgparse-ssl.c`,
//! `src/cfgparse-tcp.c` and `src/tcpcheck.c` of `HAProxy` 3.5-dev8-885761-29. Its
//! behaviour was measured with `haproxy -c` on 2026-10-03, one keyword per run, on a
//! `server` line and on a `default-server` line of a `mode http` backend:
//!
//! * every keyword below is accepted, except: `namespace ns1` (no such namespace),
//!   `usesrc` (only after `source`), `agent-check` (no agent port), `ssl` and `check-ssl`
//!   ("verify is enabled by default but no CA file specified"), and `ktls` (experimental);
//! * `quic-cc-algo` is an unknown keyword in this build, and so are `check-port` ("did you
//!   mean 'check-proto'") and anything made up;
//! * on a `default-server` line, `id`, `guid`, `no-sslv3` and `no-tlsv10`..`no-tlsv13`
//!   draw "option is not accepted in default-server sections", and the configuration is
//!   still valid (exit status 0): the keyword and its argument are skipped.
//!
//! Ibex refuses every keyword whose absence would change security, encryption, certificate
//! checking, routing, or what is sent to the server, and accepts the pure tuning keywords
//! with a warning. The warning is checked against the daemon in
//! `crates/ibex-rt/tests/server_and_option_keywords.rs`.

use ibex_config::{parse_str, Config, ConfigError};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nresolvers r1\n  nameserver ns 127.0.0.1:53\n";

fn server_line(rest: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{DEFAULTS}backend b\n  server s1 127.0.0.1:8080 {rest}\n"))
}

fn default_server_line(rest: &str) -> Result<Config, ConfigError> {
    parse_str(&format!("{DEFAULTS}backend b\n  default-server {rest}\n  server s1 127.0.0.1:8080\n"))
}

/// What Ibex does with a keyword.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ibex {
    /// Accepted: implemented, or a tuning keyword ignored with a warning.
    Accepts,
    /// Refused with an error that names the keyword.
    Refuses,
}
use Ibex::{Accepts, Refuses};

/// Every keyword `HAProxy` 3.5-dev8 registers for servers, with an argument it accepts.
const KEYWORDS: &[(&str, Ibex)] = &[
    // src/server.c
    ("backup", Accepts),
    ("cookie c1", Accepts),
    ("disabled", Accepts),
    ("enabled", Accepts),
    ("error-limit 5", Accepts),
    ("guid g1", Accepts),
    ("ws auto", Accepts),
    ("hash-key id", Refuses),
    ("id 7", Accepts),
    ("idle-ping 5s", Accepts),
    ("init-addr none", Accepts),
    ("init-state up", Refuses),
    ("log-bufsize 1024", Accepts),
    ("log-proto legacy", Accepts),
    ("maxconn 10", Accepts),
    // T240: a limit Ibex cannot apply is refused; 0, no limit, is what Ibex does.
    ("maxqueue 10", Refuses),
    ("maxqueue 0", Accepts),
    ("max-reuse 10", Accepts),
    ("minconn 5", Accepts),
    ("namespace ns1", Refuses),
    ("no-backup", Accepts),
    ("no-send-proxy", Accepts),
    ("no-send-proxy-v2", Accepts),
    ("no-tfo", Accepts),
    ("non-stick", Refuses),
    ("observe layer4", Refuses),
    ("on-error fastinter", Refuses),
    ("on-marked-down shutdown-sessions", Refuses),
    ("on-marked-up shutdown-backup-sessions", Refuses),
    ("pool-conn-name str(a)", Refuses),
    ("pool-low-conn 5", Accepts),
    ("pool-max-conn 5", Accepts),
    ("pool-purge-delay 5s", Accepts),
    ("proto h1", Accepts),
    ("proto h2", Accepts),
    ("proxy-v2-options ssl", Refuses),
    ("redir http://example.com", Refuses),
    ("resolve-net 10.0.0.0/8", Accepts),
    ("resolve-opts allow-dup-ip", Accepts),
    ("resolve-prefer ipv4", Accepts),
    ("resolvers r1", Accepts),
    ("send-proxy", Accepts),
    ("send-proxy-v2", Accepts),
    ("set-proxy-v2-tlv-fmt(0xE1) foo", Refuses),
    ("shard 1", Accepts),
    ("slowstart 10s", Accepts),
    ("source 127.0.0.1", Refuses),
    ("stick", Accepts),
    ("strict-maxconn", Accepts),
    ("tfo", Accepts),
    // `track` needs a checked server to point at, which these one-server lines lack: it is
    // implemented (T141) and tested in `crates/ibex-rt/tests/server_track.rs`.
    ("socks4 127.0.0.1:1080", Refuses),
    ("usesrc client", Refuses),
    ("weight 10", Accepts),
    // src/check.c
    ("addr 127.0.0.2", Refuses),
    ("agent-addr 127.0.0.2", Accepts),
    ("agent-check", Refuses),
    ("agent-inter 5s", Accepts),
    ("agent-port 9000", Accepts),
    ("agent-send foo", Accepts),
    ("check", Accepts),
    ("check-pool-conn-name foo", Accepts),
    ("check-proto h1", Accepts),
    ("check-proto h2", Accepts),
    ("check-reuse-pool", Accepts),
    ("check-send-proxy", Refuses),
    ("check-via-socks4", Refuses),
    ("no-agent-check", Accepts),
    ("no-check", Accepts),
    ("no-check-reuse-pool", Accepts),
    ("no-check-send-proxy", Accepts),
    ("rise 2", Accepts),
    ("fall 3", Accepts),
    ("inter 2s", Accepts),
    ("fastinter 1s", Accepts),
    ("downinter 1s", Accepts),
    ("port 81", Accepts),
    // src/cfgparse-ssl.c: TLS to servers is implemented (T113, `tests/server_tls.rs`).
    // `ssl` and `check-ssl` alone are refused as HAProxy refuses them (no CA file); a
    // keyword rustls has no equivalent for stays refused; the paths of `ca-file`, `crt`
    // and `crl-file` are opened at load (`ibex -c`), as a bind's `crt` is.
    ("allow-0rtt", Refuses),
    ("alpn h2", Accepts),
    ("ca-file /etc/ssl/ca.pem", Accepts),
    ("check-alpn h2", Accepts),
    ("check-sni foo", Accepts),
    ("check-sni-auto", Accepts),
    ("check-ssl", Refuses),
    ("ciphers ECDHE-RSA-AES128-GCM-SHA256", Refuses),
    ("ciphersuites TLS_AES_128_GCM_SHA256", Refuses),
    ("client-sigalgs RSA-PSS+SHA256", Refuses),
    ("crl-file /etc/ssl/crl.pem", Accepts),
    ("curves X25519", Refuses),
    ("crt /etc/ssl/client.pem", Accepts),
    ("force-sslv3", Refuses),
    ("force-tlsv10", Refuses),
    ("force-tlsv11", Refuses),
    ("force-tlsv12", Accepts),
    ("force-tlsv13", Accepts),
    ("ktls on", Refuses),
    ("no-check-sni-auto", Accepts),
    ("no-check-ssl", Accepts),
    ("no-renegotiate", Refuses),
    ("no-send-proxy-v2-ssl", Accepts),
    ("no-send-proxy-v2-ssl-cn", Accepts),
    ("no-sni-auto", Accepts),
    ("no-ssl", Accepts),
    ("no-ssl-reuse", Accepts),
    ("no-sslv3", Accepts),
    ("no-tlsv10", Accepts),
    ("no-tlsv11", Accepts),
    ("no-tlsv12", Accepts),
    ("no-tlsv13", Accepts),
    ("no-tls-tickets", Refuses),
    ("npn h2", Refuses),
    ("renegotiate", Refuses),
    ("send-proxy-v2-ssl", Refuses),
    ("send-proxy-v2-ssl-cn", Refuses),
    ("sigalgs RSA-PSS+SHA256", Refuses),
    ("sni str(foo)", Accepts),
    ("sni-auto", Accepts),
    ("ssl", Refuses),
    ("ssl-min-ver TLSv1.2", Accepts),
    ("ssl-max-ver TLSv1.3", Accepts),
    ("ssl-reuse", Accepts),
    ("tls-tickets", Refuses),
    ("verify none", Accepts),
    ("verifyhost foo", Accepts),
    // src/cfgparse-tcp.c
    ("cc cubic", Accepts),
    ("tcp-md5sig secret", Refuses),
    ("tcp-ut 5s", Accepts),
    // src/tcpcheck.c
    ("healthcheck hc1", Refuses),
];

/// The keywords `HAProxy` warns about and skips on a `default-server` line.
const NOT_FOR_DEFAULT_SERVER: &[&str] = &["guid g1", "id 7", "no-sslv3", "no-tlsv10", "no-tlsv11", "no-tlsv12", "no-tlsv13"];

fn keyword(line: &str) -> &str {
    let first = line.split_whitespace().next().unwrap_or(line);
    first.split('(').next().unwrap_or(first)
}

fn check(line: &str, expect: Ibex, outcome: &Result<Config, ConfigError>, place: &str) {
    match (expect, outcome) {
        (Accepts, Ok(_)) => {}
        (Accepts, Err(e)) => panic!("{place} `{line}` must load, as HAProxy loads it; Ibex said: {}", e.message),
        (Refuses, Ok(_)) => panic!(
            "{place} `{line}` loaded, and Ibex would run without what it asks for. It must be refused \
             with an error naming '{}'.",
            keyword(line)
        ),
        (Refuses, Err(e)) => assert!(
            e.message.contains(&format!("'{}", keyword(line))),
            "{place} `{line}` was refused, but the error does not name the keyword: {}",
            e.message
        ),
    }
}

#[test]
fn every_haproxy_server_keyword_is_implemented_refused_or_warned_about() {
    for &(line, expect) in KEYWORDS {
        check(line, expect, &server_line(line), "server");
    }
}

#[test]
fn every_haproxy_server_keyword_on_a_default_server_line() {
    for &(line, expect) in KEYWORDS {
        // HAProxy skips these on a default-server line with an alert, and the configuration
        // stays valid. Ibex does the same, with a warning.
        let expect = if NOT_FOR_DEFAULT_SERVER.contains(&line) { Accepts } else { expect };
        check(line, expect, &default_server_line(line), "default-server");
    }
}

#[test]
fn keywords_haproxy_does_not_know_are_refused() {
    // check-port: "unknown keyword 'check-port'; did you mean 'check-proto' maybe ?". Ibex
    // used to take it as `port`. quic-cc-algo is not built into the reference binary.
    for line in ["check-port 81", "quic-cc-algo cubic", "bogus-kw", "chek", "weigth 3"] {
        let err = server_line(line).expect_err(line);
        assert!(err.message.contains("unknown keyword"), "{line}: {}", err.message);
        assert!(err.message.contains(&format!("'{}'", keyword(line))), "{line}: {}", err.message);
        let err = default_server_line(line).expect_err(line);
        assert!(err.message.contains("unknown keyword"), "default-server {line}: {}", err.message);
    }
}

/// The configuration from T94. `HAProxy` connects with TLS and checks the server's
/// certificate against `ca.pem`; Ibex used to load it and connect in plaintext, then (T94)
/// refused it, and since T113 does what it says (`tests/server_tls.rs`; the file is
/// opened at load). A server line that would verify against nothing is refused with
/// `HAProxy`'s alert, from a `default-server` too.
#[test]
fn a_tls_server_loads_and_one_without_trust_anchors_is_refused() {
    server_line("ssl verify required ca-file ca.pem alpn h2").expect("loads");
    let err = server_line("ssl").expect_err("must not load");
    assert!(err.message.contains("no CA file specified"), "{}", err.message);
    let err = default_server_line("ssl").expect_err("must not load");
    assert!(err.message.contains("no CA file specified"), "{}", err.message);
    default_server_line("ssl verify none").expect("loads");
}

/// An argument is consumed with its keyword. `HAProxy` reads `cookie backup` as the cookie
/// value "backup"; Ibex dropped `cookie`, read `backup` as a keyword, and made the server
/// a backup. The same for a keyword that is only warned about.
#[test]
fn a_keyword_argument_is_not_read_as_the_next_keyword() {
    for line in ["cookie backup", "agent-send backup", "error-limit 3 maxconn 7", "slowstart backup"] {
        let Ok(cfg) = server_line(line) else {
            // `slowstart backup` is not a delay; HAProxy refuses it ("unexpected character").
            assert_eq!(line, "slowstart backup", "{line} must load");
            continue;
        };
        let s = &cfg.backends[0].servers[0];
        assert!(!s.backup, "`{line}` made the server a backup: its argument was read as a keyword");
        if line.contains("maxconn") {
            assert_eq!(s.maxconn, Some(7), "`{line}`: the keyword after the argument was lost");
        }
    }
    assert!(server_line("slowstart backup").is_err(), "HAProxy: 'server b/s1' : unexpected character");
}

/// A keyword whose argument is missing is an error, as in `HAProxy`:
/// "'inter' expects a delay as argument.", "'fall' expects an integer argument.",
/// "'port' expects a port number as argument.", "'check-proto' : missing value."
#[test]
fn a_missing_argument_is_an_error() {
    for kw in ["inter", "fall", "rise", "port", "proto", "check-proto", "cookie", "slowstart", "agent-send", "ssl-min-ver"] {
        let err = server_line(kw).expect_err(kw);
        assert!(err.message.contains(&format!("'{kw}'")), "{kw}: {}", err.message);
        assert!(default_server_line(kw).is_err(), "default-server {kw}");
    }
}

/// `weight` and `maxconn` with nothing after them: `HAProxy` 3.5-dev8 accepts both, on a
/// `server` and on a `default-server` line (exit status 0, measured 2026-10-03), as Ibex
/// always has. Only the keywords above it refuses are errors.
#[test]
fn a_trailing_weight_or_maxconn_is_accepted_as_haproxy_accepts_it() {
    for kw in ["weight", "maxconn"] {
        assert!(server_line(kw).is_ok(), "server {kw}");
        assert!(default_server_line(kw).is_ok(), "default-server {kw}");
    }
}

/// `proto` and `check-proto` name the protocol spoken to the server, h2 since T540 (T113:
/// until then `h2` was a warning, and the reg-tests `checks/http-check.vtc` and
/// `http-messaging/http_bodyless_response.vtc` passed only because both ends ignored it).
/// `HAProxy` refuses a protocol it has no mux for: "'proto' :  unknown MUX protocol 'h3'."
#[test]
fn proto_values() {
    for line in ["proto h1", "proto h2", "check-proto h1", "check-proto h2"] {
        assert!(server_line(line).is_ok(), "{line}");
    }
    for line in ["proto h3", "proto fcgi", "proto spop", "check-proto bogus"] {
        let err = server_line(line).expect_err(line);
        assert!(err.message.contains(&format!("'{}'", keyword(line))), "{line}: {}", err.message);
    }
}

/// What a `default-server` line sets, a `server` line inherits, and a `no-` keyword clears.
#[test]
fn default_server_settings_are_inherited_and_no_keywords_clear_them() {
    let cfg = parse_str(&format!(
        "{DEFAULTS}backend b\n  default-server check send-proxy send-proxy-v2 weight 7 backup\n  \
         server s1 127.0.0.1:8080\n  server s2 127.0.0.1:8081 no-check no-send-proxy no-send-proxy-v2 no-backup\n"
    ))
    .expect("HAProxy loads this");
    let (s1, s2) = (&cfg.backends[0].servers[0], &cfg.backends[0].servers[1]);
    assert!(s1.check && s1.send_proxy && s1.send_proxy_v2 && s1.backup, "s1 inherits: {s1:?}");
    assert_eq!(s1.weight, Some(7), "default-server weight is inherited");
    assert!(!s2.check, "no-check");
    assert!(!s2.send_proxy, "no-send-proxy");
    assert!(!s2.send_proxy_v2, "no-send-proxy-v2");
    assert!(!s2.backup, "no-backup");
    assert_eq!(s2.weight, Some(7));
}

#[test]
fn resolvers_naming_a_missing_section_is_refused_as_haproxy_refuses_it() {
    // Measured with HAProxy 3.5-dev8 (`haproxy -c`): on a `server` line the alert is
    // "backend 'b', server 's1': unable to find required resolvers 'r1'", status 1. On a
    // `default-server` line with a section present it loads.
    let defaults = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";
    let cases = [
        format!("{defaults}backend b\n  server s1 127.0.0.1:8080 resolvers r1\n"),
        format!("{defaults}backend b\n  default-server resolvers r1\n  server s1 127.0.0.1:8080\n"),
    ];
    for cfg in &cases {
        let e = parse_str(cfg).expect_err("a missing resolvers section must be refused");
        assert!(
            e.message.contains("unable to find required resolvers 'r1'"),
            "wrong message: {}",
            e.message
        );
    }
}
