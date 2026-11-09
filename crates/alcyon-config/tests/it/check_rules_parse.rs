// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-check` and `tcp-check` rules that `HAProxy` (3.5-dev8-885761-29) accepts and
//! refuses with `haproxy -c`, measured 2026-10-04 on a backend with `option httpchk`
//! (`option tcp-check` for the `tcp-check` rules), and what the parser makes of the ones
//! it accepts (T134).

use alcyon_config::{parse_str, Config};

fn parse(mode: &str, check: &str, rule: &str) -> Result<Config, alcyon_config::ConfigError> {
    parse_str(&format!(
        "defaults\n  mode {mode}\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         backend b\n  {check}\n  {rule}\n  server s 127.0.0.1:1 check\n"
    ))
}

#[test]
fn http_check_rules_haproxy_accepts() {
    for rule in [
        "http-check send comment hi",
        "http-check send hdr content-length 5 hdr transfer-encoding x",
        "http-check expect min-recv x string a",
        "http-check expect hdr name x value y comment z",
        "http-check expect !status 200",
        "http-check expect ! status 200",
        "http-check connect addr 127.0.0.1:1234",
        "http-check connect addr 127.0.0.1 port 5",
        "http-check connect port 5 comment c send-proxy",
        "http-check comment hi\n  http-check expect status 200",
        "http-check set-var(check.x) str(a)\n  http-check unset-var(check.x)",
        "http-check expect status 200\n  http-check unset-var(check.x)\n  http-check set-var(check.y) str(b)",
        "http-check connect port 7\n  http-check send meth GET",
    ] {
        parse("http", "option httpchk", rule).unwrap_or_else(|e| panic!("HAProxy accepts `{rule}`: {e}"));
    }
}

#[test]
fn http_check_rules_haproxy_refuses() {
    for rule in [
        "http-check",
        "http-check send meth",
        "http-check send hdr a",
        "http-check send hdr host a hdr Host b",
        "http-check send comment",
        "http-check expect",
        "http-check expect status 300-200",
        "http-check expect status 2x",
        "http-check expect string a rstring b",
        "http-check expect min-recv -2 string a",
        "http-check expect min-recv 1",
        "http-check expect hdr",
        "http-check expect hdr name",
        "http-check expect hdr name x -m",
        "http-check expect hdr name x -m bad",
        "http-check expect hdr name-lf x -m reg y",
        "http-check expect hdr name x value",
        "http-check expect hdr name x value -m",
        "http-check expect hdr name x value-lf -m reg y",
        "http-check expect hdr name x value -m bad y",
        "http-check expect bogus",
        "http-check expect status",
        "http-check expect string",
        "http-check expect comment",
        "http-check expect rstatus",
        "http-check expect rstatus (",
        "http-check connect addr",
        "http-check connect addr nope",
        "http-check connect port",
        "http-check connect port x",
        "http-check connect comment",
        "http-check send meth GET\n  http-check connect",
        "http-check comment",
        "http-check set-var(check.x)",
        "http-check set-var(check.x str(a)",
        "http-check set-var(check.) str(a)",
        "http-check bogus",
    ] {
        assert!(parse("http", "option httpchk", rule).is_err(), "HAProxy refuses `{rule}`");
    }
}

#[test]
fn tcp_check_rules_haproxy_accepts() {
    for rule in [
        "tcp-check connect comment c port 5 send-proxy",
        "tcp-check expect min-recv x string a",
        "tcp-check expect min-recv -1 string a",
        "tcp-check expect min-recv 3 string a",
        "tcp-check expect string a comment c",
    ] {
        parse("tcp", "option tcp-check", rule).unwrap_or_else(|e| panic!("HAProxy accepts `{rule}`: {e}"));
    }
}

#[test]
fn tcp_check_rules_haproxy_refuses() {
    for rule in [
        "tcp-check connect port",
        "tcp-check connect port x",
        "tcp-check connect comment",
        "tcp-check connect bogus",
        "tcp-check expect min-recv -2 string a",
        "tcp-check expect",
        "tcp-check expect string",
        "tcp-check expect rstring (",
        "tcp-check expect binary zz",
        "tcp-check expect string a rstring b",
        "tcp-check expect comment",
        "tcp-check expect bogus",
        "tcp-check bogus",
        "tcp-check",
        "tcp-check send",
        "tcp-check send-binary zz",
        "tcp-check comment",
        "tcp-check expect status 200",
    ] {
        assert!(parse("tcp", "option tcp-check", rule).is_err(), "HAProxy refuses `{rule}`");
    }
}

/// Rules `HAProxy` accepts and Alcyon refuses rather than drop.
#[test]
fn unimplemented_rules_are_refused() {
    for rule in [
        "http-check expect custom",
        "http-check expect string a on-error x",
        "http-check disable-on-404",
        "http-check set-var(txn.x) str(a)",
        "http-check connect ssl",
    ] {
        assert!(parse("http", "option httpchk", rule).is_err(), "`{rule}` is accepted");
    }
    for rule in ["tcp-check expect string-lf a", "tcp-check expect string a error-status L7RSP", "tcp-check send-lf a"] {
        assert!(parse("tcp", "option tcp-check", rule).is_err(), "`{rule}` is accepted");
    }
}

/// A `listen` section with its own rules takes none of the defaults'.
#[test]
fn a_listen_section_with_http_check_rules_drops_the_defaults() {
    let cfg = parse_str(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n  option httpchk GET /d\n\
         listen l\n  bind 127.0.0.1:29001\n  http-check send hdr x y\n  server s 127.0.0.1:1 check\n",
    )
    .expect("parses");
    assert_eq!(cfg.listens[0].http_checks.len(), 1);
    assert!(cfg.listens[0].http_check_own);
}

/// T304: the servers of a section whose checks resolve the same share one registered copy;
/// a server whose check differs (here its `port`) has its own, and a check is found by its
/// address too. The table is the process's: another test's parse clears it, so this tries
/// again until no parse came between.
#[test]
fn servers_resolving_to_the_same_check_share_one_copy() {
    use alcyon_config::ast::get_resolved_check_config;
    use std::net::SocketAddr;
    use std::sync::Arc;
    let text = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
                backend b\n  option httpchk GET /t304\n\
                  server s1 127.0.0.1:19971 check\n  server s2 127.0.0.1:19972 check\n\
                  server s3 127.0.0.1:19973 check port 19979\n";
    let at = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..100 {
        parse_str(text).expect("parse");
        let (Some(a), Some(b), Some(c), Some(by_addr)) = (
            get_resolved_check_config(0, 0, at(19971)),
            get_resolved_check_config(0, 1, at(19972)),
            get_resolved_check_config(0, 2, at(19973)),
            get_resolved_check_config(usize::MAX, usize::MAX, at(19972)),
        ) else {
            continue;
        };
        let alcyon_config::ast::ResolvedCheckConfig::Http(h) = &*a else { continue };
        if h.uri != "/t304" {
            continue;
        }
        assert!(Arc::ptr_eq(&a, &b), "s1 and s2 resolve the same check: one copy");
        assert!(!Arc::ptr_eq(&a, &c), "s3 checks another port");
        assert!(Arc::ptr_eq(&b, &by_addr), "found by address, the same copy");
        return;
    }
    panic!("the resolved checks were replaced on every attempt");
}
