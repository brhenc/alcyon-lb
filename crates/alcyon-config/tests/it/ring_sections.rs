// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `ring` and `log-forward` sections, and `log ring@<name>`. The messages are the reference
//! `HAProxy`'s (3.5-dev8-885761-29, 2026-10-04) where it refuses the same thing.

use alcyon_config::{
    parse_str, LogForwardBind, LogForwardHost, LogTarget, RingFormat, RingServerAddr,
};

fn refused(cfg: &str) -> String {
    parse_str(cfg).expect_err("refused").message
}

#[test]
fn a_ring_section_reads_every_keyword() {
    let cfg = parse_str(
        "ring myring\n  description \"My local buffer\"\n  format rfc5424\n  maxlen 1200\n  size 32764\n  \
         timeout connect 3s\n  timeout server 10s\n  server s1 127.0.0.1:2514 ssl verify none log-proto octet-count\n  \
         server s2 unix@/tmp/x.sock\n",
    )
    .expect("parses");
    let r = &cfg.rings[0];
    assert_eq!(r.name, "myring");
    assert_eq!(r.description.as_deref(), Some("My local buffer"));
    assert_eq!(r.format, RingFormat::Rfc5424);
    assert_eq!(r.maxlen, Some(1200));
    assert_eq!(r.size, 32764);
    assert_eq!(r.timeout_connect.as_millis(), 3000);
    assert_eq!(r.timeout_server.as_millis(), 10_000);
    assert_eq!(r.servers.len(), 2);
    assert!(r.servers[0].ssl && r.servers[0].octet_count);
    assert!(matches!(r.servers[0].addr, RingServerAddr::Tcp(a) if a.port() == 2514));
    assert_eq!(r.servers[1].addr, RingServerAddr::Unix("/tmp/x.sock".into()));
}

#[test]
fn a_ring_defaults_to_raw_and_one_buffer() {
    let cfg = parse_str("ring r\n").expect("parses");
    let r = &cfg.rings[0];
    assert_eq!((r.format, r.size, r.maxlen), (RingFormat::Raw, 16384, None));
}

#[test]
fn a_ring_refuses_what_haproxy_refuses() {
    assert_eq!(refused("ring\n"), "missing ring name.");
    assert_eq!(refused("ring r\n  size 0\n"), "invalid size '0' for new sink buffer.");
    assert_eq!(refused("ring r\n  maxlen 0\n"), "invalid size '0' for new sink buffer.");
    assert_eq!(refused("ring r\n  format foo\n"), "unknown format 'foo'.");
    assert_eq!(refused("ring r\n  foo\n"), "unknown statement 'foo'.");
    assert_eq!(refused("ring r\nring r\n"), "sink named 'r' already exists.");
    assert_eq!(refused("ring stdout\n"), "sink named 'stdout' already exists.");
    assert_eq!(refused("ring r\n  description\n"), "missing ring description text.");
}

#[test]
fn a_ring_refuses_what_alcyon_does_not_do_rather_than_dropping_it() {
    assert!(refused("ring r\n  backing-file /tmp/x\n").contains("backing-file"));
    assert!(refused("ring r\n  server s 127.0.0.1:1 check\n").contains("'check'"));
    assert!(refused("ring r\n  server s 127.0.0.1:1 ssl verify required\n").contains("verify"));
    assert!(refused("ring r\n  server s 127.0.0.1:1 log-proto bogus\n").contains("log-proto"));
}

#[test]
fn a_log_line_can_name_a_ring() {
    let cfg = parse_str("global\n  log ring@myring local0\nring myring\n").expect("parses");
    assert_eq!(cfg.global.expect("global").logs[0].target, LogTarget::Ring("myring".into()));
    assert!(parse_str("global\n  log ring@ local0\n").is_err());
}

#[test]
fn a_log_forward_section_reads_every_keyword() {
    let cfg = parse_str(
        "log-forward f\n  dgram-bind 127.0.0.1:1514\n  bind 127.0.0.1:2514\n  bind unix@/tmp/f.sock mode 660\n  \
         log 127.0.0.1:9 local0\n  log global\n  maxconn 20\n  timeout client 5s\n  option assume-rfc6587-ntf\n  \
         option dont-parse-log\n  option host replace\n",
    )
    .expect("parses");
    let f = &cfg.log_forwards[0];
    assert_eq!(f.name, "f");
    assert_eq!(f.dgram_binds.len(), 1);
    assert!(matches!(&f.binds[0], LogForwardBind::Tcp(b) if b.addr.port() == 2514 && !b.ssl));
    assert_eq!(f.binds[1], LogForwardBind::Unix { path: "/tmp/f.sock".into(), mode: Some(0o660) });
    assert_eq!(f.logs.len(), 1);
    assert!(f.log_global && f.assume_ntf && f.dont_parse);
    assert_eq!((f.maxconn, f.timeout_client.map(|t| t.as_secs())), (20, Some(5)));
    assert_eq!(f.host, LogForwardHost::Replace);
}

#[test]
fn a_log_forward_bind_can_be_tls() {
    let cfg = parse_str("log-forward f\n  bind 127.0.0.1:2514 ssl crt /tmp/c.pem\n").expect("parses");
    assert!(matches!(&cfg.log_forwards[0].binds[0], LogForwardBind::Tcp(b) if b.ssl && b.crt == ["/tmp/c.pem"]));
}

#[test]
fn a_log_forward_refuses_what_haproxy_refuses_and_what_alcyon_lacks() {
    assert_eq!(refused("log-forward\n"), "missing name for log-forward section.");
    assert_eq!(refused("log-forward f\n  foo\n"), "unknown keyword 'foo' in log-forward section.");
    assert!(refused("log-forward f\nlog-forward f\n").contains("same name"));
    assert!(refused("log-forward f\n  backlog 10\n").contains("backlog"));
    assert!(refused("log-forward f\n  option host sideways\n").contains("option host"));
    assert!(refused("log-forward f\n  dgram-bind 127.0.0.1:1 interface lo\n").contains("interface"));
}

#[test]
fn a_log_line_format_must_be_one_haproxy_has() {
    assert_eq!(refused("global\n  log 127.0.0.1:1 format foo local0\n"), "unknown log format 'foo'");
    for f in ["raw", "iso", "local", "rfc3164", "rfc5424", "short", "priority", "timed"] {
        parse_str(&format!("global\n  log 127.0.0.1:1 format {f} local0\n")).expect(f);
    }
}

#[test]
fn every_malformed_ring_line_is_refused_with_haproxys_words() {
    assert!(refused("ring a/b\n").contains("character '/' is not permitted"));
    assert_eq!(refused("ring r\n  format\n"), "unable to set format ''.");
    assert_eq!(refused("ring r\n  maxlen\n"), "invalid size '' for new sink buffer.");
    assert_eq!(refused("ring r\n  size\n"), "invalid size '' for new sink buffer.");
    assert!(refused("ring r\n  timeout connect\n").contains("expects <time>"));
    assert!(refused("ring r\n  server\n").contains("expects <name> and <addr>"));
    assert!(refused("ring r\n  server s quic4@127.0.0.1:1\n").contains("QUIC"));
    // A `timeout` other than `connect` and `server` is read and ignored, as `HAProxy` does.
    parse_str("ring r\n  timeout client 1s\n").expect("ignored");
    let cfg = parse_str("ring r\n  server s tcp@127.0.0.1:1 log-proto legacy\n  server t /tmp/x.sock\n").expect("parses");
    assert!(!cfg.rings[0].servers[0].octet_count);
    assert_eq!(cfg.rings[0].servers[1].addr, RingServerAddr::Unix("/tmp/x.sock".into()));
}

#[test]
fn every_malformed_log_forward_line_is_refused() {
    assert!(refused("log-forward a/b\n").contains("character '/' is not permitted"));
    assert!(refused("log-forward f\n  bind\n").contains("expects <addr:port>"));
    assert!(refused("log-forward f\n  bind quic4@127.0.0.1:1\n").contains("QUIC"));
    assert!(refused("log-forward f\n  bind unix@/tmp/x mode 9z\n").contains("octal"));
    assert!(refused("log-forward f\n  bind unix@/tmp/x user bob\n").contains("'user'"));
    assert!(refused("log-forward f\n  dgram-bind\n").contains("expects <addr:port>"));
    assert!(refused("log-forward f\n  dgram-bind quic4@127.0.0.1:1\n").contains("QUIC"));
    assert!(refused("log-forward f\n  maxconn\n").contains("expects an integer"));
    assert!(refused("log-forward f\n  timeout client\n").contains("expects <time>"));
    assert!(refused("log-forward f\n  timeout server 1s\n").contains("timeout"));
    assert!(refused("log-forward f\n  option nosuch\n").contains("unknown option 'nosuch'"));
    assert!(refused("log-forward f\n  option host\n").contains("option host"));
    for (kw, want) in [("replace", LogForwardHost::Replace), ("fill", LogForwardHost::Fill), ("keep", LogForwardHost::Keep), ("append", LogForwardHost::Append)] {
        let cfg = parse_str(&format!("log-forward f\n  option host {kw}\n")).expect("parses");
        assert_eq!(cfg.log_forwards[0].host, want);
    }
    let cfg = parse_str("log-forward f\n  bind /tmp/f.sock\n").expect("a bare path is a UNIX socket");
    assert_eq!(cfg.log_forwards[0].binds[0], LogForwardBind::Unix { path: "/tmp/f.sock".into(), mode: None });
}
