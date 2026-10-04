// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The RFC 7239 `Forwarded` helpers behind `option forwarded` and the `rfc7239_*`
//! converters. Every expected value was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-04, through `rfc7239_is_valid` and
//! `rfc7239_field(<name>)` on a request header, and through `option forwarded`.

use ibex_sample::rfc7239::{field, is_valid, n2nn, n2np, node_from_sample, nn, np, port_from_sample, valid_host};
use ibex_sample::Sample;

#[test]
fn is_valid_matches_haproxy() {
    let valid = [
        r#"for="unknown:132";host="[::1]:65535";by="_obfs:_port";proto=https"#,
        r#"for="127.0.0.1";host=v.test"#,
        r#"by="[::1]""#,
        r#"by="[::1]:3""#,
        r#"proto=http;for="[::1]:_id""#,
        "for=127.9.0.1",
        "for=_abc",
        "for=unknown",
        "for=1.2.3.4;by=5.6.7.8",
        "for=1.2.3.4,for=5.6.7.8",
        "for=1.2.3.4, for=5.6.7.8",
        "for=1.2.3.4 , for=5.6.7.8",
        "for=1.2.3.4,\tfor=5.6.7.8",
        "for=1.2.3.4,,for=1.2.3.5",
        ",for=1.2.3.4",
        r#"host="""#,
        r#"by="1.2.3.4:00080""#,
        r#"by="1.2.3.4:65535""#,
        r#"for="[1:2:3:4:5:6:7:8]""#,
        "for=_-.",
        r#"for="_a:_b""#,
        r#"for="unknown:80""#,
        r#"for="1.2.3.4:_a-b.c_d""#,
        r#"for="1.2.3.4:080""#,
        r#"for="[1::]""#,
        r#"for="[::]""#,
        r#"for="[::1]:80""#,
        "host=a.b",
        "host=A.B",
        r#"host="a.b:80""#,
        r#"host="[::1]""#,
        r#"host="[::1]:80""#,
        r#"host=":80""#,
        r#"host="1.2.3.4""#,
        r#"host="a..b""#,
        r#"host="a:080""#,
        "proto=https",
        "proto=http,proto=https",
        "host=a;proto=http",
        "by=1.2.3.4;for=5.6.7.8;host=h;proto=http",
    ];
    for v in valid {
        assert!(is_valid(v), "{v}");
    }
    let invalid = [
        r#"fore="unknown:132""#,
        "proto=http;proto=http",
        r#"""#,
        "by=[::1]",
        r#"by="[::1]:""#,
        "for=1.2.3.4 ;by=1.2.3.5",
        "for=1.2.3.4; by=1.2.3.5",
        "proto=h*",
        "proto=HTTP",
        "proto=ftp",
        "proto=ws",
        "proto=h",
        r#"proto="http""#,
        r#"proto="""#,
        "host=a b",
        r#"host="a b""#,
        r#"for="""#,
        r#"by="1.2.3.4:0""#,
        r#"for="[::1""#,
        r#"for="[1:2:3:4:5:6:7:8:9]""#,
        "for=_",
        r#"for="_a:b""#,
        "for=1.2.3.4;for=1.2.3.4",
        ",",
        "for=1.2.3.4,",
        r#"for="1.2.3.4"x"#,
        r#"host="a.b:""#,
        r#"host="a\"b""#,
        r#"host="a_b""#,
        r#"host="a%41""#,
        r#"for="256.1.1.1""#,
        "for=1.2.3",
        r#"for="::1""#,
        r#"for="UNKNOWN""#,
        "FOR=1.2.3.4",
        "for = 1.2.3.4",
        "for=1.2.3.4;",
        "for=_a:b",
        r#"for="1.2.3.4:99999""#,
        r#"for="[::1]:65536""#,
        r#"host="a:99999""#,
        r#"host="a:0""#,
        "host=a:80",
        "host=:80",
        "host=[::1]",
        r#"host="[::1""#,
        r#"host="[1:2:3:4:5:6:7:8:9]""#,
        r#"host="a.-b""#,
        r#"host="[::1]x""#,
        "host=a\\b",
        r#"host="a\b""#,
        r#"host="-a""#,
        r#"host="a:80:90""#,
        "for=unknown:80",
        "for=a",
        r#"for="[::ffff:1.2.3.4]""#,
        r#"for="[fe80::1%eth0]""#,
        "for=1.2.3.4;;proto=http",
    ];
    for v in invalid {
        assert!(!is_valid(v), "{v}");
    }
}

#[test]
fn field_is_read_from_the_last_element() {
    let f = |v: &str, n: &str| field(v, n);
    assert_eq!(f(r#"for="unknown:132";host="[::1]:65535";by="_obfs:_port";proto=https"#, "for").as_deref(), Some("unknown:132"));
    assert_eq!(f(r#"for="unknown:132";host="[::1]:65535";by="_obfs:_port";proto=https"#, "host").as_deref(), Some("[::1]:65535"));
    assert_eq!(f("for=1.2.3.4,for=5.6.7.8", "for").as_deref(), Some("5.6.7.8"));
    // Only the last element is read.
    assert_eq!(f("for=1.1.1.1,proto=http", "for"), None);
    assert_eq!(f("for=1.1.1.1,proto=http", "proto").as_deref(), Some("http"));
    assert_eq!(f("proto=http,proto=https", "proto").as_deref(), Some("https"));
    // An invalid header has no field, and neither has a name it does not carry.
    assert_eq!(f("fore=1.2.3.4", "for"), None);
    assert_eq!(f("for=1.2.3.4", "by"), None);
    assert_eq!(f("for=1.2.3.4", "other"), None);
}

#[test]
fn node_name_and_port_are_cut_out_of_a_node() {
    assert_eq!(n2nn("unknown:132").as_deref(), Some("unknown"));
    assert_eq!(n2np("unknown:132").as_deref(), Some("132"));
    assert_eq!(n2nn("[::1]:_id").as_deref(), Some("::1"));
    assert_eq!(n2np("[::1]:_id").as_deref(), Some("_id"));
    assert_eq!(n2nn("127.0.0.1").as_deref(), Some("127.0.0.1"));
    assert_eq!(n2np("127.0.0.1"), None);
    assert_eq!(n2nn("_abc").as_deref(), Some("_abc"));
}

#[test]
fn rfc7239_nn_and_np_build_a_node_name_and_a_port() {
    use std::net::{Ipv4Addr, Ipv6Addr};
    assert_eq!(nn(&Sample::Ipv4(Ipv4Addr::new(127, 9, 0, 1))).as_deref(), Some("127.9.0.1"));
    assert_eq!(nn(&Sample::Ipv6("ab:cd::1".parse::<Ipv6Addr>().unwrap())).as_deref(), Some("[ab:cd::1]"));
    // A string is always obfuscated, even one that already is.
    for (s, want) in [("id", "_id"), ("_id", "__id"), ("unknown", "_unknown"), ("1.2.3.4", "_1.2.3.4"), ("12", "_12")] {
        assert_eq!(nn(&Sample::Str(s.into())).as_deref(), Some(want), "{s}");
        assert_eq!(np(&Sample::Str(s.into())).as_deref(), Some(want), "{s}");
    }
    assert_eq!(nn(&Sample::Str("[::1]".into())), None);
    assert_eq!(np(&Sample::Sint(12)).as_deref(), Some("12"));
    assert_eq!(np(&Sample::Sint(70000)).as_deref(), Some("70000"));
    assert_eq!(np(&Sample::Sint(-1)).as_deref(), Some("4294967295"));
}

#[test]
fn option_forwarded_writes_the_values_haproxy_writes() {
    let n = |s: Sample| node_from_sample(Some(&s));
    let st = |s: &str| Sample::Str(s.into());
    // `for-expr`/`by-expr`: an address as it is, a string obfuscated unless it already is.
    assert_eq!(n(st("_abc")), "_abc");
    assert_eq!(n(st("unknown")), "unknown");
    assert_eq!(n(st("1.2.3.4")), "1.2.3.4");
    assert_eq!(n(st("a b")), "unknown");
    assert_eq!(n(st("")), "unknown");
    assert_eq!(n(st("_")), "__");
    assert_eq!(n(st("Unknown")), "_Unknown");
    assert_eq!(n(st("a.b-c_d")), "_a.b-c_d");
    assert_eq!(n(st("1.2.3")), "_1.2.3");
    assert_eq!(n(st("001.2.3.4")), "_001.2.3.4");
    assert_eq!(n(st("2001:db8::1")), "unknown");
    assert_eq!(n(st("[::1]")), "[::1]");
    assert_eq!(n(st("[1::2]")), "[1::2]");
    assert_eq!(n(Sample::Sint(5)), "_5");
    assert_eq!(node_from_sample(None), "unknown");
    // `for_port-expr`, `by_port-expr`.
    let p = |s: Sample| port_from_sample(Some(&s));
    assert_eq!(p(Sample::Sint(65535)).as_deref(), Some("65535"));
    assert_eq!(p(Sample::Sint(70000)).as_deref(), Some("_70000"));
    assert_eq!(p(Sample::Sint(0)).as_deref(), Some("_0"));
    assert_eq!(p(Sample::Sint(-1)).as_deref(), Some("_-1"));
    assert_eq!(p(st("80")).as_deref(), Some("80"));
    assert_eq!(p(st("abc")).as_deref(), Some("_abc"));
    assert_eq!(p(st("_x")).as_deref(), Some("_x"));
    assert_eq!(p(st("a b")), None);
    assert_eq!(p(st("")), None);
    assert_eq!(port_from_sample(None), None);
    // `host-expr`: the host, `host=""` when it is not one.
    for (h, ok) in [("a.b", true), ("a.b:80", true), ("[::1]:80", true), ("a:099", true), ("", true), ("a b", false), ("a;b", false),
        ("a:b:c", false), ("é", false), ("a:65536", false), ("a.b:0", false), ("A_B", false), ("a..b", true), ("-a", false)] {
        assert_eq!(valid_host(h), ok, "{h}");
    }
}
