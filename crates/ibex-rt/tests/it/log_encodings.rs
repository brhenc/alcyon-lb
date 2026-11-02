// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The log-format encodings `+E`, `+json`, `+utf8`, `+cbor`, `+bin` and `%(name:type)`,
//! against what the reference `HAProxy` (3.5-dev8-885761-29) wrote for the same formats and
//! the same header bytes, measured 2026-10-04: a frontend logging to a `ring`, requests sent
//! with curl, and `show events` read back.

use std::net::SocketAddr;

use ibex_rt::{LogData, LogFormat};
use ibex_sample::{sample_registry, SampleContext};

fn render_with(fmt: &str, d: &LogData, caps: &[Option<Vec<u8>>]) -> Vec<u8> {
    let reg = sample_registry();
    let client: SocketAddr = "127.0.0.1:40000".parse().expect("addr");
    let ctx = SampleContext { phase: &ibex_sample::PhaseCtx { client_addr: Some(client), captures_req_hdr: Some(caps), ..Default::default() }, live: None };
    LogFormat::compile(fmt, reg).expect("compiles").render_bytes(d, reg, &ctx)
}

fn cap(bytes: &[u8]) -> [Option<Vec<u8>>; 1] {
    [Some(bytes.to_vec())]
}

fn data() -> LogData<'static> {
    LogData { client: Some("127.0.0.1:40000".parse().expect("addr")), status: 200, frontend: "fe", ..LogData::default() }
}

fn text(fmt: &str, bytes: &[u8]) -> String {
    String::from_utf8_lossy(&render_with(fmt, &data(), &cap(bytes))).into_owned()
}

#[test]
fn a_json_node_escapes_everything_outside_32_to_126() {
    let want = r#"{"hdr":"A\u001B[31m\tB\"C\\D","bin":"\u001B"}"#;
    let fmt = "{\"hdr\":%{+json}[capture.req.hdr(0)],\"bin\":%{+json}[str(Gw==),b64dec]}";
    assert_eq!(text(fmt, b"A\x1b[31m\tB\"C\\D"), want);
    // One escape per byte above the range, so no byte can be taken for an introducer.
    assert_eq!(text("%{+json}[capture.req.hdr(0)]", b"A\xc3\xa9B\xaaC"), r#""A\u00C3\u00A9B\u00AAC""#);
}

#[test]
fn utf8_keeps_valid_sequences_and_escapes_the_rest_per_byte() {
    let got = render_with(
        "%{+json,+utf8}o %(hdr)[capture.req.hdr(0)] %(bin)[str(w6nCm+KC),b64dec]",
        &data(),
        &cap(b"A\xc3\xa9B\xaaC\xc0\x81D\xed\xa0\x80E\xc2\x9bF\xf0\x9f\x98\x80G\xf4\x90\x80\x80H\xe2\x82"),
    );
    let mut want = br#"{"hdr": "A"#.to_vec();
    want.extend_from_slice("\u{e9}".as_bytes());
    want.extend_from_slice(br"B\u00AAC\u00C0\u0081D\u00ED\u00A0\u0080E\u009BF");
    want.extend_from_slice("\u{1F600}".as_bytes());
    want.extend_from_slice(br#"G\u00F4\u0090\u0080\u0080H\u00E2\u0082", "bin": ""#);
    want.extend_from_slice("\u{e9}".as_bytes());
    want.extend_from_slice(br#"\u009B\u00E2\u0082"}"#);
    assert_eq!(got, want, "{}", String::from_utf8_lossy(&got));
}

#[test]
fn a_cbor_text_passes_the_bytes_through_as_hex() {
    assert_eq!(text("%{+cbor}[capture.req.hdr(0)]", b"A\xaaB"), "6341AA42");
    assert_eq!(text("%{+cbor}[capture.req.hdr(0)]", b"A\xc3\xa9B"), "6441C3A942");
    assert_eq!(text("%{+cbor}[capture.req.hdr(0)]", b"Aa#bB"), "654161236242");
}

#[test]
fn a_cbor_map_has_keys_and_a_binary_sample_is_a_byte_string() {
    assert_eq!(text("%{+cbor}o%(v)[str(qq==),b64dec]", b""), "BF61765F41AAFFFF");
    // `+bin` writes the bytes themselves rather than their hex.
    let raw = render_with("%{+cbor,+bin}o%(v)[capture.req.hdr(0)]", &data(), &cap(b"A\x01B"));
    assert_eq!(raw, b"\xbf\x61v\x63A\x01B\xff");
}

#[test]
fn an_encoded_line_keeps_the_type_a_name_asks_for() {
    // `%(n:str)` a number as a string, `%(m:sint)` a string as the number its digits make,
    // `%(k:bool)` any non-zero as true, and a string with no digits as 0.
    let fmt = "%{+json}o %(n:str)[int(5)] %(m:sint)[str(7)] %(k:bool)[int(3)] %(x:sint)[str(zz)] %(e)[str()] %(i)[int(5)] %(b)[bool(1)]";
    assert_eq!(
        text(fmt, b""),
        r#"{"n": "5", "m": 7, "k": true, "x": 0, "e": "", "i": 5, "b": true}"#
    );
    // CBOR: the shortest integer form, negative integers, and the null primitive for a value
    // that wrote nothing.
    let fmt = "%{+cbor}o %(n:str)[int(5)] %(m:sint)[str(7)] %(neg)[int(-300)] %(big)[int(70000)] %(huge)[int(5000000000)] %(s)[str(abc)] %(e)[str()]";
    assert_eq!(
        text(fmt, b""),
        "BF616E6135616D07636E656739012B636269671A0001117064687567651B000000012A05F2006173636162636165F6FF"
    );
}

#[test]
fn an_encoded_line_carries_the_numeric_aliases_as_numbers_and_the_rest_as_strings() {
    let d = LogData { status: 200, bytes_out: 77, frontend: "fe", accept_date: (1_791_038_898, 7), ..data() };
    let got = render_with("%{+json}o %(ci)ci %(st)ST %(b)B %(f)f %(ms)ms %(hr)hr", &d, &[]);
    assert_eq!(
        String::from_utf8_lossy(&got),
        r#"{"ci": "127.0.0.1", "st": 200, "b": 77, "f": "fe", "ms": 7, "hr": null}"#
    );
    let got = render_with("%{+cbor}o %(ci)ci %(st)ST", &d, &[]);
    assert_eq!(String::from_utf8_lossy(&got), "BF626369693132372E302E302E3162737418C8FF");
}

#[test]
fn plus_e_escapes_quote_backslash_and_bracket_only() {
    assert_eq!(
        render_with("%{+E}[capture.req.hdr(0)]|%{+E}[str(a)]|%{+Q}[str(ab)]", &data(), &cap(b"A\"b\x01\xaa#]\\")),
        b"A\\\"b\x01\xaa#\\]\\\\|a|\"ab\"".to_vec()
    );
    // Without it the bytes come out as they are, which is what a sample does.
    assert_eq!(render_with("%[capture.req.hdr(0)]", &data(), &cap(b"A\x1b[31m]B")), b"A\x1b[31m]B".to_vec());
}

#[test]
fn the_names_of_an_unencoded_line_are_not_printed() {
    assert_eq!(text("N %(a)[capture.req.hdr(0)] %(b)[int(5)] %(c)[bool(1)]", b"x"), "N x 5 1");
}

#[test]
fn a_name_must_be_made_of_name_characters_and_an_output_type_must_be_known() {
    let reg = sample_registry();
    for (fmt, want) in [
        ("%(a b)[int(1)]", "invalid character in custom name"),
        ("%(a:float)[int(1)]", "unexpected output type 'float'"),
        ("%(a", "truncated line"),
        ("%(a:raw)[int(1)]", "not implemented"),
    ] {
        let err = LogFormat::compile(fmt, reg).expect_err(fmt);
        assert!(err.contains(want), "{fmt}: {err}");
    }
}

#[test]
fn json_has_short_escapes_and_rejects_the_noncharacters_even_with_utf8() {
    let got = render_with("%{+json}[capture.req.hdr(0)]", &data(), &cap(b"\x08\x0c\n\r\x7f"));
    assert_eq!(String::from_utf8_lossy(&got), r#""\b\f\n\r\u007F""#);
    // U+FFFE is a valid sequence that is not kept: one escape per byte.
    let got = render_with("%{+json,+utf8}o %(a)[capture.req.hdr(0)]", &data(), &cap(b"\xef\xbf\xbe"));
    let want = format!(r#"{{"a": "{b}u00EF{b}u00BF{b}u00BE"}}"#, b = '\\');
    assert_eq!(String::from_utf8_lossy(&got), want);
}

#[test]
fn booleans_and_the_types_that_will_not_convert() {
    assert_eq!(text("%{+json}o %(t)[bool(1)] %(f)[bool(0)]", b""), r#"{"t": true, "f": false}"#);
    assert_eq!(text("%{+cbor}o %(t)[bool(1)] %(f)[bool(0)]", b""), "BF61 74F5 6166F4FF".replace(' ', ""));
    // An address is not an integer or a boolean: the value is empty, which JSON writes as "".
    assert_eq!(text("%{+json}o %(a:sint)[src] %(b:bool)[src] %(c:str)[src]", b""), r#"{"a": "", "b": "", "c": "127.0.0.1"}"#);
    assert_eq!(text("%{+json}o %(b:str)[bool(1)] %(s:str)[int(-4)]", b""), r#"{"b": "1", "s": "-4"}"#);
}

#[test]
fn an_ipv6_peer_and_a_method_are_strings_on_an_encoded_line() {
    let reg = sample_registry();
    let client: SocketAddr = "[::1]:40000".parse().expect("addr");
    let ctx = SampleContext { phase: &ibex_sample::PhaseCtx { client_addr: Some(client), ..Default::default() }, live: None };
    let got = LogFormat::compile("%{+json}o %(a)[src]", reg).expect("compiles").render_bytes(&data(), reg, &ctx);
    assert_eq!(String::from_utf8_lossy(&got), r#"{"a": "::1"}"#);
}

#[test]
fn plus_e_on_an_alias_escapes_it_too() {
    let d = LogData { request_line: Some("GET /a\"b] HTTP/1.1"), ..data() };
    let got = render_with("%{+E}HU", &d, &[]);
    // `HAProxy` writes `/a#22b\\]c` for `/a"b]c`: the quote is the alias's own `#22`, the bracket this.
    assert_eq!(String::from_utf8_lossy(&got), "/a#22b\\]");
}

#[test]
fn what_follows_a_name_is_an_alias_an_expression_text_or_an_error() {
    let reg = sample_registry();
    for (fmt, want) in [("%(a)", "truncated line after '%(a)'"), ("%(a) x", "unexpected alias name"), ("%(a)1", "unexpected alias name")] {
        let err = LogFormat::compile(fmt, reg).expect_err(fmt);
        assert!(err.contains(want), "{fmt}: {err}");
    }
    // A `%` is a literal one and any other character is text; the name is dropped either way.
    assert_eq!(text("%(a)%x", b""), "%x");
    assert_eq!(text("%(a)-x", b""), "-x");
}

#[test]
fn a_method_and_a_boolean_on_an_encoded_line() {
    let reg = sample_registry();
    let ctx = SampleContext { phase: &ibex_sample::PhaseCtx { req_method: Some("GET"), ..Default::default() }, live: None };
    let got = LogFormat::compile("%{+json}o %(m)[method] %(b:sint)[bool(1)]", reg).expect("compiles").render_bytes(&data(), reg, &ctx);
    assert_eq!(String::from_utf8_lossy(&got), r#"{"m": "GET", "b": 1}"#);
}
