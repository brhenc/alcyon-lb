// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Lines of `registry.rs` that the end-to-end tests of `ibex-rt` cannot reach: the other places
//! a `SampleContext` can hold a message (`htx`, `htx_slice`, `req_headers`, `res_headers`; the
//! proxy fills one of them, the unit tests of this crate another), and the defensive arms
//! of the converters that only a sample of the wrong type reaches (the cast to the input type
//! comes first, so no configuration gets there). Added for the gate's covercheck after the
//! 2026-10-17 integration.
//!
//! Where a value is checked, it is what `HAProxy` 3.5-dev8 answers to the same headers sent over
//! HTTP (`req.hdrs_bin`, `req.hdrs`, `req.hdr_names(:)`, `req.hdr_cnt`, `req.fhdr_cnt` in an
//! `http-request return`, their `res.` forms in an `http-response set-header` of a response
//! from a backend). Whatever the source of the headers, the answer is the same.

use ibex_proto::htx::{HeaderField, HttpMethod, HttpVersion, Htx, HtxBlock, HtxSlice, RequestLine};
use ibex_sample::{Registry, Sample, SampleContext};

fn s(v: &str) -> Vec<String> {
    if v.is_empty() { vec![] } else { vec![v.to_string()] }
}

/// The five request fetches, rendered the way the oracle's lf-string did (`hex` on the binary ones).
fn req_fetches(reg: &Registry, ctx: &SampleContext) -> String {
    let hex = || vec![("hex", vec![])];
    let one = |f: &str, args: &str, conv: Vec<(&str, Vec<String>)>| match reg.eval(f, &s(args), &conv, ctx) {
        Some(Sample::Str(v)) => v,
        Some(Sample::Sint(n)) => n.to_string(),
        other => format!("{other:?}"),
    };
    [
        one("req.hdrs_bin", "", hex()),
        one("req.hdrs", "", hex()),
        one("req.hdr_names", ":", vec![]),
        one("req.hdr_cnt", "", vec![]),
        one("req.fhdr_cnt", "", vec![]),
    ]
    .join("|")
}

fn res_fetches(reg: &Registry, ctx: &SampleContext) -> String {
    let hex = || vec![("hex", vec![])];
    let one = |f: &str, args: &str, conv: Vec<(&str, Vec<String>)>| match reg.eval(f, &s(args), &conv, ctx) {
        Some(Sample::Str(v)) => v,
        Some(Sample::Sint(n)) => n.to_string(),
        other => format!("{other:?}"),
    };
    [
        one("res.hdrs_bin", "", hex()),
        one("res.hdrs", "", hex()),
        one("res.hdr_names", ":", vec![]),
        one("res.hdr_cnt", "", vec![]),
        one("res.fhdr_cnt", "", vec![]),
    ]
    .join("|")
}

fn pairs(h: &[(&str, &str)]) -> Vec<(String, String)> {
    h.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

fn htx_of(h: &[(String, String)]) -> Htx {
    let mut htx = Htx::new();
    htx.push(HtxBlock::ReqLine(RequestLine { method: HttpMethod::Get, uri: "/".into(), version: HttpVersion::Http11 }));
    for (k, v) in h {
        htx.push(HtxBlock::Header(HeaderField { name: k.clone(), value: v.clone() }));
    }
    htx.push(HtxBlock::Eoh);
    htx.push(HtxBlock::Eom);
    htx
}

/// (request headers, what `HAProxy` answers). A quoted `Upgrade` value that is cut to nothing
/// by `h2c` still leaves the header out when no `Connection: upgrade` goes with it; a quoted
/// `Connection` value (with a quoted pair and a comma inside) keeps its quotes and loses `upgrade`.
fn request_cases() -> Vec<(Vec<(String, String)>, &'static str)> {
    vec![
        (
            // The counts see the `close`: while rules run, one still in `Connection` is a rule's
            // (the runtime takes the message's own out before them, T442).
            pairs(&[("Host", "a"), ("Upgrade", "\"x\\\"y\", h2c"), ("Connection", "close")]),
            "04686F737401610000|686F73743A20610D0A0D0A|host|2|2",
        ),
        (
            pairs(&[("Host", "a"), ("Connection", "\"q\\\"x,y\", upgrade"), ("X-A", "1")]),
            "04686F737401610A636F6E6E656374696F6E0822715C22782C792203782D6101310000\
             |686F73743A20610D0A636F6E6E656374696F6E3A2022715C22782C79220D0A782D613A20310D0A0D0A\
             |host:connection:x-a|3|3",
        ),
    ]
}

#[test]
fn request_headers_from_every_source_of_the_context() {
    let reg = Registry::new();
    for (hdrs, want) in request_cases() {
        // `htx`: an owned HTX message
        let htx = htx_of(&hdrs);
        let ctx = SampleContext { htx: Some(&htx), ..Default::default() };
        assert_eq!(req_fetches(&reg, &ctx), want, "htx: {hdrs:?}");

        // `req_headers`: the headers an h2 request was turned into
        let ctx = SampleContext { req_headers: Some(&hdrs), ..Default::default() };
        assert_eq!(req_fetches(&reg, &ctx), want, "req_headers: {hdrs:?}");

        // `htx_slice`: the proxy's own buffer
        let mut buf = vec![0u8; 4096];
        let mut slice = HtxSlice::new(&mut buf);
        slice.push_req_line("GET", "/", "HTTP/1.1").unwrap();
        for (k, v) in &hdrs {
            slice.push_header(k, v).unwrap();
        }
        slice.push_eoh().unwrap();
        slice.push_eom().unwrap();
        let ctx = SampleContext { htx_slice: Some(slice.as_ref()), ..Default::default() };
        assert_eq!(req_fetches(&reg, &ctx), want, "htx_slice: {hdrs:?}");
    }
}

#[test]
fn response_headers_from_the_context() {
    let reg = Registry::new();
    // (`res.hdr_cnt` counts the `close`, as while rules run it is a rule's, T442.)
    // A backend answering `Connection: "q\"x,y", close`, `Upgrade: "u\"v", h2c`, `X-A: 1` and an
    // empty body.
    let hdrs = pairs(&[
        ("Connection", "\"q\\\"x,y\", close"),
        ("Upgrade", "\"u\\\"v\", h2c"),
        ("X-A", "1"),
        ("Content-Length", "0"),
    ]);
    let ctx = SampleContext { res_headers: Some(&hdrs), ..Default::default() };
    assert_eq!(
        res_fetches(&reg, &ctx),
        "0A636F6E6E656374696F6E0822715C22782C792207757067726164650622755C22762203782D6101310E636F6E74656E742D6C656E67746801300000\
         |636F6E6E656374696F6E3A2022715C22782C79220D0A757067726164653A2022755C2276220D0A782D613A20310D0A636F6E74656E742D6C656E6774683A20300D0A0D0A\
         |connection:upgrade:x-a:content-length|5|4"
    );
}

/// `req.body_param` reads the body from the HTX buffer when the context holds no separate body;
/// with neither there is no value. (`POST` of `a=1&b=2`: `[2]` on the oracle.)
#[test]
fn req_body_param_from_the_htx_buffer() {
    let reg = Registry::new();
    let mut buf = vec![0u8; 4096];
    let mut slice = HtxSlice::new(&mut buf);
    slice.push_req_line("POST", "/", "HTTP/1.1").unwrap();
    slice.push_header("Host", "a").unwrap();
    slice.push_header("Content-Length", "7").unwrap();
    slice.push_eoh().unwrap();
    slice.push_data(b"a=1&b=2").unwrap();
    slice.push_eom().unwrap();
    let ctx = SampleContext { htx_slice: Some(slice.as_ref()), ..Default::default() };
    assert_eq!(reg.eval("req.body_param", &["b".to_string()], &[], &ctx), Some(Sample::Bin(b"2".to_vec())));
    // No message at all (a rule evaluated before any request exists): no sample. HAProxy cannot
    // be asked this from a configuration; the fetch needs the request buffer.
    assert_eq!(reg.eval("req.body_param", &["b".to_string()], &[], &SampleContext::default()), None);
}

/// Every converter that takes a binary input declares it as `Exact(Bin)`, so the cast to it
/// runs first and no configuration passes it anything else. The arm for another type is a
/// defensive `None`; there is no oracle value to measure, only that it does not panic or
/// invent one.
#[test]
fn binary_converters_give_nothing_for_another_sample_type() {
    let reg = Registry::new();
    for name in [
        "protobuf", "ungrpc", "mqtt_is_valid", "mqtt_field_value", "eth.data", "eth.dst", "eth.hdr", "eth.proto",
        "eth.src", "eth.vlan", "ip.src", "ip.dst", "ip.hdr", "ip.data", "ip.fp", "tcp.options.mss",
        "tcp.options.sack", "tcp.options.tsopt", "tcp.options.tsval", "tcp.options.wscale", "tcp.options.wsopt",
        "tcp.options_list",
    ] {
        let conv = reg.get_converter(name).unwrap_or_else(|| panic!("{name} is not registered"));
        assert_eq!((conv.func)(Sample::Str("x".to_string()), &[]), None, "{name} on a string");
        assert_eq!((conv.func)(Sample::Sint(1), &[]), None, "{name} on an integer");
    }
}

/// `jwt_verify` has a string input; a binary sample (not reachable through the cast, which
/// turns it into a string first) is read as the token's bytes, any other type has no value.
#[test]
fn jwt_verify_direct_sample_types() {
    let reg = Registry::new();
    let conv = reg.get_converter("jwt_verify").unwrap();
    let args = ["HS256".to_string(), "secret".to_string()];
    // Same token and key as the oracle test of `jwt_verify_hmac_oracle_edges` (key "secret").
    let tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.UUtsUaeO3koQylSZ3wxP4lqVvgFw6mGsVzGNBNF_1sQ";
    assert_eq!((conv.func)(Sample::Str(tok.to_string()), &args), Some(Sample::Sint(1)));
    assert_eq!((conv.func)(Sample::Bin(tok.as_bytes().to_vec()), &args), Some(Sample::Sint(1)));
    assert_eq!((conv.func)(Sample::Sint(5), &args), None);
}

/// An absolute-form target without a path has the path `/` (HAProxy 3.5-dev8 answers `/`, `/`,
/// `a/`, `a/` to `path`, `pathq`, `base`, `baseq` for `GET http://a` with `Host: a`). Ibex's
/// request reader already normalises the target, so the raw form only reaches the fetches
/// through a context built by hand.
#[test]
fn absolute_uri_without_a_path_from_a_hand_made_context() {
    let reg = Registry::new();
    let hdrs = pairs(&[("Host", "a")]);
    let ctx = SampleContext {
        req_uri: Some("http://a"),
        req_method: Some("GET"),
        req_headers: Some(&hdrs),
        ..Default::default()
    };
    for (fetch, want) in [("path", "/"), ("pathq", "/"), ("base", "a/"), ("baseq", "a/")] {
        assert_eq!(reg.eval(fetch, &[], &[], &ctx), Some(Sample::Str(want.to_string())), "{fetch}");
    }
}

/// `ocsp_check_err_str` takes an integer; the arm for another sample type is defensive (the cast
/// to the input type comes first).
#[test]
fn ocsp_check_err_str_on_another_sample_type() {
    let reg = Registry::new();
    let conv = reg.get_converter("ocsp_check_err_str").unwrap();
    assert_eq!((conv.func)(Sample::Str("1".to_string()), &[]), None);
    assert_eq!((conv.func)(Sample::Sint(1), &[]), Some(Sample::Str("OCSP verification failed".to_string())));
}

/// `base32+src` for a client without an IP address (a unix-socket client; Ibex has no unix
/// frontend, so no configuration gets here). HAProxy 3.5-dev8 gives no sample for it (`base32`
/// still has its value, 877786378 for `Host: a`, which is 0x3451F50A); Ibex gives the bare
/// 4-byte hash. Either is accepted here so this does not pin the difference: the arm is what
/// this runs.
#[test]
fn base32_src_without_a_client_address() {
    let reg = Registry::new();
    let hdrs = pairs(&[("Host", "a")]);
    let ctx = SampleContext { req_uri: Some("/"), req_method: Some("GET"), req_headers: Some(&hdrs), ..Default::default() };
    assert_eq!(reg.eval("base32", &[], &[], &ctx), Some(Sample::Sint(877_786_378)));
    match reg.eval("base32+src", &[], &[], &ctx) {
        None => {}
        Some(Sample::Bin(b)) => assert_eq!(b, 877_786_378u32.to_be_bytes().to_vec()),
        other => panic!("base32+src: {other:?}"),
    }
}

/// T337: `hdr`/`fhdr`/`hdr_val` and their `res.` forms, as a sample (`Registry::eval`) and as
/// an ACL sees them (`eval_all`), from every source of the context. `x: 1, 2, 3, 4, 5, 6` +
/// `x: 7, 8, 9, 10, 11, 12` on `HAProxy` 3.5-dev8: `hdr(x)` 12, `hdr(x,3)` 3, `hdr(x,-10)` 3,
/// `fhdr(x,-10)` empty (two lines). `hdr(x,-11)` is refused by the oracle's parser ("header
/// occurrence must be >= -10"); called directly it gives no sample.
#[test]
fn header_occurrences_from_every_source_of_the_context() {
    let reg = Registry::new();
    let hdrs = pairs(&[("Host", "h"), ("X", "1, 2, 3, 4, 5, 6"), ("x", "7, 8, 9, 10, 11, 12")]);
    let check = |ctx: &SampleContext, p: &str, what: &str| {
        let one = |f: &str, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
            match reg.eval(&format!("{p}{f}"), &args, &[], ctx) {
                Some(Sample::Str(v)) => v,
                Some(Sample::Sint(n)) => n.to_string(),
                None => "-".into(),
                other => format!("{other:?}"),
            }
        };
        let got = [
            one("hdr", &["x"]),
            one("hdr", &["x", "3"]),
            one("hdr", &["x", "-10"]),
            one("hdr", &["x", "-11"]),
            one("fhdr", &["x", "-10"]),
            one("fhdr", &["x"]),
            one("hdr_val", &["x", "-1"]),
            one("hdr", &["y"]),
        ]
        .join("|");
        assert_eq!(got, "12|3|3|-|-|7, 8, 9, 10, 11, 12|12|-", "{what}");
        let all = reg.eval_all(&format!("{p}hdr"), &["x".to_string()], &[], ctx);
        assert_eq!(all.len(), 12, "{what}: every value in an ACL");
        let all = reg.eval_all(&format!("{p}hdr_val"), &["x".to_string()], &[], ctx);
        assert_eq!(all.last(), Some(&Sample::Sint(12)), "{what}: hdr_val in an ACL");
        let occ = reg.eval_all(&format!("{p}hdr"), &["x".to_string(), "2".to_string()], &[], ctx);
        assert_eq!(occ, [Sample::Str("2".into())], "{what}: an occurrence in an ACL");
    };

    let htx = htx_of(&hdrs);
    check(&SampleContext { htx: Some(&htx), ..Default::default() }, "req.", "htx");
    check(&SampleContext { req_headers: Some(&hdrs), ..Default::default() }, "req.", "req_headers");
    let mut buf = vec![0u8; 4096];
    let mut slice = HtxSlice::new(&mut buf);
    slice.push_req_line("GET", "/", "HTTP/1.1").unwrap();
    for (k, v) in &hdrs {
        slice.push_header(k, v).unwrap();
    }
    slice.push_eoh().unwrap();
    slice.push_eom().unwrap();
    check(&SampleContext { htx_slice: Some(slice.as_ref()), ..Default::default() }, "req.", "htx_slice");

    check(&SampleContext { res_headers: Some(&hdrs), ..Default::default() }, "res.", "res_headers");
    // X3b: the response being processed is the HTX blocks its rules edit.
    struct Head<'h>(ibex_proto::htx::HtxSliceRef<'h>);
    impl ibex_sample::registry::ResHead for Head<'_> {
        fn read(&self, f: &mut dyn FnMut(ibex_proto::htx::HtxSliceRef<'_>)) {
            f(self.0);
        }
    }
    let head = Head(slice.as_ref());
    let ctx = SampleContext { res_htx: Some(&head), ..Default::default() };
    check(&ctx, "res.", "the response being processed");
    assert!(format!("{ctx:?}").contains(&format!("ResHead({} headers)", hdrs.len())), "a context shows its response head");
}

/// A converter that gives no sample for one occurrence of a multi-value fetch: outside an ACL
/// that occurrence is left out and the others are still converted; in an ACL the expression
/// ends there (`acl_exec_cond`, T362, measured on HAProxy 3.5-dev8-885761-29). The
/// user-visible non-ACL paths (`%[...]`, `set-var`) take the fetch's single sample (T337) and
/// are checked on the binary in `acl_multivalue_converter_failure`.
#[test]
fn a_converter_failing_on_one_occurrence_is_skipped_outside_an_acl_and_ends_an_acl() {
    let reg = Registry::new();
    let hdrs = pairs(&[("Host", "h"), ("X", "a:1"), ("X", "b"), ("X", "c:3")]);
    let ctx = SampleContext { req_headers: Some(&hdrs), ..Default::default() };
    let conv = [("field", vec!["2".to_string(), ":".to_string()])];
    let args = ["x".to_string()];
    assert_eq!(reg.eval_all("req.hdr", &args, &conv, &ctx), [Sample::Str("1".into()), Sample::Str("3".into())]);
    assert_eq!(reg.eval_all_acl("req.hdr", &args, &conv, &ctx), [Sample::Str("1".into())]);
}
