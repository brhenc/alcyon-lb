// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! No converter panics on any input (T358 sweep). A panic aborts the worker, so a converter
//! given attacker data and awkward arguments must return a sample or nothing, never unwind.

use alcyon_sample::registry::Registry;
use alcyon_sample::sample::Sample;
use alcyon_sample::SampleContext;
use alcyon_proto::htx::{HeaderField, HttpMethod, HttpVersion, Htx, HtxBlock, RequestLine};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn inputs() -> Vec<Sample> {
    let strs = [
        "", "a", "é", "aé,b", "%", "%4", "%é", "%zz%41", "a,b,,c", "\u{10348}x", "-1", "9223372036854775807",
        "{\"a\":[1,2,{\"b\":\"c\"}]}", "=", "a=b&c=%", "/a/../b/./c//d", "Zm9v", "Zm9vYg", "====", "@", "\0",
        "GET / HTTP/1.1", "1.2.3.4", "::1", "a b\tc", "ÿÿÿÿ", "\u{1F600}\u{1F600}",
    ];
    let mut v: Vec<Sample> = strs.iter().map(|s| Sample::Str((*s).to_string())).collect();
    for b in [&b""[..], &b"\xff"[..], &b"\xff\xfe\x00\x80"[..], &b"a,b"[..], &b"%\xff"[..], &b"Zm9v\xff"[..]] {
        v.push(Sample::Bin(b.to_vec()));
    }
    for i in [0i64, 1, -1, i64::MAX, i64::MIN, 255, 65536] {
        v.push(Sample::Sint(i));
    }
    v.push(Sample::Bool(true));
    v.push(Sample::Ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    v.push(Sample::Ipv6(std::net::Ipv6Addr::LOCALHOST));
    v
}

const ARGS: &[&str] = &[
    "", "0", "1", "2", "-1", "-9223372036854775808", "9223372036854775807", "18446744073709551615",
    "4294967296", ",", "é", "a", "%", "/", ".*", "(a)", "\\1", "g", "i", "8", "16", "sha256", "sha1",
    "$.a", "$.a[0]", "$.a[9223372036854775807]", "$[", "int", "str", "bin", "uri", "path", "query",
    "ÿ", "ab", "*",
];

#[test]
fn no_converter_panics() {
    let reg = Registry::new();
    let ctx = SampleContext::default();
    let names = reg.converter_names();
    if std::env::var_os("SHOWPANIC").is_none() { std::panic::set_hook(Box::new(|_| {})); }
    let mut bad: Vec<String> = Vec::new();
    for name in names {
        let mut found = false;
        let arglists: Vec<Vec<String>> = {
            let mut l: Vec<Vec<String>> = vec![vec![]];
            for a in ARGS {
                l.push(vec![(*a).to_string()]);
                for b in ARGS {
                    l.push(vec![(*a).to_string(), (*b).to_string()]);
                }
            }
            for a in ["0", "1", "2", "-1", "9223372036854775807", "18446744073709551615"] {
                for b in [",", "é", "", "a"] {
                    for c in ["0", "1", "-1", "9223372036854775807", "18446744073709551615", "a", "i", "g"] {
                        l.push(vec![a.to_string(), b.to_string(), c.to_string()]);
                    }
                }
            }
            l
        };
        'o: for inp in inputs() {
            for args in &arglists {
                let r = catch_unwind(AssertUnwindSafe(|| {
                    if let Some(d) = reg.get_converter(name) {
                        let _ = (d.func)(inp.clone(), args);
                    } else if let Some(d) = reg.get_ctx_converter(name) {
                        let _ = (d.func)(&ctx, inp.clone(), args);
                    }
                }));
                if r.is_err() {
                    bad.push(format!("{name}: input {inp:?} args {args:?}"));
                    found = true;
                    break 'o;
                }
            }
        }
        let _ = found;
    }
    let _ = std::panic::take_hook();
    assert!(bad.is_empty(), "converters that panic:\n{}", bad.join("\n"));
}

#[test]
fn no_fetch_panics() {
    fetches_never_panic(false);
}

/// The same through an HTX message, which is what the engine hands the fetches.
#[test]
fn no_fetch_panics_on_htx() {
    fetches_never_panic(true);
}

fn fetches_never_panic(use_htx: bool) {
    let reg = Registry::new();
    let uris = ["", "/", "?", "/?", "/a?b=c&d=%&e", "http://", "http://é:é@é/é?é", "*", "//", "/%", "/%zz",
        "http://[::1", "http://[::1]:99999/", "http://h:/x", "/a;b=c;d?x#y", "/é?é=é", "http://a@/", "a:b", "http:///",
        "/a?\u{10348}=\u{10348}&&&=", "http://u:p@h:80", "?a", "/;", "/?;"];
    let hdr_vals = ["", "a", "é", "a=b; c=d; =; e", "a=\"b", "\"", "bytes=0-", "bytes=-", "bytes=9-1", "1, 2,, 3", "b\u{10348}, é",
        "chunked", "example.com:", ":", "[::1", "[::1]:80", "e:é", "Basic Zm9v", "Basic !!!", "Bearer", "for=\"[::1]\";by=é;host=;proto=",
        "1.2.3.4:99999", "-1", "9223372036854775808", "gzip;q=, deflate;q=é"];
    let hnames = ["host", "cookie", "set-cookie", "content-length", "transfer-encoding", "x-forwarded-for", "forwarded",
        "authorization", "range", "accept-encoding", "content-type", "user-agent", "x-a", "connection", "upgrade", "referer",
        "origin", "x-real-ip", "date", "if-modified-since", "expires"];
    let mut hdrs: Vec<(String, String)> = Vec::new();
    for (i, h) in hnames.iter().enumerate() { for v in hdr_vals.iter().skip(i % 5).step_by(5) { hdrs.push((h.to_string(), v.to_string())); } }
    let bodies: [&[u8]; 6] = [b"", b"\xff", b"a=b&c=%&d", b"{\"a\":[1,{\"b\":2}]}", b"\xff\xfe\x00\x80\x16\x03\x01\x00", b"\x16\x03\x01\xff\xff\x01\x00\xff\xff\x03\x03"];
    let args: Vec<Vec<String>> = {
        let mut l: Vec<Vec<String>> = vec![vec![]];
        for a in ARGS.iter().chain(&["host", "cookie", "a", "x-a", "set-cookie", "range", "bytes"]) {
            l.push(vec![(*a).to_string()]);
            for b in ARGS.iter().take(24).step_by(3) { l.push(vec![(*a).to_string(), (*b).to_string()]); }
        }
        l
    };
    if std::env::var_os("SHOWPANIC").is_none() { std::panic::set_hook(Box::new(|_| {})); }
    let mut bad: Vec<String> = Vec::new();
    for name in reg.fetch_names() {
        let Some(d) = reg.get_fetch(name) else { continue };
        'o: for uri in uris.iter().step_by(2) { for (bi, body) in bodies.iter().enumerate().step_by(2) {
            let mut htx = Htx::new();
            htx.push(HtxBlock::ReqLine(RequestLine { method: HttpMethod::Get, uri: (*uri).into(), version: HttpVersion::Http11 }));
            for (k, v) in &hdrs { htx.push(HtxBlock::Header(HeaderField { name: k.clone(), value: v.clone() })); }
            htx.push(HtxBlock::Eoh);
            htx.push(HtxBlock::Data(body.to_vec()));
            htx.push(HtxBlock::Eom);
            let ctx = SampleContext { phase: &alcyon_sample::PhaseCtx {
                htx: use_htx.then_some(&htx),
                req_uri: Some(uri), req_method: Some("GET"), req_version: Some("HTTP/1.1"),
                req_headers: Some(&hdrs), res_headers: Some(&hdrs), res_status: Some(200), res_version: Some("HTTP/1.1"),
                req_body: Some(body), res_body: Some(body), raw_req: Some(body), raw_res: Some(body),
                proxy_tlvs: Some(body), ..Default::default()
            }, live: None };
            for a in &args {
                let r = catch_unwind(AssertUnwindSafe(|| { let _ = (d.func)(&ctx, a); }));
                if r.is_err() { bad.push(format!("{name}: uri {uri:?} body#{bi} args {a:?}")); break 'o; }
            }
        } }
    }
    let _ = std::panic::take_hook();
    assert!(bad.is_empty(), "fetches that panic:\n{}", bad.join("\n"));
}

/// A ClientHello with SNI, ALPN, supported groups and signature algorithms, to mutate.
fn client_hello() -> Vec<u8> {
    let ext = |ty: u16, body: &[u8]| {
        let mut e = ty.to_be_bytes().to_vec();
        e.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        e.extend_from_slice(body);
        e
    };
    let mut exts = ext(0, &[0, 6, 0, 0, 3, b'a', b'.', b'b']);
    exts.extend(ext(16, &[0, 3, 2, b'h', b'2']));
    exts.extend(ext(10, &[0, 4, 0, 23, 0, 24]));
    exts.extend(ext(13, &[0, 4, 4, 3, 8, 4]));
    exts.extend(ext(43, &[4, 3, 4, 3, 3]));
    let mut h = vec![3, 3];
    h.extend_from_slice(&[7u8; 32]);
    h.push(2);
    h.extend_from_slice(&[1, 2]);
    h.extend_from_slice(&[0, 4, 0x13, 1, 0xc0, 0x2f]);
    h.extend_from_slice(&[1, 0]);
    h.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    h.extend(exts);
    let mut hs = vec![1, 0];
    hs.extend_from_slice(&u16::try_from(h.len()).unwrap().to_be_bytes());
    hs.extend(h);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
    rec.extend(hs);
    rec
}

/// Raw-buffer fetches (TLS hello, RDP cookie, payload, FIX, MQTT, ...) on a truncated or
/// corrupted buffer: the client chooses every byte of it.
#[test]
fn raw_fetches_never_panic_on_a_mangled_buffer() {
    let reg = Registry::new();
    let base = client_hello();
    let sni = (reg.get_fetch("req.ssl_sni").expect("fetch").func)(&SampleContext { phase: &alcyon_sample::PhaseCtx { raw_req: Some(&base), ..Default::default() }, live: None }, &[]);
    assert_eq!(sni, Some(Sample::Str("a.b".into())), "the unmangled hello must parse, or the test proves nothing");
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut bufs: Vec<Vec<u8>> = vec![Vec::new(), b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00Cookie: mstshash=a\r\n".to_vec(),
        b"8=FIX.4.4\x019=5\x0135=A\x0110=000\x01".to_vec(), b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00".to_vec()];
    for n in 0..base.len() {
        bufs.push(base[..n].to_vec());
    }
    for _ in 0..1500 {
        let mut b = base.clone();
        for _ in 0..=(rnd() % 4) {
            let i = usize::try_from(rnd()).unwrap() % b.len();
            b[i] = u8::try_from(rnd() & 0xff).unwrap();
        }
        if rnd() % 3 == 0 {
            let n = usize::try_from(rnd()).unwrap() % b.len();
            b.truncate(n);
        }
        bufs.push(b);
    }
    let arglists: Vec<Vec<String>> = vec![vec![], vec!["0".into()], vec!["1".into(), "2".into()], vec!["0".into(), "0".into()],
        vec!["9223372036854775807".into()], vec!["2".into(), "9223372036854775807".into()], vec!["4".into(), "2".into(), "1".into()],
        vec!["a".into()], vec!["35".into()], vec!["mstshash".into()], vec!["protocol_name".into()]];
    if std::env::var_os("SHOWPANIC").is_none() { std::panic::set_hook(Box::new(|_| {})); }
    let mut bad: Vec<String> = Vec::new();
    for name in reg.fetch_names() {
        let Some(d) = reg.get_fetch(name) else { continue };
        'o: for b in &bufs {
            let ctx = SampleContext { phase: &alcyon_sample::PhaseCtx { raw_req: Some(b), raw_res: Some(b), ..Default::default() }, live: None };
            for a in &arglists {
                if catch_unwind(AssertUnwindSafe(|| { let _ = (d.func)(&ctx, a); })).is_err() {
                    bad.push(format!("{name}: buffer {b:02x?} args {a:?}"));
                    break 'o;
                }
            }
        }
    }
    let _ = std::panic::take_hook();
    assert!(bad.is_empty(), "fetches that panic:\n{}", bad.join("\n"));
}
