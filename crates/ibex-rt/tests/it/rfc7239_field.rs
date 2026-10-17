// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: `rfc7239_is_valid` and `rfc7239_field` on `Forwarded` values delivered in request
//! headers, through `req.fhdr()` (the whole line) and `req.hdr()` (on the reference, the last
//! comma-separated value). Every expected value was measured on the reference (3.5-dev8) with
//! the same configuration and request.
//!
//! Ibex's `req.hdr()` returns the whole line too, so the converters take the last value
//! themselves (`rfc7239::last_value`). That matches the reference on `req.hdr()` everywhere and
//! on `req.fhdr()` for a value without a comma; with a comma, `req.fhdr()` differs until
//! `req.hdr()` splits values (those rows carry the reference's answer in a comment).

use crate::common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

#[test]
fn rfc7239_converters_on_request_headers() {
    // (header value, through req.fhdr, through req.hdr), each as
    // rfc7239_is_valid|rfc7239_field(for)|(proto)|(by)|(host)
    let rows: [(&str, Option<&str>, &str); 36] = [
        ("for=192.0.2.43, for=198.51.100.17", None, "1|198.51.100.17|||"), // the reference on req.fhdr: 0||||
        ("for=192.0.2.43,for=198.51.100.17", None, "1|198.51.100.17|||"), // the reference on req.fhdr: 0||||
        ("proto=https, host=example.com", None, "1||||example.com"), // the reference on req.fhdr: 0||||
        ("for=192.0.2.43;proto=https, by=10.0.0.1", None, "1|||10.0.0.1|"), // the reference on req.fhdr: 0||||
        (",for=1.2.3.4", None, "1|1.2.3.4|||"), // the reference on req.fhdr: 0||||
        ("for=1.2.3.4;by=5.6.7.8;host=a.b;proto=http,garbage", None, "0||||"), // the reference on req.fhdr: 1|1.2.3.4|http|5.6.7.8|a.b
        ("proto=https, for=198.51.100.17", None, "1|198.51.100.17|||"), // the reference on req.fhdr: 0||||
        ("for=a, for=b", None, "0||||"), // the reference on req.fhdr: 0||||
        ("for=1.2.3.4;by=5.6.7.8;host=a.b;proto=http,", None, "0||||"), // the reference on req.fhdr: 1|1.2.3.4|http|5.6.7.8|a.b
        ("for=1.2.3.4; by=5.6.7.8", Some("0||||"), "0||||"),
        ("proto=httpx", Some("0||||"), "0||||"),
        ("for=1.2.3.4;by=5.6.7.8;host=a.b;proto=httpx", Some("1|1.2.3.4|http|5.6.7.8|a.b"), "1|1.2.3.4|http|5.6.7.8|a.b"),
        (r#"for="[2001:db8::1]:8080""#, Some("1|[2001:db8::1]:8080|||"), "1|[2001:db8::1]:8080|||"),
        ("for=[2001:db8::1]", Some("0||||"), "0||||"),
        (r#"for="_hidden:_port";by=unknown"#, Some("1|_hidden:_port||unknown|"), "1|_hidden:_port||unknown|"),
        (r#"host="example.com:8080""#, Some("1||||example.com:8080"), "1||||example.com:8080"),
        ("host=example.com:8080", Some("0||||"), "0||||"),
        ("for=1.2.3.4;for=5.6.7.8", Some("0||||"), "0||||"),
        ("FOR=1.2.3.4", Some("0||||"), "0||||"),
        ("for=1.2.3.4x", Some("0||||"), "0||||"),
        (r#"for="1.2.3.4"#, Some("0||||"), "0||||"),
        (r#"for=1.2.3.4;proto="https""#, Some("0||||"), "0||||"),
        ("for=unknownfoo", Some("0||||"), "0||||"),
        ("host=a_b", Some("0||||"), "0||||"),
        ("garbage, for=1.2.3.4", None, "1|1.2.3.4|||"), // the reference on req.fhdr: 0||||
        (r#"for=1.2.3.4, host="x,y""#, None, "0||||"), // the reference on req.fhdr: 0||||
        ("for=1.2.3.4;host=", Some("0||||"), "0||||"),
        ("for=192.0.2.1:80", Some("0||||"), "0||||"),
        (r#"for="192.0.2.1:80""#, Some("1|192.0.2.1:80|||"), "1|192.0.2.1:80|||"),
        (r#"by="[::1]:_x";for=_y"#, Some("1|_y||[::1]:_x|"), "1|_y||[::1]:_x|"),
        ("for=1.2.3.4;by=5.6.7.8;host=a.b;proto=https;junk", Some("1|1.2.3.4|https|5.6.7.8|a.b"), "1|1.2.3.4|https|5.6.7.8|a.b"),
        ("for=001.2.3.4", Some("0||||"), "0||||"),
        (r#"for="[::ffff:1.2.3.4]""#, Some("0||||"), "0||||"),
        (r#"host="[::1]:443";proto=http"#, Some("1||http||[::1]:443"), "1||http||[::1]:443"),
        ("for=1.2.3.4 , for=5.6.7.8", None, "1|5.6.7.8|||"), // the reference on req.fhdr: 0||||
        (r#"for="_x", by="5.6.7.8:0""#, None, "0||||"), // the reference on req.fhdr: 0||||
    ];
    let lf = (0..rows.len())
        .map(|i| {
            ["req.fhdr", "req.hdr"]
                .iter()
                .map(|f| {
                    let mut s = format!("%[{f}(x{i}),rfc7239_is_valid]");
                    for k in ["for", "proto", "by", "host"] {
                        let _ = write!(s, "|%[{f}(x{i}),rfc7239_field({k})]");
                    }
                    s
                })
                .collect::<Vec<_>>()
                .join("|")
        })
        .collect::<Vec<_>>()
        .join("~");

    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("ibex-rfc7239-field-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"{lf}\"\n"
    );
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = Ibex(child, dir);
    assert!(common::wait_listening(a), "ibex did not listen on {a}");

    let mut req = String::from("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n");
    for (i, (v, _, _)) in rows.iter().enumerate() {
        let _ = write!(req, "x{i}: {v}\r\n");
    }
    req.push_str("\r\n");
    let mut s = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out).into_owned();
    let body = out.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {out:?}"), |(_, b)| b.to_string());

    let got: Vec<&str> = body.split('~').collect();
    assert_eq!(got.len(), rows.len(), "body: {body:?}");
    let mut bad = Vec::new();
    for ((v, fhdr, hdr), got) in rows.iter().zip(got) {
        let p: Vec<&str> = got.split('|').collect();
        let (got_f, got_h) = (p[..5.min(p.len())].join("|"), p.get(5..).map(|h| h.join("|")).unwrap_or_default());
        if fhdr.is_some_and(|f| f != got_f) {
            bad.push(format!("req.fhdr {v:?}: got {got_f:?}, want {fhdr:?}"));
        }
        if *hdr != got_h {
            bad.push(format!("req.hdr {v:?}: got {got_h:?}, want {hdr:?}"));
        }
    }
    assert!(bad.is_empty(), "rows differing from the reference:\n{}", bad.join("\n"));
}
