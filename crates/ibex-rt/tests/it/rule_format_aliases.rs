// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T450: the address and name aliases (`%ci`, `%cp`, `%fi`, `%fp`, `%si`, `%sp`, `%f`, `%b`,
//! `%s`) in the formats of rules and replies (`lf-string`, `set-header`), where the format is
//! rendered without the access log's data. The client comes in through a `PROXY` line, so its
//! address is not the loopback the test connects from.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8 with the same configurations and
//! the line `PROXY TCP4 192.0.2.7 198.51.100.9 40123 8443`: the aliases print the stream's
//! addresses and names; a server address the stream has no connection for yet prints nothing.

use crate::common;

use ibex_config::parse_str;
use ibex_rt::Engine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const PROXY_LINE: &str = "PROXY TCP4 192.0.2.7 198.51.100.9 40123 8443\r\n";
const ALIASES: &str = "ci=%ci cp=%cp fi=%fi fp=%fp si=%si sp=%sp f=%f b=%b s=%s";

/// Runs `template` (`ADDR` is the proxy the client reaches, `SRV` a free address), sends
/// `request` after the `PROXY` line and returns the whole reply and the port of `SRV`.
fn exchange_srv(template: &str, request: &str) -> (String, u16) {
    let addr = common::reserve_addr();
    let srv = common::reserve_addr();
    let cfg = parse_str(&template.replace("ADDR", &addr.to_string()).replace("SRV", &srv.to_string())).expect("parse");
    let mut engine = Engine::new(&cfg, 64).expect("engine");
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).unwrap();
    c.write_all(format!("{PROXY_LINE}{request}").as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("step");
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    (String::from_utf8_lossy(&out).into_owned(), srv.port())
}

fn exchange(template: &str, request: &str) -> String {
    exchange_srv(template, request).0
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n";
const GET: &str = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

fn header<'a>(r: &'a str, name: &str) -> Option<&'a str> {
    r.split("\r\n\r\n").next()?.lines().find_map(|l| l.split_once(": ").filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
}

#[test]
fn a_stats_deny_template_renders_the_stream_addresses() {
    // HAProxy also prints `s=<STATS>` there; the server alias is left out of this one.
    let r = exchange(
        &format!(
            "{DEFAULTS}listen st\n  bind ADDR accept-proxy\n  stats uri /\n  http-error status 403 content-type text/plain lf-string \"ci=%ci cp=%cp fi=%fi fp=%fp si=%si sp=%sp f=%f b=%b end\"\n  stats http-request deny\n"
        ),
        GET,
    );
    assert!(r.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{r}");
    assert!(r.ends_with("\r\n\r\nci=192.0.2.7 cp=40123 fi=198.51.100.9 fp=8443 si= sp= f=st b=st end"), "{r}");
}

#[test]
fn a_return_body_and_a_request_header_render_the_aliases() {
    let r = exchange(
        &format!(
            "{DEFAULTS}listen ret\n  bind ADDR accept-proxy\n  http-request set-header x-a \"{ALIASES}\"\n  http-request return status 200 content-type text/plain lf-string \"{ALIASES} hdr=%[req.hdr(x-a)]\"\n"
        ),
        GET,
    );
    let want = "ci=192.0.2.7 cp=40123 fi=198.51.100.9 fp=8443 si= sp= f=ret b=ret s=<NOSRV>";
    assert!(r.ends_with(&format!("\r\n\r\n{want} hdr={want}")), "{r}");
}

#[test]
fn an_after_response_header_of_a_denied_request_renders_the_aliases() {
    let r = exchange(&format!("{DEFAULTS}listen hdr\n  bind ADDR accept-proxy\n  http-after-response set-header x-b \"{ALIASES}\"\n  http-request deny\n"), GET);
    assert_eq!(header(&r, "x-b"), Some("ci=192.0.2.7 cp=40123 fi=198.51.100.9 fp=8443 si= sp= f=hdr b=hdr s=<NOSRV>"), "{r}");
}

#[test]
fn response_headers_render_the_server_address_and_names() {
    let (r, port) = exchange_srv(
        &format!(
            "{DEFAULTS}listen be\n  bind SRV\n  http-request return status 200 content-type text/plain string ok\n\
             listen fwd\n  bind ADDR accept-proxy\n  http-response set-header x-r \"{ALIASES}\"\n  http-after-response set-header x-b \"{ALIASES}\"\n  server srv1 SRV\n"
        ),
        GET,
    );
    assert!(r.starts_with("HTTP/1.1 200 OK\r\n") && r.ends_with("\r\n\r\nok"), "{r}");
    let want = format!("ci=192.0.2.7 cp=40123 fi=198.51.100.9 fp=8443 si=127.0.0.1 sp={port} f=fwd b=fwd s=srv1");
    assert_eq!(header(&r, "x-r"), Some(want.as_str()), "{r}");
    assert_eq!(header(&r, "x-b"), Some(want.as_str()), "{r}");
}
