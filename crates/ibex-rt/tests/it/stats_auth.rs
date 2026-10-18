// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `stats auth`, `stats realm`, `stats http-request`, `stats hide-version` / `show-version`
//! reach the stats page. Every expected value was measured on HAProxy 3.5-dev8: a request
//! without valid credentials gets the 401 page with `www-authenticate: Basic realm="HAProxy
//! Statistics"` (or the `stats realm`), the page is not served, and `stats` settings in
//! `defaults` are not inherited (HAProxy drops `stats auth` there).

use crate::common;

use ibex_config::parse_str;
use ibex_rt::Engine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The userlists are process-wide state (`ibex_sample::set_userlists`): one engine at a time.
static ONE_ENGINE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Loads `top` (before the proxies) and the `listen` body `body`, sends `request` and returns
/// the whole reply.
fn exchange(top: &str, body: &str, request: &str) -> String {
    raw(&format!("{top}defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\nlisten l\n  bind ADDR\n  stats uri /st\n{body}"), request)
}

/// Runs the configuration `template` (`ADDR` is the address of its one bind).
fn raw(template: &str, request: &str) -> String {
    let _one = ONE_ENGINE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let addr = common::reserve_addr();
    let cfg = parse_str(&template.replace("ADDR", &addr.to_string())).expect("parse");
    let mut engine = Engine::new(&cfg, 64).expect("engine");
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).unwrap();
    c.write_all(request.as_bytes()).unwrap();
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
    String::from_utf8_lossy(&out).into_owned()
}

fn get(top: &str, body: &str, auth: Option<&str>) -> String {
    let a = auth.map_or(String::new(), |a| format!("Authorization: {a}\r\n"));
    exchange(top, body, &format!("GET /st;csv HTTP/1.1\r\nHost: x\r\n{a}Connection: close\r\n\r\n"))
}

fn status(r: &str) -> &str {
    r.lines().next().unwrap_or("")
}

#[test]
fn stats_auth_in_defaults_is_not_inherited() {
    // HAProxy: the proxy has no `stats auth` of its own, so the page is open.
    let r = exchange(
        "",
        "",
        "GET /st;csv HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&r), "HTTP/1.1 200 OK");
    let _one = ONE_ENGINE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let addr = common::reserve_addr();
    let cfg = parse_str(&format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n  stats auth d:d\n\
         listen l\n  bind {addr}\n  stats uri /st\n"
    ))
    .expect("parse");
    let mut engine = Engine::new(&cfg, 64).expect("engine");
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_nonblocking(true).unwrap();
    c.write_all(b"GET /st;csv HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let (mut out, mut buf, t) = (Vec::new(), [0u8; 65536], Instant::now());
    while t.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().unwrap();
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200 OK"));
}

#[test]
fn version_is_shown_only_with_show_version() {
    let page = |extra: &str| {
        exchange("", extra, "GET /st HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    };
    let v = ibex_rt::version::VERSION;
    assert!(!page("").contains(&format!("version {v}")));
    assert!(page("  stats show-version\n").contains(&format!("<h1>IBEX version {v}</h1>")));
    assert!(!page("  stats show-version\n  stats hide-version\n").contains(&format!("version {v}")));
}

fn path(top: &str, body: &str, p: &str) -> String {
    // A server, so that a request off the stats URI is routed, not answered by the page.
    let body = format!("{body}  server s 127.0.0.1:1\n");
    status(&exchange(top, &body, &format!("GET {p} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))).to_string()
}

/// The stats page is served after the proxy's `http-request` rules, never around them
/// (`http_process_req_common`; every status here measured on HAProxy 3.5-dev8).
#[test]
fn the_proxys_http_request_rules_run_before_the_stats_page() {
    let deny = "  acl trusted src 10.0.0.0/8\n  http-request deny if !trusted\n";
    assert_eq!(path("", deny, "/st"), "HTTP/1.1 403 Forbidden");
    assert_eq!(path("", deny, "/x"), "HTTP/1.1 403 Forbidden");
    assert_eq!(path("", "  http-request redirect location /elsewhere\n", "/st"), "HTTP/1.1 302 Found");
    assert_eq!(path("", "  http-request return status 202\n", "/st"), "HTTP/1.1 202 Accepted");
    // The path as the rules left it decides.
    assert_eq!(path("", "  http-request set-path /st if { path /x }\n", "/x"), "HTTP/1.1 200 OK");
    assert_eq!(
        path("", "  http-request set-path /nostats if { path /st }\n  http-request deny if { path /nostats }\n", "/st"),
        "HTTP/1.1 403 Forbidden"
    );
    // `allow` ends the rules; the page follows.
    let allow = "  http-request allow if { path /st }\n  http-request deny\n";
    assert_eq!(path("", allow, "/st"), "HTTP/1.1 200 OK");
    assert_eq!(path("", allow, "/x"), "HTTP/1.1 403 Forbidden");
}

#[test]
fn a_backends_stats_page_follows_the_backends_rules_and_the_frontends_page_precedes_use_backend() {
    let get = |cfg: &str| {
        status(&raw(
            &format!("defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n{cfg}"),
            "GET /st HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ))
        .to_string()
    };
    assert_eq!(
        get("frontend f\n  bind ADDR\n  default_backend b\nbackend b\n  http-request deny if { path /st }\n  stats enable\n  stats uri /st\n"),
        "HTTP/1.1 403 Forbidden"
    );
    assert_eq!(
        get("frontend f\n  bind ADDR\n  use_backend b if { path /st }\n  stats enable\n  stats uri /st\nbackend b\n  http-request deny\n"),
        "HTTP/1.1 200 OK"
    );
}

/// `monitor-uri` answers before any `http-request` rule (measured: 200 for the probe, 403 for
/// the rest, under `http-request deny`).
#[test]
fn monitor_uri_precedes_the_rules() {
    let m = "  monitor-uri /mon\\n  http-request deny\\n".replace("\\n", "\n");
    assert_eq!(path("", &m, "/mon"), "HTTP/1.1 200 OK");
    assert_eq!(path("", &m, "/x"), "HTTP/1.1 403 Forbidden");
}

#[test]
fn error_pages_of_the_proxy_answer_a_stats_deny_and_auth() {
    // http-error template (measured: 403, content-length 4, content-type text/plain, body "nope").
    let r = get("", "  http-error status 403 content-type text/plain string \"nope\"\n  stats http-request deny\n", None);
    assert!(r.starts_with("HTTP/1.1 403 Forbidden\r\n") && r.ends_with("\r\n\r\nnope") && r.contains("content-type: text/plain\r\n"), "{r}");
    // errorfile 401: the file as it is, plus the www-authenticate header (measured).
    let f = std::env::temp_dir().join(format!("stats-auth-e401-{}.http", std::process::id()));
    std::fs::write(&f, b"HTTP/1.0 401 Unauthorized\r\nContent-Length: 4\r\n\r\nNOPE").unwrap();
    let r = get("", &format!("  errorfile 401 {}\n  stats auth u:p\n", f.display()), None);
    let _ = std::fs::remove_file(&f);
    // (Ibex adds `connection: close`, which HAProxy leaves out of a raw errorfile.)
    assert!(
        r.starts_with("HTTP/1.0 401 Unauthorized\r\ncontent-length: 4\r\nwww-authenticate: Basic realm=\"HAProxy Statistics\"\r\n")
            && r.ends_with("\r\n\r\nNOPE"),
        "{r}"
    );
}

#[test]
fn a_realm_without_accounts_protects_nothing() {
    // Measured: `stats realm` alone leaves the page open.
    assert_eq!(status(&get("", "  stats realm Foo\n", None)), "HTTP/1.1 200 OK");
}
