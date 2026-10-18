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

const USERS: &str = "userlist ul\n  user alice insecure-password pw1 groups g1\n  user bob insecure-password pw2\n  group g1\n";

/// The userlists are process-wide state (`ibex_sample::set_userlists`): one engine at a time.
static ONE_ENGINE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn b64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Loads `top` (before the proxies) and the `listen` body `body`, sends `request` and returns
/// the whole reply.
fn exchange(top: &str, body: &str, request: &str) -> String {
    let _one = ONE_ENGINE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let addr = common::reserve_addr();
    let cfg = parse_str(&format!(
        "{top}defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         listen l\n  bind {addr}\n  stats uri /st\n{body}"
    ))
    .expect("parse");
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

fn basic(up: &str) -> String {
    format!("Basic {}", b64(up))
}

fn status(r: &str) -> &str {
    r.lines().next().unwrap_or("")
}

#[test]
fn no_credentials_get_the_401_page_byte_for_byte() {
    let r = get("", "  stats auth admin:secret\n", None);
    assert_eq!(
        r,
        "HTTP/1.1 401 Unauthorized\r\ncontent-length: 112\r\ncache-control: no-cache\r\ncontent-type: text/html\r\n\
         www-authenticate: Basic realm=\"HAProxy Statistics\"\r\nconnection: close\r\n\r\n\
         <html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n"
    );
}

#[test]
fn right_wrong_and_malformed_credentials() {
    let body = "  stats auth admin:secret\n  stats auth bob:p:w\n  stats auth empty:\n";
    assert_eq!(status(&get("", body, Some(&basic("admin:secret")))), "HTTP/1.1 200 OK");
    // Several accounts; the password is what follows the first colon.
    assert_eq!(status(&get("", body, Some(&basic("bob:p:w")))), "HTTP/1.1 200 OK");
    assert_eq!(status(&get("", body, Some(&basic("empty:")))), "HTTP/1.1 200 OK");
    // The scheme is case-insensitive.
    assert_eq!(status(&get("", body, Some(&format!("basic {}", b64("admin:secret"))))), "HTTP/1.1 200 OK");
    for bad in [basic("admin:nope"), basic("admin:secre"), basic("nobody:secret"), basic("admin"), "Basic !!!".into(), "Basic".into(), "Bearer abc".into()] {
        let r = get("", body, Some(&bad));
        assert_eq!(status(&r), "HTTP/1.1 401 Unauthorized", "{bad}");
        assert!(!r.contains("Statistics Report"), "{bad}");
    }
}

#[test]
fn realm_replaces_the_default() {
    let r = get("", "  stats auth a:b\n  stats realm \"My Area\"\n", None);
    assert!(r.contains("www-authenticate: Basic realm=\"My Area\"\r\n"), "{r}");
}

#[test]
fn the_admin_post_needs_the_credentials_too() {
    let body = "  stats auth admin:secret\n  stats admin if TRUE\n";
    let post = |a: &str| {
        exchange("", body, &format!("POST /st HTTP/1.1\r\nHost: x\r\n{a}Content-Length: 14\r\nConnection: close\r\n\r\ns=x&action=foo\r\n"))
    };
    assert_eq!(status(&post("")), "HTTP/1.1 401 Unauthorized");
    let ok = post(&format!("Authorization: {}\r\n", basic("admin:secret")));
    // (HAProxy answers 303 to `;st=ERRP` for this body; Ibex's admin reply is its own.)
    assert!(!ok.starts_with("HTTP/1.1 401"), "{ok}");
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
fn http_request_deny_allow_auth() {
    let r = get("", "  stats http-request deny\n", None);
    assert_eq!(
        r,
        "HTTP/1.1 403 Forbidden\r\ncontent-length: 93\r\ncache-control: no-cache\r\ncontent-type: text/html\r\nconnection: close\r\n\r\n\
         <html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n"
    );
    assert_eq!(status(&get("", "  stats http-request deny deny_status 404 if TRUE\n", None)), "HTTP/1.1 404 Not Found");
    // First match wins; no match lets the request through.
    let allow = "  stats http-request allow if { src 127.0.0.1 }\n  stats http-request deny\n";
    assert_eq!(status(&get("", allow, None)), "HTTP/1.1 200 OK");
    assert_eq!(status(&get("", "  stats http-request deny if { src 10.9.9.9 }\n", None)), "HTTP/1.1 200 OK");
    let auth = "  stats http-request auth unless { http_auth(ul) }\n";
    let r = get(USERS, auth, None);
    assert_eq!(status(&r), "HTTP/1.1 401 Unauthorized");
    assert!(r.contains("www-authenticate: Basic realm=\"HAProxy Statistics\"\r\n"), "{r}");
    assert_eq!(status(&get(USERS, auth, Some(&basic("bob:pw2")))), "HTTP/1.1 200 OK");
    assert_eq!(status(&get(USERS, auth, Some(&basic("bob:x")))), "HTTP/1.1 401 Unauthorized");
    let grp = "  stats http-request auth realm \"My Area\" if !{ http_auth_group(ul) g1 }\n";
    assert_eq!(status(&get(USERS, grp, Some(&basic("bob:pw2")))), "HTTP/1.1 401 Unauthorized");
    assert_eq!(status(&get(USERS, grp, Some(&basic("alice:pw1")))), "HTTP/1.1 200 OK");
    assert!(get(USERS, grp, None).contains("realm=\"My Area\""));
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
