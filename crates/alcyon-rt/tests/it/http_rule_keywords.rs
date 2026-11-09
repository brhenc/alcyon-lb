// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The HTTP rule keywords of T124 (`replace-uri`, `errorloc`, `http-err-codes`, ...).
//!
//! Every expected value below was measured on the reference binary, `HAProxy
//! 3.5-dev8-885761-29`, on 2026-10-04, with the same configurations and a raw-socket
//! client and server (the server answers with the request head it received as the body).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server answering every request with `200` and the request head it got as the body.
fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut chunk) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    }
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", buf.len());
                    let mut out = resp.into_bytes();
                    out.extend_from_slice(&buf);
                    buf.clear();
                    if c.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// A server answering `GET /<status>` with that status, an empty body, and `Connection: close`.
fn status_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let status: u16 = head.split(' ').nth(1).and_then(|p| p.trim_matches('/').parse().ok()).unwrap_or(200);
                let _ = c.write_all(format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
            });
        }
    });
    addr
}

fn start(cfg: &str) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let text = cfg
        .replace("{fe}", &fe.to_string())
        .replace("{srv}", &echo_server().to_string())
        .replace("{status}", &status_server().to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon { child, _cfg: f };
    assert!(common::wait_listening(fe), "alcyon never listened on {fe} with:\n{text}");
    (alcyon, fe)
}

/// Sends `raw`, returns everything until the peer closes or goes quiet.
fn send(fe: SocketAddr, raw: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(raw.as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_millis(800))).ok();
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = c.read(&mut chunk) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// The request line the server saw for `GET <target>` through `fe`.
fn seen_target(fe: SocketAddr, target: &str, host: &str) -> String {
    let got = send(fe, &format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"));
    let body = got.split("\r\n\r\n").nth(1).unwrap_or("");
    let line = body.lines().next().unwrap_or("").to_string();
    assert!(got.starts_with("HTTP/1.1 200"), "{target}: {got:?}");
    line
}

const REPLACE_URI: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n\
  http-request replace-uri ([^/:]*://[^/]*)?(.*) \\1/pfx\\2 if { url_param(t) -m str prefix }\n\
  http-request replace-uri ^http://(.*) https://\\1 if { url_param(t) -m str scheme }\n\
  http-request replace-uri ^/nosuchprefix/(.*) /other/\\1 if { url_param(t) -m str nomatch }\n\
  default_backend be\n\
backend be\n  server s {srv}\n";

#[test]
fn replace_uri_rewrites_the_whole_target_scheme_and_authority_included() {
    let (_i, fe) = start(REPLACE_URI);
    assert_eq!(seen_target(fe, "/bar?t=prefix", "a"), "GET /pfx/bar?t=prefix HTTP/1.1");
    assert_eq!(
        seen_target(fe, "http://www.example.com/bar?t=prefix", "www.example.com"),
        "GET http://www.example.com/pfx/bar?t=prefix HTTP/1.1"
    );
    assert_eq!(
        seen_target(fe, "http://www.example.com/bar?t=scheme", "www.example.com"),
        "GET https://www.example.com/bar?t=scheme HTTP/1.1"
    );
    assert_eq!(seen_target(fe, "/bar?t=nomatch", "a"), "GET /bar?t=nomatch HTTP/1.1");
}

const ERRORLOC: &str = "defaults\n  mode http\n  retries 0\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe1\n  bind {fe}\n  errorloc 503 http://www.example.com/oops503\n\
  http-request deny deny_status 403 if { path /denied }\n  default_backend dead\n\
backend dead\n  server s1 {dead}\n";

fn start_dead(cfg: &str) -> (Alcyon, SocketAddr) {
    let dead = common::reserve_addr();
    start(&cfg.replace("{dead}", &dead.to_string()))
}

fn get_close(fe: SocketAddr, path: &str) -> String {
    send(fe, &format!("GET {path} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"))
}

#[test]
fn errorloc_answers_with_the_redirect_haproxy_builds() {
    let (_i, fe) = start_dead(ERRORLOC);
    assert_eq!(
        // Header names are case-insensitive: Alcyon writes `Connection: close` capitalised.
        get_close(fe, "/gone").replace("Connection: close", "connection: close"),
        "HTTP/1.1 302 Found\r\ncache-control: no-cache\r\ncontent-length: 0\r\nlocation: http://www.example.com/oops503\r\nconnection: close\r\n\r\n"
    );
    // No errorloc for 403: the default page.
    let got = get_close(fe, "/denied");
    assert!(got.starts_with("HTTP/1.1 403 Forbidden\r\n") && !got.contains("location"), "{got:?}");
}

#[test]
fn errorloc303_and_a_relative_location() {
    let cfg = ERRORLOC.replace(
        "errorloc 503 http://www.example.com/oops503",
        "errorloc303 503 /l503\n  errorloc302 403 /l403",
    );
    let (_i, fe) = start_dead(&cfg);
    let got = get_close(fe, "/gone");
    assert!(got.starts_with("HTTP/1.1 303 See Other\r\n") && got.contains("location: /l503\r\n"), "{got:?}");
    let got = get_close(fe, "/denied");
    assert!(got.starts_with("HTTP/1.1 302 Found\r\n") && got.contains("location: /l403\r\n"), "{got:?}");
}

const FORWARDFOR: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n  {ffopt}\n  use_backend be1 if { path /req1 }\n  use_backend be2 if { path /req2 }\n  use_backend be3 if { path /req3 }\n\
backend be1\n  option forwardfor\n  server s {srv}\n\
backend be2\n  option forwardfor if-none\n  server s {srv}\n\
backend be3\n  server s {srv}\n";

/// How many `x-forwarded-for` header lines the server got for `path`, the client having
/// sent one of its own when `own`.
fn xff_count(fe: SocketAddr, path: &str, own: bool) -> usize {
    let hdr = if own { "x-forwarded-for: 127.0.0.9\r\n" } else { "" };
    let got = send(fe, &format!("GET {path} HTTP/1.1\r\nHost: a\r\n{hdr}Connection: close\r\n\r\n"));
    let body = got.split("\r\n\r\n").nth(1).unwrap_or("");
    body.lines().filter(|l| l.to_ascii_lowercase().starts_with("x-forwarded-for:")).count()
}

#[test]
fn forwardfor_if_none_adds_only_where_no_proxy_asks_for_it_always() {
    // Measured on HAProxy 3.5-dev8-885761-29 (reg-tests/http-rules/ifnone-forwardfor.vtc,
    // with the same frontend and backend options): the header is added always as soon as the
    // frontend or the backend asks for it without `if-none`; and it is added, not replaced.
    let (_i, fe) = start(&FORWARDFOR.replace("{ffopt}", "option forwardfor if-none"));
    assert_eq!(xff_count(fe, "/req1", true), 2);
    assert_eq!(xff_count(fe, "/req2", true), 1);
    assert_eq!(xff_count(fe, "/req2", false), 1);
    assert_eq!(xff_count(fe, "/req3", true), 1);
    assert_eq!(xff_count(fe, "/req3", false), 1);
    let (_i, fe) = start(&FORWARDFOR.replace("{ffopt}", "option forwardfor"));
    assert_eq!(xff_count(fe, "/req1", true), 2);
    assert_eq!(xff_count(fe, "/req2", true), 2);
    assert_eq!(xff_count(fe, "/req3", true), 2);
}

const PRIORITY: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n  http-after-response set-header x-prio %[prio_class]/%[prio_offset]\n\
  http-request set-priority-class int(3) if { path /a }\n  http-request set-priority-offset int(-10) if { path /a }\n\
  http-request set-priority-class int(5000) if { path /b }\n  http-request set-priority-class int(-5000) if { path /c }\n\
  http-request set-priority-offset int(2000000) if { path /d }\n  http-request set-priority-offset int(-2000000) if { path /e }\n\
  http-request set-priority-class str(abc) if { path /f }\n\
  http-request set-priority-class req.hdr(x-c) if { path /g }\n  http-request set-priority-offset req.hdr(x-o) if { path /g }\n\
  http-request set-priority-class int(5) if { path /m }\n  http-request set-priority-class str(abc) if { path /m }\n\
  http-request set-priority-offset int(5) if { path /m }\n  http-request set-priority-offset req.hdr(x-none) if { path /m }\n\
  default_backend be\n\
backend be\n  server s {srv}\n";

fn x_prio(fe: SocketAddr, path: &str, hdrs: &str) -> String {
    let got = send(fe, &format!("GET {path} HTTP/1.1\r\nHost: a\r\n{hdrs}Connection: close\r\n\r\n"));
    got.lines()
        .find_map(|l| l.strip_prefix("x-prio: ").or_else(|| l.strip_prefix("X-Prio: ")))
        .unwrap_or_else(|| panic!("{path}: no x-prio in {got:?}"))
        .trim()
        .to_string()
}

#[test]
fn set_priority_class_and_offset_are_read_back_by_the_fetches() {
    let (_i, fe) = start(PRIORITY);
    // Measured on HAProxy 3.5-dev8-885761-29 with the same rules.
    assert_eq!(x_prio(fe, "/a", ""), "3/-10");
    assert_eq!(x_prio(fe, "/none", ""), "0/0");
    // The class is clamped to +-2047, the offset to +-524287.
    assert_eq!(x_prio(fe, "/b", ""), "2047/0");
    assert_eq!(x_prio(fe, "/c", ""), "-2047/0");
    assert_eq!(x_prio(fe, "/d", ""), "0/524287");
    assert_eq!(x_prio(fe, "/e", ""), "0/-524287");
    // A string that is not a number is 0; a sample that cannot be fetched changes nothing.
    assert_eq!(x_prio(fe, "/f", ""), "0/0");
    assert_eq!(x_prio(fe, "/g", "x-c: 4\r\nx-o: -7\r\n"), "4/-7");
    assert_eq!(x_prio(fe, "/g", "x-c: zz\r\nx-o: 99999999\r\n"), "0/524287");
    assert_eq!(x_prio(fe, "/m", ""), "0/5");
}

const AUTH: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
userlist ul\n  group admins users u1\n  group dev\n  group other\n  user u1 insecure-password pass1 groups dev\n\
  user u2 insecure-password pass2 groups admins,dev\n  user u3 insecure-password pass3\n  user u4 insecure-password \"pass 4\" groups other\n\
  user u5\n\
frontend fe\n  bind {fe}\n  acl auth_ok http_auth(ul)\n  acl is_admin http_auth_group(ul) admins\n  acl is_dev http_auth_group(ul) dev\n\
  http-request set-var(txn.user) http_auth_user\n  http-request set-var(txn.pass) http_auth_pass\n  http-request set-var(txn.type) http_auth_type\n\
  http-request set-var(txn.ok) str(yes) if auth_ok\n  http-request set-var(txn.admin) str(yes) if is_admin\n  http-request set-var(txn.dev) str(yes) if is_dev\n\
  http-request auth if { path /noreal } !auth_ok\n  http-request auth realm \"my realm\" if { path /real } !auth_ok\n\
  http-request return status 200\n\
  http-after-response set-header x-got \"%[var(txn.user)]|%[var(txn.pass)]|%[var(txn.type)]|%[var(txn.ok)]|%[var(txn.admin)]|%[var(txn.dev)]\"\n";

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

/// The status line and the interesting headers the answer to `GET <path>` with `auth` as its
/// `authorization` header carried.
fn auth_get(fe: SocketAddr, path: &str, auth: Option<&str>) -> (String, String, String) {
    let hdr = auth.map_or(String::new(), |a| format!("authorization: {a}\r\n"));
    let got = send(fe, &format!("GET {path} HTTP/1.1\r\nHost: a\r\n{hdr}Connection: close\r\n\r\n"));
    let find = |name: &str| {
        got.lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix(&format!("{name}: ")).map(|_| l[name.len() + 2..].trim_end().to_string()))
            .unwrap_or_default()
    };
    (got.lines().next().unwrap_or("").to_string(), find("x-got"), find("www-authenticate"))
}

#[test]
fn http_auth_reads_the_userlist_and_the_credentials() {
    let (_i, fe) = start(AUTH);
    let basic = |c: &str| Some(format!("Basic {}", b64(c)));
    // (credentials, "user|pass|type|ok|admin|dev"), measured on HAProxy 3.5-dev8-885761-29.
    for (creds, want) in [
        (None, "|||||".to_string()),
        (basic("u1:pass1"), "u1|pass1|Basic|yes|yes|yes".to_string()),
        (basic("u2:pass2"), "u2|pass2|Basic|yes|yes|yes".to_string()),
        (basic("u3:pass3"), "u3|pass3|Basic|yes||".to_string()),
        (basic("u4:pass 4"), "u4|pass 4|Basic|yes||".to_string()),
        (basic("u1:wrong"), "u1|wrong|Basic|||".to_string()),
        (basic("nouser:x"), "nouser|x|Basic|||".to_string()),
        (basic("u1:"), "u1||Basic|||".to_string()),
        (basic(":pass1"), "|pass1|Basic|||".to_string()),
        (basic("u2:pa:ss"), "u2|pa:ss|Basic|||".to_string()),
        // A user declared without a password never authenticates.
        (basic("u5:"), "u5||Basic|||".to_string()),
        (basic("u5:x"), "u5|x|Basic|||".to_string()),
        (Some("Bearer abc".to_string()), "||Bearer|||".to_string()),
        (Some("Foo abc".to_string()), "|||||".to_string()),
        (Some("Basic !!!!".to_string()), "|||||".to_string()),
        (Some(format!("Basic {}", b64("u1pass1"))), "|||||".to_string()),
        (Some(format!("basic   {}", b64("u1:pass1"))), "u1|pass1|Basic|yes|yes|yes".to_string()),
        (Some(format!("Basic\t{}", b64("u1:pass1"))), "|||||".to_string()),
    ] {
        let (status, got, _) = auth_get(fe, "/public", creds.as_deref());
        assert_eq!(status, "HTTP/1.1 200 OK", "{creds:?}");
        assert_eq!(got, want, "{creds:?}");
    }
}

#[test]
fn the_auth_action_answers_401_with_its_realm_and_the_default_page() {
    let (_i, fe) = start(AUTH);
    // The default realm is the name of the proxy the rule is in.
    let (status, _, realm) = auth_get(fe, "/noreal", None);
    assert_eq!((status.as_str(), realm.as_str()), ("HTTP/1.1 401 Unauthorized", "Basic realm=\"fe\""));
    let (_, _, realm) = auth_get(fe, "/real", None);
    assert_eq!(realm, "Basic realm=\"my realm\"");
    let got = send(fe, "GET /real HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    assert!(got.to_ascii_lowercase().contains("content-length: 112"), "{got:?}");
    assert!(got.contains("<h1>401 Unauthorized</h1>"), "{got:?}");
    let wrong = format!("Basic {}", b64("u1:wrong"));
    assert_eq!(auth_get(fe, "/real", Some(&wrong)).0, "HTTP/1.1 401 Unauthorized");
    let right = format!("Basic {}", b64("u1:pass1"));
    assert_eq!(auth_get(fe, "/real", Some(&right)).0, "HTTP/1.1 200 OK");
}

#[test]
fn http_auth_names_a_userlist_that_exists() {
    // Measured on HAProxy 3.5-dev8-885761-29: "unable to find userlist 'nope' referenced in
    // arg 1 of ACL keyword 'http_auth' in proxy 'f'", "missing userlist name in arg 1 of ...".
    let cfg = |acl: &str| {
        format!(
            "userlist ul\n  user u insecure-password p\ndefaults\n  mode http\n  timeout client 5s\n\
             frontend f\n  bind 127.0.0.1:18082\n  acl x {acl}\n  http-request deny if x\n"
        )
    };
    let check = |acl: &str| {
        let config = alcyon_config::parse_config(&cfg(acl)).expect("parses");
        alcyon_rt::proxy_state::check_sample_refs(&config, alcyon_sample::sample_registry())
    };
    assert!(check("http_auth(ul)").is_ok());
    assert!(check("http_auth_group(ul) g").is_ok());
    for (acl, want) in [
        ("http_auth(nope)", "unable to find userlist 'nope' referenced in arg 1 of ACL keyword 'http_auth' in proxy 'f'"),
        ("http_auth_group(nope) g", "unable to find userlist 'nope' referenced in arg 1 of ACL keyword 'http_auth_group' in proxy 'f'"),
        ("http_auth", "missing userlist name in arg 1 of ACL keyword 'http_auth' in proxy 'f'"),
    ] {
        let err = check(acl).expect_err(acl);
        assert!(err.contains(want), "{acl}: {err}");
    }
}

/// Backends of the `option forwarded` test, each with the options HAProxy was measured with.
const FORWARDED: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n  http-request set-src hdr(x-src)\n  http-request set-dst hdr(x-dst)\n\
  use_backend b1 if { path /b1 }\n  use_backend b2 if { path /b2 }\n  use_backend b3 if { path /b3 }\n  use_backend b4 if { path /b4 }\n\
  use_backend b5 if { path /b5 }\n  use_backend b6 if { path /b6 }\n  use_backend b7 if { path /b7 }\n  use_backend off if { path /off }\n\
backend b1\n  option forwarded\n  server s {srv}\n\
backend b2\n  option forwarded proto host by by_port for for_port\n  server s {srv}\n\
backend b3\n  option forwarded host-expr str(override) proto\n  server s {srv}\n\
backend b4\n  option forwarded for-expr str(abc) by-expr str(my_obf)\n  server s {srv}\n\
backend b5\n  option forwarded for-expr str(a:b) by-expr str(\"x y\") host-expr str(\"a;b\")\n  server s {srv}\n\
backend b6\n  option forwarded for-expr str(unknown) for_port-expr str(_p) by-expr ipv6(::1) by_port-expr int(65535)\n  server s {srv}\n\
backend b7\n  option forwarded for-expr str(abc) for_port-expr int(70000) by-expr dst by_port-expr str(80)\n  server s {srv}\n\
backend off\n  server s {srv}\n";

/// The `forwarded` header lines the server got, and the local port of the client socket.
fn forwarded_seen(fe: SocketAddr, path: &str, hdrs: &str) -> (Vec<String>, u16) {
    let mut c = TcpStream::connect(fe).expect("connect");
    let port = c.local_addr().expect("addr").port();
    let src = if hdrs.contains("x-src") { "" } else { "x-src: 10.1.2.3\r\n" };
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: example.com:8080\r\n{src}x-dst: 192.168.0.9\r\n{hdrs}Connection: close\r\n\r\n").as_bytes())
        .expect("send");
    c.set_read_timeout(Some(Duration::from_millis(800))).ok();
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = c.read(&mut chunk) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&got).into_owned();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    let lines = body.lines().filter(|l| l.to_ascii_lowercase().starts_with("forwarded:")).map(|l| l[10..].trim().to_string()).collect();
    (lines, port)
}

#[test]
fn option_forwarded_writes_what_haproxy_writes() {
    let (_i, fe) = start(FORWARDED);
    let one = |path: &str| {
        let (lines, _) = forwarded_seen(fe, path, "");
        assert_eq!(lines.len(), 1, "{path}: {lines:?}");
        lines[0].clone()
    };
    // Measured on HAProxy 3.5-dev8-885761-29 with the same backends, and `x-src`/`x-dst` as
    // `set-src`/`set-dst`.
    assert_eq!(one("/b1"), "proto=http;for=10.1.2.3");
    assert_eq!(one("/b3"), "proto=http;host=\"override\"");
    assert_eq!(one("/b4"), "by=_my_obf;for=_abc");
    assert_eq!(one("/b5"), "host=\"\";by=unknown;for=unknown");
    assert_eq!(one("/b6"), "by=\"[::1]:65535\";for=\"unknown:_p\"");
    assert_eq!(one("/b7"), "by=\"192.168.0.9:80\";for=\"_abc:_70000\"");
    // The default `host` is the Host header, the ports are the connection's.
    let (lines, client_port) = forwarded_seen(fe, "/b2", "");
    assert_eq!(
        lines,
        [format!("proto=http;host=\"example.com:8080\";by=\"192.168.0.9:{}\";for=\"10.1.2.3:{client_port}\"", fe.port())]
    );
    // An address of the other family is bracketed.
    let (lines, _) = forwarded_seen(fe, "/b1", "x-src: 2001:db8::1\r\n");
    assert_eq!(lines, ["proto=http;for=\"[2001:db8::1]\""]);
    // No option, no header.
    assert_eq!(forwarded_seen(fe, "/off", "").0.len(), 0);
}

#[test]
fn option_forwarded_appends_to_the_last_forwarded_header() {
    let (_i, fe) = start(FORWARDED);
    let (lines, _) = forwarded_seen(fe, "/b1", "forwarded: for=1.1.1.1\r\n");
    assert_eq!(lines, ["for=1.1.1.1,proto=http;for=10.1.2.3"]);
    let (lines, _) = forwarded_seen(fe, "/b1", "forwarded: for=1.1.1.1\r\nforwarded: for=2.2.2.2\r\n");
    assert_eq!(lines, ["for=1.1.1.1", "for=2.2.2.2,proto=http;for=10.1.2.3"]);
}

#[test]
fn the_rfc7239_converters_answer_what_haproxy_answers() {
    let cfg = "defaults\n  mode http\n  timeout client 5s\n\
frontend fe\n  bind {fe}\n  http-request set-var(req.f) req.hdr(x-f)\n\
  http-request return status 200 hdr valid \"%[var(req.f),rfc7239_is_valid]\" hdr ffor \"%[var(req.f),rfc7239_field(for)]\" \
hdr n2nn \"%[var(req.f),rfc7239_field(for),rfc7239_n2nn]\" hdr n2np \"%[var(req.f),rfc7239_field(for),rfc7239_n2np]\" \
hdr nn4 \"%[ipv4(127.9.0.1),rfc7239_nn]\" hdr nn6 \"%[ipv6(ab:cd::1),rfc7239_nn]\" hdr nns \"%[var(req.f),rfc7239_nn]\" \
hdr npi \"%[int(12),rfc7239_np]\" hdr nps \"%[var(req.f),rfc7239_np]\"\n";
    let (_i, fe) = start(cfg);
    let get = |v: &str| {
        let got = send(fe, &format!("GET / HTTP/1.1\r\nHost: a\r\nx-f: {v}\r\nConnection: close\r\n\r\n"));
        let h = |n: &str| {
            got.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix(&format!("{n}: ")).map(|_| l[n.len() + 2..].trim_end().to_string())).unwrap_or_default()
        };
        ["valid", "ffor", "n2nn", "n2np", "nn4", "nn6", "nns", "npi", "nps"].map(|n| h(n)).join("|")
    };
    let tail = "127.9.0.1|[ab:cd::1]";
    // Measured on HAProxy 3.5-dev8-885761-29 with the same config.
    assert_eq!(get(r#"for="unknown:132";host="[::1]:65535";by="_obfs:_port";proto=https"#), format!("1|unknown:132|unknown|132|{tail}||12|"));
    assert_eq!(get("fore=\"unknown:132\""), format!("0||||{tail}||12|"));
    assert_eq!(get(r#"proto=http;for="[::1]:_id""#), format!("1|[::1]:_id|::1|_id|{tail}||12|"));
    assert_eq!(get("for=127.9.0.1"), format!("1|127.9.0.1|127.9.0.1||{tail}||12|"));
    assert_eq!(get("id"), format!("0||||{tail}|_id|12|_id"));
}

#[test]
fn option_forwarded_expressions_are_checked_at_load() {
    // HAProxy: "failed to parse 'option forwarded' expression 'foo(1)' in : unknown fetch method 'foo'."
    let check = |opt: &str| {
        let config = alcyon_config::parse_config(&format!(
            "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\nbackend b\n  {opt}\n  server s 127.0.0.1:9\n"
        ))
        .expect("parses");
        alcyon_rt::rule_exprs::validate_rule_exprs(&config, alcyon_sample::sample_registry())
    };
    assert!(check("option forwarded for-expr req.hdr(x),lower").is_ok());
    for (opt, want) in [
        ("option forwarded for-expr foo(1)", "failed to parse 'option forwarded' expression 'foo(1)' in : unknown fetch method 'foo'"),
        ("option forwarded host-expr nosuchconv,x", "unknown fetch method 'nosuchconv'"),
        ("option forwarded by-expr str(a),nosuchconv", "unknown converter 'nosuchconv'"),
    ] {
        let err = check(opt).expect_err(opt);
        assert!(err.contains(want), "{opt}: {err}");
    }
}

#[test]
fn the_auth_action_uses_the_401_page_the_proxy_has() {
    // Measured on HAProxy 3.5-dev8-885761-29: the `http-error status 401` page, with
    // `www-authenticate` added.
    let cfg = "defaults\n  mode http\n  timeout client 5s\n\
frontend fe\n  bind {fe}\n  http-error status 401 content-type text/plain string \"need login\"\n  http-request auth realm r\n";
    let (_i, fe) = start(cfg);
    let got = send(fe, "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").to_ascii_lowercase();
    assert!(got.starts_with("http/1.1 401 unauthorized\r\n"), "{got:?}");
    assert!(got.contains("www-authenticate: basic realm=\"r\"\r\n") && got.contains("content-type: text/plain"), "{got:?}");
    assert!(got.ends_with("\r\n\r\nneed login"), "{got:?}");
}

const ERR_FAIL: &str = "{global}defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n  http-request track-sc0 path\n\
  http-after-response add-header x-table err=%[sc0_http_err_cnt],fail=%[sc0_http_fail_cnt]\n\
  stick-table type string size 100 store http_err_cnt,http_fail_cnt,http_err_rate(10s)\n\
  http-request deny if { path /deny }\n  http-request return status 404 if { path /ret404 }\n\
  http-request return status 500 if { path /ret500 }\n  default_backend be\n\
backend be\n  server s {status}\n";

/// The `x-table` header `HAProxy` answered for `GET /<code>` (the counters as the response
/// leaves, so counting the response itself).
fn x_table(fe: SocketAddr, code: &str) -> String {
    let got = get_close(fe, &format!("/{code}"));
    got.lines()
        .find_map(|l| l.strip_prefix("x-table: ").or_else(|| l.strip_prefix("X-Table: ")))
        .unwrap_or_else(|| panic!("/{code}: no x-table in {got:?}"))
        .to_string()
}

#[test]
fn the_default_error_and_failure_codes_count_what_haproxy_counts() {
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", ""));
    // (path, "err=..,fail=..") measured on HAProxy 3.5-dev8-885761-29 with the same config.
    for (code, want) in [
        ("200", "err=0,fail=0"),
        ("301", "err=0,fail=0"),
        ("399", "err=0,fail=0"),
        ("400", "err=1,fail=0"),
        ("401", "err=1,fail=0"),
        ("404", "err=1,fail=0"),
        ("407", "err=1,fail=0"),
        ("499", "err=1,fail=0"),
        ("500", "err=0,fail=1"),
        ("501", "err=0,fail=0"),
        ("502", "err=0,fail=1"),
        ("505", "err=0,fail=0"),
        ("599", "err=0,fail=1"),
        ("600", "err=0,fail=0"),
    ] {
        assert_eq!(x_table(fe, code), want, "status {code}");
    }
}

#[test]
fn deny_counts_an_error_and_return_does_not() {
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", ""));
    assert_eq!(x_table(fe, "deny"), "err=1,fail=0");
    assert_eq!(x_table(fe, "deny"), "err=2,fail=0");
    assert_eq!(x_table(fe, "ret404"), "err=0,fail=0");
    assert_eq!(x_table(fe, "ret500"), "err=0,fail=0");
}

#[test]
fn http_err_codes_and_http_fail_codes_redefine_the_sets() {
    // The vtc's lines: `220 +300-499 -300-399` leaves 220 and 400-499; the fail codes lose
    // 550-580 and gain 555, 599, 556-566.
    let g = "global\n  http-err-codes 220 +300-499 -300-399\n  http-fail-codes -550-580 +555,599,556-566\n";
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", g));
    for (code, want) in [
        ("220", "err=1,fail=0"),
        ("300", "err=0,fail=0"),
        ("400", "err=1,fail=0"),
        ("555", "err=0,fail=1"),
        ("550", "err=0,fail=0"),
        ("556", "err=0,fail=1"),
        ("500", "err=0,fail=1"),
        ("301", "err=0,fail=0"),
    ] {
        assert_eq!(x_table(fe, code), want, "status {code}");
    }
    // A sign sticks along a comma list; an unsigned element clears the set first.
    let g = "global\n  http-err-codes +300,310 -400,401\n";
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", g));
    for (code, want) in
        [("300", "err=1"), ("310", "err=1"), ("400", "err=0"), ("401", "err=0"), ("402", "err=1")]
    {
        assert!(x_table(fe, code).starts_with(want), "status {code}");
    }
}
