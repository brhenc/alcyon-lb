// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The backend `cookie` directive: persistence as HAProxy runs it
//! (`http_manage_client_side_cookies`, `http_manage_server_side_cookies` and the
//! `Set-Cookie` insertion in `http_process_res_common`, `src/http_ana.c`).
//!
//! Every expected value below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-03: a raw-socket client sending
//! `GET / HTTP/1.1` with `Connection: close` (and the headers each test names) through a
//! frontend to a backend of servers that answer `200` with `X-Server: <name>` and
//! `X-Got-Cookie: <the Cookie headers they received, joined by " | ", or "-">`, and that
//! send `Set-Cookie: <v>` when the request carries `X-Want-Set-Cookie: <v>`, `ETag: "x"`
//! for `X-Want-Etag`, and `Cache-Control: <v>` for `X-Want-CC: <v>`. Server `s1` has
//! `cookie a` and `s2` has `cookie b` unless a test says otherwise.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n";
const SERVERS: &str = "  server s1 {s1} cookie a\n  server s2 {s2} cookie b\n";
/// What `HAProxy` sends to make a client forget the cookie of a server that has none.
const DELETE: &str = "SRV=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/";

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server answering every request as the module documentation describes.
fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        buf.drain(..end + 4);
                        let hdrs: Vec<(String, String)> = head
                            .split("\r\n")
                            .skip(1)
                            .filter_map(|l| l.split_once(':'))
                            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                            .collect();
                        let cookies: Vec<&str> = hdrs.iter().filter(|(k, _)| k == "cookie").map(|(_, v)| v.as_str()).collect();
                        let mut resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Server: {name}\r\nX-Got-Cookie: {}\r\n",
                            if cookies.is_empty() { "-".to_string() } else { cookies.join(" | ") }
                        );
                        for (k, v) in &hdrs {
                            match k.as_str() {
                                "x-want-set-cookie" => resp.push_str(&format!("Set-Cookie: {v}\r\n")),
                                "x-want-etag" => resp.push_str("ETag: \"x\"\r\n"),
                                "x-want-cc" => resp.push_str(&format!("Cache-Control: {v}\r\n")),
                                _ => {}
                            }
                        }
                        resp.push_str("\r\nok");
                        if c.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
            });
        }
    });
    addr
}

/// Starts ibex on `cfg` with `{fe}` and `{s1}`..`{s3}` replaced by live addresses.
fn start(cfg: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string());
    for name in ["s1", "s2", "s3"] {
        let pat = format!("{{{name}}}");
        if text.contains(&pat) {
            text = text.replace(&pat, &server(name).to_string());
        }
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe)
}

/// `ibex -c -f` on `cfg`: whether it was accepted, and what it said.
fn check(cfg: &str) -> (bool, String) {
    // Nothing is started, so the addresses only have to parse.
    let cfg = cfg.replace("{fe}", "127.0.0.1:1").replace("{s1}", "127.0.0.1:2").replace("{s2}", "127.0.0.1:3");
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

/// A frontend `f` on `{fe}` and a backend `b` with `cookie_line` and `servers`.
fn fe_be(cookie_line: &str, servers: &str) -> String {
    format!("{DEFAULTS}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  balance roundrobin\n  {cookie_line}\n{servers}")
}

#[derive(Debug)]
struct Resp {
    status: u16,
    server: String,
    got_cookie: String,
    set_cookies: Vec<String>,
    /// `Set-Cookie` and `Cache-Control`, in the order they came: `("set-cookie", v)`.
    cookie_and_cc: Vec<(String, String)>,
}

impl Resp {
    /// The `cookie` value of the server that answered (`s1`: `a`, `s2`: `b`).
    fn srv_cookie(&self) -> &'static str {
        match self.server.as_str() {
            "s1" => "a",
            "s2" => "b",
            "s3" => "c",
            s => panic!("unexpected server {s:?}"),
        }
    }
}

/// One request on its own connection, `extra` header lines added.
fn req(fe: SocketAddr, method: &str, extra: &[&str]) -> Resp {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut r = format!("{method} / HTTP/1.1\r\nHost: x\r\n");
    if method == "POST" {
        r.push_str("Content-Length: 0\r\n");
    }
    for h in extra {
        r.push_str(h);
        r.push_str("\r\n");
    }
    r.push_str("Connection: close\r\n\r\n");
    c.write_all(r.as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    let mut lines = head.split("\r\n");
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut resp = Resp { status, server: String::new(), got_cookie: String::new(), set_cookies: Vec::new(), cookie_and_cc: Vec::new() };
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match k.as_str() {
            "x-server" => resp.server = v,
            "x-got-cookie" => resp.got_cookie = v,
            "set-cookie" => {
                resp.set_cookies.push(v.clone());
                resp.cookie_and_cc.push((k, v));
            }
            "cache-control" => resp.cookie_and_cc.push((k, v)),
            _ => {}
        }
    }
    resp
}

fn get(fe: SocketAddr, extra: &[&str]) -> Resp {
    req(fe, "GET", extra)
}

// --- base64 dates, as `s30tob64` / `b64tos30` (`src/base64.c`) ---

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
}

/// A date as `HAProxy` writes it in a cookie: seconds / 4, five base64 digits.
fn date(secs: u64) -> String {
    let v = secs >> 2;
    (0..5).map(|i| B64[((v >> (24 - 6 * i)) & 0x3f) as usize] as char).collect()
}

fn undate(s: &str) -> u64 {
    s.bytes().fold(0u64, |acc, b| (acc << 6) | B64.iter().position(|&c| c == b).expect("base64 digit") as u64) << 2
}

/// Asserts `v` is `<srv>|<date>[|<date>]; path=/` with its dates within a few seconds of
/// now (or equal to `first`, for a `maxlife` first date carried over); returns the dates.
fn assert_dated(v: &str, srv: &str, dates: usize) -> Vec<u64> {
    let (val, rest) = v.split_once("; ").unwrap_or_else(|| panic!("{v:?}"));
    assert_eq!(rest, "path=/", "{v:?}");
    let parts: Vec<&str> = val.split('|').collect();
    assert_eq!(parts.len(), dates + 1, "{v:?}");
    assert_eq!(parts[0], format!("SRV={srv}"), "{v:?}");
    parts[1..].iter().map(|d| {
        assert_eq!(d.len(), 5, "{v:?}");
        undate(d)
    }).collect()
}

// --- the backend's cookie, in a frontend/backend pair ---

/// `cookie_name` was read from the frontend, so a backend's `cookie` never did anything:
/// no `Set-Cookie`, and a client's cookie chose nothing.
#[test]
fn insert_in_a_backend_sets_the_cookie_and_follows_it() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert", SERVERS));
    for _ in 0..2 {
        let r = get(fe, &[]);
        assert_eq!(r.status, 200);
        assert_eq!(r.got_cookie, "-");
        assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())], "{r:?}");
    }
    for _ in 0..3 {
        let r = get(fe, &["Cookie: SRV=b"]);
        assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", "SRV=b"), "{r:?}");
        assert!(r.set_cookies.is_empty(), "a direct access gets no new cookie: {r:?}");
    }
    let r = get(fe, &["Cookie: SRV=b; o=1"]);
    assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", "SRV=b; o=1"));
    // A cookie naming no server: balanced, and told which server it got.
    let r = get(fe, &["Cookie: SRV=zz"]);
    assert_eq!(r.got_cookie, "SRV=zz");
    assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())], "{r:?}");
}

/// `indirect` with `insert`: the server never sees the persistence cookie, and a cookie
/// of that name the server sets on a direct access is removed.
#[test]
fn insert_indirect_hides_the_cookie_from_the_server() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert indirect", SERVERS));
    let cases: [(&[&str], &str, &str); 5] = [
        (&["Cookie: SRV=b"], "s2", "-"),
        (&["Cookie: SRV=b; o=1"], "s2", "o=1"),
        (&["Cookie: o=1; SRV=a"], "s1", "o=1"),
        (&["Cookie: o=1; SRV=a; p=2"], "s1", "o=1; p=2"),
        (&["Cookie: SRV=b", "X-Want-Set-Cookie: SRV=x"], "s2", "-"),
    ];
    for (hdrs, srv, seen) in cases {
        let r = get(fe, hdrs);
        assert_eq!((r.server.as_str(), r.got_cookie.as_str()), (srv, seen), "{hdrs:?}: {r:?}");
        assert!(r.set_cookies.is_empty(), "{hdrs:?}: {r:?}");
    }
}

/// How the `Cookie` header is cut, `http_del_hdr_value` byte for byte: spaces around `=`
/// are removed, `$` attributes go with the cookie before them, `,` separates as `;` does,
/// a quoted `;` is not a separator, and each `Cookie` header is cut on its own.
#[test]
fn the_cookie_header_is_cut_as_haproxy_cuts_it() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert indirect", SERVERS));
    let cases: [(&[&str], &str); 6] = [
        (&["Cookie: o = 1 ; SRV = b ; p=2"], "o=1; p=2"),
        (&["Cookie: q=\"x;y\"; SRV=b"], "q=\"x;y\""),
        (&["Cookie: $Version=1; SRV=b; $Path=/; o=1"], "$Version=1; o=1"),
        (&["Cookie: SRV=b, o=1"], "o=1"),
        (&["Cookie: o=1", "Cookie: SRV=b"], "o=1"),
        (&["Cookie: SRV=b", "Cookie: p=2; SRV=a"], "p=2"),
    ];
    for (hdrs, seen) in cases {
        let r = get(fe, hdrs);
        assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", seen), "{hdrs:?}: {r:?}");
    }
}

/// The name and the server's value are compared exactly; an empty value is no value.
#[test]
fn the_cookie_is_matched_exactly() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert", SERVERS));
    for hdr in ["Cookie: srv=b", "Cookie: SRV=B", "Cookie: SRV=", "Cookie: SRV"] {
        let r = get(fe, &[hdr]);
        assert_eq!(r.got_cookie, &hdr["Cookie: ".len()..]);
        assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())], "{hdr}: {r:?}");
    }
}

/// `nocache`: `Cache-control: private` after the inserted cookie, only when the response
/// would otherwise be cacheable -- a safe method, a cacheable status, and freshness or a
/// validator (`http_check_response_for_cacheability`).
#[test]
fn nocache_marks_only_a_cacheable_response_private() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert indirect nocache", SERVERS));
    let sc = |r: &Resp| ("set-cookie".to_string(), format!("SRV={}; path=/", r.srv_cookie()));
    let cc = |v: &str| ("cache-control".to_string(), v.to_string());

    let r = get(fe, &[]);
    assert_eq!(r.cookie_and_cc, vec![sc(&r)], "no validator, no freshness: {r:?}");
    let r = get(fe, &["X-Want-Etag: 1"]);
    assert_eq!(r.cookie_and_cc, vec![sc(&r), cc("private")], "{r:?}");
    let r = req(fe, "POST", &["X-Want-Etag: 1"]);
    assert_eq!(r.cookie_and_cc, vec![sc(&r)], "POST is not cacheable: {r:?}");
    let r = get(fe, &["X-Want-CC: max-age=60"]);
    assert_eq!(r.cookie_and_cc, vec![cc("max-age=60"), sc(&r), cc("private")], "{r:?}");
    let r = get(fe, &["X-Want-CC: public"]);
    assert_eq!(r.cookie_and_cc, vec![cc("public"), sc(&r)], "public alone is no freshness: {r:?}");
    let r = get(fe, &["Cookie: SRV=b", "X-Want-Etag: 1"]);
    assert_eq!(r.cookie_and_cc, vec![], "nothing inserted, nothing marked: {r:?}");
}

#[test]
fn the_inserted_cookie_carries_its_attributes_in_haproxy_order() {
    let (_ibex, fe) = start(&fe_be(
        "cookie SRV insert httponly secure domain .example.com domain .ex.org attr SameSite=Lax attr Foo",
        SERVERS,
    ));
    let r = get(fe, &[]);
    assert_eq!(
        r.set_cookies,
        vec![format!("SRV={}; path=/; domain=.example.com; domain=.ex.org; HttpOnly; Secure; SameSite=Lax; Foo", r.srv_cookie())]
    );
}

#[test]
fn postonly_inserts_only_on_a_post() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert postonly", SERVERS));
    let r = get(fe, &[]);
    assert!(r.set_cookies.is_empty(), "{r:?}");
    let r = req(fe, "POST", &[]);
    assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())]);
}

/// `insert` replaces a cookie of its name that the server set; `preserve` keeps the
/// server's and inserts nothing.
#[test]
fn insert_replaces_the_servers_cookie_and_preserve_keeps_it() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert", SERVERS));
    let r = get(fe, &["X-Want-Set-Cookie: SRV=zzz; path=/x"]);
    assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())], "{r:?}");
    let r = get(fe, &["X-Want-Set-Cookie: other=1"]);
    assert_eq!(r.set_cookies, vec!["other=1".to_string(), format!("SRV={}; path=/", r.srv_cookie())], "{r:?}");
    let r = get(fe, &["Cookie: SRV=b", "X-Want-Set-Cookie: SRV=zzz"]);
    assert_eq!((r.server.as_str(), r.set_cookies.len()), ("s2", 0), "{r:?}");

    let (_ibex, fe) = start(&fe_be("cookie SRV insert preserve", SERVERS));
    let r = get(fe, &["X-Want-Set-Cookie: SRV=zzz; path=/x"]);
    assert_eq!(r.set_cookies, vec!["SRV=zzz; path=/x".to_string()], "{r:?}");
    let r = get(fe, &[]);
    assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())], "{r:?}");
}

/// `rewrite`: the value of the server's own cookie becomes the server's `cookie` value;
/// its attributes stay. Nothing is inserted.
#[test]
fn rewrite_replaces_the_value_the_server_set() {
    let (_ibex, fe) = start(&fe_be("cookie SRV rewrite", SERVERS));
    let r = get(fe, &["X-Want-Set-Cookie: SRV=zzz; path=/x"]);
    assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/x", r.srv_cookie())], "{r:?}");
    let r = get(fe, &[]);
    assert!(r.set_cookies.is_empty(), "{r:?}");
    let r = get(fe, &["Cookie: SRV=b", "X-Want-Set-Cookie: SRV=zzz"]);
    assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", "SRV=b"));
    assert_eq!(r.set_cookies, vec!["SRV=b".to_string()]);
}

/// `prefix`: the server's cookie goes out as `<srv>~<value>`, and comes back to it with
/// the prefix taken off.
#[test]
fn prefix_wraps_the_servers_cookie_and_unwraps_it_on_the_way_back() {
    let (_ibex, fe) = start(&fe_be("cookie JS prefix", SERVERS));
    let r = get(fe, &["X-Want-Set-Cookie: JS=abc; path=/"]);
    assert_eq!(r.set_cookies, vec![format!("JS={}~abc; path=/", r.srv_cookie())], "{r:?}");
    let cases: [(&str, &str); 3] = [("Cookie: JS=b~xyz", "JS=xyz"), ("Cookie: o=1; JS=b~xyz", "o=1; JS=xyz"), ("Cookie: JS=b~", "JS=")];
    for (hdr, seen) in cases {
        let r = get(fe, &[hdr]);
        assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", seen), "{hdr}: {r:?}");
    }
    let r = get(fe, &["Cookie: JS=xyz"]);
    assert_eq!(r.got_cookie, "JS=xyz", "no prefix, nothing taken off: {r:?}");
}

/// No mode: the cookie the server set chooses the server, and nothing is changed.
#[test]
fn a_passive_cookie_is_followed_and_left_alone() {
    let (_ibex, fe) = start(&fe_be("cookie SRV", SERVERS));
    for _ in 0..3 {
        let r = get(fe, &["Cookie: SRV=b"]);
        assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", "SRV=b"));
        assert!(r.set_cookies.is_empty());
    }
    let r = get(fe, &["X-Want-Set-Cookie: SRV=zzz"]);
    assert_eq!(r.set_cookies, vec!["SRV=zzz".to_string()]);
}

/// `indirect` alone: the server's cookie is removed only on a direct access.
#[test]
fn indirect_removes_the_servers_cookie_only_on_a_direct_access() {
    let (_ibex, fe) = start(&fe_be("cookie SRV indirect", SERVERS));
    let r = get(fe, &["Cookie: SRV=b", "X-Want-Set-Cookie: SRV=b"]);
    assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", "SRV=b"));
    assert!(r.set_cookies.is_empty(), "{r:?}");
    let r = get(fe, &["X-Want-Set-Cookie: SRV=a"]);
    assert_eq!(r.set_cookies, vec!["SRV=a".to_string()], "{r:?}");
}

/// A server without a `cookie` value is not chosen by its name, and in `insert` mode its
/// client is told to forget the cookie.
#[test]
fn a_server_is_not_chosen_by_its_name() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert", "  server s1 {s1}\n  server s2 {s2}\n"));
    let mut servers = Vec::new();
    for _ in 0..4 {
        let r = get(fe, &["Cookie: SRV=s2"]);
        assert_eq!(r.got_cookie, "SRV=s2");
        assert_eq!(r.set_cookies, vec![DELETE.to_string()], "{r:?}");
        servers.push(r.server);
    }
    assert!(servers.iter().any(|s| s == "s1"), "the name chose the server: {servers:?}");
}

#[test]
fn a_server_without_a_cookie_value_tells_the_client_to_forget_it() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert", "  server s1 {s1}\n  server s2 {s2} cookie b\n"));
    for _ in 0..4 {
        let r = get(fe, &[]);
        let want = if r.server == "s1" { DELETE.to_string() } else { "SRV=b; path=/".to_string() };
        assert_eq!(r.set_cookies, vec![want], "{r:?}");
    }
}

/// A cookie naming a server that is down: balanced elsewhere, and given a new cookie.
#[test]
fn a_cookie_for_a_down_server_is_balanced_and_replaced() {
    let (_ibex, fe) = start(&fe_be(
        "cookie SRV insert",
        "  server s1 {s1} cookie a\n  server s2 127.0.0.1:1 cookie b check inter 100ms fall 1\n",
    ));
    thread::sleep(Duration::from_millis(1000));
    for _ in 0..2 {
        let r = get(fe, &["Cookie: SRV=b"]);
        assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s1", "SRV=b"), "{r:?}");
        assert_eq!(r.set_cookies, vec!["SRV=a; path=/".to_string()]);
    }
}

/// A cookie can choose a backup server while the active ones are up.
#[test]
fn a_cookie_can_choose_a_backup_server() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert", "  server s1 {s1} cookie a\n  server s2 {s2} cookie b backup\n"));
    for _ in 0..2 {
        let r = get(fe, &["Cookie: SRV=b"]);
        assert_eq!((r.server.as_str(), r.set_cookies.len()), ("s2", 0), "{r:?}");
    }
    let r = get(fe, &[]);
    assert_eq!((r.server.as_str(), r.set_cookies), ("s1", vec!["SRV=a; path=/".to_string()]));
}

// --- where the cookie line comes from ---

/// `HAProxy` warns "'cookie' ignored because frontend 'f' has no backend capability", and
/// runs without it. Ibex refused the configuration.
#[test]
fn a_frontend_cookie_is_ignored_with_a_warning() {
    let cfg = format!("{DEFAULTS}frontend f\n  bind {{fe}}\n  cookie SRV insert\n  default_backend b\nbackend b\n{SERVERS}");
    let (ok, out) = check(&cfg);
    assert!(ok, "{out}");
    assert!(out.contains("'cookie' ignored because frontend 'f' has no backend capability"), "{out}");
    let (_ibex, fe) = start(&cfg);
    let mut servers = Vec::new();
    for _ in 0..3 {
        let r = get(fe, &["Cookie: SRV=b"]);
        assert!(r.set_cookies.is_empty(), "{r:?}");
        servers.push(r.server);
    }
    assert!(servers.iter().any(|s| s == "s1"), "the frontend's cookie chose the server: {servers:?}");
}

/// The last `cookie` line wins, whole: the defaults' is replaced by the backend's, and a
/// second line drops the first's options. Ibex kept the first name it saw.
#[test]
fn the_last_cookie_line_replaces_the_one_before() {
    let dflt = DEFAULTS.replace("mode http\n", "mode http\n  cookie SRV insert\n");
    let (_ibex, fe) = start(&format!("{dflt}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n{SERVERS}"));
    let r = get(fe, &[]);
    assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())], "inherited from defaults: {r:?}");

    let (_ibex, fe) = start(&format!("{dflt}frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  cookie OTHER insert\n{SERVERS}"));
    let r = get(fe, &[]);
    assert_eq!(r.set_cookies, vec![format!("OTHER={}; path=/", r.srv_cookie())], "{r:?}");
    for _ in 0..2 {
        let r = get(fe, &["Cookie: OTHER=b"]);
        assert_eq!((r.server.as_str(), r.set_cookies.len()), ("s2", 0), "{r:?}");
    }

    let (_ibex, fe) = start(&fe_be("cookie A insert\n  cookie B rewrite", SERVERS));
    let r = get(fe, &[]);
    assert!(r.set_cookies.is_empty(), "the first line's insert survived: {r:?}");
    let r = get(fe, &["X-Want-Set-Cookie: B=zz"]);
    assert_eq!(r.set_cookies, vec![format!("B={}", r.srv_cookie())], "{r:?}");
}

#[test]
fn a_listen_section_inserts_and_hides_the_cookie() {
    let (_ibex, fe) = start(&format!("{DEFAULTS}listen l\n  bind {{fe}}\n  cookie SRV insert indirect\n{SERVERS}"));
    let r = get(fe, &[]);
    assert_eq!(r.set_cookies, vec![format!("SRV={}; path=/", r.srv_cookie())], "{r:?}");
    let r = get(fe, &["Cookie: SRV=b; o=1"]);
    assert_eq!((r.server.as_str(), r.got_cookie.as_str(), r.set_cookies.len()), ("s2", "o=1", 0), "{r:?}");
}

// --- maxidle and maxlife ---

/// `maxidle`: the cookie carries the date it was last seen, refreshed while it is in the
/// past, and a cookie idle for longer is not followed.
#[test]
fn maxidle_dates_the_cookie_and_expires_an_idle_one() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert maxidle 1h", SERVERS));
    let r = get(fe, &[]);
    let d = assert_dated(&r.set_cookies[0], r.srv_cookie(), 1);
    assert!(d[0].abs_diff(now()) <= 8, "{r:?}");

    // Seen a minute ago: followed, and its date refreshed.
    let r = get(fe, &[&format!("Cookie: SRV=b|{}", date(now() - 60))]);
    assert_eq!(r.server, "s2");
    let d = assert_dated(&r.set_cookies[0], "b", 1);
    assert!(d[0].abs_diff(now()) <= 8, "{r:?}");

    // Dated where Ibex itself would date it now: followed, nothing to refresh.
    let r = get(fe, &[&format!("Cookie: SRV=b|{}", date(now() + 3))]);
    assert_eq!((r.server.as_str(), r.set_cookies.len()), ("s2", 0), "{r:?}");

    // Idle two hours, or dated two days ahead: not followed.
    for when in [now() - 7200, now() + 2 * 86400] {
        let mut servers = Vec::new();
        for _ in 0..4 {
            let r = get(fe, &[&format!("Cookie: SRV=b|{}", date(when))]);
            assert_dated(&r.set_cookies[0], r.srv_cookie(), 1);
            servers.push(r.server);
        }
        assert!(servers.iter().any(|s| s == "s1"), "an expired cookie was followed: {servers:?}");
    }

    // A date that is not one is ignored: followed, and dated.
    for v in ["b|ab=cd", "b|ab"] {
        let r = get(fe, &[&format!("Cookie: SRV={v}")]);
        assert_eq!(r.server, "s2");
        assert_dated(&r.set_cookies[0], "b", 1);
    }
}

/// `maxlife`: a second date, the cookie's first, kept while the cookie lives.
#[test]
fn maxlife_keeps_the_first_date_and_expires_an_old_cookie() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert maxlife 1h", SERVERS));
    let r = get(fe, &[]);
    let d = assert_dated(&r.set_cookies[0], r.srv_cookie(), 2);
    assert!(d[0].abs_diff(now()) <= 8 && d[1].abs_diff(now()) <= 8, "{r:?}");

    let first = now() - 60;
    let r = get(fe, &[&format!("Cookie: SRV=b|{}|{}", date(first), date(first))]);
    assert_eq!(r.server, "s2");
    let d = assert_dated(&r.set_cookies[0], "b", 2);
    assert!(d[0].abs_diff(now()) <= 8, "{r:?}");
    assert_eq!(d[1], (first >> 2) << 2, "the first date is carried: {r:?}");

    let mut servers = Vec::new();
    for _ in 0..4 {
        let r = get(fe, &[&format!("Cookie: SRV=b|{}|{}", date(now() - 60), date(now() - 7200))]);
        assert_dated(&r.set_cookies[0], r.srv_cookie(), 2);
        servers.push(r.server);
    }
    assert!(servers.iter().any(|s| s == "s1"), "a cookie past its life was followed: {servers:?}");
}

/// Without `maxidle` or `maxlife`, dates are read but not checked, and a cookie that
/// carries a first date is rewritten without one.
#[test]
fn dates_are_dropped_when_nothing_asks_for_them() {
    let (_ibex, fe) = start(&fe_be("cookie SRV insert", SERVERS));
    let r = get(fe, &[&format!("Cookie: SRV=b|{}", date(now() - 7200))]);
    assert_eq!((r.server.as_str(), r.set_cookies), ("s2", vec!["SRV=b; path=/".to_string()]));
    let r = get(fe, &[&format!("Cookie: SRV=b|{0}|{0}", date(now() - 60))]);
    assert_eq!((r.server.as_str(), r.set_cookies), ("s2", vec!["SRV=b; path=/".to_string()]));

    let (_ibex, fe) = start(&fe_be("cookie SRV insert indirect maxidle 1h", SERVERS));
    let r = get(fe, &[&format!("Cookie: SRV=b|{}; o=1", date(now() - 60))]);
    assert_eq!((r.server.as_str(), r.got_cookie.as_str()), ("s2", "o=1"));
    assert_dated(&r.set_cookies[0], "b", 1);

    let (_ibex, fe) = start(&fe_be("cookie SRV", SERVERS));
    let v = format!("SRV=b|{}", date(now() - 7200));
    let r = get(fe, &[&format!("Cookie: {v}")]);
    assert_eq!((r.server.as_str(), r.got_cookie.as_str(), r.set_cookies.len()), ("s2", v.as_str(), 0));
}

// --- the parser ---

#[test]
fn cookie_options_haproxy_refuses_are_refused() {
    let cases = [
        ("cookie S rewrite indirect", "cookie 'rewrite' and 'indirect' modes are incompatible"),
        ("cookie S insert prefix", "cookie 'rewrite', 'insert' and 'prefix' modes are incompatible"),
        ("cookie S rewrite prefix", "cookie 'rewrite', 'insert' and 'prefix' modes are incompatible"),
        ("cookie S preserve", "cookie 'preserve' requires at least 'insert' or 'indirect'"),
        ("cookie", "'cookie' expects <cookie_name> as argument."),
        ("cookie S insert bogus", "'cookie' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache', 'postonly', 'domain', 'maxidle', 'dynamic', 'maxlife' and 'attr' options"),
        ("cookie S insert domain", "'domain' expects <domain> as argument"),
        ("cookie S insert domain a/b.c", "character '/' is not permitted in domain name 'a/b.c'"),
        ("cookie S insert attr a;b", "character '%x3B' is not permitted in attribute value"),
        ("cookie S insert attr", "'attr' expects <value> as argument"),
        ("cookie S insert maxidle", "'maxidle' expects <idletime> in seconds as argument"),
        ("cookie S insert maxidle x", "unexpected character 'x' in argument to <maxidle>"),
        ("cookie S insert maxidle 5x", "unexpected character 'x' in argument to <maxidle>"),
        ("cookie S insert maxlife", "'maxlife' expects <lifetime> in seconds as argument"),
        ("cookie S insert maxlife 100000d", "timer overflow in argument <100000d> to <maxlife>, maximum value is 2147483647 s (~68 years)"),
        // HAProxy accepts this; Ibex has no dynamic cookies (AGENTS.md section 5).
        ("cookie S insert dynamic", "'cookie ... dynamic' is not implemented"),
    ];
    for (line, msg) in cases {
        let (ok, out) = check(&fe_be(line, SERVERS));
        assert!(!ok, "{line}: accepted:\n{out}");
        assert!(out.contains(msg), "{line}: wanted {msg:?}, got:\n{out}");
    }
}

#[test]
fn a_domain_without_a_dot_is_accepted_with_haproxys_warning() {
    let (ok, out) = check(&fe_be("cookie S insert domain localhost", SERVERS));
    assert!(ok, "{out}");
    assert!(out.contains("domain 'localhost' contains no embedded dot, this configuration may not work properly (see RFC6265#5.2.3)"), "{out}");
}

// --- the cookie characters of the termination state ---

/// `%tsc`'s last two characters (`sess_cookie`, `sess_set_cookie`, `src/log.c`): what the
/// client's cookie was, and what became of the persistence cookie in the response. Only a
/// backend with `rewrite`, `insert`, `prefix` or `indirect` shows them. Measured on
/// `HAProxy 3.5-dev8-885761-29`, 2026-10-03: servers `s1` (cookie `a`), `s2` (cookie `b`)
/// and `s3` (none), `balance first`, `log-format "tsc=%tsc"`.
#[test]
fn the_log_shows_what_became_of_the_cookie() {
    let now_b64: String = date(now()).to_string();
    let cases: Vec<(&str, Vec<String>, &str)> = vec![
        ("cookie SRV insert", vec![], "NI"),
        ("cookie SRV insert", vec!["Cookie: SRV=b".into()], "VN"),
        ("cookie SRV insert", vec!["Cookie: SRV=zz".into()], "II"),
        ("cookie SRV insert indirect", vec!["Cookie: SRV=b".into(), "X-Want-Set-Cookie: SRV=x".into()], "VD"),
        ("cookie SRV indirect", vec!["Cookie: SRV=b".into(), "X-Want-Set-Cookie: SRV=x".into()], "VD"),
        ("cookie SRV rewrite", vec!["X-Want-Set-Cookie: SRV=x".into()], "NR"),
        ("cookie SRV prefix", vec!["X-Want-Set-Cookie: SRV=x".into()], "NR"),
        ("cookie SRV insert preserve", vec!["X-Want-Set-Cookie: SRV=x".into()], "NP"),
        ("cookie SRV insert maxidle 1h", vec!["Cookie: SRV=b|AAAAB".into()], "EI"),
        ("cookie SRV insert maxlife 1h", vec!["Cookie: SRV=b|AAAAB|AAAAB".into()], "OI"),
        ("cookie SRV insert maxidle 1h", vec![format!("Cookie: SRV=b|{now_b64}")], "VU"),
        ("cookie SRV insert", vec!["Cookie: SRV=c".into()], "II"),
        ("cookie SRV insert postonly", vec![], "NN"),
        ("cookie SRV insert", vec!["Cookie: SRV=a".into(), "Cookie: SRV=b".into()], "VN"),
        ("cookie SRV insert", vec!["Cookie: SRV=zz; SRV=b".into()], "VN"),
        ("cookie SRV insert", vec!["Cookie: SRV=b; SRV=zz".into()], "VN"),
        // Neither passive, `nocache` nor `postonly` alone is a cookie mode.
        ("cookie SRV", vec!["X-Want-Set-Cookie: SRV=x".into()], "--"),
        ("cookie SRV nocache", vec![], "--"),
    ];
    for (line, hdrs, want) in cases {
        let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
        collector.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        let log = collector.local_addr().expect("addr");
        let cfg = format!(
            "{DEFAULTS}frontend f\n  bind {{fe}}\n  log {log} local0\n  log-format \"/%HU tsc=%tsc\"\n  default_backend b\n\
             backend b\n  balance first\n  {line}\n  server s1 {{s1}} cookie a\n  server s2 {{s2}} cookie b\n  server s3 {{s3}}\n"
        );
        let (_ibex, fe) = start(&cfg);
        let hdrs: Vec<&str> = hdrs.iter().map(String::as_str).collect();
        let _ = get(fe, &hdrs);
        // The probe that waited for the listener is logged too: take the request's own line.
        let mut got = String::new();
        let mut buf = [0u8; 2048];
        while let Ok(n) = collector.recv(&mut buf) {
            got = String::from_utf8_lossy(&buf[..n]).into_owned();
            if got.contains("/ tsc=") {
                break;
            }
        }
        let tsc = got.rsplit("tsc=").next().unwrap_or_default().trim();
        assert_eq!(&tsc[tsc.len().saturating_sub(2)..], want, "{line} {hdrs:?}: {got}");
    }
}
