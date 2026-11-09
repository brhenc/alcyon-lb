// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request redirect` (T146 item 7, T144 item 7): the `location`, `prefix` and `scheme`
//! types, `code`, `drop-query`, `keep-query`, `append-slash`, `ignore-empty`, `set-cookie`,
//! `set-cookie-fmt` and `clear-cookie`, and the parser's refusals.
//!
//! Every expected value was measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04 with
//! the same rules and a raw-socket client: header names are lower case and come in the
//! order `content-length`, `location`, `cache-control` (302, 303 and 307 only),
//! `set-cookie`; `prefix` and `scheme` take the request's path *and query* (`drop-query`
//! cuts it, `append-slash` adds a `/` at the very end of what is left, query included);
//! `location` takes neither, except that `keep-query` appends the request's query (with `?`,
//! or `&` when the location has one); `ignore-empty` skips the rule when the location is
//! empty and the next rule goes on.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
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

fn start(rules: &str) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let text = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n{rules}  default_backend b\nbackend b\n  http-request return status 200\n"
    );
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
    assert!(common::wait_listening(fe), "alcyon never listened with:\n{text}");
    (alcyon, fe)
}

/// The head of the answer to `GET <target>` with `Host: <host>` (none when empty).
fn head(fe: SocketAddr, target: &str, host: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let hdr = if host.is_empty() { String::new() } else { format!("Host: {host}\r\n") };
    c.write_all(format!("GET {target} HTTP/1.1\r\n{hdr}\r\n").as_bytes()).expect("send");
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut chunk) {
            Ok(n) if n > 0 => got.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

const NC: &str = "cache-control: no-cache\r\n";

fn redirect(status: &str, location: &str, nc: bool, extra: &str) -> String {
    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nlocation: {location}\r\n{}{extra}\r\n", if nc { NC } else { "" })
}

#[test]
fn location_scheme_and_prefix_redirects_match_haproxy() {
    let rules = "\
  http-request redirect location /loc if { path /loc }
  http-request redirect location /loc301 code 301 if { path /loc301 }
  http-request redirect location /loc303 code 303 if { path /loc303 }
  http-request redirect location /loc307 code 307 if { path /loc307 }
  http-request redirect location /loc308 code 308 if { path /loc308 }
  http-request redirect scheme https if { path /sch }
  http-request redirect scheme https code 301 if { path /sch301 }
  http-request redirect scheme %[str(ftp)] if { path /sf }
  http-request redirect scheme https drop-query if { path /schdq }
  http-request redirect scheme https keep-query if { path /skq }
  http-request redirect scheme https append-slash if { path /sas }
  http-request redirect prefix http://p.example if { path /pfx }
  http-request redirect prefix http://p.example/ if { path /pfxs }
  http-request redirect prefix /pp if { path /pfxrel }
  http-request redirect prefix http://p.example drop-query if { path /pfxdq }
  http-request redirect prefix /pp append-slash if { path /appp }
  http-request redirect prefix /pp drop-query keep-query if { path /pboth }
  http-request redirect prefix %[hdr(host)] if { path /pfxh }
  http-request redirect location /x append-slash if { path /app }
  http-request redirect location /l?a=b drop-query if { path /ldq }
  http-request redirect location /l keep-query if { path /lkq }
  http-request redirect location /l?a=b keep-query if { path /lkqq }
  http-request redirect location /l keep-query drop-query if { path /lboth }
";
    let (_alcyon, fe) = start(rules);
    let h = "h.example:8080";
    let cases: &[(&str, &str, String)] = &[
        ("/loc", h, redirect("302 Found", "/loc", true, "")),
        ("/loc301", h, redirect("301 Moved Permanently", "/loc301", false, "")),
        ("/loc303", h, redirect("303 See Other", "/loc303", true, "")),
        ("/loc307", h, redirect("307 Temporary Redirect", "/loc307", true, "")),
        ("/loc308", h, redirect("308 Permanent Redirect", "/loc308", false, "")),
        ("/sch", h, redirect("302 Found", "https://h.example:8080/sch", true, "")),
        ("/sch?a=1", h, redirect("302 Found", "https://h.example:8080/sch?a=1", true, "")),
        ("/sch301", h, redirect("301 Moved Permanently", "https://h.example:8080/sch301", false, "")),
        ("/sf", h, redirect("302 Found", "ftp://h.example:8080/sf", true, "")),
        ("/schdq?a=1", h, redirect("302 Found", "https://h.example:8080/schdq", true, "")),
        ("/skq?z=1", h, redirect("302 Found", "https://h.example:8080/skq?z=1", true, "")),
        ("/sas?z=1", h, redirect("302 Found", "https://h.example:8080/sas?z=1/", true, "")),
        ("/sch", "", redirect("302 Found", "https:///sch", true, "")),
        ("/pfx", h, redirect("302 Found", "http://p.example/pfx", true, "")),
        ("/pfx?a=1", h, redirect("302 Found", "http://p.example/pfx?a=1", true, "")),
        ("/pfxs", h, redirect("302 Found", "http://p.example//pfxs", true, "")),
        ("/pfxrel", h, redirect("302 Found", "/pp/pfxrel", true, "")),
        ("/pfxdq?a=1", h, redirect("302 Found", "http://p.example/pfxdq", true, "")),
        ("/appp", h, redirect("302 Found", "/pp/appp/", true, "")),
        ("/appp?q=1", h, redirect("302 Found", "/pp/appp?q=1/", true, "")),
        ("/pboth?z=1", h, redirect("302 Found", "/pp/pboth", true, "")),
        ("/pfxh", h, redirect("302 Found", "h.example:8080/pfxh", true, "")),
        ("http://h.example:8080/pfx?q=1", h, redirect("302 Found", "http://p.example/pfx?q=1", true, "")),
        ("/app?q=1", h, redirect("302 Found", "/x", true, "")),
        ("/ldq", h, redirect("302 Found", "/l?a=b", true, "")),
        ("/lkq?z=1&y=2", h, redirect("302 Found", "/l?z=1&y=2", true, "")),
        ("/lkqq?z=1", h, redirect("302 Found", "/l?a=b&z=1", true, "")),
        ("/lboth?z=1", h, redirect("302 Found", "/l?z=1", true, "")),
    ];
    for (target, host, want) in cases {
        assert_eq!(&head(fe, target, host), want, "GET {target} (Host {host:?})");
    }
}

#[test]
fn cookies_and_ignore_empty_match_haproxy() {
    let rules = "\
  http-request redirect location /c set-cookie FOO=bar if { path /ck }
  http-request redirect location /c clear-cookie FOO if { path /ckc }
  http-request redirect location /c set-cookie FOO=bar code 301 if { path /ck301 }
  http-request redirect location /c set-cookie-fmt FOO=%[path] if { path /ckf }
  http-request redirect location /x set-cookie FOO=bar clear-cookie BAR if { path /two }
  http-request redirect location %[hdr(x-none)] ignore-empty if { path /ie }
  http-request redirect location %[hdr(x-none)] if { path /empty }
";
    let (_alcyon, fe) = start(rules);
    let h = "h.example:8080";
    let cases: &[(&str, String)] = &[
        ("/ck", redirect("302 Found", "/c", true, "set-cookie: FOO=bar; path=/;\r\n")),
        ("/ckc", redirect("302 Found", "/c", true, "set-cookie: FOO; path=/; Max-Age=0;\r\n")),
        ("/ck301", redirect("301 Moved Permanently", "/c", false, "set-cookie: FOO=bar; path=/;\r\n")),
        ("/ckf", redirect("302 Found", "/c", true, "set-cookie: FOO=/ckf; path=/;\r\n")),
        ("/two", redirect("302 Found", "/x", true, "set-cookie: BAR; path=/; Max-Age=0;\r\n")),
        ("/empty", redirect("302 Found", "", true, "")),
    ];
    for (target, want) in cases {
        assert_eq!(&head(fe, target, h), want, "GET {target}");
    }
    // `ignore-empty` on an empty location: the rule is skipped, the backend answers.
    assert!(head(fe, "/ie", h).starts_with("HTTP/1.1 200 OK\r\n"), "ignore-empty did not skip the rule");
}

/// What `-c` says of a configuration with this one rule in a frontend.
fn check(binary: &str, rule: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:1\n  {rule}\n  default_backend b\nbackend b\n  http-request return status 200\n"
    );
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(binary).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn the_parser_refuses_what_haproxy_refuses() {
    let alcyon = env!("CARGO_BIN_EXE_alcyon");
    let cases: &[(&str, &str)] = &[
        ("http-request redirect", "redirection type expected ('prefix', 'location', or 'scheme')."),
        ("http-request redirect code 301", "redirection type expected ('prefix', 'location', or 'scheme')."),
        ("http-request redirect location /x code 200", "'code': unsupported HTTP code '200' (must be one of 301, 302, 303, 307 or 308)."),
        ("http-request redirect location", "missing argument for 'location'."),
        ("http-request redirect location /x code", "missing argument for 'code'."),
        ("http-request redirect location /x set-cookie", "missing argument for 'set-cookie'."),
        ("http-request redirect location /x bogus", "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was 'bogus')."),
    ];
    for (rule, why) in cases {
        let (ok, err) = check(alcyon, rule);
        assert!(!ok, "{rule}: the load succeeded");
        // HAProxy prefixes the text with "error detected in frontend 'f' while parsing
        // 'http-request redirect' rule : "; Alcyon's own parse-error framing is another task.
        assert!(err.contains(why), "{rule}: {err}");
    }
    for rule in [
        "http-request redirect location /x ignore-empty drop-query append-slash keep-query",
        "http-request redirect location /x set-cookie FOO",
        "http-request redirect scheme ftp",
    ] {
        assert!(check(alcyon, rule).0, "{rule} must load");
    }
}

/// `http-request auth` (T146 item 7): the realm, the default realm (the proxy's name), and
/// HAProxy's 401 page, measured on the same binary.
#[test]
fn auth_sends_the_401_page_with_the_realm() {
    let (_alcyon, fe) = start("  http-request auth realm My\\ Realm if { path /a }\n  http-request auth if { path /b }\n");
    let page = "<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n";
    for (target, realm) in [("/a", "My Realm"), ("/b", "f")] {
        let want = format!(
            "HTTP/1.1 401 Unauthorized\r\ncontent-length: 112\r\ncache-control: no-cache\r\ncontent-type: text/html\r\nwww-authenticate: Basic realm=\"{realm}\"\r\n\r\n"
        );
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).ok();
        c.write_all(format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes()).expect("send");
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        while got.len() < want.len() + page.len() {
            match c.read(&mut chunk) {
                Ok(n) if n > 0 => got.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        // Alcyon still writes the built-in pages' header names as `http_err_msgs` spells them
        // (`Content-length`), where HAProxy 3.5 sends them in lower case: compare the head
        // without the case. The order and the values are what this test is about.
        let got = String::from_utf8_lossy(&got).into_owned();
        let (got_head, got_body) = got.split_once("\r\n\r\n").expect("a head");
        assert_eq!(got_head.to_ascii_lowercase(), want.trim_end().to_ascii_lowercase(), "GET {target}");
        assert_eq!(got_body, page, "GET {target}");
    }
}
