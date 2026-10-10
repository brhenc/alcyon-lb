// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `errorfile` against the real binary, with what `HAProxy` 3.5 sends for the same
//! configuration.
//!
//! The reg-tests in `reg-tests/http-errorfiles` reach error pages through `http-request
//! deny`/`return`. The page an operator most often customises is the 503 the proxy sends
//! itself when no server can take the request; `HAProxy` looks for it in the backend's
//! pages, then the frontend's (`http_error_message`, `src/http_ana.c`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfgs: Vec<NamedTempFile>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        stop(&mut self.child);
    }
}

/// Stops the binary the way it exits cleanly -- `SIGUSR1`, the soft stop -- so an
/// instrumented build writes its coverage profile; `SIGKILL` discards it, which left every
/// line these tests run invisible to `harness/covercheck.py`. Killed if it lingers.
fn stop(child: &mut Child) {
    let _ = Command::new("kill").arg("-USR1").arg(child.id().to_string()).status();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn page(raw: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(raw.as_bytes()).expect("write page");
    f
}

/// Starts ibex on `cfg`, where `{fe}` is the listening address and `{0}`, `{1}`, ... are the
/// paths of `pages`.
fn start(cfg: &str, pages: Vec<NamedTempFile>) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string());
    for (i, p) in pages.iter().enumerate() {
        text = text.replace(&format!("{{{i}}}"), &p.path().display().to_string());
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
    let mut files = pages;
    files.push(f);
    let ibex = Ibex { child, _cfgs: files };
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    (ibex, fe)
}

/// Sends `GET path` on `c` and reads until `quiet` passes with nothing arriving, the peer
/// closes, or two seconds pass. The bool is whether the peer closed.
fn get(c: &mut TcpStream, path: &str, quiet: Duration) -> (String, bool) {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
    c.set_read_timeout(Some(quiet)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    let mut closed = false;
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&resp).into_owned(), closed)
}

const DEFAULTS: &str =
    "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n";

/// `HAProxy`: `x-page: custom503` for `/own`, `x-page: fe` for `/bare`.
#[test]
fn the_proxys_own_503_uses_the_backends_errorfile_then_the_frontends() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  errorfile 503 {{0}}\n\
             \x20 use_backend own if {{ path /own }}\n  default_backend bare\n\
             backend own\n  errorfile 503 {{1}}\nbackend bare\n"
        ),
        vec![
            page("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\nX-Page: fe\r\n\r\nfe\n"),
            page("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 6\r\nX-Page: custom503\r\n\r\nsorry\n"),
        ],
    );
    for (path, want) in [("/own", "x-page: custom503"), ("/bare", "x-page: fe")] {
        let mut c = TcpStream::connect(fe).expect("connect");
        let (resp, _) = get(&mut c, path, Duration::from_millis(300));
        assert!(resp.starts_with("HTTP/1.1 503"), "{path}: {resp:?}");
        assert!(resp.contains(want), "{path}: wanted {want}: {resp:?}");
    }
}

/// `http-request return ... errorfile` answers and keeps the connection, like `return` with
/// an inline body: `HAProxy` answered three requests in a row on one connection.
#[test]
fn return_with_an_errorfile_keeps_the_connection() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  http-request return status 200 errorfile {{0}}\n\
             \x20 default_backend be\nbackend be\n"
        ),
        vec![page("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Page: ret200\r\n\r\nhi\n")],
    );
    let mut c = TcpStream::connect(fe).expect("connect");
    for i in 0..3 {
        let (resp, closed) = get(&mut c, &format!("/{i}"), Duration::from_millis(300));
        assert_eq!(resp.matches("x-page: ret200").count(), 1, "request {i}: {resp:?}");
        assert!(!closed, "request {i} closed the connection: {resp:?}");
    }
}

// ---- which proxy's page, and which declaration wins ---------------------------------
//
// Every expectation below is what `HAProxy` 3.5 (`/home/bhenc/reference/haproxy/haproxy`)
// sent for the same configuration. Its header names are lower case (HTX); Ibex keeps the
// case it was given, so responses are compared lower-cased.

/// One request on a fresh connection; the response lower-cased.
fn fetch(fe: SocketAddr, path: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    get(&mut c, path, Duration::from_millis(300)).0.to_ascii_lowercase()
}

fn assert_page(fe: SocketAddr, path: &str, status: &str, wants: &[&str]) {
    let resp = fetch(fe, path);
    assert!(resp.starts_with(&format!("http/1.1 {status}")), "{path}: {resp:?}");
    for want in wants {
        assert!(resp.contains(want), "{path}: wanted {want:?} in {resp:?}");
    }
}

fn raw_page(status: &str, tag: &str) -> NamedTempFile {
    page(&format!("HTTP/1.1 {status}\r\nContent-Length: 4\r\nX-Page: {tag}\r\n\r\nbody"))
}

/// A `deny` evaluated in a backend answers with the backend's page, then the frontend's,
/// as `http_error_message` picks them (`s->be`, then `strm_fe(s)`). Ibex took the
/// frontend's page for every rule, so a backend's own `errorfile 403` or `http-error
/// status 403` was parsed and never sent by a `deny`.
///
/// `HAProxy`: `/fe/deny` and `/plain/deny` get the frontend's file, `/befile/deny` the
/// backend's file, `/behe/deny` `denied /behe/deny` as text/plain, `/beherr/deny` the
/// file its `http-error ... errorfile` names.
#[test]
fn a_deny_in_a_backend_uses_the_backends_page_then_the_frontends() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n  errorfile 403 {{0}}\n\
             \x20 http-request deny if {{ path /fe/deny }}\n\
             \x20 use_backend befile if {{ path_beg /befile }}\n\
             \x20 use_backend behe if {{ path_beg /behe/ }}\n\
             \x20 use_backend beherr if {{ path_beg /beherr }}\n\
             \x20 default_backend plain\n\
             backend plain\n  http-request deny if {{ path /plain/deny }}\n\
             backend befile\n  errorfile 403 {{1}}\n  http-request deny if {{ path /befile/deny }}\n\
             backend behe\n  http-error status 403 content-type text/plain lf-string \"denied %[path]\"\n\
             \x20 http-request deny if {{ path /behe/deny }}\n\
             backend beherr\n  http-error status 403 errorfile {{2}}\n  http-request deny\n"
        ),
        vec![raw_page("403 Forbidden", "fe403"), raw_page("403 Forbidden", "be403"), raw_page("403 Forbidden", "he403")],
    );
    assert_page(fe, "/fe/deny", "403", &["x-page: fe403"]);
    assert_page(fe, "/plain/deny", "403", &["x-page: fe403"]);
    assert_page(fe, "/befile/deny", "403", &["x-page: be403"]);
    assert_page(fe, "/behe/deny", "403", &["content-type: text/plain", "\r\n\r\ndenied /behe/deny"]);
    assert_page(fe, "/beherr/deny", "403", &["x-page: he403"]);
}


/// `http-errors <name>` declares pages; `errorfiles <name> [<code>...]` imports all or
/// some of them; `deny ... errorfiles <name>` answers with one.
///
/// `HAProxy`: `/all` gets the section's 503; `/only403` the built-in 503 (only 403 was
/// imported); `/only403/deny` the section's 403; `/rule/deny` the section's 403.
#[test]
fn errorfiles_imports_an_http_errors_section() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}http-errors site\n  errorfile 503 {{0}}\n  errorfile 403 {{1}}\n\
             frontend fe\n  bind {{fe}}\n\
             \x20 use_backend only403 if {{ path_beg /only403 }}\n\
             \x20 use_backend rule if {{ path_beg /rule }}\n\
             \x20 default_backend all\n\
             backend all\n  errorfiles site\n\
             backend only403\n  errorfiles site 403\n  http-request deny if {{ path /only403/deny }}\n\
             backend rule\n  http-request deny deny_status 403 errorfiles site\n"
        ),
        vec![raw_page("503 Service Unavailable", "sec503"), raw_page("403 Forbidden", "sec403")],
    );
    assert_page(fe, "/all", "503", &["x-page: sec503"]);
    assert_page(fe, "/only403", "503", &["no server is available to handle this request"]);
    assert_page(fe, "/only403/deny", "403", &["x-page: sec403"]);
    assert_page(fe, "/rule/deny", "403", &["x-page: sec403"]);
}

/// `http-error status <code>` replaces the page the proxy sends itself for `<code>`,
/// from an inline template (headers are log-formats) or from an `errorfile`.
///
/// `HAProxy`: `/custom` -> 503 `x-foo: bar`, `x-path: /custom`, text/plain `custom503`;
/// `/raw` -> the file's 503.
#[test]
fn http_error_replaces_the_proxys_own_page() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n\
             \x20 use_backend custom if {{ path_beg /custom }}\n  default_backend raw\n\
             backend custom\n  http-error status 503 content-type text/plain string \"custom503\" \
             hdr X-Foo bar hdr X-Path \"%[path]\"\n\
             backend raw\n  http-error status 503 errorfile {{0}}\n"
        ),
        vec![raw_page("503 Service Unavailable", "he503")],
    );
    assert_page(
        fe,
        "/custom",
        "503",
        &["x-foo: bar\r\n", "x-path: /custom\r\n", "content-type: text/plain", "content-length: 9\r\n", "\r\n\r\ncustom503"],
    );
    assert_page(fe, "/raw", "503", &["x-page: he503"]);
}

/// `errorfile`, `errorfiles` and `http-error` fill one table per proxy, and for a code
/// the last declaration wins; `http-error ... default-errorfiles` clears the code (the
/// frontend's page, else the built-in one, answers).
///
/// `HAProxy`: `/r2` built-in 403 (the earlier `errorfile` is cleared too); `/r3` the
/// file (declared after the reset); `/r4` the `http-error` string (declared after the
/// file); `/r5` the file (declared after the `http-error`).
#[test]
fn for_one_code_the_last_error_page_declaration_wins() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n\
             \x20 use_backend r3 if {{ path_beg /r3 }}\n  use_backend r4 if {{ path_beg /r4 }}\n\
             \x20 use_backend r5 if {{ path_beg /r5 }}\n  default_backend r2\n\
             backend r2\n  errorfile 403 {{0}}\n\
             \x20 http-error status 403 content-type text/plain string \"overridden\"\n\
             \x20 http-error status 403 default-errorfiles\n  http-request deny\n\
             backend r3\n  http-error status 403 default-errorfiles\n  errorfile 403 {{0}}\n  http-request deny\n\
             backend r4\n  errorfile 403 {{0}}\n  http-error status 403 content-type text/plain string \"he\"\n\
             \x20 http-request deny\n\
             backend r5\n  http-error status 403 content-type text/plain string \"he\"\n  errorfile 403 {{0}}\n\
             \x20 http-request deny\n"
        ),
        vec![raw_page("403 Forbidden", "file403")],
    );
    assert_page(fe, "/r2", "403", &["request forbidden by administrative rules"]);
    assert_page(fe, "/r3", "403", &["x-page: file403"]);
    assert_page(fe, "/r4", "403", &["\r\n\r\nhe"]);
    assert_page(fe, "/r5", "403", &["x-page: file403"]);
}

/// A section that has no page for the status is accepted (`HAProxy` warns): `deny ...
/// errorfiles <name>` then answers with an empty reply, and `http-error ... errorfiles
/// <name>` changes nothing. Ibex refused the configuration.
///
/// `HAProxy`: `/a` -> `HTTP/1.1 403 Forbidden`, `content-length: 0`, no body; `/b` -> the
/// backend's earlier `errorfile 429`.
#[test]
fn a_section_without_the_status_is_an_empty_reply_or_no_change() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}http-errors site\n  errorfile 503 {{0}}\n\
             frontend fe\n  bind {{fe}}\n  default_backend be\n\
             backend be\n  http-request deny deny_status 403 errorfiles site if {{ path /a }}\n\
             \x20 errorfile 429 {{1}}\n  http-error status 429 errorfiles site\n\
             \x20 http-request deny deny_status 429 if {{ path /b }}\n"
        ),
        vec![raw_page("503 Service Unavailable", "sec503"), raw_page("429 Too Many Requests", "be429")],
    );
    let a = fetch(fe, "/a");
    assert!(a.starts_with("http/1.1 403 forbidden\r\n"), "{a:?}");
    assert!(a.contains("content-length: 0\r\n") && a.ends_with("\r\n\r\n"), "{a:?}");
    assert_page(fe, "/b", "429", &["x-page: be429"]);
}

/// `deny` and `return` with `hdr` (a log-format; an empty value drops the header),
/// `string`, `file` and `lf-file`.
///
/// `HAProxy`: `/hdrs` -> 429 `x-a: a-/hdrs`, no `x-empty`, text/plain `slow down`;
/// `/file` -> `from file\n`; `/lf` -> `path=/lf\n`.
#[test]
fn deny_and_return_bodies_from_hdr_string_file_and_lf_file() {
    let (_ibex, fe) = start(
        &format!(
            "{DEFAULTS}frontend fe\n  bind {{fe}}\n\
             \x20 http-request return status 200 content-type text/plain file {{0}} if {{ path /file }}\n\
             \x20 http-request return status 200 content-type text/plain lf-file {{1}} if {{ path /lf }}\n\
             \x20 http-request deny deny_status 429 content-type text/plain hdr X-A \"a-%[path]\" \
             hdr X-Empty \"%[req.hdr(nope)]\" string \"slow down\"\n"
        ),
        vec![page("from file\n"), page("path=%[path]\n")],
    );
    assert_page(fe, "/hdrs", "429", &["x-a: a-/hdrs\r\n", "content-type: text/plain", "\r\n\r\nslow down"]);
    assert!(!fetch(fe, "/hdrs").contains("x-empty"), "an empty hdr value is dropped");
    assert_page(fe, "/file", "200", &["content-length: 10\r\n", "\r\n\r\nfrom file\n"]);
    assert_page(fe, "/lf", "200", &["content-length: 9\r\n", "\r\n\r\npath=/lf\n"]);
}
