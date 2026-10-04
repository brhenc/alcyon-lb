// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `http-request` actions that answer or rewrite the request -- `deny`, `tarpit`,
//! `return`, `set-header`, `replace-header`, `replace-value` -- the way
//! `response_rule_actions.rs` does for `http-response`, and what a rewrite does when the
//! request has no room left.
//!
//! Every expected value below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-04, with a raw-socket client and a server that
//! answers with the request head it received as the body ([`echo_server`]). `HAProxy`
//! lower-cases header names on the way out and Ibex keeps the case it was given, so the
//! tests compare names case-insensitively.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const G: &str = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Starts ibex on `cfg`, `{fe}` replaced by the listening address and `{srv}` by `srv`.
fn start(cfg: &str, srv: Option<SocketAddr>) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string());
    if let Some(s) = srv {
        text = text.replace("{srv}", &s.to_string());
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
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

/// A server answering the first request on a connection with its own request head as the
/// body (`Content-Length` set), then reading and dropping whatever else the client sends.
fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                let mut answered = false;
                loop {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                    if answered {
                        continue;
                    }
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let req = buf[..end].to_vec();
                        let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", req.len()).into_bytes();
                        resp.extend_from_slice(&req);
                        if c.write_all(&resp).is_err() {
                            return;
                        }
                        answered = true;
                    }
                }
            });
        }
    });
    addr
}


/// Sends each of `reqs` in turn on one connection and returns each response: its head and
/// as much body as its `Content-Length` says, or what came until the peer closed or a
/// second passed with nothing arriving.
fn exchange(fe: SocketAddr, reqs: &[&str]) -> Vec<String> {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(1))).expect("timeout");
    let mut out = Vec::new();
    for req in reqs {
        c.write_all(req.as_bytes()).expect("send");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        let mut buf = [0u8; 65536];
        while Instant::now() < deadline {
            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                let len = head
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok());
                if len.is_some_and(|l| got.len() >= end + 4 + l) {
                    break;
                }
            }
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        out.push(String::from_utf8_lossy(&got).into_owned());
    }
    out
}

fn one(fe: SocketAddr, req: &str) -> String {
    exchange(fe, &[req]).remove(0)
}

fn head(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map_or(resp, |(h, _)| h)
}

/// The header lines of `resp`, name lower-cased, in order, as `name: value`.
fn header_lines(resp: &str) -> Vec<String> {
    head(resp)
        .split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':').map(|(k, v)| format!("{}: {}", k.trim().to_ascii_lowercase(), v.trim())))
        .collect()
}

/// The header lines named `name` (any case), as `name: value` with `name` lower-cased.
fn lines_named(resp: &str, name: &str) -> Vec<String> {
    let want = format!("{}:", name.to_ascii_lowercase());
    header_lines(resp).into_iter().filter(|l| l.starts_with(&want)).collect()
}

/// A `GET /` carrying an `x` header of `n` bytes, then `more` (header lines, `\r\n` ended).
fn req(n: usize, more: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: x\r\nx: {}\r\n{more}\r\n", "A".repeat(n))
}

/// The header lines the server received, from its echo: `name: value`, name lower-cased.
fn seen(resp: &str) -> Vec<String> {
    let body = resp.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    body.split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':').map(|(k, v)| format!("{}: {}", k.trim().to_ascii_lowercase(), v.trim())))
        .collect()
}

fn status_line(resp: &str) -> &str {
    resp.split("\r\n").next().unwrap_or("")
}

/// The names (of `names`) the server received, sorted.
fn received<'a>(resp: &str, names: &[&'a str]) -> Vec<&'a str> {
    let got = seen(resp);
    let mut out: Vec<&str> = names.iter().copied().filter(|n| got.iter().any(|l| l.starts_with(&format!("{n}:")))).collect();
    out.sort_unstable();
    out
}

/// `http-request deny` with `status` sends the status line and `content-length: 0` and
/// nothing else; `deny_status` (alone, or bare `deny`) sends the proxy's page for the
/// status. The same for `tarpit` once its timeout has passed. Measured:
///
/// ```text
/// deny                    HTTP/1.1 403 Forbidden            content-length: 93 (the page)
/// deny status 403         HTTP/1.1 403 Forbidden            content-length: 0
/// deny status 418         HTTP/1.1 418 I'm a teapot         content-length: 0
/// deny status 200         HTTP/1.1 200 OK                   content-length: 0
/// deny status 599         HTTP/1.1 599 Server Error         content-length: 0
/// deny deny_status 404    HTTP/1.1 404 Not Found            content-length: 83 (the page)
/// tarpit status 418       HTTP/1.1 418 I'm a teapot         content-length: 0
/// return status 418       HTTP/1.1 418 I'm a teapot         content-length: 0
/// ```
///
/// Ibex sent the 403 page for `deny status 403`.
#[test]
fn http_request_deny_status_sends_an_empty_reply() {
    let cases = [
        ("deny", "HTTP/1.1 403 Forbidden", "content-length: 93"),
        ("deny status 403", "HTTP/1.1 403 Forbidden", "content-length: 0"),
        ("deny status 418", "HTTP/1.1 418 I'm a teapot", "content-length: 0"),
        ("deny status 200", "HTTP/1.1 200 OK", "content-length: 0"),
        ("deny status 599", "HTTP/1.1 599 Server Error", "content-length: 0"),
        ("deny deny_status 404", "HTTP/1.1 404 Not Found", "content-length: 83"),
        ("tarpit status 418", "HTTP/1.1 418 I'm a teapot", "content-length: 0"),
        ("return status 418", "HTTP/1.1 418 I'm a teapot", "content-length: 0"),
    ];
    for (rule, line, len) in cases {
        let cfg = format!("{DEFAULTS}listen l\n  bind {{fe}}\n  timeout tarpit 100ms\n  http-request {rule}\n");
        let (_ibex, fe) = start(&cfg, None);
        let resp = one(fe, G);
        assert_eq!(status_line(&resp), line, "{rule}: {resp:?}");
        assert_eq!(lines_named(&resp, "content-length"), [len], "{rule}: {resp:?}");
        if len.ends_with(" 0") {
            assert!(resp.ends_with("\r\n\r\n"), "{rule}: a body was sent: {resp:?}");
        }
    }
}

/// What `HAProxy` refuses at load. Measured with `haproxy -c`:
///
/// ```text
/// http-request deny deny_status 418       status code '418' not handled by default with 'default-errorfiles' argument.
/// http-request tarpit deny_status 418     (the same)
/// http-request deny status 600            Unexpected status code '600'.
/// http-request deny status 199            Unexpected status code '199'.
/// http-request tarpit status 600          Unexpected status code '600'.
/// http-request replace-header x '(' y     regex '(' is invalid (error=missing closing parenthesis, erroffset=1).
/// http-request replace-value x '(' y      (the same)
/// ```
///
/// and accepts `deny status 418`. `deny status 403 deny_status 404` is refused too
/// (`deny_status` is only the first argument). Ibex loaded the two regexes, where the rule
/// would then have done nothing.
#[test]
fn request_rules_haproxy_refuses_are_refused() {
    let cfg = |rule: &str| format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  {rule}\n");
    for (rule, says) in [
        ("http-request deny deny_status 418", "status code '418' not handled by default"),
        ("http-request tarpit deny_status 418", "status code '418' not handled by default"),
        ("http-request deny status 600", "Unexpected status code '600'"),
        ("http-request deny status 199", "Unexpected status code '199'"),
        ("http-request tarpit status 600", "Unexpected status code '600'"),
        ("http-request deny status 403 deny_status 404", "deny_status"),
        ("http-request replace-header x '(' y", "bad regular expression"),
        ("http-request replace-value x '(' y", "bad regular expression"),
    ] {
        let (ok, text) = check(&cfg(rule));
        assert!(!ok, "{rule} was loaded: {text}");
        assert!(text.contains(says), "{rule}: {text}");
    }
    let (ok, text) = check(&cfg("http-request deny status 418"));
    assert!(ok, "{text}");
}

/// A regex only a PCRE has: look-around and a back-reference load (`fancy-regex` runs them,
/// T154, tested in `pcre_regex.rs`); one `fancy-regex` lacks -- recursion, a subroutine
/// call -- is refused at load with the regex and the reason, rather than loaded as a rule
/// that never matches. `HAProxy` takes all of these (measured: `replace-header x '(?=a)' y`,
/// `'(a)\1'`, `'(?<=a)b'`, `'(?R)'`, `'(a)(?1)'` are accepted); that last pair is the known gap.
#[test]
fn a_regex_ibex_cannot_run_is_refused_with_its_reason() {
    for re in ["(?=a)", "(a)\\1", "(?<=a)b"] {
        for kind in ["replace-header", "replace-value"] {
            let (ok, text) = check(&format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  http-request {kind} x '{re}' y\n"));
            assert!(ok, "{kind} {re} was refused: {text}");
        }
    }
    for re in ["(?R)", "(a)(?1)"] {
        for kind in ["replace-header", "replace-value"] {
            let (ok, text) = check(&format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  http-request {kind} x '{re}' y\n"));
            assert!(!ok, "{kind} {re} was loaded");
            assert!(text.contains(re) && text.contains("not supported"), "{kind} {re}: {text}");
        }
    }
}

/// `set-header` removes every occurrence and appends one; `replace-header` replaces the
/// whole value with the replacement, its `\N` taken from the first match; `replace-value`
/// does that to each comma-separated value, the blanks around a replaced one going with
/// it. What the server received, measured (the request carried `X-Srv: 1`, `X-Dup: a`,
/// `X-Dup: b`, `X-List: foo=1, bar=2`):
///
/// ```text
/// x-srv: v1                    replace-value X-Srv '^(\d)$' "v\1"
/// x-list: bar=2; was 1         replace-header X-List '^foo=(\d+), (.*)$' "\2; was \1"
/// x-dup: <e>                   set-header X-Dup new (both X-Dup gone, one at the end), then
///                              replace-header X-Dup "n(e)w" "<\1>"
/// x-multi: 1a,2b               add-header X-Multi "a1, b2", replace-value '^([a-z])(\d)$' "\2\1"
/// a: <e>                       "xnewy",        replace-header "n(e)w" "<\1>"
/// b: 1a, zz ,2b                "a1, zz ,  b2", replace-value '([a-z])(\d)' "\2\1"
/// c: keep, me                  "keep, me",     replace-value 'nomatch' "X"
/// d: b                         "aaa",          replace-header "a" "b"
/// e: [b]                       "AbC",          replace-header "b" "[\0]"
/// ```
#[test]
fn set_header_replace_header_and_replace_value() {
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-request set-header X-Dup new\n  \
         http-request replace-header X-List '^foo=(\\d+), (.*)$' \"\\2; was \\1\"\n  \
         http-request replace-value X-Srv '^(\\d)$' \"v\\1\"\n  \
         http-request add-header X-Multi \"a1, b2\"\n  \
         http-request replace-value X-Multi '^([a-z])(\\d)$' \"\\2\\1\"\n  \
         http-request replace-header X-Dup \"n(e)w\" \"<\\1>\"\n  \
         http-request add-header a \"xnewy\"\n  \
         http-request replace-header a \"n(e)w\" \"<\\1>\"\n  \
         http-request add-header b \"a1, zz ,  b2\"\n  \
         http-request replace-value b '([a-z])(\\d)' \"\\2\\1\"\n  \
         http-request add-header c \"keep, me\"\n  \
         http-request replace-value c 'nomatch' \"X\"\n  \
         http-request add-header d \"aaa\"\n  \
         http-request replace-header d \"a\" \"b\"\n  \
         http-request add-header e \"AbC\"\n  \
         http-request replace-header e \"b\" \"[\\0]\"\n  \
         server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(echo_server()));
    let resp = one(fe, "GET / HTTP/1.1\r\nHost: x\r\nX-Srv: 1\r\nX-Dup: a\r\nX-Dup: b\r\nX-List: foo=1, bar=2\r\n\r\n");
    assert_eq!(
        seen(&resp),
        [
            "host: x",
            "x-srv: v1",
            "x-list: bar=2; was 1",
            "x-dup: <e>",
            "x-multi: 1a,2b",
            "a: <e>",
            "b: 1a, zz ,2b",
            "c: keep, me",
            "d: b",
            "e: [b]",
        ],
        "{resp:?}"
    );
}

/// The replacement's escapes, a quoted comma, a group that did not match, a header that
/// does not match, and `del-header`. Measured (what the server received):
///
/// ```text
/// a: <A.q0>          "v",           replace-header "v" '<\x41\.\q\x2g>'  (\x2g is 0x30, as HAProxy computes it)
/// b: "x,1",[y]       '"x,1", y1',   replace-value '^(.)1$' '[\1]'
/// q: <|z>            'z',           replace-value '^(z)(w)?$' '<\2|\1>'
/// x-srv: 1           replace-header X-Srv nomatch z
/// (no x-dup)         del-header X-Dup
/// b2: "x\",1",[y]    '"x\",1", y1', replace-value '^(.)1$' '[\1]'
/// ```
#[test]
fn replacement_escapes_quoted_values_and_misses() {
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-request add-header a \"v\"\n  \
         http-request replace-header a \"v\" '<\\x41\\.\\q\\x2g>'\n  \
         http-request add-header b '\"x,1\", y1'\n  \
         http-request replace-value b '^(.)1$' '[\\1]'\n  \
         http-request add-header q 'z'\n  \
         http-request replace-value q '^(z)(w)?$' '<\\2|\\1>'\n  \
         http-request replace-header X-Srv nomatch z\n  \
         http-request del-header X-Dup\n  \
         http-request add-header b2 '\"x\\\",1\", y1'\n  \
         http-request replace-value b2 '^(.)1$' '[\\1]'\n  \
         server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(echo_server()));
    let resp = one(fe, "GET / HTTP/1.1\r\nHost: x\r\nX-Srv: 1\r\nX-Dup: a\r\nX-Dup: b\r\n\r\n");
    assert_eq!(
        seen(&resp),
        ["host: x", "x-srv: 1", "a: <A.q0>", "b: \"x,1\",[y]", "q: <|z>", "b2: \"x\\\",1\",[y]"],
        "{resp:?}"
    );
}

/// A replacement that ends inside an escape fails the rewrite (`exp_replace` returns -1),
/// which in strict mode is the 500. Measured with `add-header x v` then `replace-header x v
/// 'a\'` (or `'a\x4'`): `HTTP/1.1 500 Internal Server Error`.
#[test]
fn a_replacement_cut_short_fails_the_rewrite() {
    for repl in ["'a\\'", "'a\\x4'"] {
        let cfg = format!(
            "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request add-header x v\n  \
             http-request replace-header x v {repl}\n  server s {{srv}}\n"
        );
        let (_ibex, fe) = start(&cfg, Some(echo_server()));
        let resp = one(fe, G);
        assert!(resp.starts_with("HTTP/1.1 500 "), "{repl}: {resp:?}");
    }
}

/// A rewrite fails when the request's HTX message has no room for it (a buffer of
/// `tune.bufsize` less 40 bytes: the request line 8 + 20 + its three strings, each header
/// 8 + name + value, the 9-byte end of headers, and any body bytes already read, 8 + data),
/// not when additions pass `tune.maxrewrite`. The request carries `x: <n bytes>` and the
/// rules copy it. Measured, the largest `n` for which `set-header h1 %[var(txn.x)]` is
/// taken (200) and the next one, which in strict mode is the 500:
///
/// ```text
/// GET, no body                              8131 / 8132
/// POST, Content-Length: 5, body hello       8113
/// POST, Content-Length: 5000, 5000 bytes    5614
/// tune.maxrewrite 1024, POST of 40000       1014 / 1015   (the body fills the buffer but for maxrewrite)
/// tune.maxrewrite 1024, GET                 8131
/// ```
///
/// and with `strict-mode off` the rule is skipped: `n` = 1015 on the 40000-byte POST
/// leaves `h1` out and `after` in. Ibex failed at 8192 bytes added.
#[test]
fn a_request_rewrite_fails_when_the_buffer_is_full() {
    let copy = "  http-request set-var(txn.x) req.hdr(x)\n  http-request set-header h1 %[var(txn.x)]\n";
    let post = |n: usize, len: usize| {
        format!("POST / HTTP/1.1\r\nHost: x\r\nx: {}\r\nContent-Length: {len}\r\n\r\n{}", "A".repeat(n), "b".repeat(len))
    };
    let mr = "global\n  tune.maxrewrite 1024\n";
    type Mk = Box<dyn Fn(usize) -> String>;
    let cases: Vec<(&str, &str, Mk, usize)> = vec![
        ("", "GET", Box::new(|n| req(n, "")), 8131),
        ("", "POST 5", Box::new(move |n| post(n, 5)), 8113),
        ("", "POST 5000", Box::new(move |n| post(n, 5000)), 5614),
        (mr, "mr GET", Box::new(|n| req(n, "")), 8131),
        (mr, "mr POST 40000", Box::new(move |n| post(n, 40000)), 1014),
    ];
    for (glob, what, mk, max) in cases {
        let cfg = format!("{glob}{DEFAULTS}listen l\n  bind {{fe}}\n{copy}  server s {{srv}}\n");
        let (_ibex, fe) = start(&cfg, Some(echo_server()));
        let resp = one(fe, &mk(max));
        assert!(resp.starts_with("HTTP/1.1 200 "), "{what} {max}: {}", &resp[..resp.len().min(120)]);
        assert_eq!(received(&resp, &["h1"]), ["h1"], "{what} {max}");
        let resp = one(fe, &mk(max + 1));
        assert!(resp.starts_with("HTTP/1.1 500 "), "{what} {}: {}", max + 1, &resp[..resp.len().min(120)]);
    }
    let post = |n: usize, len: usize| {
        format!("POST / HTTP/1.1\r\nHost: x\r\nx: {}\r\nContent-Length: {len}\r\n\r\n{}", "A".repeat(n), "b".repeat(len))
    };
    let cfg = format!(
        "global\n  tune.maxrewrite 1024\n{DEFAULTS}listen l\n  bind {{fe}}\n  http-request strict-mode off\n{copy}  \
         http-request set-header after yes\n  server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(echo_server()));
    let resp = one(fe, &post(1015, 40000));
    assert!(resp.starts_with("HTTP/1.1 200 "), "{}", &resp[..resp.len().min(120)]);
    assert_eq!(received(&resp, &["h1", "after"]), ["after"], "{resp:?}");
}

/// `replace-header` and `replace-value` need room for what they grow, header by header,
/// the first that does not fit failing the action with the ones before it rewritten.
/// The request has `x: <n>`, `X-Dup: a`, `X-Dup: b`; the rules are `set-header hh1
/// %[var(txn.x)]`, `replace-header X-Dup '^(.)$' '\1\1\1'` (or `replace-value`), `set-header
/// after yes`. Measured, for either action:
///
/// ```text
/// n = 8116  strict       500
///           strict off   200: x-dup: aaa, x-dup: b, hh1, no after
/// n = 8115  strict       500
///           strict off   200: x-dup: aaa, x-dup: bbb, hh1, no after
/// ```
#[test]
fn replace_header_and_value_fail_when_there_is_no_room() {
    for kind in ["replace-header", "replace-value"] {
        for (n, want) in [(8116, ["aaa", "b"]), (8115, ["aaa", "bbb"])] {
            for strict in [true, false] {
                let cfg = format!(
                    "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.x) req.hdr(x)\n  {}\
                     http-request set-header hh1 %[var(txn.x)]\n  \
                     http-request {kind} X-Dup '^(.)$' '\\1\\1\\1'\n  http-request set-header after yes\n  server s {{srv}}\n",
                    if strict { "" } else { "http-request strict-mode off\n  " }
                );
                let (_ibex, fe) = start(&cfg, Some(echo_server()));
                let resp = one(fe, &req(n, "X-Dup: a\r\nX-Dup: b\r\n"));
                let tag = format!("{kind} n={n} strict={strict}");
                if strict {
                    assert!(resp.starts_with("HTTP/1.1 500 "), "{tag}: {}", &resp[..resp.len().min(120)]);
                } else {
                    assert!(resp.starts_with("HTTP/1.1 200 "), "{tag}: {}", &resp[..resp.len().min(120)]);
                    let dups: Vec<String> = seen(&resp).into_iter().filter(|l| l.starts_with("x-dup:")).collect();
                    assert_eq!(dups, [format!("x-dup: {}", want[0]), format!("x-dup: {}", want[1])], "{tag}");
                    assert_eq!(received(&resp, &["hh1", "after"]), ["hh1"], "{tag}");
                }
            }
        }
    }
}

/// `strict-mode` lasts to the end of the rule list it is in: the frontend's and the
/// backend's `http-request` lists each start strict. The request has `x` of 4000 bytes
/// and four copies of it do not fit (three do). Measured:
///
/// ```text
/// frontend strict-mode off, backend 4 copies + after          500
/// frontend strict-mode off + 4 copies + after, backend set-header be
///                                                             200: h1 h2 h3 after be
/// strict-mode off, 4 copies + after                           200: h1 h2 h3 after
/// strict-mode off, strict-mode on, 4 copies + after           500
/// 4 copies + after                                            500
/// frontend set-header fe, backend strict-mode off + 4 copies + after
///                                                             200: fe h1 h2 h3 after
/// ```
///
/// Ibex kept `strict-mode off` from the frontend's list into the backend's.
#[test]
fn request_strict_mode_lasts_until_the_end_of_its_rule_list() {
    let copies: String =
        (1..=4).map(|i| format!("  http-request set-header h{i} %[var(txn.x)]\n")).collect::<String>() + "  http-request set-header after yes\n";
    let off = "  http-request strict-mode off\n";
    let names = ["fe", "h1", "h2", "h3", "h4", "after", "be"];
    let fb = |fe: &str, be: &str| {
        format!(
            "{DEFAULTS}frontend f\n  bind {{fe}}\n  http-request set-var(txn.x) req.hdr(x)\n{fe}  default_backend b\n\
             backend b\n{be}  server s {{srv}}\n"
        )
    };
    let cases: Vec<(String, &str, Vec<&str>)> = vec![
        (fb(off, &copies), "HTTP/1.1 500 ", vec![]),
        (fb(&format!("{off}{copies}"), "  http-request set-header be yes\n"), "HTTP/1.1 200 ", vec!["after", "be", "h1", "h2", "h3"]),
        (fb(&format!("{off}{copies}"), ""), "HTTP/1.1 200 ", vec!["after", "h1", "h2", "h3"]),
        (fb(&format!("{off}  http-request strict-mode on\n{copies}"), ""), "HTTP/1.1 500 ", vec![]),
        (fb(&copies, ""), "HTTP/1.1 500 ", vec![]),
        (fb("  http-request set-header fe yes\n", &format!("{off}{copies}")), "HTTP/1.1 200 ", vec!["after", "fe", "h1", "h2", "h3"]),
    ];
    for (cfg, status, present) in cases {
        let (_ibex, fe) = start(&cfg, Some(echo_server()));
        let resp = one(fe, &req(4000, ""));
        let short = &resp[..resp.len().min(120)];
        assert!(resp.starts_with(status), "{cfg}: {short}");
        assert_eq!(received(&resp, &names), present, "{cfg}: {short}");
    }
}
