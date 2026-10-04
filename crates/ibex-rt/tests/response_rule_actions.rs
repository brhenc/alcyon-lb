// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The actions `http-response` and `http-after-response` share (`res_action`,
//! `eval_after_res_rules` in `engine.rs`): `deny`, `allow`, `set-var`, `set-var-fmt`,
//! `unset-var`, `strict-mode`, `set-header`, `replace-header`, `replace-value`, and what a
//! rewrite does when the response has no room left for it.
//!
//! Every expected value below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-03, with a raw-socket client sending
//! `GET / HTTP/1.1\r\nHost: x\r\n\r\n` (and a `x: <n bytes>` header where a test needs a
//! big value) to a server answering, on a keep-alive connection, [`SRV`]:
//! `HTTP/1.1 200 OK`, `Content-Length: 2`, `X-Srv: 1`, `X-Dup: a`, `X-Dup: b`,
//! `X-List: foo=1, bar=2`, body `ok`. `HAProxy` lower-cases header names on the way out
//! and Ibex keeps the case it was given, so the tests compare names case-insensitively.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const G: &str = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";
const SRV: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv: 1\r\nX-Dup: a\r\nX-Dup: b\r\nX-List: foo=1, bar=2\r\n\r\nok";

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

/// A server answering every request on a connection with `resp`.
fn server(resp: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let resp = resp.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        if c.write_all(&resp).is_err() {
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

/// A request carrying an `x` header of `n` bytes.
fn big_request(n: usize) -> String {
    format!("GET / HTTP/1.1\r\nHost: x\r\nx: {}\r\n\r\n", "A".repeat(n))
}

/// `http-response deny` refuses the server's response. With nothing after it, the reply is
/// the 502 page; `deny_status` picks another page; `status` alone sends an empty reply.
/// Measured:
///
/// ```text
/// deny                    HTTP/1.1 502 Bad Gateway\r\ncontent-length: 107\r\n...<h1>502 Bad Gateway</h1>...
/// deny deny_status 404    HTTP/1.1 404 Not Found\r\ncontent-length: 83\r\n...<h1>404 Not Found</h1>...
/// deny status 403         HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n
/// deny status 418         HTTP/1.1 418 I'm a teapot\r\ncontent-length: 0\r\nstatic: yes\r\n\r\n
/// ```
///
/// (`http_parse_http_reply` with `default-errorfiles` for the first two, an empty reply
/// for `status`, `src/http_act.c`.) Ibex sent the 403 *page* for `deny status 403`, and for
/// `deny status 418` a `Content-Type: text/plain` and `Connection: close` `HAProxy` does
/// not send. The reason phrase is not compared (Ibex has no `I'm a teapot`).
#[test]
fn http_response_deny_sends_the_page_or_an_empty_reply() {
    let srv = server(SRV.to_vec());
    let cases = [
        ("  http-response deny\n", "HTTP/1.1 502 ", Some("<h1>502 Bad Gateway</h1>")),
        ("  http-response deny deny_status 404\n", "HTTP/1.1 404 ", Some("<h1>404 Not Found</h1>")),
        ("  http-response deny status 403\n", "HTTP/1.1 403 ", None),
        ("  http-response deny status 418\n", "HTTP/1.1 418 ", None),
    ];
    for (rule, status, page) in cases {
        let cfg = format!("{DEFAULTS}listen l\n  bind {{fe}}\n{rule}  http-after-response set-header static yes\n  server s {{srv}}\n");
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = one(fe, G);
        assert!(resp.starts_with(status), "{rule}: {resp:?}");
        assert_eq!(lines_named(&resp, "static"), ["static: yes"], "{rule}: {resp:?}");
        let body = resp.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        match page {
            Some(p) => assert!(body.contains(p), "{rule}: not the error page: {resp:?}"),
            None => {
                assert_eq!(header_lines(&resp), ["content-length: 0", "static: yes"], "{rule}: {resp:?}");
                assert_eq!(body, "", "{rule}: {resp:?}");
            }
        }
    }
}

/// What `HAProxy` refuses at load and Ibex accepted. Measured with `haproxy -c`:
///
/// ```text
/// http-response deny deny_status 418              status code '418' not handled by default with 'default-errorfiles' argument.
/// http-after-response deny                         'http-after-response' expects 'set-log-level', ... but got 'deny'.
/// http-response set-var(txn.x) str(a) str(b)       'http-response set-var(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'str(b)'.
/// http-after-response set-var(txn.x) str(a) str(b) (the same, for 'http-after-response set-var(txn.x)')
/// http-response deny status 600                    Unexpected status code '600'.
/// http-response deny status 199                    Unexpected status code '199'.
/// http-response replace-header x '(' y             regex '(' is invalid (error=missing closing parenthesis, erroffset=1).
/// ```
///
/// (`http-after-response replace-value` with the same regex: the same.)
///
/// and accepted: `http-response deny status 418`, `http-response set-var(txn.x) str(a) if
/// TRUE`, `http-after-response set-var(txn.x) 'str(a b)'`.
#[test]
fn response_rules_haproxy_refuses_are_refused() {
    let cfg = |rule: &str| format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  {rule}\n");
    for (rule, says) in [
        ("http-response deny deny_status 418", "status code '418' not handled by default"),
        ("http-after-response deny", "deny"),
        ("http-response set-var(txn.x) str(a) str(b)", "str(b)"),
        ("http-after-response set-var(txn.x) str(a) str(b)", "str(b)"),
        ("http-response deny status 600", "Unexpected status code '600'"),
        ("http-response deny status 199", "Unexpected status code '199'"),
        ("http-response replace-header x '(' y", "("),
        ("http-after-response replace-value x '(' y", "("),
    ] {
        let (ok, text) = check(&cfg(rule));
        assert!(!ok, "`{rule}` was accepted: {text}");
        assert!(text.contains(says), "`{rule}`: {text}");
    }
    for rule in [
        "http-response deny status 418",
        "http-response set-var(txn.x) str(a) if TRUE",
        "http-after-response set-var(txn.x) 'str(a b)'",
    ] {
        let (ok, text) = check(&cfg(rule));
        assert!(ok, "`{rule}` was refused: {text}");
    }
}

/// Variables set and unset by the response rules, read by later rules and by the next
/// request on the connection. Measured, two requests on one connection:
///
/// ```text
/// 1st   in-res: a=A b=1-fmt u=
///       vals: a= b=1-fmt c=C d=200-d s=S k= p=P u=
///       seen: s= k= p=
/// 2nd   (the same in-res and vals)
///       seen: s=S k= p=P
/// ```
///
/// `sess.s` set by `http-response` lives on into the next request; `sess.k`, unset by
/// `http-after-response`, does not. Ibex's second request saw `k=K`: `unset-var` in a
/// response rule removed the variable from what later rules of that response read, not
/// from the session.
#[test]
fn response_rules_set_and_unset_variables() {
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-request set-header x-seen \"s=%[var(sess.s)] k=%[var(sess.k)] p=%[var(proc.p)]\"\n  \
         http-request set-var(txn.seen) req.hdr(x-seen)\n  \
         http-response set-var(txn.a) str(A)\n  \
         http-response set-var-fmt(txn.b) \"%[res.hdr(x-srv)]-fmt\"\n  \
         http-response set-var(sess.s) str(S)\n  \
         http-response set-var(sess.k) str(K)\n  \
         http-response set-var(proc.p) str(P)\n  \
         http-response set-var(txn.u) str(U)\n  \
         http-response unset-var(txn.u)\n  \
         http-response set-header in-res \"a=%[var(txn.a)] b=%[var(txn.b)] u=%[var(txn.u)]\"\n  \
         http-after-response set-var(txn.c) str(C)\n  \
         http-after-response set-var-fmt(txn.d) \"%[status]-d\"\n  \
         http-after-response unset-var(txn.a)\n  \
         http-after-response unset-var(sess.k)\n  \
         http-after-response set-header vals \"a=%[var(txn.a)] b=%[var(txn.b)] c=%[var(txn.c)] d=%[var(txn.d)] s=%[var(sess.s)] k=%[var(sess.k)] p=%[var(proc.p)] u=%[var(txn.u)]\"\n  \
         http-after-response set-header seen \"%[var(txn.seen)]\"\n  \
         server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(server(SRV.to_vec())));
    let resps = exchange(fe, &[G, G]);
    let seen = ["seen: s= k= p=", "seen: s=S k= p=P"];
    for (resp, seen) in resps.iter().zip(seen) {
        assert_eq!(lines_named(resp, "in-res"), ["in-res: a=A b=1-fmt u="], "{resp:?}");
        assert_eq!(lines_named(resp, "vals"), ["vals: a= b=1-fmt c=C d=200-d s=S k= p=P u="], "{resp:?}");
        assert_eq!(lines_named(resp, "seen"), [seen], "{resp:?}");
    }
}

/// `http-response unset-var(sess.k)` takes the variable from the session too. Measured,
/// two requests on one connection, the request rules setting `sess.k` after reading it:
/// `seen: k= now=` on both. Ibex's second said `k=K`.
#[test]
fn http_response_unset_var_reaches_the_session() {
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-request set-var(txn.seen) \"str(),concat(k=,sess.k,)\"\n  \
         http-request set-var(sess.k) str(K)\n  \
         http-response unset-var(sess.k)\n  \
         http-response set-header seen \"%[var(txn.seen)] now=%[var(sess.k)]\"\n  \
         server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(server(SRV.to_vec())));
    for resp in exchange(fe, &[G, G]) {
        assert_eq!(lines_named(&resp, "seen"), ["seen: k= now="], "{resp:?}");
    }
}

/// A `set-var` whose fetch finds nothing leaves the variable as it was. Measured:
/// `out: x=before y=y0`. Ibex set both to the empty string.
#[test]
fn set_var_with_a_fetch_that_finds_nothing_leaves_the_variable() {
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-request set-var(txn.x) str(before)\n  \
         http-response set-var(txn.x) res.hdr(nonexistent)\n  \
         http-after-response set-var(txn.y) str(y0)\n  \
         http-after-response set-var(txn.y) res.hdr(nonexistent)\n  \
         http-after-response set-header out \"x=%[var(txn.x)] y=%[var(txn.y)]\"\n  \
         server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(server(SRV.to_vec())));
    let resp = one(fe, G);
    assert_eq!(lines_named(&resp, "out"), ["out: x=before y=y0"], "{resp:?}");
}

/// `set-header` removes every occurrence and appends one; `replace-header` replaces the
/// whole value with the replacement, its `\N` taken from the first match; `replace-value`
/// does that to each comma-separated value, the blanks around a replaced one going with
/// it (`http_replace_hdrs`, `exp_replace`, `http_replace_header_value`). Measured:
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
///
/// Ibex kept `X-Dup: b`, rewrote only the matched part of a value (`x<e>y`, `bbb`,
/// `A[b]C`), and ran `replace-value` on the whole line (`a1, b2` unchanged).
#[test]
fn set_header_replace_header_and_replace_value() {
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-response set-header X-Dup new\n  \
         http-response replace-header X-List '^foo=(\\d+), (.*)$' \"\\2; was \\1\"\n  \
         http-response replace-value X-Srv '^(\\d)$' \"v\\1\"\n  \
         http-after-response add-header X-Multi \"a1, b2\"\n  \
         http-after-response replace-value X-Multi '^([a-z])(\\d)$' \"\\2\\1\"\n  \
         http-after-response replace-header X-Dup \"n(e)w\" \"<\\1>\"\n  \
         http-after-response add-header a \"xnewy\"\n  \
         http-after-response replace-header a \"n(e)w\" \"<\\1>\"\n  \
         http-after-response add-header b \"a1, zz ,  b2\"\n  \
         http-after-response replace-value b '([a-z])(\\d)' \"\\2\\1\"\n  \
         http-after-response add-header c \"keep, me\"\n  \
         http-after-response replace-value c 'nomatch' \"X\"\n  \
         http-after-response add-header d \"aaa\"\n  \
         http-after-response replace-header d \"a\" \"b\"\n  \
         http-after-response add-header e \"AbC\"\n  \
         http-after-response replace-header e \"b\" \"[\\0]\"\n  \
         server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(server(SRV.to_vec())));
    let resp = one(fe, G);
    assert_eq!(
        header_lines(&resp),
        [
            "content-length: 2",
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

/// `strict-mode` lasts to the end of the rule list it is in: each list starts strict
/// (`http_res_get_intercept_rule` clears `HTTP_MSGF_SOFT_RW`). Three 7000-byte headers do
/// not fit in the response; in strict mode the third fails the response with a 500.
/// Measured:
///
/// ```text
/// http-response strict-mode off, 3 big http-response set-header   200, h1, h2, after: yes
/// 3 big http-response set-header                                   500
/// http-request strict-mode off, 3 big http-response set-header    500
/// http-response strict-mode off, 3 big http-after-response        500
/// http-response strict-mode off then on, 3 big                     500
/// ```
///
/// Ibex let `strict-mode off` from the request rules, and from `http-response`, carry into
/// the next list, and sent 200s.
#[test]
fn strict_mode_lasts_until_the_end_of_its_rule_list() {
    let srv = server(SRV.to_vec());
    let big = |kw: &str| {
        format!(
            "  {kw} set-header h1 %[var(txn.big)]\n  {kw} set-header h2 %[var(txn.big)]\n  \
             {kw} set-header h3 %[var(txn.big)]\n  {kw} set-header after yes\n"
        )
    };
    let res = big("http-response");
    let cases = [
        (format!("  http-response strict-mode off\n{res}"), "HTTP/1.1 200 ", vec!["h1", "h2", "after"]),
        (res.clone(), "HTTP/1.1 500 ", vec![]),
        (format!("  http-request strict-mode off\n{res}"), "HTTP/1.1 500 ", vec![]),
        (format!("  http-response strict-mode off\n{}", big("http-after-response")), "HTTP/1.1 500 ", vec![]),
        (format!("  http-response strict-mode off\n  http-response strict-mode on\n{res}"), "HTTP/1.1 500 ", vec![]),
    ];
    for (rules, status, present) in cases {
        let cfg = format!(
            "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.big) req.hdr(x)\n{rules}  server s {{srv}}\n"
        );
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = one(fe, &big_request(7000));
        let short = &resp[..resp.len().min(200)];
        assert!(resp.starts_with(status), "{rules}: {short}");
        let got: Vec<&str> =
            ["h1", "h2", "h3", "after"].into_iter().filter(|n| !lines_named(&resp, n).is_empty()).collect();
        assert_eq!(got, present, "{rules}: {short}");
    }
}

/// A rewrite fails when the response's buffer has no room for it, not when it adds more
/// than `tune.maxrewrite`: that is the room the buffer keeps free while the response is
/// read, so it bounds the rewrites only when the response filled the rest. Measured:
///
/// ```text
/// tune.maxrewrite 1024, small body, set-header h1 <3000 bytes>          200, h1 (3004-byte line)
/// default maxrewrite, small body, set-header h1, h2 <7000 bytes each>   200, h1, h2
/// tune.maxrewrite 1024, 40000-byte body, set-header h1 <900 bytes>      200, h1
/// tune.maxrewrite 1024, 40000-byte body, set-header h1 <1500 bytes>     500
///   the same after http-response strict-mode off                        200, no h1, after: yes
/// http-request return, http-after-response strict-mode off,
///   add-header h1, h2, h3 <7000 bytes each>, add-header after yes        200, h1, h2, after
/// ```
///
/// Ibex counted the bytes the rules added against `tune.maxrewrite` (8192 when unset):
/// it failed the first case and the 9000-byte one `HAProxy` takes.
#[test]
fn a_rewrite_fails_when_the_buffer_is_full_not_past_maxrewrite() {
    let small = server(SRV.to_vec());
    let mut big_body = b"HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n".to_vec();
    big_body.extend(std::iter::repeat_n(b'B', 40000));
    let large = server(big_body);
    let cfg = |global: &str, rules: &str| {
        format!(
            "global\n{global}{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.big) req.hdr(x)\n{rules}  \
             http-response set-header after yes\n  server s {{srv}}\n"
        )
    };
    let one_hdr = "  http-response set-header h1 %[var(txn.big)]\n";
    let two_hdrs = "  http-response set-header h1 %[var(txn.big)]\n  http-response set-header h2 %[var(txn.big)]\n";
    let mr = "  tune.maxrewrite 1024\n";
    let cases = [
        ("maxrewrite 1024, 3000", cfg(mr, one_hdr), small, 3000, "HTTP/1.1 200 ", vec!["h1", "after"]),
        ("default, 2 x 7000", cfg("", two_hdrs), small, 7000, "HTTP/1.1 200 ", vec!["h1", "h2", "after"]),
        ("default, 9000", cfg("", one_hdr), small, 9000, "HTTP/1.1 200 ", vec!["h1", "after"]),
        ("big body, 900", cfg(mr, one_hdr), large, 900, "HTTP/1.1 200 ", vec!["h1", "after"]),
        ("big body, 1500", cfg(mr, one_hdr), large, 1500, "HTTP/1.1 500 ", vec![]),
        (
            "big body, 1500, not strict",
            cfg(mr, &format!("  http-response strict-mode off\n{one_hdr}")),
            large,
            1500,
            "HTTP/1.1 200 ",
            vec!["after"],
        ),
    ];
    for (what, cfg, srv, n, status, present) in cases {
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = one(fe, &big_request(n));
        let short = &resp[..resp.len().min(200)];
        assert!(resp.starts_with(status), "{what}: {short}");
        let got: Vec<&str> = ["h1", "h2", "after"].into_iter().filter(|h| !lines_named(&resp, h).is_empty()).collect();
        assert_eq!(got, present, "{what}: {short}");
        if present.contains(&"h1") {
            assert_eq!(lines_named(&resp, "h1")[0].len(), n + 4, "{what}");
        }
    }

    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.big) req.hdr(x)\n  \
         http-request return status 200\n  http-after-response strict-mode off\n  \
         http-after-response add-header h1 %[var(txn.big)]\n  http-after-response add-header h2 %[var(txn.big)]\n  \
         http-after-response add-header h3 %[var(txn.big)]\n  http-after-response add-header after yes\n"
    );
    let (_ibex, fe) = start(&cfg, None);
    let resp = one(fe, &big_request(7000));
    let got: Vec<&str> = ["h1", "h2", "h3", "after"].into_iter().filter(|h| !lines_named(&resp, h).is_empty()).collect();
    assert!(resp.starts_with("HTTP/1.1 200 "), "{}", &resp[..resp.len().min(200)]);
    assert_eq!(got, ["h1", "h2", "after"], "{}", &resp[..resp.len().min(200)]);
}

/// `allow` ends its own rule list; the frontend's list still runs. Measured, a frontend
/// with `http-response set-header fe-res 1` and `http-after-response set-header fe-after
/// 1`, its backend with `allow` ahead of a `set-header` in both lists: `fe-res: 1`,
/// `fe-after: 1`, and neither of the backend's headers.
#[test]
fn allow_ends_its_own_rule_list_only() {
    let cfg = format!(
        "{DEFAULTS}frontend f\n  bind {{fe}}\n  http-response set-header fe-res 1\n  \
         http-after-response set-header fe-after 1\n  default_backend b\n\
         backend b\n  http-response allow\n  http-response set-header be-res-skipped 1\n  \
         http-after-response allow\n  http-after-response set-header be-after-skipped 1\n  server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(server(SRV.to_vec())));
    let resp = one(fe, G);
    let added: Vec<String> = header_lines(&resp).into_iter().filter(|l| l.starts_with("fe-") || l.starts_with("be-")).collect();
    assert_eq!(added, ["fe-res: 1", "fe-after: 1"], "{resp:?}");
}

/// An empty errorfile -- `/dev/null` is the documented idiom -- is a reply of nothing:
/// the connection closes without a byte, `http-after-response` rules or not. Measured on
/// a `listen` with no server, `errorfile 503 <empty file>` and `http-after-response
/// set-header static yes`: the client read nothing, then the close.
#[test]
fn an_empty_errorfile_sends_nothing_whatever_the_rules() {
    let empty = NamedTempFile::new().expect("tmp");
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  errorfile 503 {}\n  http-after-response set-header static yes\n",
        empty.path().display()
    );
    let (_ibex, fe) = start(&cfg, None);
    assert_eq!(one(fe, G), "");
}

/// An errorfile that is not an HTTP response is refused at load (`http_str_to_htx`,
/// `src/http_htx.c`). Measured with `haproxy -c`, `errorfile 503 <file>`:
///
/// ```text
/// "garbage without head end"                         unable to parse headers (error offset: 0)
/// "HTTP/1.1 abc Bad\r\nContent-Length: 0\r\n\r\n"    unable to parse headers (error offset: 9)
/// "HTTP/1.1 503 X\r\nContent-Length: 0\r\n"          unable to parse headers (error offset: -2)
/// "NOTHTTP 503 X\r\nContent-Length: 0\r\n\r\n"       invalid http version (NOTHTTP)
/// "HTTP/1.1 503 X\r\nBadHeader\r\n\r\n"               unable to parse headers (error offset: 25)
/// "HTTP/1.1 100 Continue\r\n\r\n"                     invalid http status code for an error message (100)
/// ```
///
/// Ibex loaded each and sent its bytes as they were, the last one with the after-response
/// rules' header after a status line no client can read.
#[test]
fn an_errorfile_that_is_not_a_response_is_refused() {
    for (content, says) in [
        (&b"garbage without head end"[..], "unable to parse headers"),
        (b"HTTP/1.1 abc Bad\r\nContent-Length: 0\r\n\r\n", "unable to parse headers"),
        (b"HTTP/1.1 503 X\r\nContent-Length: 0\r\n", "unable to parse headers"),
        (b"NOTHTTP 503 X\r\nContent-Length: 0\r\n\r\n", "invalid http version (NOTHTTP)"),
        (b"HTTP/1.1 503 X\r\nBadHeader\r\n\r\n", "unable to parse headers"),
        (b"HTTP/1.1 100 Continue\r\n\r\n", "invalid http status code for an error message (100)"),
    ] {
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(content).expect("write");
        let (ok, text) = check(&format!("{DEFAULTS}listen l\n  bind 127.0.0.1:1\n  errorfile 503 {}\n", f.path().display()));
        assert!(!ok, "{:?} was loaded: {text}", String::from_utf8_lossy(content));
        assert!(text.contains(says), "{:?}: {text}", String::from_utf8_lossy(content));
    }
}

/// The replacement's escapes, a quoted comma, a group that did not match, a header that
/// does not match, and `del-header`. Measured, on a `return` (`a`, `b`, `q`) and on the
/// server's response (the rest):
///
/// ```text
/// a: <A.q0>          "v",           replace-header "v" '<\x41\.\q\x2g>'  (\x2g is 0x30, as HAProxy computes it)
/// b: "x,1",[y]       '"x,1", y1',   replace-value '^(.)1$' '[\1]'
/// q: <|z>            'z',           replace-value '^(z)(w)?$' '<\2|\1>'
/// x-srv: 1           replace-header X-Srv nomatch z
/// (no x-dup)         del-header X-Dup
/// b: "x\",1",[y]     '"x\",1", y1', replace-value '^(.)1$' '[\1]'
/// ```
#[test]
fn replacement_escapes_quoted_values_and_misses() {
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-after-response add-header a \"v\"\n  \
         http-after-response replace-header a \"v\" '<\\x41\\.\\q\\x2g>'\n  \
         http-after-response add-header b '\"x,1\", y1'\n  \
         http-after-response replace-value b '^(.)1$' '[\\1]'\n  \
         http-after-response add-header q 'z'\n  \
         http-after-response replace-value q '^(z)(w)?$' '<\\2|\\1>'\n  \
         http-request return status 200\n"
    );
    let (_ibex, fe) = start(&cfg, None);
    let resp = one(fe, G);
    let got: Vec<String> = ["a", "b", "q"].iter().flat_map(|n| lines_named(&resp, n)).collect();
    assert_eq!(got, ["a: <A.q0>", "b: \"x,1\",[y]", "q: <|z>"], "{resp:?}");

    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  \
         http-response del-header X-Dup\n  \
         http-response replace-header X-Srv nomatch z\n  \
         http-after-response add-header b '\"x\\\",1\", y1'\n  \
         http-after-response replace-value b '^(.)1$' '[\\1]'\n  \
         server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(server(SRV.to_vec())));
    let resp = one(fe, G);
    assert_eq!(
        header_lines(&resp),
        ["content-length: 2", "x-srv: 1", "x-list: foo=1, bar=2", "b: \"x\\\",1\",[y]"],
        "{resp:?}"
    );
}

/// A replacement that ends inside an escape fails the rewrite (`exp_replace` returns -1),
/// which in strict mode is the 500. Measured on a `return` with `add-header x v` then
/// `replace-header x v 'a\'` (or `'a\x4'`): `HTTP/1.1 500 Internal Server Error`.
#[test]
fn a_replacement_cut_short_fails_the_rewrite() {
    for repl in ["'a\\'", "'a\\x4'"] {
        let cfg = format!(
            "{DEFAULTS}listen l\n  bind {{fe}}\n  http-after-response add-header x v\n  \
             http-after-response replace-header x v {repl}\n  http-request return status 200\n"
        );
        let (_ibex, fe) = start(&cfg, None);
        let resp = one(fe, G);
        assert!(resp.starts_with("HTTP/1.1 500 "), "{repl}: {resp:?}");
    }
}

/// `set-status` and `replace-header`/`replace-value` need room too. Two `set-header` of
/// 8086-byte values leave the server's response one byte short of full; 8078-byte ones
/// leave 17, as many as `200 OK` to `503 Service Unavailable` takes. Measured:
///
/// ```text
/// h1, h2 <8086>, set-status 503                        500
/// h1, h2 <8078>, set-status 503                        503
/// strict-mode off, h1, h2 <8086>, set-status 503      200
/// h1, h2 <8086>, replace-header X-Dup '^(.)$' '\1\1\1'                    500
/// the same with replace-value                                             500
/// strict-mode off, either, then set-header after yes   200, x-dup: a, x-dup: b, no after
/// ```
#[test]
fn set_status_and_replace_fail_when_there_is_no_room() {
    let srv = server(SRV.to_vec());
    let cfg = |strict: bool, last: &str| {
        format!(
            "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(txn.big) req.hdr(x)\n{}  \
             http-response set-header h1 %[var(txn.big)]\n  http-response set-header h2 %[var(txn.big)]\n  \
             {last}\n  server s {{srv}}\n",
            if strict { "" } else { "  http-response strict-mode off\n" }
        )
    };
    let status = "http-response set-status 503";
    let cases = [
        (cfg(true, status), 8086, "HTTP/1.1 500 "),
        (cfg(true, status), 8078, "HTTP/1.1 503 "),
        (cfg(false, status), 8086, "HTTP/1.1 200 "),
        (cfg(true, "http-response replace-header X-Dup '^(.)$' '\\1\\1\\1'"), 8086, "HTTP/1.1 500 "),
        (cfg(true, "http-response replace-value X-Dup '^(.)$' '\\1\\1\\1'"), 8086, "HTTP/1.1 500 "),
    ];
    for (cfg, n, want) in cases {
        let (_ibex, fe) = start(&cfg, Some(srv));
        let resp = one(fe, &big_request(n));
        assert!(resp.starts_with(want), "{cfg}: {}", &resp[..resp.len().min(120)]);
    }
    for kind in ["replace-header", "replace-value"] {
        let (_ibex, fe) = start(
            &cfg(false, &format!("http-response {kind} X-Dup '^(.)$' '\\1\\1\\1'\n  http-response set-header after yes")),
            Some(srv),
        );
        let resp = one(fe, &big_request(8086));
        assert!(resp.starts_with("HTTP/1.1 200 "), "{kind}: {}", &resp[..resp.len().min(120)]);
        assert_eq!(lines_named(&resp, "x-dup"), ["x-dup: a", "x-dup: b"], "{kind}");
        assert!(lines_named(&resp, "after").is_empty(), "{kind}");
    }
}

/// The request's `req.*` variables are gone once the response is here: `http-response` and
/// `http-after-response` rules read them empty, while `txn.*` lives on. Measured:
///
/// ```text
/// x-resp-req:      x-resp-txn: txnv      x-aft-req:      x-aft-res: resv      x-aft-txn: txnv
/// ```
#[test]
fn http_response_rules_do_not_see_the_requests_variables() {
    let srv = server(SRV.to_vec());
    let cfg = format!(
        "{DEFAULTS}listen l\n  bind {{fe}}\n  http-request set-var(req.a) str(reqv)\n  \
         http-request set-var(txn.a) str(txnv)\n  \
         http-response set-header x-resp-req \"%[var(req.a)]\"\n  \
         http-response set-header x-resp-txn \"%[var(txn.a)]\"\n  \
         http-response set-var(res.b) str(resv)\n  \
         http-after-response set-header x-aft-req \"%[var(req.a)]\"\n  \
         http-after-response set-header x-aft-res \"%[var(res.b)]\"\n  \
         http-after-response set-header x-aft-txn \"%[var(txn.a)]\"\n  server s {{srv}}\n"
    );
    let (_ibex, fe) = start(&cfg, Some(srv));
    let resp = one(fe, G);
    let got: Vec<String> = ["x-resp-req", "x-resp-txn", "x-aft-req", "x-aft-res", "x-aft-txn"]
        .iter()
        .flat_map(|n| lines_named(&resp, n))
        .collect();
    assert_eq!(
        got,
        ["x-resp-req: ", "x-resp-txn: txnv", "x-aft-req: ", "x-aft-res: resv", "x-aft-txn: txnv"],
        "{resp:?}"
    );
}
