// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request pause` / `http-response pause` and `txn.sess_term_state` (T380).
//! Measured on `HAProxy 3.5-dev8-885761-29` with curl on 2026-10-18:
//!
//! ```text
//! pause 300 if path /p          300 ms, then the 200
//! pause var(txn.p) (x: 400)     400 ms;  x: 0, x: -5, x: abc, no x:  no wait at all
//! normal 200 via a server       http-response x-ts: --     http-after-response x-as: --
//! deny                          x-as: PR     tarpit  x-as: PT
//! http-response pause 300       300 ms before the response goes out
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A server answering `200 ok` to every request, on every connection.
fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let mut b = [0u8; 4096];
                while let Ok(n) = c.read(&mut b) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                        break;
                    }
                }
            });
        }
    });
    a
}

fn with_alcyon<T>(body: &str, f: impl FnOnce(SocketAddr) -> T) -> T {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n  timeout tarpit 100ms\n\
         frontend fe\n  bind {fe}\n  default_backend b\n{body}\nbackend b\n  server s {}\n",
        server()
    );
    let mut file = NamedTempFile::new().expect("tmp");
    file.write_all(cfg.as_bytes()).expect("write");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(file.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened with:\n{cfg}");
    let out = f(fe);
    common::stop(&mut child);
    out
}

/// Sends `GET <path>` with `extra` header lines and reads one response (to its end).
fn get(fe: SocketAddr, path: &str, extra: &str) -> (Duration, String) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(6))).expect("timeout");
    let start = Instant::now();
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n").as_bytes()).expect("send");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    (start.elapsed(), String::from_utf8_lossy(&out).into_owned())
}

fn header<'a>(resp: &'a str, name: &str) -> Option<&'a str> {
    resp.lines().find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

const MS: fn(u64) -> Duration = Duration::from_millis;

#[test]
fn request_pause_delays_that_request_only_and_blocks_no_thread() {
    let rules = "  http-request pause 400 if { path /p }\n";
    with_alcyon(rules, |fe| {
        let slow = std::thread::spawn(move || get(fe, "/p", ""));
        std::thread::sleep(MS(100));
        let (fast, resp) = get(fe, "/other", "");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
        assert!(fast < MS(250), "a second connection waited {fast:?} behind the pause");
        let (took, resp) = slow.join().expect("join");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
        assert!(took >= MS(380) && took < MS(1200), "{took:?}");
    });
}

#[test]
fn request_pause_with_an_expression_waits_that_many_ms_or_not_at_all() {
    let rules = "  http-request set-var(txn.p) req.hdr(x),mul(1)\n  http-request pause var(txn.p)\n";
    with_alcyon(rules, |fe| {
        let (took, resp) = get(fe, "/", "x: 400\r\n");
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");
        assert!(took >= MS(380) && took < MS(1200), "{took:?}");
        for x in ["x: 0\r\n", "x: -5\r\n", "x: abc\r\n", ""] {
            let (took, resp) = get(fe, "/", x);
            assert!(resp.starts_with("HTTP/1.1 200") && took < MS(250), "{x:?}: {took:?} {resp:?}");
        }
    });
}

#[test]
fn response_pause_holds_the_response() {
    let rules = "  http-response pause 400 if { status 200 }\n";
    with_alcyon(rules, |fe| {
        let (took, resp) = get(fe, "/", "");
        assert!(resp.starts_with("HTTP/1.1 200") && resp.ends_with("ok"), "{resp:?}");
        assert!(took >= MS(380) && took < MS(1200), "{took:?}");
    });
}

#[test]
fn sess_term_state_reads_the_state_of_the_stream_at_that_moment() {
    let rules = "  http-request deny if { path /deny }\n  http-request tarpit if { path /tar }\n  \
                 http-response set-header x-ts %[txn.sess_term_state]\n  \
                 http-after-response set-header x-as %[txn.sess_term_state]\n";
    with_alcyon(rules, |fe| {
        let (_, ok) = get(fe, "/", "");
        assert_eq!((header(&ok, "x-ts"), header(&ok, "x-as")), (Some("--"), Some("--")), "{ok:?}");
        let (_, deny) = get(fe, "/deny", "");
        assert!(deny.starts_with("HTTP/1.1 403") && header(&deny, "x-as") == Some("PR"), "{deny:?}");
        let (_, tar) = get(fe, "/tar", "");
        assert!(tar.starts_with("HTTP/1.1 500") && header(&tar, "x-as") == Some("PT"), "{tar:?}");
    });
}

/// T430 row 6: the termination flags are set before the reply of `return`, `deny` or `tarpit`
/// is formatted, so a `hdr` of it sees them. A `redirect` is not such a reply (measured on
/// `HAProxy 3.5-dev8-885761-29` on 2026-10-19: `LR`, `PR`, `PT`, and `/--` in the location).
#[test]
fn sess_term_state_in_the_headers_of_a_generated_reply() {
    let rules = "  http-request return status 200 hdr x-ts \"%[txn.sess_term_state]\" if { path /ret }\n  \
                 http-request deny hdr x-ts \"%[txn.sess_term_state]\" if { path /deny }\n  \
                 http-request tarpit hdr x-ts \"%[txn.sess_term_state]\" if { path /tar }\n  \
                 http-request redirect location \"/%[txn.sess_term_state]\" if { path /redir }\n";
    with_alcyon(rules, |fe| {
        for (path, want) in [("/ret", "LR"), ("/deny", "PR"), ("/tar", "PT")] {
            let (_, resp) = get(fe, path, "");
            assert_eq!(header(&resp, "x-ts"), Some(want), "{path}: {resp:?}");
        }
        let (_, resp) = get(fe, "/redir", "");
        assert_eq!(header(&resp, "location"), Some("/--"), "{resp:?}");
    });
}

/// `alcyon -c` on a frontend carrying `rule`: (exit code, stdout + stderr).
fn check(rule: &str) -> (Option<i32>, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind 127.0.0.1:1\n  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"
    );
    let mut file = NamedTempFile::new().expect("tmp");
    file.write_all(cfg.as_bytes()).expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(file.path()).output().expect("run alcyon -c");
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// Measured with `haproxy -c` (3.5-dev8-885761-29, 2026-10-18): both directions refuse an
/// expression that does not parse by its first character, and accept a fetch with a converter.
#[test]
fn an_expression_is_checked_in_both_directions() {
    for dir in ["request", "response"] {
        let (code, out) = check(&format!("http-{dir} pause nosuch"));
        assert_eq!(code, Some(1), "{dir}: {out}");
        assert!(
            out.contains(&format!("error detected in frontend 'fe' while parsing 'http-{dir} pause' rule : unexpected character 'n' in rule 'pause'.")),
            "{dir}: {out}"
        );
    }
    for rule in ["http-response pause var(txn.a)", "http-response pause res.hdr(x),mul(1)"] {
        let (code, out) = check(rule);
        assert_eq!(code, Some(0), "{rule}: {out}");
    }
}
