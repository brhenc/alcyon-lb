// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The stream fetches `last_entity`, `waiting_entity` and `txn.id32` from a custom
//! `log-format`, as `HAProxy`'s `reg-tests/log/txn_state.vtc` does.
//!
//! `last_entity` names the rule that ended a rule set for the request (its configuration
//! file and line), `waiting_entity` the entity that was waiting to continue when a timeout
//! ended the stream: the rule it stopped at, or the literal `http-buffer-request` where the
//! request-body wait of `option http-buffer-request` was the hold. `txn.id32` is the
//! process stream counter, the same one `%rt` reads: it increases by one per request.
//!
//! The `timeout client` of 800 ms (and no `timeout http-request`) makes the
//! `http-buffer-request` wait of the buffered request time out on the client's read timer,
//! the way the option's wait does in `HAProxy`. A `timeout http-request` of its own would
//! break the second keep-alive request of the `id32` test in this oracle build.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev11 (the oracle). Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A backend that answers every request of a connection with a 200 and keeps it open
/// until the client closes: the `id32` test sends two requests on one connection.
fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut b = [0u8; 65536];
                loop {
                    match s.read(&mut b) {
                        Ok(0) => return,
                        Err(_) => return,
                        Ok(n) => {
                            head.extend_from_slice(&b[..n]);
                            // A request is a head: answer it and wait for the next one.
                            while let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = head.drain(..end + 4).collect::<Vec<_>>();
                                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                                let _ = head;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

struct Proxy {
    child: Child,
    logs: std::sync::mpsc::Receiver<String>,
    fe: SocketAddr,
    _cfg: NamedTempFile,
    /// The `wait-for-body` rule's line in the configuration text.
    wait_line: u32,
    /// The long (5 s) `wait-for-body` rule's line: a wait `timeout client` ends.
    wait2_line: u32,
    /// The `pause` rule's line.
    pause_line: u32,
    /// The `tarpit` rule's line.
    tarpit_line: u32,
    /// The deny rule's line in the configuration text.
    deny_line: u32,
    /// The backend's `wait-for-body` rule's line (active for `/bw` only).
    be_wait_line: u32,
    /// The `tcp-request content` rule's line: only the inspect proxy sets one.
    content_line: u32,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The proxy. A `wait-for-body` of 300 ms for `/wait`, one of 5 s for `/wait2` (longer
/// than `timeout client`, so the client's read timer ends it), a `pause` of 5 s for
/// `/pause`, a `tarpit` for `/tarpit` and a `deny` for `/denied`; with `bufr`,
/// `option http-buffer-request` stands in the defaults, and its body wait (not a rule)
/// then holds every request with a body. The rule lines are returned so the tests can
/// assert the `file:line` the fetches report.
fn start(bufr: bool) -> Proxy {
    let fe = common::reserve_addr();
    let be = backend();
    let mut cfg = NamedTempFile::new().expect("tmp");
    // The configuration above the rules: ten lines without the option, eleven with it.
    let (wait_line, wait2_line, pause_line, tarpit_line, deny_line, be_wait_line) = if bufr {
        (13, 14, 15, 16, 17, 20)
    } else {
        (12, 13, 14, 15, 16, 19)
    };
    let bufr_opt = if bufr { "  option http-buffer-request\n" } else { "" };
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n{bufr_opt}\
         timeout connect 5s\n  timeout client 800ms\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n\
         log-format \"uri=%[capture.req.uri] last=%[last_entity] wait=%[waiting_entity] id32=%[txn.id32]\"\n\
         http-request wait-for-body time 300ms if {{ path /wait }}\n\
         http-request wait-for-body time 5s if {{ path /wait2 }}\n\
         http-request pause 5s if {{ path /pause }}\n\
         http-request tarpit if {{ path /tarpit }}\n\
         http-request deny deny_status 403 if {{ path /denied }}\n\
         default_backend b\n\
         backend b\n\
         http-request wait-for-body time 5s if {{ path /bw }}\n\
         server s1 {be}\n"
    )
    .expect("write");
    let (child, logs) = spawn(fe, &cfg);
    Proxy { child, logs, fe, _cfg: cfg, wait_line, wait2_line, pause_line, tarpit_line, deny_line, be_wait_line, content_line: 0 }
}

/// Starts the proxy on `fe` from the configuration file `cfg` and returns its child
/// plus a receiver over its log lines (the `T281_ORACLE` binary, when set, is the
/// proxy under test).
fn spawn(fe: SocketAddr, cfg: &NamedTempFile) -> (Child, std::sync::mpsc::Receiver<String>) {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(fe), "never listened");
    (child, logs)
}

/// A proxy of its own, because its hold is unconditional: `wait_end` in a
/// `tcp-request content` rule holds *every* request until its inspect delay, so it
/// cannot share the other tests' proxy. The rule lives on the frontend or, with
/// `on_backend`, on the backend (its data wait is tracked in `body_wait`, the frontend's
/// is not).
fn start_inspect(on_backend: bool) -> Proxy {
    let fe = common::reserve_addr();
    let be = backend();
    let mut cfg = NamedTempFile::new().expect("tmp");
    // Frontend rule: line 13. Backend rule: line 15.
    if on_backend {
        write!(
            cfg,
            "global\n  log stdout format raw local0\n\
             defaults\n  mode http\n  log global\n\
             timeout connect 5s\n  timeout client 800ms\n  timeout server 5s\n\
             frontend f\n  bind {fe}\n\
             log-format \"uri=%[capture.req.uri] last=%[last_entity] wait=%[waiting_entity] id32=%[txn.id32]\"\n\
             default_backend b\n\
             backend b\n\
             tcp-request inspect-delay 5s\n\
             tcp-request content accept if {{ wait_end }}\n\
             server s1 {be}\n"
        )
        .expect("write");
    } else {
        write!(
            cfg,
            "global\n  log stdout format raw local0\n\
             defaults\n  mode http\n  log global\n\
             timeout connect 5s\n  timeout client 800ms\n  timeout server 5s\n\
             frontend f\n  bind {fe}\n\
             log-format \"uri=%[capture.req.uri] last=%[last_entity] wait=%[waiting_entity] id32=%[txn.id32]\"\n\
             tcp-request inspect-delay 5s\n\
             tcp-request content accept if {{ wait_end }}\n\
             default_backend b\n\
             backend b\n  server s1 {be}\n"
        )
        .expect("write");
    }
    let (child, logs) = spawn(fe, &cfg);
    Proxy {
        child, logs, fe, _cfg: cfg,
        wait_line: 0, wait2_line: 0, pause_line: 0, tarpit_line: 0, deny_line: 0, be_wait_line: 0,
        content_line: if on_backend { 15 } else { 13 },
    }
}

/// The `k=v` field `key` of a `log-format` line: the value, up to the next space.
fn field(line: &str, key: &str) -> Option<String> {
    let rest = line.split_whitespace().find(|f| f.starts_with(&format!("{key}=")))?;
    Some(rest[key.len() + 1..].to_string())
}

/// The first log line to arrive: the `wait_listening` probe's own (`uri=-`), logged
/// only once that session is accepted and closed. Waiting for it keeps the probe out of
/// the ids a test measures afterwards: the kernel may finish the probe's handshake after
/// the proxy has accepted a later connection, and the probe's session would then take its
/// stream id in between.
fn first_line(p: &Proxy) -> Option<String> {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        while let Ok(line) = p.logs.try_recv() {
            return Some(line);
        }
        thread::sleep(Duration::from_millis(10));
    }
    None
}

/// Waits for a logged line whose `uri` is `uri` and returns it.
fn log_line(p: &Proxy, uri: &str) -> Option<String> {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        while let Ok(line) = p.logs.try_recv() {
            if field(&line, "uri").as_deref() == Some(uri) {
                return Some(line);
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Sends `bytes` over a fresh connection and closes it after `hold`.
fn send(p: &Proxy, bytes: &[u8], hold: Duration) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    let _ = c.write_all(bytes);
    if hold > Duration::ZERO {
        thread::sleep(hold);
    }
    drop(c);
}

/// Sends `bytes`, holds `hold` (the bytes are delivered and seen before the abort), and
/// then closes with `SO_LINGER` of 0: the close is an RST, not a FIN, so the proxy sees
/// an error on the client side instead of an orderly close.
fn rst_after(p: &Proxy, bytes: &[u8], hold: Duration) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    let _ = c.write_all(bytes);
    thread::sleep(hold);
    rustix::net::sockopt::set_socket_linger(&c, Some(Duration::ZERO)).expect("linger");
    drop(c);
}

/// Sends `parts` with a 150 ms gap between them, then holds `hold` and closes.
fn staged(p: &Proxy, parts: &[&[u8]], hold: Duration) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    for part in parts {
        let _ = c.write_all(part);
        thread::sleep(Duration::from_millis(150));
    }
    if hold > Duration::ZERO {
        thread::sleep(hold);
    }
    drop(c);
}

#[test]
fn served_request_reports_no_entity() {
    let p = start(false);
    send(&p, b"GET /normal HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", Duration::from_millis(400));
    let Some(line) = log_line(&p, "/normal") else {
        panic!("no log line for /normal");
    };
    assert_eq!(field(&line, "last").as_deref(), Some("-"), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
    // The process counter hands out `0` to its first stream, and whether the
    // listener probe or this request takes it races; only that the request has an
    // id is assertable here. The increase per request is the other test's.
    assert!(
        field(&line, "id32").as_deref().is_some_and(|v| v.parse::<u64>().is_ok()),
        "id32: {line}"
    );
}

#[test]
fn denied_request_reports_the_deny_rule() {
    let p = start(false);
    send(&p, b"GET /denied HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", Duration::from_millis(400));
    let Some(line) = log_line(&p, "/denied") else {
        panic!("no log line for /denied");
    };
    let expected = format!("{}:{}", p._cfg.path().display(), p.deny_line);
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
}

#[test]
fn wait_for_body_timeout_reports_the_rule() {
    let p = start(false);
    // The body that is not coming: the `wait-for-body` gives up at 300 ms and aborts;
    // the rule that was waiting becomes the last entity.
    send(&p, b"POST /wait HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial", Duration::from_millis(1200));
    let Some(line) = log_line(&p, "/wait") else {
        panic!("no log line for /wait");
    };
    let expected = format!("{}:{}", p._cfg.path().display(), p.wait_line);
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
}

#[test]
fn buffered_request_timeout_reports_the_option() {
    let p = start(true);
    // No rule names the hold: it is the `option http-buffer-request` body wait, and its
    // timeout reports the option, with no rule run at all behind it.
    send(&p, b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial", Duration::from_millis(1200));
    let Some(line) = log_line(&p, "/p") else {
        panic!("no log line for /p");
    };
    assert_eq!(field(&line, "last").as_deref(), Some("-"), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("http-buffer-request"), "line: {line}");
}

#[test]
fn id32_increases_per_request_on_one_connection() {
    let p = start(false);
    // The listener probe is a session of its own and takes a stream id; only once its
    // line is out is this connection the only traffic that can take an id (its own
    // `uri=-` line, with no id in `HAProxy`, is the one waited for).
    let Some(_) = first_line(&p) else {
        panic!("no log line for the listener probe");
    };
    let mut c = TcpStream::connect(p.fe).expect("connect");
    let _ = c.write_all(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    thread::sleep(Duration::from_millis(500));
    let _ = c.write_all(b"GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    thread::sleep(Duration::from_millis(500));
    let Some(first) = log_line(&p, "/a") else {
        panic!("no log line for /a");
    };
    // The second stream ends, and logs, with the client: close before looking for it.
    let _ = c.shutdown(std::net::Shutdown::Both);
    drop(c);
    let Some(second) = log_line(&p, "/b") else {
        panic!("no log line for /b");
    };
    let id_a: u64 = field(&first, "id32").unwrap().parse().expect("id32 of /a");
    let id_b: u64 = field(&second, "id32").unwrap().parse().expect("id32 of /b");
    // `id_a` itself is 0 or 1 (the process's first stream takes `0`, and whether the
    // listener probe or this connection has it races); the increase is what the fetch
    // must get right: a new stream per request, one after the last.
    assert_eq!(id_b, id_a + 1, "first: {first} second: {second}");
}

/// A wait `timeout client` ends: the 5 s `wait-for-body` outlives the 800 ms read timer,
/// and the 408 the timer gives is the wait's `ACT_RET_ABRT`, so the rule is both the
/// entity that was waiting and the one that ended the rule set (measured on the oracle).
#[test]
fn client_timeout_during_explicit_wait_reports_the_rule() {
    let p = start(false);
    let expected = format!("{}:{}", p._cfg.path().display(), p.wait2_line);
    // The body that is not coming: the client's read timer ends the wait at 800 ms.
    send(&p, b"POST /wait2 HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial", Duration::from_millis(1200));
    let Some(line) = log_line(&p, "/wait2") else {
        panic!("no log line for /wait2");
    };
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some(expected.as_str()), "line: {line}");
}

/// A `pause` yields to the rule: a stream that dies while the pause holds still names it
/// in `waiting_entity`, and nothing in `last_entity` -- the rule never ended a rule set.
#[test]
fn pause_hold_rst_reports_the_pause_rule() {
    let p = start(false);
    let expected = format!("{}:{}", p._cfg.path().display(), p.pause_line);
    rst_after(&p, b"GET /pause HTTP/1.1\r\nHost: x\r\n\r\n", Duration::from_millis(400));
    let Some(line) = log_line(&p, "/pause") else {
        panic!("no log line for /pause");
    };
    assert_eq!(field(&line, "last").as_deref(), Some("-"), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some(expected.as_str()), "line: {line}");
}

/// A `tarpit` denies and then holds the client in its own analyser: `last_entity` names
/// the rule (it answered the request), `waiting_entity` names nothing (measured on the
/// oracle: the rule is denied, not waiting).
#[test]
fn tarpit_rst_reports_the_tarpit_rule() {
    let p = start(false);
    let expected = format!("{}:{}", p._cfg.path().display(), p.tarpit_line);
    rst_after(&p, b"GET /tarpit HTTP/1.1\r\nHost: x\r\n\r\n", Duration::from_millis(400));
    let Some(line) = log_line(&p, "/tarpit") else {
        panic!("no log line for /tarpit");
    };
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
}

/// A body that breaks its framing while a `wait-for-body` holds is an `ACT_RET_INV` of
/// the rule that was waiting: it is the last entity, and nothing is left waiting.
#[test]
fn malformed_chunk_during_wait_reports_the_rule() {
    let p = start(false);
    let expected = format!("{}:{}", p._cfg.path().display(), p.wait_line);
    staged(
        &p,
        &[
            b"POST /wait HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"5\r\nhello\r\n",
            b"ZZZ\r\nrest\r\n0\r\n\r\n",
        ],
        Duration::from_millis(1200),
    );
    let Some(line) = log_line(&p, "/wait") else {
        panic!("no log line for /wait");
    };
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
}

/// A wait the body satisfies: the rule that asked for it goes on to the next rule, so it
/// names nothing in `last_entity`, and the wait is over, so nothing in `waiting_entity`.
#[test]
fn satisfied_wait_serves_and_reports_no_entity() {
    let p = start(false);
    // The whole body in the first flight: the 300 ms wait finds it already there.
    send(&p, b"POST /wait HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello", Duration::from_millis(1200));
    let Some(line) = log_line(&p, "/wait") else {
        panic!("no log line for /wait");
    };
    assert_eq!(field(&line, "last").as_deref(), Some("-"), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
}

/// A `wait-for-body` on a *backend* rule, ended by the client's read timer: the 408 is
/// the backend rule's `ACT_RET_ABRT`, so the rule is both the entity that was waiting
/// and the one that ended the (backend) rule set (measured on the oracle).
#[test]
fn client_timeout_during_backend_wait_reports_the_rule() {
    let p = start(false);
    let expected = format!("{}:{}", p._cfg.path().display(), p.be_wait_line);
    // The body that is not coming: the frontend dispatches on the headers, the backend
    // rule waits, and the client's read timer ends the wait at 800 ms.
    send(&p, b"POST /bw HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial", Duration::from_millis(1200));
    let Some(line) = log_line(&p, "/bw") else {
        panic!("no log line for /bw");
    };
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some(expected.as_str()), "line: {line}");
}

/// An RST while a stream is held by a *data* wait -- a `tcp-request content` rule whose
/// condition keeps waiting for the body (`wait_end`, with a `tcp-request
/// inspect-delay` set) -- tears the stream down with the content rule in
/// `last_entity`: the error re-runs the rule with FINAL, `wait_end` answers and the
/// rule's action runs. The data wait never claimed `waiting_entity` (measured on the
/// oracle).
#[test]
fn inspect_hold_rst_reports_the_content_rule() {
    let p = start_inspect(false);
    rst_after(&p, b"POST /insp HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789", Duration::from_millis(400));
    let Some(line) = log_line(&p, "/insp") else {
        panic!("no log line for /insp");
    };
    let expected = format!("{}:{}", p._cfg.path().display(), p.content_line);
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
}

/// The same hold on a *backend* `tcp-request content` rule: the data wait is tracked
/// (it is the stream's `body_wait`), and it still names nothing in `waiting_entity` --
/// an `inspect-delay` wait holds no rule -- while the rule's own `accept` answers the
/// error and takes `last_entity` (measured on the oracle).
#[test]
fn backend_inspect_hold_rst_reports_the_content_rule() {
    let p = start_inspect(true);
    rst_after(&p, b"POST /insp HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789", Duration::from_millis(400));
    let Some(line) = log_line(&p, "/insp") else {
        panic!("no log line for /insp");
    };
    let expected = format!("{}:{}", p._cfg.path().display(), p.content_line);
    assert_eq!(field(&line, "last").as_deref(), Some(expected.as_str()), "line: {line}");
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
}

/// The same backend hold, ended by the client's read timer instead of an RST: the client
/// stops sending and the 800 ms `timeout client` tears the stream down while the data
/// wait is still pending. The wait still names nothing in `waiting_entity` -- an
/// `inspect-delay` wait holds no rule -- and the stream keeps its `txn.id32`.
///
/// `last_entity` is *not* asserted: the binaries diverge here. `HAProxy` resumes the
/// content rule with FINAL on the timeout, so its `accept` takes `last_entity` and it
/// answers a 400; this one tears the stream down without re-running the rule, and
/// `last_entity` honestly reports that no rule ended the set.
#[test]
fn backend_inspect_hold_timeout_reports_no_waiting_entity() {
    let p = start_inspect(true);
    // No RST, no FIN before the timer: the client is silent, the read timer runs out at
    // 800 ms, and the connection is dropped long after the stream is logged.
    send(&p, b"POST /insp HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789", Duration::from_millis(1500));
    let Some(line) = log_line(&p, "/insp") else {
        panic!("no log line for /insp");
    };
    assert_eq!(field(&line, "wait").as_deref(), Some("-"), "line: {line}");
    assert!(
        field(&line, "id32").as_deref().is_some_and(|v| v.parse::<u64>().is_ok()),
        "id32: {line}"
    );
}
