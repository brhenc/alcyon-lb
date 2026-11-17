// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request disable-l7-retry` and the stream's end on a server close
//! (`server_close_ends_stream`, proxy.rs).
//!
//! A server that answers at the request's head and closes, while the client is still
//! streaming the body, ends the stream at the first write of the request that cannot
//! reach it: the log keeps the answer's status, the termination is the server's close
//! (`SL--`), the rest of the body is read and dropped, and the client's connection is
//! kept (`chunked_body_errors::a_server_that_answers_at_the_head_and_closes_logs_a_server_close`).
//! The one exception is a request that may still be replayed on the answer -- a
//! `retry-on` backend with the request kept (`L7Retry::Armed`/`Saved`): its close is not
//! the stream's end.
//!
//! `http-request disable-l7-retry` takes the request out of that exception for the rest
//! of the request: since the fold of `HttpTxn::l7_off` into the enum, it is
//! `L7Retry::Disabled`, and it belongs in `server_close_ends_stream`'s `Off | Dead` arm,
//! not in the `Armed | Saved` one -- a disabled request on a `retry-on` backend ends the
//! stream at the close, `SL--`, and this test is red if `Disabled` were in the other arm.
//! The same request without the rule ends it as well: by the time the server closes, the
//! first write has already spent the retry copy (`l7_keep` keeps it only when the whole
//! request went at once, else `Dead`), so it is in the same arm. Measured on both
//! `HAProxy` 3.5-dev8-885761-29 and the base alcyon: both cases log `SL--` at the close,
//! status 200, the whole body out of the client. Set
//! `L7D_ORACLE=/path/to/haproxy` to run this test against `HAProxy`.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// The body parts' pause: the answer lands between them.
const PAUSE: Duration = Duration::from_millis(300);

/// A piece of the request: bytes to send, or a pause before the next ones.
#[derive(Clone)]
enum Part {
    Bytes(Vec<u8>),
    Pause,
}
use Part::{Bytes, Pause};

struct Proxy {
    child: Child,
    logs: mpsc::Receiver<String>,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers a `POST` at its head -- `200`, two bytes, `Connection: close` --
/// and lets the connection go, without the body.
fn early_close_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let mut req = Vec::new();
                let mut b = [0u8; 65536];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    addr
}

/// `f` logs to stdout as raw `local0`; `bd` is `retry-on 503` with
/// `http-request disable-l7-retry`, `bc` is `retry-on 503` without it. The body is relayed
/// as it arrives (no `option http-buffer-request`).
fn start() -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let sd = early_close_server();
    let sc = early_close_server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  \
         timeout client 6s\n  timeout server 5s\n  timeout http-request 5s\n\
         frontend f\n  bind {fe}\n  use_backend bd if {{ path /d }}\n  default_backend bc\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend bd\n  retries 1\n  retry-on 503\n  http-request disable-l7-retry\n  server s {sd}\n\
         backend bc\n  retries 1\n  retry-on 503\n  server s {sc}\n"
    )
    .expect("write");
    let bin = std::env::var("L7D_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, logs, fe, _cfg: cfg }
}

/// The line's `%TR/%Tw/%Tc/%Tr/%Ta`, `%ST`, `%B`, and `%tsc`, by position (the default
/// `httplog` format of `HAProxy` and Alcyon).
fn log_fields(l: &str) -> Option<([i64; 5], i64, i64, String)> {
    let f: Vec<&str> = l.split_whitespace().collect();
    let parts: Vec<&str> = f.get(4)?.split('/').collect();
    if parts.len() != 5 {
        return None;
    }
    let t = [parts[0].parse().ok()?, parts[1].parse().ok()?, parts[2].parse().ok()?, parts[3].parse().ok()?, parts[4].parse().ok()?];
    Some((t, f.get(5)?.parse().ok()?, f.get(6)?.parse().ok()?, f.get(9)?.to_string()))
}

/// The log line naming `path` (the `s` sentinel frontend's `<BADREQ>` lines never match).
fn log_of(p: &Proxy, path: &str) -> String {
    let want = format!("{path} HTTP/");
    while let Ok(l) = p.logs.recv_timeout(Duration::from_secs(3)) {
        if l.contains(&want) {
            return l;
        }
    }
    String::new()
}

fn esc(b: &[u8]) -> String {
    let s = b.escape_ascii().to_string();
    if s.len() > 300 {
        format!("{}...({} bytes)", &s[..300], b.len())
    } else {
        s
    }
}

/// The body the client got after the response head.
fn body_of(got: &[u8]) -> &[u8] {
    got.windows(4).position(|w| w == b"\r\n\r\n").map_or(&[][..], |i| &got[i + 4..])
}

/// Sends `parts`, half-closes the write side, then reads until the proxy closes: what came
/// back, how much of the request got out of the client, and how long the close took from
/// the last byte sent.
fn stream_body(p: &Proxy, parts: &[Part]) -> (Vec<u8>, usize, Duration) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(12))).unwrap();
    let mut sent = 0;
    for part in parts {
        match part {
            Bytes(b) => match c.write_all(b) {
                Ok(()) => sent += b.len(),
                Err(_) => break,
            },
            Pause => thread::sleep(PAUSE),
        }
    }
    let _ = c.shutdown(Shutdown::Write);
    let t0 = Instant::now();
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    (got, sent, t0.elapsed())
}

#[test]
fn a_disabled_l7_retry_is_not_the_exception_to_the_server_close() {
    let p = start();
    let clen = 4000;
    let mut wrong = Vec::new();
    // head, then 4 x 1000 with 300 ms pauses: the answer (at the head) and the server's
    // close land while the body is still coming. The client asks for no close.
    let head = |path: &str| format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {clen}\r\n\r\n").into_bytes();
    let mk_parts = |path: &str| {
        let head = head(path);
        let mut parts = vec![Bytes(head.clone())];
        for _ in 0..4 {
            parts.push(Pause);
            parts.push(Bytes(vec![b'a'; 1000]));
        }
        (parts, head.len())
    };
    for path in ["/d", "/c"] {
        let (parts, head_len) = mk_parts(path);
        let (got, sent, close) = stream_body(&p, &parts);
        let log = log_of(&p, path);
        let Some((timers, status, _bytes, tsc)) = log_fields(&log) else {
            wrong.push(format!("{path}: no log line within 3 s (last: {log:?})"));
            continue;
        };
        // The response is the server's: 200, two bytes, and no `Connection: close` of the
        // client's own (what the server closed is its side).
        let head_end = got.windows(4).position(|w| w == b"\r\n\r\n").map_or(got.len(), |i| i);
        let no_close = !got[..head_end].to_ascii_lowercase().windows(11).any(|w| w == b"connection:");
        // Both backends retry on 503; the only difference is the disable rule. The close
        // ends the stream in both: `SL--` at the write that cannot be made (under a
        // second), the rest of the body read and dropped. `/d` is red if `Disabled` were
        // not in `server_close_ends_stream`'s `Off | Dead` arm.
        let fine = got.starts_with(b"HTTP/1.1 200 OK\r\n") && body_of(&got) == b"ok" && no_close
            && status == 200 && sent == head_len + clen && tsc == "SL--" && timers[4] < 2000
            && close < Duration::from_millis(2500);
        if !fine {
            wrong.push(format!("{path}: got {} / sent {sent} / close after {} ms / log {log} (ST {status} T {timers:?} tsc {tsc})", esc(&got), close.as_millis()));
        }
    }
    assert!(wrong.is_empty(), "{} of 2 cases differ:\n{}", wrong.len(), wrong.join("\n"));
}
