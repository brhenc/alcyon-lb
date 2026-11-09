// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Rules that edit `Content-Length`, `Transfer-Encoding` or `Connection` (T439).
//!
//! `HAProxy` reads these headers into the message flags when it parses a message, takes
//! `close` and `keep-alive` out of `Connection` there (`h1_parse_connection_header`, so no
//! rule sees them), and reads the headers again when it writes the message out, after the
//! rules (`h1_process_emit_headers` / `h1_make_eoh` in `src/mux_h1.c`): a framing header the
//! message was not framed by is not written, a response left with no length is closed after,
//! and a `close` a rule wrote closes the connection it goes out on.
//!
//! Every row was measured on `HAProxy` 3.5-dev8 (`~/ibex-worktrees/review/t439-oracle/`,
//! `probe.py`): one request on a new connection, the heads the server saw, the bytes the
//! client got within 500 ms, and whether the client connection was closed by then.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

/// `(rules, request, server response, heads the server saw, what the client got, closed)`.
type Row = (&'static str, &'static [u8], &'static [u8], &'static [&'static str], &'static [u8], bool);

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const SRV_GET: &[&str] = &["GET / HTTP/1.1\r\nhost: a"];
const CLI_OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

const ROWS: &[Row] = &[
    // T439 row 1: the response loses its length, so it is closed after.
    ("http-response del-header content-length", GET, OK, SRV_GET, b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nok", true),
    // The same for an HTTP/1.0 client that asked to keep its connection.
    (
        "http-response del-header content-length",
        b"GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
        OK,
        &["GET / HTTP/1.0\r\nhost: a\r\nconnection: keep-alive"],
        b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // And for a response to HEAD, which has no body but had a length.
    (
        "http-response del-header content-length",
        b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
        &["HEAD / HTTP/1.1\r\nhost: a"],
        b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n",
        true,
    ),
    // T439 row 2: a `close` a response rule writes closes the client connection.
    ("http-response set-header connection close", GET, OK, SRV_GET, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok", true),
    // Also when the server had sent one (which no rule sees).
    (
        "http-response set-header connection close",
        GET,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // Also on a 204.
    (
        "http-response set-header connection close",
        GET,
        b"HTTP/1.1 204 No Content\r\n\r\n",
        SRV_GET,
        b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n",
        true,
    ),
    // Also when it was written before a `wait-for-body`.
    (
        "http-response set-header connection close\n  http-response wait-for-body time 1s",
        GET,
        OK,
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // The server's own `close` does not close the client connection, through a wait either.
    ("http-response wait-for-body time 1s", GET, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", SRV_GET, CLI_OK, false),
    ("http-response del-header connection", GET, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", SRV_GET, CLI_OK, false),
    // The rules do not see the server's `close`.
    (
        "http-response set-header x-n \"%[res.hdr_cnt(connection)]/%[res.hdr(connection)]\"",
        GET,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-n: 0/\r\n\r\nok",
        false,
    ),
    // A `Transfer-Encoding` a rule adds to a response framed by its length is not written.
    ("http-response set-header transfer-encoding chunked", GET, OK, SRV_GET, CLI_OK, false),
    // T439 row 3: a `close` a request rule writes goes to the server.
    ("http-request set-header connection close", GET, OK, &["GET / HTTP/1.1\r\nhost: a\r\nconnection: close"], CLI_OK, false),
    (
        "http-request set-header connection close",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\nconnection: close"],
        CLI_OK,
        false,
    ),
    // Also when the client had sent one (which no rule sees), and the client connection
    // still closes for the client's.
    (
        "http-request set-header connection close",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\nconnection: close"],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // The client's own `close` does not go to the server.
    (
        "http-request del-header connection",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        OK,
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // The rules do not see the client's `close`.
    (
        "http-request set-header x-n \"%[req.hdr_cnt(connection)]/%[req.hdr(connection)]\"",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\nx-n: 0/"],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // T439 row 4: a `Content-Length` a rule adds to a request without one is not written.
    ("http-request set-header content-length 0", GET, OK, SRV_GET, CLI_OK, false),
    // One the request had is.
    (
        "http-request set-header content-length 0",
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\ncontent-length: 0"],
        CLI_OK,
        false,
    ),
    // Nor a `Transfer-Encoding` added to a request without a body.
    ("http-request set-header transfer-encoding chunked", GET, OK, SRV_GET, CLI_OK, false),
    // T442 row 3: a length a rule gives a request that had none to send (`Content-Length:
    // 0`) closes the server connection after it (`h1_make_eoh`: "C-L without data"). The
    // server reads no body bytes after the head (the second entry).
    (
        "http-request set-header content-length 2",
        b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\ncontent-length: 2\r\nconnection: close", ""],
        CLI_OK,
        false,
    ),
    // T442 row 4b: a second `Content-Length` a rule adds is not written, on either side.
    (
        "http-request add-header content-length 5",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
        OK,
        &["POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 5"],
        CLI_OK,
        false,
    ),
    ("http-response add-header content-length 2", GET, OK, SRV_GET, CLI_OK, false),
    // T442 row 2: a chunked response whose `Transfer-Encoding` a rule removed goes with its
    // chunk framing taken off (sizes, extensions, the last chunk and the trailers), and is
    // closed after: nothing else tells the client where it ends.
    ("http-response del-header transfer-encoding", GET, CHUNKED_OK, SRV_GET, CLI_RAW_OK, true),
    (
        "http-response del-header transfer-encoding",
        GET,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n1\r\nx\r\n3;e=1\r\nabc\r\n0\r\nt: 1\r\n\r\n",
        SRV_GET,
        b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nokxabc",
        true,
    ),
    // The same when the body comes in pieces (`\0`: the server waits 150 ms), each cut
    // inside the framing.
    (
        "http-response del-header transfer-encoding",
        GET,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n1\0\r\nx\r\n3;e=1\r\nab\0c\r\n0\r\nt: 1\r\n\0\r\n",
        SRV_GET,
        b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nokxabc",
        true,
    ),
    // A head that comes alone, its body after it has gone.
    (
        "http-response del-header transfer-encoding",
        GET,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\x002\r\nok\r\n0\r\n\r\n",
        SRV_GET,
        CLI_RAW_OK,
        true,
    ),
    // For an HTTP/1.0 client that asked to keep its connection, and with a length a rule
    // wrote (not one the response was framed by, so not written).
    (
        "http-response del-header transfer-encoding",
        b"GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
        CHUNKED_OK,
        &["GET / HTTP/1.0\r\nhost: a\r\nconnection: keep-alive"],
        CLI_RAW_OK,
        true,
    ),
    ("http-response del-header transfer-encoding\nhttp-response set-header content-length 2", GET, CHUNKED_OK, SRV_GET, CLI_RAW_OK, true),
    // A chunk that breaks its framing after the start: what came before it has gone, and the
    // connection closes.
    (
        "http-response del-header transfer-encoding",
        GET,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n\0zz\r\n",
        SRV_GET,
        CLI_RAW_OK,
        true,
    ),
    // A response to HEAD has no body to take the framing off.
    (
        "http-response del-header transfer-encoding",
        b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        &["HEAD / HTTP/1.1\r\nhost: a"],
        b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n",
        true,
    ),
    // T442 row 4a: a `keep-alive` a request rule writes keeps the server connection that
    // `option http-server-close` would close (`h1_set_srv_conn_mode`: no `H1_MF_CONN_KAL`).
    ("option http-server-close\nhttp-request set-header connection keep-alive", GET, OK, SRV_GET, CLI_OK, false),
    // With a `close` beside it, the close wins.
    (
        "option http-server-close\nhttp-request set-header connection \"keep-alive, close\"",
        GET,
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\nconnection: close"],
        CLI_OK,
        false,
    ),
    // An HTTP/1.0 request is sent with the `keep-alive` it then needs.
    (
        "option http-server-close\nhttp-request set-header connection keep-alive",
        b"GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
        OK,
        &["GET / HTTP/1.0\r\nhost: a\r\nconnection: keep-alive"],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
        false,
    ),
    // `option httpclose` in the frontend leaves the server connection alone; the client
    // connection still closes for a request rule's `keep-alive`.
    (
        "option httpclose\nhttp-request set-header connection keep-alive",
        GET,
        OK,
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // A response rule's `keep-alive` keeps the client connection that `option httpclose`
    // would close (`h1_set_cli_conn_mode`).
    ("option httpclose\nhttp-response set-header connection keep-alive", GET, OK, SRV_GET, CLI_OK, false),
    (
        "option httpclose\nhttp-response set-header connection \"foo, keep-alive\"",
        GET,
        OK,
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: foo\r\n\r\nok",
        false,
    ),
    // Not one the client closes: its own `close`, or HTTP/1.0 without `keep-alive`.
    (
        "option httpclose\nhttp-response set-header connection keep-alive",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        OK,
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    (
        "option httpclose\nhttp-response set-header connection keep-alive",
        b"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
        OK,
        &["GET / HTTP/1.0\r\nhost: a\r\nconnection: keep-alive"],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    ),
    // T442 row 5: a `Connection` a rule wrote is counted as `hdr` reads it, on both sides.
    (
        "http-request set-header connection close\nhttp-request set-header x-n \"%[req.hdr_cnt(connection)]/%[req.hdr(connection)]/%[req.fhdr_cnt(connection)]\"",
        GET,
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\nx-n: 1/close/1\r\nconnection: close"],
        CLI_OK,
        false,
    ),
    (
        "http-request set-header connection \"foo, keep-alive\"\nhttp-request set-header x-n \"%[req.hdr_cnt(connection)]/%[req.hdr(connection)]/%[req.fhdr_cnt(connection)]\"",
        GET,
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\nconnection: foo\r\nx-n: 2/keep-alive/1"],
        CLI_OK,
        false,
    ),
    (
        "http-response set-header connection close\nhttp-response set-header x-n \"%[res.hdr_cnt(connection)]/%[res.hdr(connection)]/%[res.fhdr_cnt(connection)]\"",
        GET,
        OK,
        SRV_GET,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-n: 1/close/1\r\nconnection: close\r\n\r\nok",
        true,
    ),
];

const CHUNKED_OK: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";
const CLI_RAW_OK: &[u8] = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nok";

/// A server that records each request head it reads (and the two body bytes of one with
/// `content-length: 2`), and answers each with `resp` (in pieces 150 ms apart where it
/// has a NUL byte).
fn backend(resp: &'static [u8], got: Arc<Mutex<Vec<String>>>) -> SocketAddr {
    backend_counted(resp, got, Arc::new(AtomicUsize::new(0)))
}

/// [`backend`], counting in `conns` the connections it accepts.
fn backend_counted(resp: &'static [u8], got: Arc<Mutex<Vec<String>>>, conns: Arc<AtomicUsize>) -> SocketAddr {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("backend addr");
    thread::spawn(move || {
        for c in ls.incoming() {
            let Ok(mut c) = c else { return };
            conns.fetch_add(1, Ordering::SeqCst);
            let got = Arc::clone(&got);
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 16384];
                loop {
                    let n = match c.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..at]).into_owned();
                        let mut tail = buf.split_off(at + 4);
                        if head.to_ascii_lowercase().contains("content-length: 2") {
                            let take = tail.len().min(2);
                            got.lock().unwrap().push(head);
                            got.lock().unwrap().push(String::from_utf8_lossy(&tail[..take]).into_owned());
                            tail.drain(..take);
                        } else {
                            got.lock().unwrap().push(head);
                        }
                        buf = tail;
                        for (i, piece) in resp.split(|&b| b == 0).enumerate() {
                            if i > 0 {
                                thread::sleep(Duration::from_millis(150));
                            }
                            if c.write_all(piece).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// What `row` gives through alcyon: the heads the server saw, the bytes the client got, and
/// whether the client connection closed.
fn run(rules: &str, req: &[u8], resp: &'static [u8]) -> (Vec<String>, Vec<u8>, bool) {
    run_parts(rules, &[req], resp)
}

/// [`run`] for a request sent in `parts`, 200 ms apart.
fn run_parts(rules: &str, parts: &[&[u8]], resp: &'static [u8]) -> (Vec<String>, Vec<u8>, bool) {
    let (heads, out, closed, _) = run_counted(rules, parts, resp);
    (heads, out, closed)
}

/// [`run_parts`], and how many connections the server accepted.
fn run_counted(rules: &str, parts: &[&[u8]], resp: &'static [u8]) -> (Vec<String>, Vec<u8>, bool, usize) {
    let got = Arc::new(Mutex::new(Vec::new()));
    let conns = Arc::new(AtomicUsize::new(0));
    let be = backend_counted(resp, Arc::clone(&got), Arc::clone(&conns));
    let fe = common::reserve_addr();
    let rules: String = rules.lines().fold(String::new(), |mut out, l| {
        out.push_str("  ");
        out.push_str(l.trim());
        out.push('\n');
        out
    });
    let cfg = format!(
        "global\n  tune.alcyon.h1-lowercase-headers on\n  nbthread 1\ndefaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\nfrontend f\n  bind {fe}\n{rules}  default_backend b\nbackend b\n  server s1 {be}\n"
    );
    let mut f = NamedTempFile::new().expect("config");
    f.write_all(cfg.as_bytes()).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon did not listen");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            thread::sleep(Duration::from_millis(200));
        }
        c.write_all(part).expect("send");
    }
    let mut out = Vec::new();
    let mut closed = false;
    let mut chunk = [0u8; 16384];
    loop {
        match c.read(&mut chunk) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    common::stop(&mut child);
    let heads = got.lock().unwrap().clone();
    (heads, out, closed, conns.load(Ordering::SeqCst))
}

#[test]
fn rules_that_edit_framing_or_connection_are_read_again_as_haproxy_does() {
    let mut bad = Vec::new();
    for &(rules, req, resp, srv, cli, closed) in ROWS {
        let (got_srv, got_cli, got_closed) = run(rules, req, resp);
        let want_srv: Vec<String> = srv.iter().map(|s| (*s).to_string()).collect();
        if got_srv != want_srv || got_cli != cli || got_closed != closed {
            bad.push(format!(
                "{rules:?} on {:?}:\n  server saw {got_srv:?}, want {want_srv:?}\n  client got {:?}, want {:?}\n  closed {got_closed}, want {closed}",
                String::from_utf8_lossy(req),
                String::from_utf8_lossy(&got_cli),
                String::from_utf8_lossy(cli)
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} rows differ from HAProxy:\n{}", bad.len(), ROWS.len(), bad.join("\n"));
}

/// `(rules, request in parts, heads the server saw, what the client got)`: the client
/// connection stays open on each.
type BodyRow = (&'static str, &'static [&'static [u8]], &'static [&'static str], &'static [u8]);

const SRV_POST0: &str = "POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 0";

/// T442 row 1: a request whose rules removed the header its body was framed by. `HAProxy`
/// writes `content-length: 0` and drops the body (`h1_make_eoh`, `H1S_F_BODYLESS_REQ`):
/// forwarded with no length, the body is read by the server as the next request (request
/// smuggling). Measured on 3.5-dev8 (`/tmp/t442/p442b.py`, T442).
const BODY_ROWS: &[BodyRow] = &[
    (
        "http-request del-header content-length",
        &[b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 28\r\n\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n"],
        &[SRV_POST0],
        CLI_OK,
    ),
    (
        "http-request del-header transfer-encoding",
        &[b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1c\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n\r\n0\r\n\r\n"],
        &[SRV_POST0],
        CLI_OK,
    ),
    // An empty body too: the length is written.
    ("http-request del-header content-length", &[b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n"], &[SRV_POST0], CLI_OK),
    // The connection is kept: the request after the dropped body is the next one.
    (
        "http-request del-header content-length",
        &[b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhelloGET /y HTTP/1.1\r\nHost: a\r\n\r\n"],
        &[SRV_POST0, "GET /y HTTP/1.1\r\nhost: a"],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nokHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
    ),
    // Also when the body arrives after the head has gone, in pieces.
    (
        "http-request del-header content-length",
        &[b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 28\r\n\r\nGET /x", b" HTTP/1.1\r\nHost: a\r\n\r\n", b"GET /y HTTP/1.1\r\nHost: a\r\n\r\n"],
        &[SRV_POST0, "GET /y HTTP/1.1\r\nhost: a"],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nokHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
    ),
    (
        "http-request del-header transfer-encoding",
        &[b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", b"1c\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n\r\n", b"0\r\n\r\nGET /y HTTP/1.1\r\nHost: a\r\n\r\n"],
        &[SRV_POST0, "GET /y HTTP/1.1\r\nhost: a"],
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nokHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
    ),
];

#[test]
fn a_request_whose_rules_removed_its_framing_goes_with_no_body_as_haproxy_sends_it() {
    let mut bad = Vec::new();
    for &(rules, parts, srv, cli) in BODY_ROWS {
        let (got_srv, got_cli, got_closed) = run_parts(rules, parts, OK);
        let want_srv: Vec<String> = srv.iter().map(|s| (*s).to_string()).collect();
        if got_srv != want_srv || got_cli != cli || got_closed {
            bad.push(format!(
                "{rules:?} on {:?}:\n  server saw {got_srv:?}, want {want_srv:?}\n  client got {:?}, want {:?}\n  closed {got_closed}, want false",
                String::from_utf8_lossy(&parts.concat()),
                String::from_utf8_lossy(&got_cli),
                String::from_utf8_lossy(cli)
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} rows differ from HAProxy:\n{}", bad.len(), BODY_ROWS.len(), bad.join("\n"));
}

fn h2_frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame length");
    let mut f = len.to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[kind, flags]);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Literal header fields without indexing, new names.
fn h2_block(list: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (n, v) in list {
        out.extend_from_slice(&[0, u8::try_from(n.len()).expect("name")]);
        out.extend_from_slice(n.as_bytes());
        out.push(u8::try_from(v.len()).expect("value"));
        out.extend_from_slice(v.as_bytes());
    }
    out
}

/// T442 row 1 over HTTP/2: the client's `content-length` removed by a rule, the request goes
/// to the server with `content-length: 0` and no body, as `HAProxy` sends it (measured on
/// 3.5-dev8 with `curl --http2-prior-knowledge -d`, `/tmp/t442/h2probe.sh`). The body comes
/// in two DATA frames, the second after the head has gone.
/// The heads the server saw of one HTTP/2 POST to a `proto h2` frontend with `rules`, a
/// `content-length: 28` and its body in two DATA frames, the second 300 ms after the first.
fn h2_post(rules: &str) -> Vec<String> {
    let got = Arc::new(Mutex::new(Vec::new()));
    let be = backend(OK, Arc::clone(&got));
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  tune.alcyon.h1-lowercase-headers on\n  nbthread 1\ndefaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\nfrontend f\n  bind {fe} proto h2\n  {rules}\n  default_backend b\nbackend b\n  server s1 {be}\n"
    );
    let mut f = NamedTempFile::new().expect("config");
    f.write_all(cfg.as_bytes()).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon did not listen");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    c.write_all(&h2_frame(4, 0, 0, &[])).unwrap();
    c.write_all(&h2_frame(4, 1, 0, &[])).unwrap();
    let head = h2_block(&[(":method", "POST"), (":scheme", "http"), (":authority", "a"), (":path", "/"), ("content-length", "28")]);
    c.write_all(&h2_frame(1, 4, 1, &head)).unwrap();
    c.write_all(&h2_frame(0, 0, 1, b"GET /x HTTP/1.1\r\n")).unwrap();
    thread::sleep(Duration::from_millis(300));
    c.write_all(&h2_frame(0, 1, 1, b"Host: a\r\n\r\n")).unwrap();
    let mut chunk = [0u8; 16384];
    while let Ok(1..) = c.read(&mut chunk) {}
    common::stop(&mut child);
    let heads = got.lock().unwrap().clone();
    heads
}

#[test]
fn an_h2_request_whose_rules_removed_its_length_goes_with_no_body() {
    assert_eq!(h2_post("http-request del-header content-length"), vec![SRV_POST0.to_string()], "the server saw the body as a request");
    // And a second length a rule adds is not written (T442 row 4b over HTTP/2: the request
    // keeps a copy of its headers, which loses it too).
    let heads = h2_post("http-request add-header content-length 28");
    assert_eq!(heads.first().map(String::as_str), Some("POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 28"), "{heads:?}");
}

/// T442: a request whose rules gave it a length shorter than the body it has. `HAProxy`
/// answers 500 (`IH` in the log) and keeps the client connection; forwarded, the rest of the
/// body is read by the server as the next request. Measured on 3.5-dev8 (`/tmp/t442`,
/// `p442b.py` cases `1v`, `m0`, `p442log.py` `s3`). `HAProxy` has sent the head to the server
/// before it fails; Alcyon answers before it sends anything.
#[test]
fn a_request_length_a_rule_made_shorter_than_its_body_is_refused() {
    let req: &[u8] = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 28\r\n\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n";
    for rules in ["http-request set-header content-length 3", "http-request set-header content-length 0", "http-request set-header content-length x"] {
        let (srv, cli, closed) = run(rules, req, OK);
        assert!(srv.iter().all(|h| h.starts_with("POST / HTTP/1.1")), "{rules}: the server read the body as a request: {srv:?}");
        assert!(cli.starts_with(b"HTTP/1.1 500 "), "{rules}: client got {:?}", String::from_utf8_lossy(&cli));
        assert!(!closed, "{rules}: the client connection closed");
    }
}

/// T442 row 4a: the server and client connections a rule's `keep-alive` keeps are used
/// again. Two requests, 200 ms apart, on one client connection; measured on 3.5-dev8
/// (`/tmp/t442/p442c.py` cases `4f0`, `4f1`, `4f2`).
#[test]
fn a_keep_alive_a_rule_wrote_keeps_the_connection_an_option_would_close() {
    let two: &[&[u8]] = &[GET, b"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n"];
    let both = [CLI_OK, CLI_OK].concat();
    for (rules, heads, conns) in [
        ("option http-server-close", ["GET / HTTP/1.1\r\nhost: a\r\nconnection: close", "GET /2 HTTP/1.1\r\nhost: a\r\nconnection: close"], 2),
        ("option http-server-close\nhttp-request set-header connection keep-alive", ["GET / HTTP/1.1\r\nhost: a", "GET /2 HTTP/1.1\r\nhost: a"], 1),
        ("option httpclose\nhttp-response set-header connection keep-alive", ["GET / HTTP/1.1\r\nhost: a", "GET /2 HTTP/1.1\r\nhost: a"], 1),
    ] {
        let (got_srv, got_cli, closed, got_conns) = run_counted(rules, two, OK);
        assert_eq!(got_srv, heads, "{rules}");
        assert_eq!(String::from_utf8_lossy(&got_cli), String::from_utf8_lossy(&both), "{rules}");
        assert!(!closed, "{rules}: the client connection closed");
        assert_eq!(got_conns, conns, "{rules}: server connections");
    }
}

/// T442: a request whose rules gave it a length longer than the body it has. `HAProxy` sends
/// it and closes the server connection after (measured on 3.5-dev8, `/tmp/t442/p442c.py`
/// cases `m7`, `m7b`): used again, the next request would be read by the server as the rest
/// of the body. (`HAProxy` then answers that next request 500 after sending part of its
/// head; Alcyon sends it whole on a new connection.)
#[test]
fn a_request_length_a_rule_made_longer_than_its_body_closes_the_server_connection() {
    let parts: &[&[u8]] = &[b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello", b"GET /y HTTP/1.1\r\nHost: a\r\n\r\n"];
    let (srv, cli, closed, conns) = run_counted("http-request set-header content-length 7", parts, OK);
    assert_eq!(srv, ["POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 7", "GET /y HTTP/1.1\r\nhost: a"], "the server read the next request as the body");
    assert_eq!(conns, 2, "server connections");
    assert!(cli.starts_with(CLI_OK), "client got {:?}", String::from_utf8_lossy(&cli));
    assert!(!closed, "the client connection closed");
}
