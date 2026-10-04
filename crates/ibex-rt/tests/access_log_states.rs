// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Header captures, the unique ID, and the termination state of streams that did not end
//! well, as the reference `HAProxy` (3.5-dev8-885761-29) logged them for this frontend,
//! measured 2026-10-03 (one process per scenario, a UDP collector):
//!
//! ```text
//! /ok ts=-- ST=201 hr={examp|abc|last} hrl=examp abc last hs={seco} hsl=seco ID=U-abcdef uid=U-abcdef c0=examp c1=abc c2=last r0=seco
//! <BADREQ> ts=cR ST=408 hr= hrl= hs= hsl= ID=- uid=- c0=- c1=- c2=- r0=-
//! /hang ts=sH ST=504 hr={x||} hrl=x - - hs={} hsl=- ID=U- uid=U- c0=x c1=- c2=- r0=-
//! /srvclose ts=SH ST=502 hr={x||} hrl=x - - hs={} hsl=- ID=U- uid=U- c0=x c1=- c2=- r0=-
//! /partial ts=SD ST=200 hr={x||} hrl=x - - hs={} hsl=- ID=U- uid=U- c0=x c1=- c2=- r0=-
//! /slowbody ts=CD ST=200 hr={x||} hrl=x - - hs={} hsl=- ID=U- uid=U- c0=x c1=- c2=- r0=-
//! <BADREQ> ts=CR ST=400 hr= hrl= hs= hsl= ID=- uid=- c0=- c1=- c2=- r0=-
//! /slowbody ts=cD ... (a client that stops reading until `timeout client`)
//! /post ts=cL ST=201 ... hs={seco} ... (a request body that stops after the response is
//!                                       complete: `SF_FINST_L`, `http_set_term_flags`)
//! ```
//!
//! and the server of `/ok` received `x-uid: U-abcdef` (the name lower-cased, as `HAProxy`
//! sends every H1 header name).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::Engine;

/// A server that answers by path: `/hang` never, `/srvclose` by closing, `/partial` with
/// 3 of 100 body bytes then a close (`/reset`: a reset), `/slowbody` with an endless body, anything else
/// 201 with two `X-R` headers. It reports each request head it read.
fn server() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let tx = tx.clone();
            thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
                let mut d = Vec::new();
                let mut buf = [0u8; 4096];
                while !d.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(n) if n > 0 => d.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&d).into_owned();
                let path = head.split(' ').nth(1).unwrap_or("").to_string();
                let _ = tx.send(head);
                match path.as_str() {
                    "/hang" => thread::sleep(Duration::from_secs(2)),
                    "/srvclose" => {}
                    "/partial" => {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc");
                        thread::sleep(Duration::from_millis(200));
                    }
                    "/reset" => {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc");
                        thread::sleep(Duration::from_millis(200));
                        // SO_LINGER 0: the close is a reset.
                        let _ = rustix::net::sockopt::set_socket_linger(&c, Some(Duration::ZERO));
                    }
                    "/slowbody" => {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n");
                        for _ in 0..200 {
                            if c.write_all(&[b'x'; 65536]).is_err() {
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                    }
                    _ => {
                        let _ = c.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nX-R: resvalue\r\nX-R: second\r\n\r\n");
                    }
                }
            });
        }
    });
    (addr, rx)
}

const FORMAT: &str = "%HU ts=%ts ST=%ST hr=%hr hrl=%hrl hs=%hs hsl=%hsl ID=%ID uid=%[unique-id] \
                      c0=%[capture.req.hdr(0)] c1=%[capture.req.hdr(1)] c2=%[capture.req.hdr(2)] r0=%[capture.res.hdr(0)]";

/// Runs one client scenario against a fresh engine and returns the log line it produced.
fn scenario(client: impl FnOnce(SocketAddr) + Send + 'static) -> (Option<String>, mpsc::Receiver<String>) {
    scenario_be("", client)
}

/// [`scenario`], with `be_extra` added to the backend.
fn scenario_be(be_extra: &str, client: impl FnOnce(SocketAddr) + Send + 'static) -> (Option<String>, mpsc::Receiver<String>) {
    scenario_with(FORMAT, be_extra, client)
}

/// [`scenario_be`], with the frontend's `log-format` `format`.
fn scenario_with(format: &str, be_extra: &str, client: impl FnOnce(SocketAddr) + Send + 'static) -> (Option<String>, mpsc::Receiver<String>) {
    let (srv, heads) = server();
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 500ms\n  timeout server 500ms\n\
         frontend fe\n  bind {fe}\n  log {} local0\n  \
         capture request header host len 5\n  http-request capture req.hdr(x-a) len 3\n  \
         capture request header x-b len 10\n  capture response header x-r len 4\n  \
         unique-id-format U-%[req.hdr(x-a)]\n  unique-id-header X-Uid\n  \
         log-format \"{format}\"\n  default_backend be\n\
         backend be\n{be_extra}  server s {srv}\n",
        collector.local_addr().expect("addr")
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let c = thread::spawn(move || client(fe));
    let mut line = None;
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(5);
    while line.is_none() && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            line = Some(String::from_utf8_lossy(&buf[..n]).split_once("]: ").map_or("", |(_, b)| b.trim_end()).to_string());
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = c.join();
    (line, heads)
}

fn send(fe: SocketAddr, req: &[u8]) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    c.write_all(req).expect("send");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").into_bytes()
}

const BADREQ_TAIL: &str = "hr= hrl= hs= hsl= ID=- uid=- c0=- c1=- c2=- r0=-";
const NO_HDRS_TAIL: &str = "hr={x||} hrl=x - - hs={} hsl=- ID=U- uid=U- c0=x c1=- c2=- r0=-";

#[test]
fn a_transaction_logs_its_captures_and_unique_id() {
    let (line, heads) = scenario(|fe| {
        send(fe, b"GET /ok HTTP/1.1\r\nHost: example.com\r\nX-A: abcdef\r\nX-B: beebee\r\nX-B: last\r\nConnection: close\r\n\r\n");
    });
    assert_eq!(
        line.as_deref(),
        Some("/ok ts=-- ST=201 hr={examp|abc|last} hrl=examp abc last hs={seco} hsl=seco ID=U-abcdef uid=U-abcdef c0=examp c1=abc c2=last r0=seco")
    );
    let head = heads.recv_timeout(Duration::from_secs(1)).expect("the server saw the request");
    assert!(head.contains("\r\nx-uid: U-abcdef\r\n"), "{head:?}");
}

#[test]
fn a_client_that_never_sends_a_request_times_out_with_408() {
    let (line, _) = scenario(|fe| {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_millis(1500))).expect("timeout");
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
    });
    assert_eq!(line, Some(format!("<BADREQ> ts=cR ST=408 {BADREQ_TAIL}")));
}

#[test]
fn a_client_that_leaves_mid_request_is_cr_400() {
    let (line, _) = scenario(|fe| {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(b"GET /half HTTP/1.1\r\nHost: x\r\n").expect("send");
        thread::sleep(Duration::from_millis(200));
    });
    assert_eq!(line, Some(format!("<BADREQ> ts=CR ST=400 {BADREQ_TAIL}")));
}

/// A connection closed before a byte of request: `HAProxy` logged
/// `ts=CR ST=400 r=<BADREQ>` for `nc -z` (measured 2026-10-03, no `option dontlognull`).
#[test]
fn a_client_that_leaves_without_a_byte_is_cr_400() {
    let (line, _) = scenario(|fe| drop(TcpStream::connect(fe).expect("connect")));
    assert_eq!(line, Some(format!("<BADREQ> ts=CR ST=400 {BADREQ_TAIL}")));
}

#[test]
fn a_server_that_never_answers_is_sh_504() {
    let (line, _) = scenario(|fe| send(fe, &get("/hang")));
    assert_eq!(line, Some(format!("/hang ts=sH ST=504 {NO_HDRS_TAIL}")));
}

#[test]
fn a_server_that_closes_without_answering_is_sh_502() {
    let (line, _) = scenario(|fe| send(fe, &get("/srvclose")));
    assert_eq!(line, Some(format!("/srvclose ts=SH ST=502 {NO_HDRS_TAIL}")));
}

#[test]
fn a_server_that_closes_mid_body_is_sd() {
    let (line, _) = scenario(|fe| send(fe, &get("/partial")));
    assert_eq!(line, Some(format!("/partial ts=SD ST=200 {NO_HDRS_TAIL}")));
}

/// A reset instead of a close is still the server's doing: `HAProxy` logged
/// `ts=SD ST=200` for a server that sent 3 of 100 body bytes and reset (SO_LINGER 0),
/// measured 2026-10-03.
#[test]
fn a_server_that_resets_mid_body_is_sd() {
    let (line, _) = scenario(|fe| send(fe, &get("/reset")));
    assert_eq!(line, Some(format!("/reset ts=SD ST=200 {NO_HDRS_TAIL}")));
}

#[test]
fn a_client_that_leaves_mid_response_is_cd() {
    let (line, _) = scenario(|fe| {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(&get("/slowbody")).expect("send");
        let mut buf = [0u8; 1000];
        let _ = c.read(&mut buf);
        thread::sleep(Duration::from_millis(200));
    });
    assert_eq!(line, Some(format!("/slowbody ts=CD ST=200 {NO_HDRS_TAIL}")));
}

#[test]
fn a_client_that_stops_reading_times_out_in_the_data_phase() {
    let (line, _) = scenario(|fe| {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(&get("/slowbody")).expect("send");
        thread::sleep(Duration::from_millis(2500));
    });
    assert_eq!(line, Some(format!("/slowbody ts=cD ST=200 {NO_HDRS_TAIL}")));
}

#[test]
fn a_request_body_that_stalls_after_the_response_is_cl() {
    let (line, _) = scenario(|fe| {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(b"POST /post HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc").expect("send");
        thread::sleep(Duration::from_millis(2000));
    });
    assert_eq!(line, Some("/post ts=cL ST=201 hr={x||} hrl=x - - hs={seco} hsl=seco ID=U- uid=U- c0=x c1=- c2=- r0=seco".to_string()));
}

/// `declare capture request len 4` + `http-request capture req.hdr(x-a) id 0`: HAProxy
/// logged `c0=abcd hr={abcd}` for `X-A: abcdef` (measured 2026-10-03), the value cut to
/// the declared length; an `id` that no `declare capture` made is refused ("unable to
/// find capture id '1' referenced by http-request capture rule").
#[test]
fn a_declared_capture_is_filled_by_its_rule() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n\
         frontend fe\n  bind {fe}\n  log {} local0\n  declare capture request len 4\n  \
         http-request capture req.hdr(x-a) id 0\n  log-format \"c0=%[capture.req.hdr(0)] hr=%hr\"\n  \
         http-request return status 200\n",
        collector.local_addr().expect("addr")
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 16).expect("Engine::new");
    let c = thread::spawn(move || send(fe, b"GET / HTTP/1.1\r\nHost: x\r\nX-A: abcdef\r\nConnection: close\r\n\r\n"));
    let mut line = None;
    let mut buf = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(5);
    while line.is_none() && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            line = Some(String::from_utf8_lossy(&buf[..n]).split_once("]: ").map_or("", |(_, b)| b.trim_end()).to_string());
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = c.join();
    assert_eq!(line.as_deref(), Some("c0=abcd hr={abcd}"));

    let bad = ibex_config::parse_str(
        "frontend fe\n  mode http\n  bind 127.0.0.1:1\n  declare capture request len 4\n  http-request capture req.hdr(x) id 1\n",
    )
    .expect("parses");
    let err = Engine::new(&bad, 4).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("unable to find capture id '1' referenced by http-request capture rule"), "{err:?}");
}

/// A backend's `http-request capture ... id <n>` names a slot of the frontend's; one
/// past the frontend's slots captures nothing (`http_action_req_capture_by_id`: `id >=
/// fe->nb_req_cap`); one within them is cut to that slot's length. For this frontend and
/// a backend with `id 9` then `id 2`, `HAProxy` logged `hrl=h - zzzzzzzzzz` (measured
/// 2026-10-03; `c0=-` too for `id 0` from a backend whose frontend declared none).
#[test]
fn a_backend_capture_id_past_the_frontend_s_slots_captures_nothing() {
    let (line, _) = scenario_be("  http-request capture req.hdr(x-z) id 9\n  http-request capture req.hdr(x-z) id 2\n", |fe| {
        send(fe, b"GET /ok HTTP/1.1\r\nHost: h\r\nX-Z: zzzzzzzzzzzz\r\nConnection: close\r\n\r\n");
    });
    let line = line.expect("a log line");
    assert!(line.contains(" hrl=h - zzzzzzzzzz hs="), "{line}");
    // Without `id` a backend has no slot to take: `haproxy -c` refuses it with "error
    // detected in backend 'be' while parsing 'http-request capture' rule : proxy 'be' has
    // no frontend capability."
    let bad = ibex_config::parse_str("backend be\n  mode http\n  http-request capture req.hdr(x) len 3\n").expect("parses");
    let err = Engine::new(&bad, 4).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("'http-request capture' rule : proxy 'be' has no frontend capability"), "{err:?}");
}

/// `%lc` counts the lines the frontend logged, so a frontend with a format and no `log`
/// target never moves it. `HAProxy` sent `x-uid: lc=0` three times without a target and
/// `lc=0`, `lc=1`, `lc=2` with one (`unique-id-format "lc=%lc"`, measured 2026-10-03).
#[test]
fn the_log_counter_counts_only_lines_logged() {
    for (log, want) in [("", ["lc=0", "lc=0", "lc=0"]), ("  log 127.0.0.1:9 local0\n", ["lc=0", "lc=1", "lc=2"])] {
        let (srv, heads) = server();
        let fe = common::reserve_addr();
        let cfg = format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 500ms\n  timeout server 500ms\n\
             frontend fe\n  bind {fe}\n{log}  log-format \"%ci %r\"\n  unique-id-format \"lc=%lc\"\n  \
             unique-id-header X-Uid\n  default_backend be\nbackend be\n  server s {srv}\n"
        );
        let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        let mut got = Vec::new();
        for _ in 0..3 {
            let c = thread::spawn(move || send(fe, &get("/ok")));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !c.is_finished() && Instant::now() < deadline {
                let _ = engine.run_once();
                thread::sleep(Duration::from_millis(1));
            }
            let _ = c.join();
            let head = heads.recv_timeout(Duration::from_secs(1)).expect("the server saw the request");
            got.push(head.split("\r\n").find_map(|l| l.strip_prefix("x-uid: ")).unwrap_or("").to_string());
        }
        assert_eq!(got, want, "{log:?}");
    }
}

/// A capture length that ends inside a UTF-8 character. `HAProxy` keeps the byte it cut
/// at: `hr={a#C3|b#C3}` for `x-a: a\u{e9}` into `len 2` (measured 2026-10-03); `%hr` writes the
/// stray byte as `#C3`. Captures are bytes (T105). `x-a` is captured here to 3 bytes, so
/// `ab\u{e9}` keeps `ab` and the first byte of the accent. The control, a cut on the
/// boundary, keeps the whole character.
#[test]
fn a_capture_cut_inside_a_character_keeps_the_byte_it_cut_at() {
    let (line, _) = scenario(|fe| send(fe, "GET /ok HTTP/1.1\r\nHost: x\r\nX-A: ab\u{e9}\r\nConnection: close\r\n\r\n".as_bytes()));
    let line = line.expect("a log line");
    assert!(line.contains("|ab#C3|"), "the capture should end in the cut byte, #C3: {line}");
    let (line, _) = scenario(|fe| send(fe, "GET /ok HTTP/1.1\r\nHost: x\r\nX-A: a\u{e9}\r\nConnection: close\r\n\r\n".as_bytes()));
    let line = line.expect("a log line");
    assert!(line.contains("|a#C3#A9|"), "a cut after the whole character keeps both its bytes: {line}");
}

/// `%[method]` at log time: the request buffer is gone and `HAProxy` reads `txn->meth`,
/// which names only its enum, so a method outside it logs `-` (`PATCH`, `FOO`) while
/// `%HM`, from the request line, still has it. Measured 2026-10-03 (3.5-dev8-885761-29):
/// `GET` `OPTIONS` `HEAD` `POST` `PUT` `DELETE` `TRACE` log themselves; `PATCH`, `FOO` and
/// `LINK` log `-`.
#[test]
fn method_at_log_time_is_dash_outside_haproxy_s_enum() {
    for (m, want) in [("GET", "GET"), ("OPTIONS", "OPTIONS"), ("DELETE", "DELETE"), ("TRACE", "TRACE"), ("PATCH", "-"), ("FOO", "-")] {
        let req = format!("{m} /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let (line, _) = scenario_with("m=%[method] hm=%HM", "", move |fe| send(fe, req.as_bytes()));
        let line = line.expect("a log line");
        assert!(line.contains(&format!("m={want} hm={m}")), "`%[method]` for {m} should log `{want}`: {line}");
    }
}
