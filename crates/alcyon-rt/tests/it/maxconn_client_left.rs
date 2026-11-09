// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Termination state of a client that leaves while its connection waits for the frontend's
//! `maxconn` (T231).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-10 (`maxconn 2`, two connections
//! kept busy, three more sent a request or part of one and closed while they waited in the
//! kernel's accept queue; each run repeated 5 times with the same result):
//!
//! | what the waiting client sent | closes | line |
//! |------------------------------|--------|------|
//! | a whole request              | RST    | `400 CL--`, server `s` chosen, never connected |
//! | a whole request              | FIN    | `400 CH--` |
//! | part of a request            | FIN or RST | `400 CR--` `<BADREQ>` |
//! | nothing                      | FIN or RST | `400 CR--` `<BADREQ>` |

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How the waiting client leaves.
#[derive(Clone, Copy)]
enum Leave {
    Fin,
    Rst,
}

/// The `%ts %ST %r` of the stream of the client that left while it waited, if logged.
fn waiting_client(sent: &[u8], how: Leave) -> Option<String> {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
    let fe = common::reserve_addr();
    let server = TcpListener::bind("127.0.0.1:0").expect("server");
    let cfg = format!(
        "global\n  maxconn 1\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 2s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  log {} local0\n  log-format \"%ts %ST %r\"\n  default_backend b\n\
         backend b\n  server s {}\n",
        collector.local_addr().unwrap(),
        server.local_addr().unwrap()
    );
    let path = std::env::temp_dir().join(format!("alcyon-t231-{}-{}.cfg", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    std::fs::write(&path, cfg).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened");
    let _ = std::fs::remove_file(&path);
    // `wait_listening` connected and left: that connection has a line of its own.
    // On a loaded host the line comes late: wait for it, not for 100 ms.
    let mut buf = [0u8; 2048];
    collector.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let _ = collector.recv(&mut buf);
    collector.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");

    // The one connection `maxconn` allows, held while its request is at the server.
    let mut holder = TcpStream::connect(fe).expect("connect");
    holder.write_all(b"GET /hold HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let (mut s, _) = server.accept().expect("accept the holder");
    let mut b = [0u8; 512];
    let _ = s.read(&mut b).expect("the holder's request");

    // It waits in the accept queue, sends what it sends, and leaves.
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(sent).expect("send");
    std::thread::sleep(Duration::from_millis(300));
    if matches!(how, Leave::Rst) {
        rustix::net::sockopt::set_socket_linger(&c, Some(Duration::ZERO)).expect("linger");
    }
    drop(c);
    std::thread::sleep(Duration::from_millis(100));
    // The holder is answered and leaves: the slot is freed, the waiting connection is
    // accepted now.
    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").expect("answer");
    holder.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let _ = holder.read(&mut b).expect("the holder's response");
    drop(holder);

    let mut log = None;
    let end = Instant::now() + Duration::from_secs(15);
    while log.is_none() && Instant::now() < end {
        if let Ok(n) = collector.recv(&mut buf) {
            let line = String::from_utf8_lossy(&buf[..n]).into_owned();
            if !line.contains("/hold") {
                log = Some(line[line.rfind(": ").map_or(0, |i| i + 2)..].trim_end().to_string());
            }
        }
    }
    common::stop(&mut child);
    log
}

const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

#[test]
fn a_whole_request_and_a_reset_while_waiting_is_cl() {
    assert_eq!(waiting_client(REQ, Leave::Rst).as_deref(), Some("CL 400 GET / HTTP/1.1"));
}

#[test]
fn a_whole_request_and_a_fin_while_waiting_is_ch() {
    assert_eq!(waiting_client(REQ, Leave::Fin).as_deref(), Some("CH 400 GET / HTTP/1.1"));
}

#[test]
fn part_of_a_request_while_waiting_is_cr() {
    assert_eq!(waiting_client(b"GET / HT", Leave::Fin).as_deref(), Some("CR 400 <BADREQ>"));
    assert_eq!(waiting_client(b"GET / HT", Leave::Rst).as_deref(), Some("CR 400 <BADREQ>"));
}

#[test]
fn nothing_sent_while_waiting_is_cr() {
    assert_eq!(waiting_client(b"", Leave::Fin).as_deref(), Some("CR 400 <BADREQ>"));
    assert_eq!(waiting_client(b"", Leave::Rst).as_deref(), Some("CR 400 <BADREQ>"));
}
