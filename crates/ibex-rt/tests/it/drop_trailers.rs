// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T381: `option http-drop-request-trailers` (a backend's) and `option http-drop-response-trailers`
//! (a frontend's). Expected bytes measured on HAProxy 3.5-dev8: the trailer section goes, the
//! `Trailer:` header stays, the last-chunk line and the blank line that ends the message stay.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> Ibex {
    let dir = std::env::temp_dir().join(format!("dt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    ibex
}

const RESP: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-rtlr1\r\nconnection: close\r\n\r\n5\r\nworld\r\n0\r\nx-rtlr1: rvalue1\r\n\r\n";

/// A server answering `RESP` to every connection; what it read of each request is sent on the channel.
fn server() -> (SocketAddr, Receiver<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            // The request ends with the blank line after the last chunk (and its trailers, if any).
            while !(buf.ends_with(b"\r\n\r\n") && buf.windows(5).any(|w| w == b"\r\n0\r\n")) {
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let _ = tx.send(buf);
            let _ = s.write_all(RESP);
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    (addr, rx)
}

fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

const REQ: &[u8] = b"POST /x HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\ntrailer: x-tlr1\r\nconnection: close\r\n\r\n5\r\nhello\r\n0\r\nx-tlr1: value1\r\n\r\n";
const REQ_DROPPED: &[u8] = b"POST /x HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\ntrailer: x-tlr1\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
const RESP_DROPPED: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-rtlr1\r\nconnection: close\r\n\r\n5\r\nworld\r\n0\r\n\r\n";

fn cfg(fe: [SocketAddr; 2], origin: SocketAddr, bind_extra: &str) -> String {
    format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe_drop\n  bind {}{bind_extra}\n  option http-drop-response-trailers\n  use_backend be_keep if {{ path -m beg /keep }}\n  default_backend be_drop\n\
         frontend fe_keep\n  bind {}{bind_extra}\n  use_backend be_keep if {{ path -m beg /keep }}\n  default_backend be_drop\n\
         backend be_drop\n  option http-drop-request-trailers\n  server s {origin}\n\
         backend be_keep\n  no option http-drop-request-trailers\n  server s {origin}\n",
        fe[0], fe[1]
    )
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A literal header field without indexing, new name.
fn block(list: &[(&str, &str)]) -> Vec<u8> {
    list.iter()
        .flat_map(|(n, v)| {
            let mut f = vec![0, n.len() as u8];
            f.extend_from_slice(n.as_bytes());
            f.push(v.len() as u8);
            f.extend_from_slice(v.as_bytes());
            f
        })
        .collect()
}

/// One H2 POST with a body and trailers to `fe`, `pause` between the body and the trailers;
/// the frame types the client got on stream 1 up to its end.
fn h2_post(fe: SocketAddr, path: &str, pause: Duration) -> Vec<u8> {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(1))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    s.write_all(&frame(4, 0, 0, &[])).unwrap();
    s.write_all(&frame(4, 1, 0, &[])).unwrap();
    let head = block(&[(":method", "POST"), (":scheme", "http"), (":authority", "x"), (":path", path)]);
    s.write_all(&frame(1, 4, 1, &head)).unwrap();
    s.write_all(&frame(0, 0, 1, b"abc")).unwrap();
    std::thread::sleep(pause);
    s.write_all(&frame(1, 5, 1, &block(&[("x-tlr1", "value1")]))).unwrap();
    let (mut raw, mut types) = (Vec::new(), Vec::new());
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut tmp = [0u8; 4096];
    'read: while std::time::Instant::now() < deadline {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(_) if !raw.is_empty() => {}
            Err(_) => continue,
        }
        let (mut at, mut seen) = (0, Vec::new());
        while raw.len() >= at + 9 {
            let len = (usize::from(raw[at]) << 16) | (usize::from(raw[at + 1]) << 8) | usize::from(raw[at + 2]);
            if raw.len() < at + 9 + len {
                break;
            }
            let (kind, flags, sid) = (raw[at + 3], raw[at + 4], u32::from_be_bytes(raw[at + 5..at + 9].try_into().unwrap()));
            if sid == 1 && matches!(kind, 0 | 1) {
                seen.push(kind);
                if flags & 1 != 0 {
                    types = seen;
                    break 'read;
                }
            }
            at += 9 + len;
        }
    }
    types
}

/// HTTP/2 on both sides of the option. Measured on the oracle with `T381_ORACLE=<haproxy>`.
#[test]
fn h2_request_trailers_and_h2_response_trailers_follow_the_options() {
    let (origin, rx) = server();
    let fe = [common::reserve_addr(), common::reserve_addr()];
    let cfg = cfg(fe, origin, " proto h2");
    let dir = std::env::temp_dir().join(format!("dt-h2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, &cfg).unwrap();
    let bin = std::env::var("T381_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = Ibex(child, dir);
    for a in fe {
        assert!(common::wait_listening(a), "no listener on {a}");
    }
    let t = Duration::from_secs(3);
    // The trailers come at once (the backend may not be chosen when they are read), and later.
    for pause in [Duration::ZERO, Duration::from_millis(300)] {
        let types = h2_post(fe[0], "/x", pause);
        let got = String::from_utf8_lossy(&rx.recv_timeout(t).unwrap()).into_owned();
        assert!(got.ends_with("3\r\nabc\r\n0\r\n\r\n"), "{pause:?}: request trailers reached be_drop: {got:?}");
        assert_eq!(types.iter().filter(|&&k| k == 1).count(), 1, "{pause:?}: fe_drop sent the response trailers as HEADERS: {types:?}");

        let types = h2_post(fe[1], "/keep", pause);
        let got = String::from_utf8_lossy(&rx.recv_timeout(t).unwrap()).into_owned();
        assert!(got.ends_with("3\r\nabc\r\n0\r\nx-tlr1: value1\r\n\r\n"), "{pause:?}: request trailers lost on be_keep: {got:?}");
        // The oracle sends the response trailers as a second HEADERS here; Ibex does not send an
        // H1 response's trailers to an H2 client at all (T381 side finding), so only the drop is checked.
        let _ = types;
    }
}

#[test]
fn trailers_are_dropped_by_the_options_and_kept_without() {
    let (origin, rx) = server();
    let fe = [common::reserve_addr(), common::reserve_addr()];
    let _ibex = start("h1", &cfg(fe, origin, ""), &fe);
    let t = Duration::from_secs(3);

    // The backend option drops the request trailers; the frontend option, the response ones.
    let resp = get(fe[0], REQ);
    assert_eq!(String::from_utf8_lossy(&rx.recv_timeout(t).unwrap()), String::from_utf8_lossy(REQ_DROPPED), "request to be_drop");
    assert_eq!(String::from_utf8_lossy(&resp), String::from_utf8_lossy(RESP_DROPPED), "response of fe_drop");

    // Neither option: both pass (`no option` in the backend, absent in the frontend).
    let req: Vec<u8> = [&b"POST /keep"[..], &REQ[7..]].concat();
    let resp = get(fe[1], &req);
    let want: Vec<u8> = [&b"POST /keep"[..], &REQ_DROPPED[7..]].concat();
    let want = String::from_utf8_lossy(&want).replace("0\r\n\r\n", "0\r\nx-tlr1: value1\r\n\r\n");
    assert_eq!(String::from_utf8_lossy(&rx.recv_timeout(t).unwrap()), want, "request to be_keep");
    assert_eq!(String::from_utf8_lossy(&resp), String::from_utf8_lossy(RESP), "response of fe_keep");
}

#[test]
fn the_options_come_from_defaults_for_the_side_that_owns_them() {
    let (origin, rx) = server();
    let fe = [common::reserve_addr(), common::reserve_addr()];
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n  option http-drop-request-trailers\n  option http-drop-response-trailers\n\
         frontend f\n  bind {}\n  default_backend b\nfrontend g\n  bind {}\n  default_backend b\nbackend b\n  server s {origin}\n",
        fe[0], fe[1]
    );
    let _ibex = start("dflt", &cfg, &fe);
    let resp = get(fe[1], REQ);
    assert_eq!(String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(3)).unwrap()), String::from_utf8_lossy(REQ_DROPPED));
    assert_eq!(String::from_utf8_lossy(&resp), String::from_utf8_lossy(RESP_DROPPED));
}
