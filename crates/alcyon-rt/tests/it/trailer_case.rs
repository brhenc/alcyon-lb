// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T302: lowercase HTTP/1 trailer names

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Alcyon, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "alcyon did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (alcyon, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

#[test]
fn trailer_names_are_lowercased() {
    // Start a backend that echoes the received trailer section and sends its own chunked response with trailers.
    let be = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = be.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let (mut stream, _) = be.accept().unwrap();
        // Read until we have the full request including the trailer section.
        let mut buf = Vec::new();
        loop {
            let mut tmp = [0u8; 1024];
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 { break; }
            buf.extend_from_slice(&tmp[..n]);
            // Check if we've seen the end of the chunked body (0\r\n followed by trailer lines and an empty line).
            // The trailer section ends with \r\n\r\n after the last trailer field.
            if buf.len() >= 4 && buf.ends_with(b"\r\n\r\n") {
                // Verify we saw a 0\r\n chunk (last chunk)
                if let Some(pos) = buf.windows(2).position(|w| w == b"0\r") {
                    if pos + 2 < buf.len() && buf[pos + 2] == b'\n' {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(buf);
        // Answer with a chunked response that has its own trailers.
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Res-Trailer\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\nRes-Trailer: Abc\r\nX-UP: Q\r\n\r\n";
        let _ = stream.write_all(resp);
    });

    let fe = common::reserve_addr();
    let cfg = http_cfg("", &format!("frontend fe\n  bind {fe}\n  default_backend be\nbackend be\n  server s {be_addr}\n"));
    let (alcyon, _sock) = start("t302", &cfg, &[fe]);

    // Send a chunked POST with trailers.
    let req = b"POST /t HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\nAnother-Trailer: W\r\n\r\n";
    let resp = get(fe, req);

    // Check what the backend received.
    let received = rx.recv().expect("backend received data");
    // The backend should have received the request with lowercased trailer names.
    // The last chunk is 0\r\n, then trailer lines with lowercased names, then \r\n\r\n.
    let expected_trailers = b"0\r\nx-t: v\r\nanother-trailer: W\r\n\r\n";
    assert!(
        received.ends_with(expected_trailers),
        "backend received trailers with wrong case: {:?} (expected: {:?})",
        String::from_utf8_lossy(&received),
        expected_trailers
    );

    // Check what the client received.
    // The client should receive the response with lowercased trailer names.
    let expected_client_trailers = b"0\r\nres-trailer: Abc\r\nx-up: Q\r\n\r\n";
    assert!(
        resp.ends_with(expected_client_trailers),
        "client received trailers with wrong case: {:?} (expected: {:?})",
        String::from_utf8_lossy(&resp),
        expected_client_trailers
    );

    drop(alcyon);
}
