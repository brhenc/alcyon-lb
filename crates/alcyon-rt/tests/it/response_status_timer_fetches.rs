// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T385: `server_status`, `res.comp`, `res.comp_algo`, `res.timer.hdr` in an `http-response` rule.
//! The expected line was measured on HAProxy 3.5-dev8: with `set-status 202` ahead of the fetches and
//! a server that answers 201 after 300 ms, `[201|202|0||300]`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn backend() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            std::thread::sleep(Duration::from_millis(300));
            let _ = c.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    addr
}

#[test]
fn server_status_comp_and_header_timer() {
    let a = common::reserve_addr();
    let be = backend();
    let dir = std::env::temp_dir().join(format!("t385-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  default_backend b\n  http-response set-status 202\n  \
             http-response set-header x-out \"[%[server_status]|%[status]|%[res.comp]|%[res.comp_algo]|%[res.timer.hdr]]\"\n\
             backend b\n  server s {be}\n"
        ),
    )
    .unwrap();
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    assert!(common::wait_listening(a), "alcyon did not listen");
    let mut s = TcpStream::connect(a).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    let line = out.lines().find(|l| l.starts_with("x-out:")).unwrap_or_else(|| panic!("no x-out in {out:?}")).trim_start_matches("x-out:").trim();
    let inner = line.trim_start_matches('[').trim_end_matches(']');
    let f: Vec<&str> = inner.split('|').collect();
    assert_eq!(&f[..4], ["201", "202", "0", ""], "line {line}");
    let tr: i64 = f[4].parse().unwrap_or_else(|_| panic!("Tr {:?}", f[4]));
    assert!((290..400).contains(&tr), "Tr {tr}");
}

/// A reply Alcyon builds itself after a proxied 201 on the same worker: HAProxy (3.5-dev8) gives
/// `[0|403|-1]` for `/deny` and `/ret`, and `[201|201|<ms>]` again for a proxied one.
#[test]
fn local_reply_does_not_inherit_previous_response() {
    let a = common::reserve_addr();
    let be = backend();
    let dir = std::env::temp_dir().join(format!("t385b-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  http-request deny if {{ path /deny }}\n  http-request return status 403 if {{ path /ret }}\n  \
             default_backend b\n  http-after-response set-header x-out \"[%[server_status]|%[status]|%[res.timer.hdr]]\"\n\
             backend b\n  server s {be}\n"
        ),
    )
    .unwrap();
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    assert!(common::wait_listening(a), "alcyon did not listen");
    let mut got = Vec::new();
    for p in ["/", "/deny", "/ret", "/"] {
        let mut s = TcpStream::connect(a).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(format!("GET {p} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        let l = out.lines().find(|l| l.starts_with("x-out:")).unwrap_or_else(|| panic!("no x-out for {p}: {out:?}")).trim_start_matches("x-out:").trim().to_string();
        got.push(l);
    }
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(got[0].starts_with("[201|201|") && got[3].starts_with("[201|201|"), "{got:?}");
    assert_eq!(got[1], "[0|403|-1]", "{got:?}");
    assert_eq!(got[2], "[0|403|-1]", "{got:?}");
}

/// T385, h2: three concurrent streams of one h2c connection on one thread, A (server answers 201
/// after 300 ms), B (`deny`, answered while A waits) and C (server answers 201 at once). Measured on
/// HAProxy 3.5-dev8: A `[201|201|~300]`, B `[0|403|-1]`, C `[201|201|~1]`, and the log lines
/// (`%[server_status] %Tr`) `/slow 201 ~300`, `/deny 0 -1`, `/fast 201 ~1`.
#[test]
fn h2_streams_keep_their_own_status_and_timer() {
    let a = common::reserve_addr();
    let be = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { continue };
                std::thread::spawn(move || {
                    let mut b = [0u8; 4096];
                    let n = c.read(&mut b).unwrap_or(0);
                    if b[..n].windows(5).any(|w| w == b"/slow") {
                        std::thread::sleep(Duration::from_millis(300));
                    }
                    let _ = c.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                });
            }
        });
        addr
    };
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let dir = std::env::temp_dir().join(format!("t385c-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a} proto h2\n  log {} format raw local0\n  log-format \"L %HP %[server_status] %Tr\"\n  \
             http-request deny if {{ path /deny }}\n  default_backend b\n  \
             http-after-response set-header x-out \"[%[server_status]|%[status]|%[res.timer.hdr]]\"\n\
             backend b\n  server s {be}\n",
            udp.local_addr().unwrap()
        ),
    )
    .unwrap();
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    assert!(common::wait_listening(a), "alcyon did not listen");
    let url = |p: &str| format!("http://{a}/{p}");
    let st = Command::new("curl")
        .current_dir(&dir)
        .args(["-s", "--http2-prior-knowledge", "--parallel", "--parallel-immediate", "-i", "-o", "a", &url("slow"), "-o", "b", &url("deny"), "-o", "c", &url("fast")])
        .status()
        .unwrap();
    assert!(st.success());
    let mut logs = Vec::new();
    let mut buf = [0u8; 1024];
    while logs.len() < 4 {
        let Ok(n) = udp.recv(&mut buf) else { break };
        logs.push(String::from_utf8_lossy(&buf[..n]).trim().to_string());
    }
    let xout = |f: &str| {
        let t = std::fs::read_to_string(dir.join(f)).unwrap();
        t.lines().find(|l| l.starts_with("x-out:")).unwrap_or_else(|| panic!("no x-out in {f}: {t:?}")).trim_start_matches("x-out:").trim().to_string()
    };
    let (xa, xb, xc) = (xout("a"), xout("b"), xout("c"));
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    let tr = |s: &str| -> i64 { s.trim_end_matches(']').rsplit('|').next().unwrap().parse().unwrap() };
    assert!(xa.starts_with("[201|201|") && (290..450).contains(&tr(&xa)), "A {xa}");
    assert_eq!(xb, "[0|403|-1]", "B");
    assert!(xc.starts_with("[201|201|") && (0..150).contains(&tr(&xc)), "C {xc}");
    let log = |p: &str| logs.iter().find(|l| l.contains(p)).unwrap_or_else(|| panic!("no log for {p}: {logs:?}")).split(' ').skip(2).collect::<Vec<_>>().join(" ");
    let (ls, ld, lf) = (log("/slow"), log("/deny"), log("/fast"));
    assert!(ls.starts_with("201 ") && (290..450).contains(&ls[4..].parse::<i64>().unwrap()), "log slow {ls}");
    assert_eq!(ld, "0 -1", "log deny");
    assert!(lf.starts_with("201 ") && (0..150).contains(&lf[4..].parse::<i64>().unwrap()), "log fast {lf}");
}

/// T467, h2: a stream answered by a rule logs `%[server_status]` 0 and `%Tr` -1 (HAProxy), also when
/// it ends after a sibling stream's server answer arrived. The client opens `/deny` and `/fast`
/// with a stream window of 0, so no body goes out and neither stream ends; once the 201 head of
/// `/fast` is read it opens the window of `/deny`, which ends and logs after that 201.
#[test]
fn h2_denied_stream_ending_after_a_server_answer_logs_no_server_status() {
    fn frame(t: u8, fl: u8, sid: u32, p: &[u8]) -> Vec<u8> {
        let n = p.len();
        let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, t, fl];
        f.extend_from_slice(&sid.to_be_bytes());
        f.extend_from_slice(p);
        f
    }
    fn get(sid: u32, path: &str) -> Vec<u8> {
        let mut b = vec![0x82, 0x86, 0x04, path.len() as u8];
        b.extend_from_slice(path.as_bytes());
        b.extend_from_slice(&[0x01, 1, b'x']);
        frame(1, 0x5, sid, &b)
    }
    let a = common::reserve_addr();
    let be = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { continue };
                std::thread::spawn(move || {
                    let mut b = [0u8; 4096];
                    let _ = c.read(&mut b);
                    let _ = c.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                });
            }
        });
        addr
    };
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let dir = std::env::temp_dir().join(format!("t467-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a} proto h2\n  log {} format raw local0\n  log-format \"L %HP %[server_status] %Tr\"\n  \
             http-request deny if {{ path /deny }}\n  default_backend b\n  \
             http-after-response set-header x-out \"[%[server_status]]\"\n\
             backend b\n  server s {be}\n",
            udp.local_addr().unwrap()
        ),
    )
    .unwrap();
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    assert!(common::wait_listening(a), "alcyon did not listen");
    let mut c = std::net::TcpStream::connect(a).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(4, 0, 0, &[0, 4, 0, 0, 0, 0])); // SETTINGS_INITIAL_WINDOW_SIZE = 0
    out.extend(get(1, "/deny"));
    out.extend(get(3, "/fast"));
    c.write_all(&out).unwrap();
    // Read frames until the HEADERS of stream 3: the server's 201 has arrived.
    let mut seen3 = false;
    while !seen3 {
        let mut h = [0u8; 9];
        c.read_exact(&mut h).unwrap();
        let n = (usize::from(h[0]) << 16) | (usize::from(h[1]) << 8) | usize::from(h[2]);
        let mut p = vec![0u8; n];
        c.read_exact(&mut p).unwrap();
        seen3 = h[3] == 1 && u32::from_be_bytes([h[5], h[6], h[7], h[8]]) == 3;
    }
    std::thread::sleep(Duration::from_millis(100));
    c.write_all(&frame(8, 0, 1, &[0, 0, 0xff, 0xff])).unwrap();
    c.write_all(&frame(8, 0, 3, &[0, 0, 0xff, 0xff])).unwrap();
    let mut logs = Vec::new();
    let mut buf = [0u8; 1024];
    while logs.len() < 3 {
        let Ok(n) = udp.recv(&mut buf) else { break };
        logs.push(String::from_utf8_lossy(&buf[..n]).trim().to_string());
    }
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    let log = |p: &str| logs.iter().find(|l| l.contains(p)).unwrap_or_else(|| panic!("no log for {p}: {logs:?}")).split(' ').skip(2).collect::<Vec<_>>().join(" ");
    assert_eq!(log("/deny"), "0 -1", "{logs:?}");
    assert!(log("/fast").starts_with("201 "), "{logs:?}");
}
