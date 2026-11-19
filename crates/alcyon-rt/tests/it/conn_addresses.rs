// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The connection sample fetches of the reference reg-test
//! `reg-tests/sample_fetches/conn_addresses.vtc`: `fc_nb_streams`, `bc_src`,
//! `bc_src_port`, `bc_nb_streams`, `bc_be_queue`, `bc_srv_queue`, `bc_err_name`,
//! in the rule contexts and over the protocols that reg-test covers: HTTP/1 to a
//! live server, and local replies over HTTP/1 and HTTP/2.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: they pass all.
//! The values are what HAProxy 3.5-dev11 measures: `fc_nb_streams` is 1 on an HTTP/1
//! connection and on a one-stream HTTP/2 connection, `bc_src` the loopback address of
//! the backend connection, the queues 0 and `bc_err_name` empty without an error.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Stdio};
use std::thread;
use std::time::Duration;

/// The binary under test: alcyon, or the oracle when `T281_ORACLE` is set.
fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// The fetches the reg-test exercises that Alcyon lacks or refuses on this base.
const FETCHES: [&str; 7] = [
    "fc_nb_streams",
    "bc_src",
    "bc_src_port",
    "bc_nb_streams",
    "bc_be_queue",
    "bc_srv_queue",
    "bc_err_name",
];

/// Checks a config with the binary under test: whether it loads and what it said.
fn check_cfg(cfg: &str) -> (bool, String) {
    let path = std::env::temp_dir().join(format!(
        "connaddr-{}-{}.cfg",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, cfg).unwrap();
    let out = common::alcyon_command(bin()).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The six `bc_*` fetches need the server connection, which an `http-request` rule has
/// not yet: the reference refuses them there and accepts them in `http-response`.
/// `fc_nb_streams` is accepted in both contexts (it reads the client connection).
#[test]
fn load_matrix() {
    let port = common::reserve_port();
    for f in FETCHES {
        let req_cfg = format!(
            "global\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:{port}\n  http-request set-header x-a %[{f}]\n"
        );
        let res_cfg = format!(
            "global\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:{port}\n  http-response set-header x-a %[{f}]\n"
        );
        let (ok, out) = check_cfg(&res_cfg);
        assert!(ok, "{f} in http-response must be accepted, got: {out}");
        let (ok, out) = check_cfg(&req_cfg);
        if f.starts_with("bc_") {
            assert!(
                !ok && out.contains("may not be reliably used here"),
                "{f} in http-request must be refused 'may not be reliably used here', got ok={ok}: {out}"
            );
        } else {
            assert!(ok, "{f} in http-request must be accepted, got: {out}");
        }
    }
}

/// The header `name`'s value in `out`, case-insensitively.
fn hdr(out: &str, name: &str) -> String {
    out.lines()
        .find_map(|l| {
            let l = l.trim_end();
            let idx = l.find(':')?;
            if l[..idx].trim().eq_ignore_ascii_case(name) {
                Some(l[idx + 1..].trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("header {name} missing in:\n{out}"))
}

/// A one-shot backend answering a fixed HTTP/1 response.
fn be_server() -> SocketAddr {
    let port = common::reserve_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let l = TcpListener::bind(addr).unwrap();
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(RESP);
        }
    });
    addr
}

/// Starts the binary under test on `cfg` and returns the child once it listens on `fe`.
fn start(cfg: &str, tag: &str, fe: SocketAddr) -> Child {
    let dir = std::env::temp_dir().join(format!("connaddr-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let mut child = common::alcyon_command(bin())
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(common::wait_listening(fe), "the proxy did not listen on {fe}");
    child
}

#[test]
fn h1_http_response_values() {
    let be = be_server();
    let fe_port = common::reserve_port();
    let fe: SocketAddr = format!("127.0.0.1:{fe_port}").parse().unwrap();
    let cfg = format!(
        "global\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{fe_port}\n  default_backend b\n\
         http-response set-header x-fcs %[fc_nb_streams]\n\
         http-response set-header x-bcs \"[%[bc_src]]\"\n\
         http-response set-header x-bcsp %[bc_src_port]\n\
         http-response set-header x-bcnb %[bc_nb_streams]\n\
         http-response set-header x-bbq %[bc_be_queue]\n\
         http-response set-header x-bsq %[bc_srv_queue]\n\
         http-response set-header x-bce \"e%[bc_err_name]e\"\n\
         backend b\n  server s1 127.0.0.1:{}\n",
        be.port(),
    );
    let mut child = start(&cfg, "h1res", fe);
    let mut s = TcpStream::connect_timeout(&fe, Duration::from_secs(3)).expect("connect to the frontend");
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.read_to_string(&mut out).unwrap();
    common::stop(&mut child);
    assert_eq!(hdr(&out, "x-fcs"), "1", "fc_nb_streams over HTTP/1:\n{out}");
    assert_eq!(hdr(&out, "x-bcs"), "[127.0.0.1]", "bc_src:\n{out}");
    let sp = hdr(&out, "x-bcsp");
    assert!(
        !sp.is_empty() && sp.bytes().all(|b| b.is_ascii_digit()),
        "bc_src_port must be digits, got {sp:?}:\n{out}"
    );
    assert_eq!(hdr(&out, "x-bcnb"), "1", "bc_nb_streams:\n{out}");
    assert_eq!(hdr(&out, "x-bbq"), "0", "bc_be_queue:\n{out}");
    assert_eq!(hdr(&out, "x-bsq"), "0", "bc_srv_queue:\n{out}");
    // The name of `CO_ER_NONE` is empty: the markers around the fetch read back "ee".
    assert_eq!(hdr(&out, "x-bce"), "ee", "bc_err_name without an error:\n{out}");
}

/// `bc_src` over an IPv6 server connection: the local address of the socket to
/// the server is the IPv6 loopback, and the fetch renders it the way the
/// reference does -- the bare address, without brackets.
#[test]
fn bc_src_ipv6_backend() {
    let be_port = common::reserve_port();
    let be: SocketAddr = format!("[::1]:{be_port}").parse().unwrap();
    let l = TcpListener::bind(be).unwrap();
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(RESP);
        }
    });
    let fe_port = common::reserve_port();
    let fe: SocketAddr = format!("127.0.0.1:{fe_port}").parse().unwrap();
    let cfg = format!(
        "global\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{fe_port}\n  default_backend b\n\
         http-response set-header x-bcs %[bc_src]\n\
         http-response set-header x-bcsp %[bc_src_port]\n\
         backend b\n  server s1 [::1]:{be_port}\n",
    );
    let mut child = start(&cfg, "v6be", fe);
    let mut s = TcpStream::connect_timeout(&fe, Duration::from_secs(3)).expect("connect to the frontend");
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.read_to_string(&mut out).unwrap();
    common::stop(&mut child);
    assert_eq!(hdr(&out, "x-bcs"), "::1", "bc_src of an IPv6 server connection:\n{out}");
    let sp = hdr(&out, "x-bcsp");
    assert!(
        !sp.is_empty() && sp.bytes().all(|b| b.is_ascii_digit()),
        "bc_src_port must be digits, got {sp:?}:\n{out}"
    );
}

/// `fc_nb_streams` on an `http-request` rule of a local reply: the HTTP/1 stream
/// counts as 1, as measured on the reference.
#[test]
fn h1_http_request_fc_nb_streams() {
    let port = common::reserve_port();
    let fe: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = format!(
        "global\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:{port}\n  http-request return status 200 content-type text/plain lf-string \"req=[%[fc_nb_streams]]\" if {{ req.hdr(host) -m str x }}\n"
    );
    let mut child = start(&cfg, "h1req", fe);
    let mut s = TcpStream::connect_timeout(&fe, Duration::from_secs(3)).expect("connect");
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.read_to_string(&mut out).unwrap();
    common::stop(&mut child);
    assert!(out.contains("req=[1]"), "expected body req=[1] in:\n{out}");
}

fn h2_frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    let len_bytes = u32::try_from(len).expect("frame fits u24").to_be_bytes();
    out.extend_from_slice(&[len_bytes[1], len_bytes[2], len_bytes[3], ftype, flags]);
    out.extend_from_slice(&(sid & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn h2_read_frame(s: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; 9];
    s.read_exact(&mut hdr).ok()?;
    let len = (usize::from(hdr[0]) << 16) | (usize::from(hdr[1]) << 8) | usize::from(hdr[2]);
    let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
    let mut pay = vec![0u8; len];
    s.read_exact(&mut pay).ok()?;
    Some((hdr[3], hdr[4], sid, pay))
}

/// One HTTP/2 stream, `GET /x`, and the body it gets back.
fn h2_get_one(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut init = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    init.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    s.write_all(&init).expect("preface");
    let mut blk = Vec::new();
    for (k, v) in [
        (":method", "GET"),
        (":scheme", "http"),
        (":authority", "x"),
        (":path", "/x"),
    ] {
        blk.push(0);
        blk.push(u8::try_from(k.len()).expect("name < 127"));
        blk.extend_from_slice(k.as_bytes());
        blk.push(u8::try_from(v.len()).expect("value < 127"));
        blk.extend_from_slice(v.as_bytes());
    }
    s.write_all(&h2_frame(1, 0x05, 1, &blk)).expect("headers");
    let mut body = Vec::new();
    while let Some((ft, fl, rsid, pay)) = h2_read_frame(&mut s) {
        if ft == 4 && (fl & 1) == 0 {
            let _ = s.write_all(&h2_frame(4, 1, 0, &[]));
        } else if ft == 6 && (fl & 1) == 0 && pay.len() == 8 {
            let _ = s.write_all(&h2_frame(6, 1, 0, &pay));
        } else if ft == 0 && rsid == 1 {
            body.extend_from_slice(&pay);
            if (fl & 1) != 0 {
                break;
            }
        } else if ft == 1 && rsid == 1 && (fl & 1) != 0 {
            break;
        } else if (ft == 3 && rsid == 1) || ft == 7 {
            body.clear();
            break;
        }
    }
    String::from_utf8(body).unwrap()
}

/// `fc_nb_streams` on an HTTP/2 connection's single stream: it counts as 1, as on HTTP/1.
#[test]
fn h2_single_stream_fc_nb_streams() {
    let port = common::reserve_port();
    let fe: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cfg = format!(
        "global\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:{port} proto h2\n  http-request return status 200 content-type text/plain lf-string \"req=[%[fc_nb_streams]]\" if {{ req.hdr(host) -m str x }}\n"
    );
    let mut child = start(&cfg, "h2", fe);
    let body = h2_get_one(port);
    common::stop(&mut child);
    assert_eq!(body, "req=[1]", "fc_nb_streams over one HTTP/2 stream");
}
