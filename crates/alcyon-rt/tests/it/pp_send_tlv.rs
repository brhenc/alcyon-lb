// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `set-proxy-v2-tlv-fmt(<id>) <fmt>` on a `server` or `default-server` line: a TLV of
//! type `<id>` goes into the PROXY v2 header the proxy sends to the server, with the
//! log-format `<fmt>` evaluated for each connection (an empty TLV when no format is
//! given). `HAProxy`: `srv_parse_set_proxy_v2_tlv_fmt` (src/server.c) and
//! `make_proxy_line_v2` (src/connection.c); the reg-test
//! `connection/proxy_protocol_send_generic.vtc`.
//!
//! Every expected value was measured on the oracle (3.5-dev11):
//! * the reg-test's two configurations (a `server` with two TLVs, one of them without a
//!   format; a `default-server` with one);
//! * three TLVs on one server go out in the order of the line;
//! * a `default-server` TLV and a `server` TLV of the same id are both sent, the
//!   `default-server`'s one first;
//! * a server with only `send-proxy-v2` sends a header with no TLV at all;
//! * a keyword without parentheses keeps id 0 and takes the next word as the format
//!   (`set-proxy-v2-tlv-fmt "zero"` sends TLV 0x00 "zero");
//! * the id parses with C's `strtoul(, 0)`: `+1` and `0b100` load, `-1`, `0777` and
//!   `0b100000000000000000` refuse with "the maximum allowed TLV ID is 255", and `0x`,
//!   `0b7`, `08` refuse with "expects set-proxy-v2-tlv(<TLV ID>)" (a `0x`/`0b`/`0`
//!   without the right digits is an octal `0` followed by junk);
//! * `-c` refuses `set-proxy-v2-tlv-fmt(0x100)` with "the maximum allowed TLV ID is 255",
//!   `set-proxy-v2-tlv-fmt(abc)` with "could not convert TLV ID", and
//!   `set-proxy-v2-tlv-fmt(0xE1x)` with "expects set-proxy-v2-tlv(<TLV ID>)".
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes
//! all.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// The PROXY v2 signature (`PP2_SIGNATURE`).
const PP2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

/// The binary under test: the oracle's when `T281_ORACLE` names one, alcyon otherwise.
fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// A proxy running the test configuration, stopped with it.
struct Proxy {
    child: std::process::Child,
    _cfg: NamedTempFile,
    fe: SocketAddr,
    stderr: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Starts the proxy: a `listen` of `mode tcp` with one server at `be`. `defaults_extra`
/// is an optional `default-server` line ahead of the `server` one; `server_line` the
/// server's keywords.
fn start(defaults_extra: &str, server_line: &str, be: SocketAddr) -> Proxy {
    let fe = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("tmp file");
    let defaults = if defaults_extra.is_empty() {
        String::new()
    } else {
        format!("    {defaults_extra}\n")
    };
    let text = format!(
        "global\n\
         defaults\n\
             mode tcp\n\
             timeout connect 5s\n\
             timeout client 5s\n\
             timeout server 5s\n\
         listen l\n\
             bind {fe}\n\
         {defaults}\
             server s {be} {server_line}\n"
    );
    cfg.write_all(text.as_bytes()).expect("write config");
    let stderr = Arc::new(std::sync::Mutex::new(Vec::new()));
    let err_sink = Arc::clone(&stderr);
    let mut child = Command::new(bin())
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the proxy");
    drain_pipe(child.stdout.take().expect("stdout"), Arc::clone(&stderr));
    drain_pipe(child.stderr.take().expect("stderr"), err_sink);
    let mut p = Proxy { child, _cfg: cfg, fe, stderr };
    if !common::wait_listening(p.fe) {
        let guard = p.stderr.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let err = String::from_utf8_lossy(guard.as_slice());
        panic!("the proxy never listened ({})\n{err}", bin());
    }
    p
}

/// Drains one of the proxy's pipes into `sink`, locking only per chunk: holding the lock
/// while the child lives would deadlock the test thread, which reads it before dropping
/// the proxy. One thread per pipe: the proxy logs to stderr and writes nothing to stdout,
/// so draining one after the other would capture no log line until the child dies.
fn drain_pipe(mut r: impl Read + Send + 'static, sink: Arc<std::sync::Mutex<Vec<u8>>>) {
    thread::spawn(move || loop {
        let mut buf = [0u8; 4096];
        let n = r.read(&mut buf).unwrap_or(0);
        if n == 0 {
            return;
        }
        let mut g = sink.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.extend_from_slice(&buf[..n]);
    });
}

/// The raw backend on `be`: reads the PROXY v2 header the proxy sends to it and answers
/// with the header's TLVs, in wire order, as `OK <n> <id> <value>...` (lowercase hex), so
/// the client sees exactly what the header carried.
fn spawn_backend(be: SocketAddr, running: Arc<AtomicBool>) {
    // Bound on the calling thread: it is listening before the proxy starts, so the proxy's
    // connection never meets an unbound port.
    let listener = TcpListener::bind(be).expect("bind the backend");
    listener.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                // One handler per connection: the `wait_listening` probe connection must not
                // hold the accept loop while the proxy connects the client's server socket.
                Ok((mut stream, _)) => {
                    thread::spawn(move || {
                        stream.set_read_timeout(Some(Duration::from_secs(8))).ok();
                        if let Some(summary) = read_pp2_tlvs(&mut stream) {
                            let _ = stream.write_all(summary.as_bytes());
                            let _ = stream.write_all(b"\r\n");
                            let _ = stream.flush();
                            thread::sleep(Duration::from_millis(200));
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
}

/// The header's TLVs as `OK <n> <id> <value>...`; `None` when the stream does not start
/// with a PROXY v2 `PROXY` header.
fn read_pp2_tlvs(stream: &mut TcpStream) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        if buf.len() >= 16 {
            let ln = u16::from_be_bytes([buf[14], buf[15]]) as usize;
            if buf.len() >= 16 + ln {
                break;
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        match stream.read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return None,
        }
    }
    if &buf[..12] != PP2_SIG {
        return None;
    }
    let ver_cmd = buf[12];
    // `PP2_VERSION | PP2_CMD_PROXY` (src/proxy_protocol.c): version field is the top three
    // bits, 2 => 0x20; command PROXY is 1.
    if ver_cmd & 0xE0 != 0x20 || ver_cmd & 0x1F != 0x01 {
        return None;
    }
    let ln = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let (addr_len, tlv_start) = match buf[13] & 0x0F {
        0x01 => (12usize, 28usize), // AF_INET
        0x02 => (20, 36), // AF_INET6
        _ => return None,
    };
    let tlv_end = tlv_start + ln.saturating_sub(addr_len);
    if tlv_end > buf.len() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    let mut i = tlv_start;
    while i + 3 <= tlv_end {
        let ty = buf[i];
        let l = u16::from_be_bytes([buf[i + 1], buf[i + 2]]) as usize;
        if i + 3 + l > tlv_end {
            break;
        }
        let mut part = format!("{ty:02x} ");
        for b in &buf[i + 3..i + 3 + l] {
            part.push_str(&format!("{b:02x}"));
        }
        parts.push(part);
        i += 3 + l;
    }
    Some(format!("OK {} {}", parts.len(), parts.join(" ")))
}

/// Connects to the proxy's frontend, sends a request so the server connection opens and the
/// PROXY header is flushed, and reads the backend's `OK ...` line.
fn exchange(p: &Proxy) -> String {
    let mut c = TcpStream::connect(p.fe).expect("connect to the frontend");
    c.set_read_timeout(Some(Duration::from_secs(8))).expect("timeout");
    let _ = c.write_all(b"PING\r\n");
    let mut got = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        if let Some(pos) = got.windows(2).position(|w| w == b"\r\n") {
            return String::from_utf8_lossy(&got[..pos]).trim_end().to_string();
        }
        match c.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&got).to_string()
}

/// One running-proxy check: `defaults_extra` + `server_line`, the expected `OK ...` line.
fn wire_case(defaults_extra: &str, server_line: &str, expected: &str) {
    let be = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    spawn_backend(be, Arc::clone(&running));
    let p = start(defaults_extra, server_line, be);
    let line = exchange(&p);
    running.store(false, Ordering::Relaxed);
    let proxy_err = {
        let guard = p.stderr.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(guard.as_slice()).into_owned()
    };
    drop(p);
    assert_eq!(line, expected, "the PROXY v2 header carried {line:?}\nproxy stderr:\n{proxy_err}");
}

/// Runs `-c` on a config whose only server line is
/// `server s 127.0.0.1:9 send-proxy-v2 {server_line}`; the exit status and the stderr.
fn run_check(server_line: &str) -> (bool, String) {
    let mut cfg = NamedTempFile::new().expect("tmp file");
    let fe = common::reserve_addr();
    let text = format!(
        "global\n\
         defaults\n\
             mode tcp\n\
             timeout connect 5s\n\
             timeout client 5s\n\
             timeout server 5s\n\
         listen l\n\
             bind {fe}\n\
             server s 127.0.0.1:9 send-proxy-v2 {server_line}\n"
    );
    cfg.write_all(text.as_bytes()).expect("write config");
    let out = Command::new(bin())
        .arg("-c")
        .arg("-f")
        .arg(cfg.path())
        .output()
        .expect("run the check");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// A `-c` check that must refuse, with the oracle's words.
fn check_refused(server_line: &str, fragment: &str) {
    let (ok, stderr) = run_check(server_line);
    assert!(!ok, "the check accepted {server_line:?}\n{stderr}");
    assert!(
        stderr.contains(fragment),
        "the check refused {server_line:?}, but not with the oracle's words:\n{stderr}"
    );
}

/// A `-c` check that must accept: `HAProxy` loads the line and Alcyon must not refuse it.
fn check_accepted(server_line: &str) {
    let (ok, stderr) = run_check(server_line);
    assert!(ok, "the check refused {server_line:?}\n{stderr}");
}

/// The reg-test's first configuration: a `server` with two TLVs, one without a format.
#[test]
fn server_line_two_tlvs_regtest() {
    wire_case(
        "",
        "send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) %[str(\"foo\")] set-proxy-v2-tlv-fmt(0xE2)",
        "OK 2 e1 666f6f e2",
    );
}

/// The reg-test's second configuration: a `default-server` TLV.
#[test]
fn default_server_tlv_regtest() {
    wire_case(
        "default-server send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) %[str(\"bar\")]",
        "",
        "OK 1 e1 626172",
    );
}

/// Three TLVs on one server go out in the order of the line.
#[test]
fn three_tlvs_in_line_order() {
    wire_case(
        "",
        "send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) \"a\" set-proxy-v2-tlv-fmt(0xE2) \"bb\" set-proxy-v2-tlv-fmt(0xE3) \"ccc\"",
        "OK 3 e1 61 e2 6262 e3 636363",
    );
}

/// A `default-server` TLV and a `server` TLV of the same id: both go, default first.
#[test]
fn default_and_server_same_id() {
    wire_case(
        "default-server send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) \"fromdefault\"",
        "send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) \"fromserver\"",
        "OK 2 e1 66726f6d64656661756c74 e1 66726f6d736572766572",
    );
}

/// The baseline a server without the keyword must keep: a header with no TLV at all.
#[test]
fn no_keyword_no_tlv() {
    wire_case("", "send-proxy-v2", "OK 0");
}

/// `-c` refuses an id above 255, in hex.
#[test]
fn check_refuses_id_above_255() {
    check_refused("set-proxy-v2-tlv-fmt(0x100) \"x\"", "the maximum allowed TLV ID is 255");
}

/// `-c` refuses an id that is not a number.
#[test]
fn check_refuses_non_numeric_id() {
    check_refused("set-proxy-v2-tlv-fmt(abc) \"x\"", "could not convert TLV ID");
}

/// `-c` refuses an id that carries bytes past the closing parenthesis.
#[test]
fn check_refuses_id_past_parenthesis() {
    check_refused("set-proxy-v2-tlv-fmt(0xE1x) \"x\"", "expects set-proxy-v2-tlv(<TLV ID>)");
}

/// Without parentheses the id stays 0 and the next word is the format.
#[test]
fn no_parenthesis_is_tlv_zero() {
    wire_case("", "send-proxy-v2 set-proxy-v2-tlv-fmt \"zero\"", "OK 1 00 7a65726f");
}

/// A `+` sign is read: `+1` is a TLV id of 1.
#[test]
fn check_accepts_positive_sign_id() {
    check_accepted("set-proxy-v2-tlv-fmt(+1) \"x\"");
}

/// A `-` sign is read: `-1` is the largest unsigned and trips the 255 limit.
#[test]
fn check_refuses_negative_id() {
    check_refused("set-proxy-v2-tlv-fmt(-1) \"x\"", "the maximum allowed TLV ID is 255");
}

/// A binary id loads: `0b100` is 4.
#[test]
fn check_accepts_binary_id() {
    check_accepted("set-proxy-v2-tlv-fmt(0b100) \"x\"");
}

/// An 18-bit binary id trips the 255 limit.
#[test]
fn check_refuses_binary_id_above_255() {
    check_refused("set-proxy-v2-tlv-fmt(0b100000000000000000) \"x\"", "the maximum allowed TLV ID is 255");
}

/// A `0b` without a 0/1 digit is an octal `0` followed by junk.
#[test]
fn check_refuses_binary_with_seven() {
    check_refused("set-proxy-v2-tlv-fmt(0b7) \"x\"", "expects set-proxy-v2-tlv(<TLV ID>)");
}

/// A `0x` without a hex digit is an octal `0` followed by junk.
#[test]
fn check_refuses_hex_without_digits() {
    check_refused("set-proxy-v2-tlv-fmt(0x) \"x\"", "expects set-proxy-v2-tlv(<TLV ID>)");
}

/// A leading-`0` id is octal: `08` stops at the 8.
#[test]
fn check_refuses_octal_eight() {
    check_refused("set-proxy-v2-tlv-fmt(08) \"x\"", "expects set-proxy-v2-tlv(<TLV ID>)");
}

/// An octal id above 255 trips the limit: `0777` is 511.
#[test]
fn check_refuses_octal_above_255() {
    check_refused("set-proxy-v2-tlv-fmt(0777) \"x\"", "the maximum allowed TLV ID is 255");
}

/// `-c` refuses an unknown fetch method in a TLV format.
#[test]
fn check_refuses_unknown_fetch_in_tlv_fmt() {
    check_refused("set-proxy-v2-tlv-fmt(1) %[nosuchfetch]", "unknown fetch method 'nosuchfetch'");
}

/// A dynamic sample fetch other than `str()` (`%[src]`) is evaluated per connection.
#[test]
fn dynamic_fetch_src() {
    wire_case("", "send-proxy-v2 set-proxy-v2-tlv-fmt(0xE1) %[src]", "OK 1 e1 3132372e302e302e31");
}
