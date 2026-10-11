// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `error-log-format` (T296).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`log <udp> local0`, `option httplog`):
//! - A connection that fails before a session exists (a TLS handshake, a PROXY header) logs
//!   `error-log-format` in place of the plain `<src>:<port> [<date>] <fe>/<id>: <message>`
//!   line, with the connection's values: `%ts` `PR`, `%ST` 0, `%HM` `<BADREQ>`, no backend.
//!   `fc_err`, `fc_err_str`, `fc_err_name`, `ssl_fc_err`, `ssl_fc_err_str` say why.
//! - A request the H1 mux refuses (400, 408, 501) and an HTTP/2 connection error log it too,
//!   instead of the frontend's `log-format`. A request that became a stream does not.
//! - Without it: the plain line for the first, `log-format` for the second.
//! - `defaults` hands it down; a frontend's own replaces it; `no log` logs nothing; `option
//!   dontlognull` still drops the empty cases; a backend accepts and ignores it.
//!
//! Set `T296B_ORACLE=/path/to/haproxy` to run these tests against HAProxy.
use crate::common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const PLAIN: &[u8] = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
const HELLO_PART: &[u8] = b"\x16\x03\x01\x00\xff\x01";
const H2_BAD_SETTINGS: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\x05\x04\0\0\0\0\0\0\0\0\0\0";
const SHAPE: &str = "%ft|%ts|%tsc|%ST|%B|%U|%Tt|%Tw|%Th|%Ti|%Tq|%HM|%r|%[fc_err]|%[fc_err_str]|%[fc_err_name]|%[ssl_fc_err]|%[ssl_fc_err_str]|%[be_name]";

fn cert() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem")
}

fn binary() -> String {
    std::env::var("T296B_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string())
}

/// What `template` (with `@LOG@`, `@B0@`, `@B1@`, `@CERT@`) logged for each probe `(bind, bytes,
/// half-close)`, the syslog header cut. `Err` is what the process said when it did not start.
fn session(template: &str, probes: &[(usize, &[u8], bool)]) -> Result<Vec<Vec<String>>, String> {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(400))).expect("timeout");
    let binds = [common::reserve_addr(), common::reserve_addr()];
    let cfg = template
        .replace("@LOG@", &collector.local_addr().expect("addr").to_string())
        .replace("@B0@", &binds[0].to_string())
        .replace("@B1@", &binds[1].to_string())
        .replace("@CERT@", cert());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write");
    let mut child = Command::new(binary()).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("spawn");
    if !common::wait_listening(binds[0]) {
        common::stop(&mut child);
        let mut stderr = String::new();
        let _ = child.stderr.take().map(|mut e| e.read_to_string(&mut stderr));
        return Err(stderr);
    }
    let _ = common::wait_listening(binds[1]);
    std::thread::sleep(Duration::from_millis(300));
    let mut buf = [0u8; 4096];
    while collector.recv(&mut buf).is_ok() {}
    let mut out = Vec::new();
    for (bind, send, half_close) in probes {
        let mut c = TcpStream::connect(binds[*bind]).expect("connect");
        c.write_all(send).expect("send");
        if *half_close {
            c.shutdown(Shutdown::Write).expect("shutdown");
        }
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(3) {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        drop(c);
        let mut lines = Vec::new();
        while let Ok(n) = collector.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            lines.push(l.split_once("]: ").map_or(l.clone(), |(_, b)| b.trim_end().to_string()));
        }
        out.push(lines);
    }
    common::stop(&mut child);
    Ok(out)
}

/// A frontend named `t` on `@B0@` (TLS when `ssl`), with `extra` lines in it.
fn frontend(ssl: bool, mode: &str, extra: &str) -> String {
    let tls = if ssl { " ssl crt @CERT@" } else { "" };
    format!(
        "defaults\n  mode {mode}\n  timeout connect 2s\n  timeout client 1s\n  timeout server 2s\n\
         frontend t\n  bind @B0@{tls}\n  log @LOG@ local0\n  option httplog\n  {extra}\n  http-request return status 200\n"
    )
}

fn one(r: &Result<Vec<Vec<String>>, String>, probe: usize) -> String {
    let logs = r.as_ref().unwrap_or_else(|e| panic!("did not start: {e}"));
    assert_eq!(logs[probe].len(), 1, "probe {probe}: {logs:#?}");
    logs[probe][0].clone()
}

const EMPTY: &str = "ELF t~|PR|PR--|0|0|0|0|-1|0|0|-1|<BADREQ>|<BADREQ>|24|Connection closed during SSL handshake|SSL_EMPTY|0|-|-";
const HTTP_ON_TLS: &str = "ELF t~|PR|PR--|0|0|0|0|-1|0|0|-1|<BADREQ>|<BADREQ>|34|SSL handshake failure|SSL_HANDSHAKE|167772316|error:0A00009C:SSL routines::http request|-";

#[test]
fn a_failed_tls_handshake_logs_error_log_format() {
    let fmt = format!("error-log-format \"ELF {SHAPE}\"");
    let r = session(&frontend(true, "http", &fmt), &[(0, b"", true), (0, PLAIN, false), (0, HELLO_PART, true)]);
    assert_eq!(one(&r, 0), EMPTY);
    assert_eq!(one(&r, 1), HTTP_ON_TLS);
    assert_eq!(one(&r, 2), EMPTY, "part of a hello is logged as a closed connection");
}

#[test]
fn a_tcp_frontend_logs_it_too() {
    let fmt = "error-log-format \"ELF %ci %ft %[fc_err_str]\"";
    let r = session(&frontend(true, "tcp", fmt).replace("option httplog", "option tcplog").replace("http-request return status 200", "default_backend b\nbackend b\n  server s 127.0.0.1:1"), &[(0, b"", true), (0, PLAIN, false)]);
    assert_eq!(one(&r, 0), "ELF 127.0.0.1 t~ Connection closed during SSL handshake");
    assert_eq!(one(&r, 1), "ELF 127.0.0.1 t~ SSL handshake failure");
}

#[test]
fn a_refused_proxy_header_logs_it_with_its_error() {
    let cfg = frontend(false, "http", "accept-proxy-placeholder").replace("bind @B0@", "bind @B0@ accept-proxy").replace("accept-proxy-placeholder", "error-log-format \"ELF %ft|%ts|%ST|%[fc_err]|%[fc_err_name]|%[fc_err_str]|%[ssl_fc_err]\"");
    let r = session(&cfg, &[(0, b"", true), (0, b"PROXY TCP4 x y z w\r\n", false), (0, b"PROXY FOO 1 2 3 4\r\n", false), (0, b"GARBAGE-LONGER-THAN-THE-SIGNATURE\r\n", false)]);
    assert_eq!(one(&r, 0), "ELF t|PR|0|11|PRX_EMPTY|Connection closed while waiting for PROXY protocol header|-");
    assert_eq!(one(&r, 1), "ELF t|PR|0|16|PRX_BAD_HDR|Received an invalid PROXY protocol header|-");
    assert_eq!(one(&r, 2), "ELF t|PR|0|17|PRX_BAD_PROTO|Received an unhandled protocol in the PROXY protocol header|-");
    assert_eq!(one(&r, 3), "ELF t|PR|0|15|PRX_NOT_HDR|Received something which does not look like a PROXY protocol header|-");
}

#[test]
fn a_request_the_mux_refuses_logs_it_and_a_served_one_does_not() {
    let cfg = frontend(false, "http", "error-log-format \"ELF %ft %ST\"\n  log-format \"NORMAL %ft %ST\"");
    let r = session(&cfg, &[(0, PLAIN, false), (0, b"GARBAGE\r\n\r\n", false), (0, b"", true), (0, b"GET / HTT", false), (0, b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n", false)]);
    assert_eq!(one(&r, 0), "NORMAL t 200");
    assert_eq!(one(&r, 1), "ELF t 400");
    assert_eq!(one(&r, 2), "ELF t 400");
    assert_eq!(one(&r, 3), "ELF t 408");
    assert_eq!(one(&r, 4), "ELF t 400");
}

#[test]
fn an_http2_connection_error_logs_it() {
    let cfg = frontend(false, "http", "error-log-format \"ELF %ft %ts\"\n  log-format \"NORMAL %ft %ts\"").replace("bind @B0@", "bind @B0@ proto h2");
    let r = session(&cfg, &[(0, H2_BAD_SETTINGS, false)]);
    assert_eq!(one(&r, 0), "ELF t PR");
}

#[test]
fn without_it_the_plain_line_and_the_log_format_stay() {
    let r = session(&frontend(true, "http", "log-format \"NORMAL %ft\""), &[(0, b"", true)]);
    let line = one(&r, 0);
    assert!(line.contains(" t/") && line.ends_with("Connection closed during SSL handshake"), "{line}");
    let r = session(&frontend(false, "http", "log-format \"NORMAL %ft %ST\""), &[(0, b"GARBAGE\r\n\r\n", false)]);
    assert_eq!(one(&r, 0), "NORMAL t 400");
}

#[test]
fn defaults_hand_it_down_and_a_frontend_replaces_it() {
    let cfg = "defaults\n  mode http\n  timeout client 1s\n  log @LOG@ local0\n  error-log-format \"DEF %ft\"\n\
               frontend a\n  bind @B0@ ssl crt @CERT@\n  option httplog\n\
               frontend b\n  bind @B1@ ssl crt @CERT@\n  option httplog\n  error-log-format \"OWN %ft\"\n";
    let r = session(cfg, &[(0, b"", true), (1, b"", true)]);
    assert_eq!(one(&r, 0), "DEF a~");
    assert_eq!(one(&r, 1), "OWN b~");
}

#[test]
fn no_log_logs_nothing_and_dontlognull_drops_the_empty_ones() {
    let r = session(&frontend(true, "http", "error-log-format \"ELF %ft\"\n  no log"), &[(0, b"", true)]);
    assert!(r.as_ref().unwrap_or_else(|e| panic!("{e}"))[0].is_empty(), "{r:?}");
    let r = session(&frontend(true, "http", "error-log-format \"ELF %ft\"\n  option dontlognull"), &[(0, b"", true), (0, PLAIN, false)]);
    assert!(r.as_ref().unwrap_or_else(|e| panic!("{e}"))[0].is_empty(), "{r:?}");
    assert_eq!(one(&r, 1), "ELF t~");
}

#[test]
fn it_wants_one_argument_a_format_that_compiles_and_is_ignored_in_a_backend() {
    let starts = |extra: &str| session(&frontend(false, "http", extra), &[]);
    assert!(starts("error-log-format").is_err());
    assert!(starts("error-log-format a b").is_err());
    let e = starts("error-log-format \"%[nosuchfetch]\"").expect_err("bad fetch");
    assert!(e.contains("error-log-format"), "{e}");
    let e = starts("error-log-format \"%[req.hdr(host)]\"").expect_err("headers are gone when the line is made");
    assert!(e.contains("error-log-format"), "{e}");
    let cfg = frontend(false, "http", "") + "backend b\n  error-log-format \"x\"\n  server s 127.0.0.1:1\n";
    assert!(session(&cfg, &[]).is_ok(), "accepted and ignored in a backend");
}
