// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The case of header names on HTTP/1 (T244). `HAProxy` 3.5-dev8 writes every header name of a
//! response to the client in lower case, and `h1-case-adjust <from> <to>` (global) with
//! `option h1-case-adjust-bogus-client` (frontend: the response to the client) or
//! `option h1-case-adjust-bogus-server` (backend: the request to the server) restores the
//! case of the names in the table. A name not in the table stays lower case; the table is
//! matched on the name as given in `<from>` (lower case in practice).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

const SRV_RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Foo: Bar\r\nSet-Cookie: A=b\r\nCONTENT-Type: text/plain\r\nConnection: close\r\n\r\nok";
const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nX-My-Header: A\r\nUser-Agent: U\r\nConnection: close\r\n\r\n";

/// Returns (what the client received, what the server received).
fn exchange(global: &str, fe: &str, be: &str) -> (String, String) {
    let fa = common::reserve_addr();
    let ba = common::reserve_addr();
    let listener = TcpListener::bind(ba).expect("bind backend");
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let _ = s.write_all(SRV_RESP);
        String::from_utf8_lossy(&got).into_owned()
    });
    let cfg = format!(
        "global\n  tune.alcyon.h1-lowercase-headers on\n{global}\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fa}\n{fe}  default_backend b\nbackend b\n{be}  server s {ba}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon"));
    assert!(common::wait_listening(fa), "alcyon never listened on {fa}");
    let mut c = TcpStream::connect(fa).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(REQ).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = c.read(&mut buf) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    common::stop(&mut child);
    (String::from_utf8_lossy(&got).into_owned(), server.join().expect("server thread"))
}

fn check(cfg: &str) -> (Option<i32>, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(format!("global\n  tune.alcyon.h1-lowercase-headers on\n{cfg}\ndefaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\nfrontend f\n  bind 127.0.0.1:1\n").as_bytes()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("alcyon -c");
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

const TABLE: &str = "  h1-case-adjust x-foo X-Foo\n  h1-case-adjust host Host\n  h1-case-adjust content-length Content-Length\n";

/// Oracle: the response to the client has lower-case names, whatever the server sent.
#[test]
fn the_response_to_the_client_has_lower_case_header_names() {
    let (client, _) = exchange("", "", "");
    assert_eq!(client, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-foo: Bar\r\nset-cookie: A=b\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nok");
}

/// Oracle: bogus-client in the frontend adjusts the names in the table in the response; the
/// request to the server is untouched (lower case).
#[test]
fn bogus_client_adjusts_the_response_only() {
    let (client, server) = exchange(TABLE, "  option h1-case-adjust-bogus-client\n", "");
    assert_eq!(client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Foo: Bar\r\nset-cookie: A=b\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nok");
    assert_eq!(server, "GET / HTTP/1.1\r\nhost: x\r\nx-my-header: A\r\nuser-agent: U\r\n\r\n");
}

/// Oracle: bogus-server in the backend adjusts the request to the server only.
#[test]
fn bogus_server_adjusts_the_request_only() {
    let (client, server) = exchange(TABLE, "", "  option h1-case-adjust-bogus-server\n");
    assert_eq!(client, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-foo: Bar\r\nset-cookie: A=b\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nok");
    assert_eq!(server, "GET / HTTP/1.1\r\nHost: x\r\nx-my-header: A\r\nuser-agent: U\r\n\r\n");
}

/// Oracle: the table is matched on `<from>` as written: `X-Foo` never matches `x-foo`.
#[test]
fn the_table_key_is_matched_as_written() {
    let (client, _) = exchange("  h1-case-adjust X-Foo X-FOO\n", "  option h1-case-adjust-bogus-client\n", "");
    assert!(client.contains("\r\nx-foo: Bar\r\n"), "{client}");
}

/// Oracle: `h1-case-adjust-file` holds `<from> <to>` lines; `#` comments and blanks are skipped.
#[test]
fn the_file_fills_the_table() {
    let mut t = NamedTempFile::new().unwrap();
    t.write_all(b"x-foo X-FOO\n# comment\n\ncontent-length   Content-Length\n").unwrap();
    let (client, _) = exchange(&format!("  h1-case-adjust-file {}\n", t.path().display()), "  option h1-case-adjust-bogus-client\n", "");
    assert!(client.contains("\r\nContent-Length: 2\r\nX-FOO: Bar\r\n"), "{client}");
}

/// Oracle texts (`add_hdr_case_adjust`, `cfg_parse_h1_header_case_adjust`).
#[test]
fn the_global_keywords_are_checked_like_haproxy() {
    let cases = [
        ("h1-case-adjust", "'h1-case-adjust' expects <from> and <to> as argument."),
        ("h1-case-adjust a", "'h1-case-adjust' expects <from> and <to> as argument."),
        ("h1-case-adjust a b c", "'h1-case-adjust' cannot handle unexpected argument 'c'."),
        ("h1-case-adjust a b", "<from> and <to> must not differ except the case"),
        ("h1-case-adjust a A\n  h1-case-adjust a A", "duplicate entry 'a'"),
        ("h1-case-adjust-file", "'h1-case-adjust-file' expects <file> as argument."),
        ("h1-case-adjust-file /tmp/x y", "'h1-case-adjust-file' cannot handle unexpected argument 'y'."),
        ("h1-case-adjust-file /nonexistent/t244", "h1-headers-case-adjust-file '/nonexistent/t244': failed to open file."),
    ];
    for (cfg, text) in cases {
        let (code, out) = check(&format!("  {cfg}"));
        assert_eq!(code, Some(1), "{cfg}: {out}");
        assert!(out.contains(text), "{cfg}: {out}");
    }
    let (code, out) = check("  h1-case-adjust a A");
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn a_bad_file_line_is_refused_with_its_number() {
    let mut t = NamedTempFile::new().unwrap();
    t.write_all(b"a A\nx-foo\n").unwrap();
    let p = t.path().display().to_string();
    let (code, out) = check(&format!("  h1-case-adjust-file {p}"));
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains(&format!("h1-headers-case-adjust-file '{p}' : expect <to> at line 2.")), "{out}");
}

/// Oracle (T228 item 2): a generated reply with a content type writes its `hdr` lines, then
/// `content-length`, then `content-type`.
#[test]
fn a_return_with_a_content_type_writes_content_length_first() {
    let fa = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fa}\n  http-request return status 200 content-type text/plain string hello hdr x-A 1\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon"));
    assert!(common::wait_listening(fa), "alcyon never listened on {fa}");
    let mut c = TcpStream::connect(fa).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(REQ).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = c.read(&mut buf) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    common::stop(&mut child);
    assert_eq!(
        String::from_utf8_lossy(&got),
        "HTTP/1.1 200 OK\r\nx-a: 1\r\ncontent-length: 5\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nhello"
    );
}

/// Oracle: a head the response rules rewrote is written the same way (lower case, the table
/// applied to the names the rules added too).
#[test]
fn a_response_rewritten_by_rules_is_written_the_same_way() {
    let (client, _) = exchange(
        "  h1-case-adjust x-bar X-BAR\n  h1-case-adjust content-length Content-Length\n",
        "  option h1-case-adjust-bogus-client\n  http-response add-header X-Bar Baz\n  http-response set-header Content-Type text/x\n",
        "",
    );
    assert_eq!(
        client,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nx-foo: Bar\r\nset-cookie: A=b\r\nX-BAR: Baz\r\ncontent-type: text/x\r\nconnection: close\r\n\r\nok"
    );
}
