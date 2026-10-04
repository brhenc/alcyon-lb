// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T155: `userlist ... user <u> password <crypt(3) hash>` through `http_auth`.
//!
//! The hashes are of the password `secret`, made by `openssl passwd` and glibc `crypt`; every
//! verdict below was measured on `HAProxy 3.5-dev8-885761-29` (glibc `crypt`) with the same
//! configuration on 2026-10-04.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

const HASHES: &[(&str, &str)] = &[
    ("sha512", "$6$fQ6HnDPa64.3Z6.O$GjsvUJiFS2JYIZa3urNVWBoQ0C.wK18sKYqqn853aGzhYHEjP6bbDM2zYkNna8mCV/S6xlSI4v9rjADlEJ037."),
    ("sha512r", "$6$rounds=1000$BLlpd4DDOChXrHSH$5TZWbB7HWmA2x6tDw6y0Z2yKoXXzTxusdjTxnwMd/MLirF6e5bi7UUHwfkRlwzWPXy2DS544/HljqTUOOFijI0"),
    ("sha256", "$5$IZZu.tdofQvnNaZk$KXPkRxltAZIwLOSV29AmLeAl/A/.R6Lr8JGVYwzqa9B"),
    ("sha256r", "$5$rounds=1000$saltsalt$eKLZU9t9OoPWrqOQsoTIKG0aYkZ5rGOoOQhiIvoSWX2"),
    ("md5", "$1$1G0VykCx$OwomHlpoy3dfHps5jUrK81"),
    ("bc2a", "$2a$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu"),
    ("bc2b", "$2b$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu"),
    ("bc2y", "$2y$05$fDT1s53J9hc2GdGrAK.LQOtqRsu5pcbLSuKdbfWmKNcCLmW5Y6rgu"),
    // Well formed up to the end of the salt, but not the hash of any password: loads, never matches.
    ("trunc", "$6$salt$short"),
];

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in s.as_bytes().chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() { T[((n >> (18 - 6 * i)) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn start() -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = String::from("userlist ul\n");
    for (name, hash) in HASHES {
        text.push_str(&format!("  user {name} password {hash}\n"));
    }
    text.push_str("  user plain insecure-password secret\n");
    text.push_str(&format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  http-request deny unless {{ http_auth(ul) }}\n  http-request return status 200\n"
    ));
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe)
}

fn status(fe: SocketAddr, user: &str, pass: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    let a = b64(&format!("{user}:{pass}"));
    c.write_all(format!("GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Basic {a}\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_millis(800))).ok();
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = c.read(&mut chunk) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string()
}

#[test]
fn a_crypt_hash_is_checked_against_the_password_of_the_request() {
    let (_i, fe) = start();
    for (name, _) in HASHES {
        let right = if *name == "trunc" { "HTTP/1.1 403 Forbidden" } else { "HTTP/1.1 200 OK" };
        assert_eq!(status(fe, name, "secret"), right, "{name} with the right password");
        assert_eq!(status(fe, name, "wrong"), "HTTP/1.1 403 Forbidden", "{name} with a wrong password");
        assert_eq!(status(fe, name, ""), "HTTP/1.1 403 Forbidden", "{name} with none");
        assert_eq!(status(fe, name, "secre"), "HTTP/1.1 403 Forbidden", "{name} with a prefix of it");
    }
    // Next to a plain one, and a hash is not a password: its own text does not log in.
    assert_eq!(status(fe, "plain", "secret"), "HTTP/1.1 200 OK");
    assert_eq!(status(fe, "md5", HASHES[4].1), "HTTP/1.1 403 Forbidden");
}
