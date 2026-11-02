// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! R2: a header carrying bytes 0x80-0xFF goes through ACLs, converters, `set-header`,
//! `set-var` and the log line as bytes, as `HAProxy` reads `smp->data.u.str`: `-m len`
//! counts bytes, a regex `\xe9` or `[\x80-\xff]` is a byte, `-i` folds ASCII only, a
//! converter delimiter is a byte, `url_enc` escapes each byte.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29. Set
//! `R2_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`. The fuller table of
//! the same probe, at the sample level, is `ibex-sample`'s `bytes_samples` test.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Proxy {
    child: Child,
    logs: Arc<Mutex<Vec<Vec<u8>>>>,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The ACLs and converters, each stored in a variable and sent back as the response header
/// `x-<name>`; `x-seen` is what the server got of `http-request set-header x-up "%[req.hdr(x)]"`.
const RULES: &[(&str, &str)] = &[
    ("len4", "bool(1) if { req.hdr(x) -m len 4 }"),
    ("regx", "bool(1) if { req.hdr(x) -m reg \"\\\\xe9\" }"),
    ("regcls", "bool(1) if { req.hdr(x) -m reg \"[\\\\x80-\\\\xff]\" }"),
    ("stri", "bool(1) if { req.hdr(x) -m str -i \"CAF\\xc3\\x89\" }"),
    ("begi", "bool(1) if { req.hdr(x) -m beg -i \"CAF\\xc3\" }"),
    ("sub", "bool(1) if { req.hdr(x) -m sub \"\\xe9\" }"),
    ("field", "req.hdr(x),field(1,\\xe9)"),
    ("urlenc", "req.hdr(x),url_enc"),
    ("lower", "req.hdr(x),lower"),
];

fn start() -> Proxy {
    let (fe, be) = (common::reserve_addr(), common::reserve_addr());
    let mut cfg = NamedTempFile::new().expect("tmp");
    let mut text = format!(
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n\
         \x20 log-format \"LOG %[var(txn.raw)] |%[var(txn.lower)]| %{{+Q}}[var(txn.raw)] %hr\"\n\
         \x20 capture request header x len 20\n\
         \x20 http-request set-var(txn.raw) req.hdr(x)\n\
         \x20 http-request set-header x-up \"%[req.hdr(x)]\"\n"
    );
    for (name, rule) in RULES {
        text.push_str(&format!("  http-request set-var(txn.{name}) {rule}\n"));
    }
    for (name, _) in RULES {
        text.push_str(&format!("  http-response set-header x-{name} \"%[var(txn.{name})]\"\n"));
    }
    text.push_str(&format!(
        "  default_backend b\n\
         backend b\n  server s {be}\n\
         frontend s\n  bind {be}\n  http-request return status 200 hdr x-seen \"%[req.hdr(x-up)]\"\n"
    ));
    cfg.write_all(text.as_bytes()).expect("write");
    let bin = std::env::var("R2_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let logs: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let sink = Arc::clone(&logs);
    thread::spawn(move || {
        let mut r = BufReader::new(out);
        let mut line = Vec::new();
        while r.read_until(b'\n', &mut line).map_or(0, |n| n) > 0 {
            sink.lock().unwrap().push(std::mem::take(&mut line));
        }
    });
    assert!(common::wait_listening(fe) && common::wait_listening(be), "never listened");
    Proxy { child, logs, fe, _cfg: cfg }
}

/// The response headers to `GET /` with `X: value`, names in lower case.
fn probe(p: &Proxy, value: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\nX: ".to_vec();
    req.extend_from_slice(value);
    req.extend_from_slice(b"\r\n\r\n");
    c.write_all(&req).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let head = &got[..];
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(head.len());
    head[..end]
        .split(|&b| b == b'\n')
        .skip(1)
        .filter_map(|l| {
            let l = l.strip_suffix(b"\r").unwrap_or(l);
            let at = l.iter().position(|&b| b == b':')?;
            let v = &l[at + 1..];
            let v = &v[v.iter().position(|&b| b != b' ').unwrap_or(v.len())..];
            Some((String::from_utf8_lossy(&l[..at]).to_ascii_lowercase(), v.to_vec()))
        })
        .collect()
}

/// For each value: (`x-seen`, then each of [`RULES`]' header in order).
const WANT: &[(&[u8], &[&[u8]])] = &[
    (b"caf\xe9", &[b"caf\xe9", b"1", b"1", b"1", b"", b"", b"1", b"caf", b"caf%E9", b"caf\xe9"]),
    (b"caf\xc3\xa9", &[b"caf\xc3\xa9", b"", b"", b"1", b"", b"1", b"", b"caf\xc3\xa9", b"caf%C3%A9", b"caf\xc3\xa9"]),
    (b"CAF\xc3\x89", &[b"CAF\xc3\x89", b"", b"", b"1", b"1", b"1", b"", b"CAF\xc3\x89", b"CAF%C3%89", b"caf\xc3\x89"]),
    (b"\xe9caf\xe9", &[b"\xe9caf\xe9", b"", b"1", b"1", b"", b"", b"1", b"", b"%E9caf%E9", b"\xe9caf\xe9"]),
];

#[test]
fn acls_converters_and_set_header_read_the_header_as_bytes() {
    let p = start();
    let mut wrong = Vec::new();
    for (value, want) in WANT {
        let got = probe(&p, value);
        let header = |n: &str| got.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or_default();
        let names = std::iter::once("seen").chain(RULES.iter().map(|(n, _)| *n));
        for (name, want) in names.zip(want.iter()) {
            let have = header(&format!("x-{name}"));
            if have != *want {
                wrong.push(format!("X: {} x-{name}: got {} want {}", value.escape_ascii(), have.escape_ascii(), want.escape_ascii()));
            }
        }
    }
    assert!(wrong.is_empty(), "differ from HAProxy:\n{}", wrong.join("\n"));
}

#[test]
fn the_log_line_carries_the_bytes() {
    let p = start();
    for (value, _) in WANT {
        let _ = probe(&p, value);
    }
    thread::sleep(Duration::from_millis(500));
    // The line of `wait_listening`'s empty connection, which captured nothing, is not one.
    let logs: Vec<Vec<u8>> = p.logs.lock().unwrap().iter().filter(|l| l.starts_with(b"LOG ") && l.contains(&b'{')).cloned().collect();
    let want: &[&[u8]] = &[
        b"LOG caf\xe9 |caf\xe9| \"caf\xe9\" {caf#E9}\n",
        b"LOG caf\xc3\xa9 |caf\xc3\xa9| \"caf\xc3\xa9\" {caf#C3#A9}\n",
        b"LOG CAF\xc3\x89 |caf\xc3\x89| \"CAF\xc3\x89\" {CAF#C3#89}\n",
        b"LOG \xe9caf\xe9 |\xe9caf\xe9| \"\xe9caf\xe9\" {#E9caf#E9}\n",
    ];
    let got: Vec<String> = logs.iter().map(|l| l.escape_ascii().to_string()).collect();
    let want: Vec<String> = want.iter().map(|l| l.escape_ascii().to_string()).collect();
    assert_eq!(got, want);
}
