// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sample expressions, `%[...]` formats and regexes are compiled once, not on every
//! request (T174). `HAProxy` compiles them when the configuration loads
//! (`sample_parse_expr`, `build_acl_cond`, `regex_comp`); Ibex was parsing anonymous ACL
//! terms (`if { path_beg /x }`), rule expressions and every `%[...]` again per request, and
//! compiling `replace-*` regexes per request. An ACL with `-f <file>` also `stat`ed its
//! file on each parse.
//!
//! Counted on the thread that runs the engine: after a warm-up request, a second request
//! parses no expression and compiles no regex.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::engine::Engine;

fn drive(fe: SocketAddr, e: &mut Engine, path: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    write!(c, "GET {path} HTTP/1.1\r\nHost: Localhost\r\nConnection: close\r\n\r\n").expect("write");
    let st = Instant::now();
    let mut r = Vec::new();
    let mut b = [0u8; 512];
    while st.elapsed() < Duration::from_secs(3) {
        let _ = e.run_once();
        match c.read(&mut b) {
            Ok(0) => break,
            Ok(n) => r.extend_from_slice(&b[..n]),
            Err(_) => {}
        }
        thread::sleep(Duration::from_millis(1));
    }
    String::from_utf8_lossy(&r).into_owned()
}

/// Parses and regex compiles of one request after a warm-up one, with `rules` in the
/// frontend; the request must be answered `want`.
fn compiles_per_request(rules: &str, path: &str, want: &str) -> (u64, u64) {
    compiles_per_request_after(rules, (path, want), None, (path, want))
}

/// As [`compiles_per_request`], with `added` put in the `@LIST@` pattern file (`add acl`)
/// between the warm-up request and the measured one.
fn compiles_per_request_after(rules: &str, warm: (&str, &str), added: Option<&str>, (path, want): (&str, &str)) -> (u64, u64) {
    let sl = TcpListener::bind("127.0.0.1:0").expect("bind");
    let sa = sl.local_addr().expect("addr");
    let fl = TcpListener::bind("127.0.0.1:0").expect("bind");
    let fa = fl.local_addr().expect("addr");
    drop(fl);
    let run = Arc::new(AtomicBool::new(true));
    let run2 = Arc::clone(&run);
    sl.set_nonblocking(true).expect("nonblocking");
    let be = thread::spawn(move || {
        while run2.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = sl.accept() {
                s.set_nonblocking(false).ok();
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
    let list = std::env::temp_dir().join(format!("ibex-t174-{}-{}.lst", std::process::id(), fa.port()));
    std::fs::write(&list, "/blocked\n/also-blocked\n").expect("write list");
    let cfg = format!(
        "frontend fe\n  mode http\n  bind {fa}\n  timeout client 5s\n{}\n  default_backend be\n\
         backend be\n  mode http\n  timeout connect 5s\n  timeout server 5s\n  server s1 {sa}\n",
        rules.replace("@LIST@", &list.display().to_string())
    );
    let mut e = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let first = drive(fa, &mut e, warm.0);
    assert!(first.starts_with(warm.1), "warm-up request: want {:?}, got {first:?}", warm.1);
    if let Some(key) = added {
        let list = list.display().to_string();
        let out = ibex_sample::patref::command("add", ibex_sample::patref::RefKind::Acl, &[&list, key], None);
        assert_eq!(out, "", "add acl {list} {key}");
    }
    let (p0, r0) = (ibex_sample::expr::parses_on_this_thread(), ibex_regex::compiles_on_this_thread());
    let second = drive(fa, &mut e, path);
    let (p1, r1) = (ibex_sample::expr::parses_on_this_thread(), ibex_regex::compiles_on_this_thread());
    assert!(second.starts_with(want), "measured request: want {want:?}, got {second:?}");
    run.store(false, Ordering::Relaxed);
    let _ = be.join();
    let _ = std::fs::remove_file(&list);
    (p1 - p0, r1 - r0)
}

#[test]
fn an_anonymous_acl_is_not_parsed_per_request() {
    let rules = "  http-request deny if { path_beg /x }\n  http-request deny if { path -f @LIST@ }\n  \
                 http-request deny if !{ req.hdr(host),lower -m str localhost }";
    assert_eq!(compiles_per_request(rules, "/api/t", "HTTP/1.1 200"), (0, 0));
    // The `-f` term still matches what its file lists.
    assert_eq!(compiles_per_request(rules, "/also-blocked", "HTTP/1.1 403"), (0, 0));
}

#[test]
fn an_anonymous_acl_file_still_follows_add_acl() {
    // Compiled once, the `-f` term still sees a pattern added at run time (T171).
    let rules = "  http-request deny if { path -f @LIST@ }";
    let got = compiles_per_request_after(rules, ("/new", "HTTP/1.1 200"), Some("/new"), ("/new", "HTTP/1.1 403"));
    assert_eq!(got.0, 0, "parses");
}

#[test]
fn rule_expressions_and_formats_are_not_parsed_per_request() {
    let rules = "  http-request set-var(txn.p) path,lower\n  \
                 http-request set-header X-A %[req.hdr(host),lower]-%[var(txn.p)]\n  \
                 http-request capture req.hdr(host) len 10\n  \
                 http-response set-header X-B %[var(txn.p)]";
    assert_eq!(compiles_per_request(rules, "/api/t", "HTTP/1.1 200"), (0, 0));
}

#[test]
fn rewrite_regexes_are_not_compiled_per_request() {
    let rules = "  http-request replace-path ^/api/(.*) /v1/\\1\n  \
                 http-request replace-uri ^(.*)$ \\1\n  \
                 http-request replace-header Host (.*) \\1\n  \
                 http-request del-header X-Foo -m reg ^x-f";
    assert_eq!(compiles_per_request(rules, "/api/t", "HTTP/1.1 200"), (0, 0));
}
