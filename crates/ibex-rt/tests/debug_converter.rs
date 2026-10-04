// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `debug([prefix][,destination])` converter copies its input to an event sink, `buf0`
//! by default, read back with `show events` (`converter/when_debug.vtc`, T131 item 6).
//!
//! Measured against `HAProxy` 3.5-dev8-885761-29: after one request through
//! `http-request set-var(txn.dbg) str(hello),debug(mytag)`, `show events buf0 -0` answers
//! `<0>2026-10-04T20:45:31.823886+02:00 [debug] mytag: type=str <hello>\0`. A sink the
//! converter names must exist (`debug converter: sink 'mysink' doesn't exist.` at load); a
//! `ring` without a format takes the bare line `[debug] num: type=sint <42>\0`, and the
//! sample is passed on unchanged.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn live_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

fn cli(sock: &std::path::Path, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
    writeln!(c, "{cmd}").expect("write");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn debug_copies_the_sample_to_buf0_and_to_a_named_sink() {
    let live = live_backend();
    let port = common::reserve_port();
    let sock = std::path::PathBuf::from(format!("/tmp/ibex_test_debugconv_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  stats socket {}\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  \
         http-request set-var(txn.dbg) str(hello),debug(mytag)\n  \
         http-request set-var(txn.dbg2) int(42),debug(num,mysink)\n  \
         http-response set-header x-dbg \"%[var(txn.dbg)]\"\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:{live}\n\
         ring mysink\n  description \"my sink\"\n  size 4096\n",
        sock.display()
    );
    let path = std::env::temp_dir().join(format!("ibex_debugconv_{}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() || !sock.exists() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    let resp = String::from_utf8_lossy(&resp).into_owned();
    let buf0 = cli(&sock, "show events buf0 -0");
    let named = cli(&sock, "show events mysink -0");
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&sock);

    assert!(resp.to_ascii_lowercase().contains("x-dbg: hello"), "the sample is passed through: {resp}");
    assert!(buf0.starts_with("<0>"), "{buf0:?}");
    assert!(buf0.contains(" [debug] mytag: type=str <hello>\0"), "{buf0:?}");
    assert_eq!(named, "[debug] num: type=sint <42>\0\n", "a ring with no format keeps the bare line");
}

/// `debug(x,nosuch)`: HAProxy refuses the configuration, "debug converter: sink 'nosuch'
/// doesn't exist." (measured, `haproxy -c`).
#[test]
fn debug_to_an_unknown_sink_is_refused() {
    let path = std::env::temp_dir().join(format!("ibex_debugconv_bad_{}", std::process::id()));
    std::fs::write(
        &path,
        "defaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n\
         frontend fe\n  bind 127.0.0.1:0\n  http-request set-var(txn.d) str(a),debug(x,nosuch)\n  default_backend be\n\
         backend be\n  server s1 127.0.0.1:9\n",
    )
    .expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&path);
    let text = String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("debug converter: sink 'nosuch' doesn't exist."), "{text}");
}
