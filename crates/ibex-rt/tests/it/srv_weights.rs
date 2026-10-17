// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: `srv_weight`, `srv_iweight` and `srv_uweight`, at runtime and as the configuration
//! names their server. Every expected value was measured on `HAProxy` 3.5-dev8.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `{X}` is the `lf-string` of the frontend's answer.
const CFG: &str = r#"global
  stats socket {sock} level admin
  nbthread 1
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "{X}"
backend b
  balance roundrobin
  server s1 127.0.0.1:9 weight 7
  server s2 127.0.0.1:9 weight 200
"#;

const ALL: &str = "%[srv_weight(b/s1)]|%[srv_iweight(b/s1)]|%[srv_uweight(b/s1)]|%[srv_weight(b/s2)]|%[srv_iweight(b/s2)]|%[srv_uweight(b/s2)]";

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// The body of the answer to one request on a new connection.
fn body(addr: SocketAddr) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let s = String::from_utf8_lossy(&out).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

#[test]
fn srv_weights() {
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("srv-weights-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, CFG.replace("{sock}", &sock).replace("{A}", &a.to_string()).replace("{X}", ALL)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = common::Ibex(child);
    assert!(common::wait_listening(a), "ibex did not listen on {a}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let initial = body(a);
    // `set server weight` changes the user weight and the effective one, not the initial.
    cli(&sock, "set server b/s1 weight 3");
    let after = body(a);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!((initial.as_str(), after.as_str()), ("7|7|7|200|200|200", "3|7|3|200|200|200"));
}

/// The `<backend>/<server>` argument is resolved at load, as for `srv_conn`: `HAProxy`
/// refuses an unknown proxy or server, and a missing argument.
#[test]
fn srv_weights_server_argument_is_resolved_at_load() {
    let rows = [
        ("srv_weight(nosuch/x)", "unable to find proxy 'nosuch' referenced in arg 1 of sample fetch keyword 'srv_weight'"),
        ("srv_iweight(b/nosuch)", "unable to find server 'nosuch' in proxy 'b'"),
        ("srv_uweight", "missing server name in arg 1 of sample fetch keyword 'srv_uweight'"),
        ("srv_iweight(s1)", "unable to find server 's1' in proxy 'fe'"),
    ];
    for (i, (expr, want)) in rows.iter().enumerate() {
        let dir = std::env::temp_dir().join(format!("srv-weights-c{i}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.cfg");
        let cfg = CFG.replace("  stats socket {sock} level admin\n", "").replace("{A}", "127.0.0.1:0").replace("{X}", &format!("%[{expr}]"));
        std::fs::write(&path, cfg).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success() && text.contains(want), "{expr}: {text}");
    }
}
