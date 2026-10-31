// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `quic` bind in a `listen` section serves HTTP/3 like one in a `frontend` (T530).
//! `listen` was refused at parse time (`QUIC is not supported in listen sections`) and the
//! engine's `listen` loop opened TCP sockets only. HAProxy (3.5-dev7 +QUIC) accepts it, which
//! is what `reg-tests/quic/retry.vtc` and `h3_unknown_length_req.vtc` rely on.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A server that answers every request with its request head.
fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut data = Vec::new();
                let mut buf = [0u8; 8192];
                while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => data.extend_from_slice(&buf[..n]),
                    }
                }
                let body = format!("server=s1\n{}", String::from_utf8_lossy(&data));
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    addr
}

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    quic: SocketAddr,
    log: UdpSocket,
}

impl Ibex {
    fn start() -> Self {
        let s1 = backend();
        let log = UdpSocket::bind("127.0.0.1:0").expect("bind syslog");
        log.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
        let log_addr = log.local_addr().expect("addr");
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let tcp = common::reserve_addr();
        let quic = common::reserve_addr();
        let cfg = format!(
            "global\n  nbthread 1\n  log {log_addr} local0\n\
             defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             listen ls\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n\
             \x20 http-request deny if {{ path /deny }}\n\
             \x20 http-request set-header X-Added yes\n\
             \x20 server s1 {s1}\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex");
        assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
        Self { child, _cfg: f, quic, log }
    }

    fn h3(&self, path: &str) -> String {
        let out = Command::new("curl")
            .args(["-sS", "-i", "--http3-only", "-k", "--max-time", "8", "--resolve"])
            .arg(format!("localhost:{}:127.0.0.1", self.quic.port()))
            .arg(format!("https://localhost:{}{path}", self.quic.port()))
            .output()
            .expect("curl");
        String::from_utf8_lossy(&out.stdout).replace('\r', "") + &String::from_utf8_lossy(&out.stderr)
    }

    fn logs(&self, wait: Duration) -> Vec<String> {
        let deadline = Instant::now() + wait;
        let mut lines = Vec::new();
        let mut buf = [0u8; 4096];
        while Instant::now() < deadline {
            if let Ok(n) = self.log.recv(&mut buf) {
                lines.push(String::from_utf8_lossy(&buf[..n]).to_string());
            }
        }
        lines
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn require_curl_http3() {
    let ok = Command::new("curl")
        .arg("--version")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    assert!(ok, "this test needs a curl with HTTP/3; it fails rather than skips");
}

crate::h3_both_paths! {
fn listen_serves_h3_through_its_rules_and_server() {
    require_curl_http3();
    let ibex = Ibex::start();
    let _ = ibex.logs(Duration::from_millis(300));
    let ok = ibex.h3("/a");
    assert!(ok.starts_with("HTTP/3 200"), "a listen's QUIC bind must serve H3:\n{ok}");
    assert!(ok.contains("server=s1"), "the listen's own server answers:\n{ok}");
    assert!(ok.to_ascii_lowercase().contains("x-added: yes"), "the listen's http-request rules run:\n{ok}");
    let deny = ibex.h3("/deny");
    assert!(deny.starts_with("HTTP/3 403"), "http-request deny runs on H3:\n{deny}");
    let lines = ibex.logs(Duration::from_millis(800));
    assert_eq!(lines.len(), 2, "one log line per H3 request: {lines:#?}");
    assert!(lines[0].contains(" ls~ ls/s1 ") && lines[0].contains(" 200 "), "{}", lines[0]);
    assert!(lines[1].contains(" ls~ ls/<NOSRV> ") && lines[1].contains(" 403 "), "{}", lines[1]);
}
}

/// `-c` loads a `listen`'s QUIC certificate as it does a frontend's (`validate_tls`): a missing
/// file is reported before the process would start on it.
#[test]
fn check_only_loads_the_certificate_of_a_listen_quic_bind() {
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let run = |crt: &str| {
        let cfg = format!(
            "defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             listen ls\n  bind quic4@127.0.0.1:0 ssl crt {crt} alpn h3\n  server s1 127.0.0.1:9\n"
        );
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let out = common::ibex_command(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run -c");
        (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let (ok, err) = run(&crt);
    assert!(ok, "valid listen QUIC bind refused by -c: {err}");
    let (ok, err) = run("/nonexistent/t530.pem");
    assert!(!ok, "-c accepted a listen QUIC bind whose certificate does not exist");
    assert!(err.contains("t530.pem"), "{err}");
}
