// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T588, left by T573: the stats page's `;typed` (before: the HTML page), the CLI's
//! `show schema json`, and the backend `algo` under `stats show-legends` (`unknown` without a
//! `balance` line). The expectations are `HAProxy` 3.5-dev8-885761-29's answers for the T573
//! configuration (2 frontends, 2 backends, 3 servers); `tests/data/stats_typed_page_keys.txt`
//! is its `;typed` page with the values cut off.

use crate::common;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Setup {
    child: common::Alcyon,
    st: SocketAddr,
    sock: String,
    cfg: std::path::PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.cfg);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// `fe_extra` goes in frontend f1, `be_extra` in backend b1.
fn start(fe_extra: &str, be_extra: &str) -> Setup {
    let (st, f2) = (common::reserve_addr(), common::reserve_addr());
    let id = format!("{}-{}", std::process::id(), st.port());
    let cfg = std::env::temp_dir().join(format!("alcyon-t588-{id}.cfg"));
    let sock = format!("/tmp/alcyon-t588-{id}.sock");
    std::fs::write(
        &cfg,
        format!(
            "global\n    stats socket {sock} level admin\n\
             defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\
             frontend f1\n    bind {st}\n    stats enable\n    stats uri /s\n{fe_extra}    default_backend b1\n\
             frontend f2\n    bind {f2}\n    default_backend b2\n\
             backend b1\n{be_extra}    server s1 127.0.0.1:19001\n    server s2 127.0.0.1:19002\n\
             backend b2\n    server s3 127.0.0.1:19003\n"
        ),
    )
    .expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn");
    let s = Setup { child, st, sock, cfg };
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(s.st).is_err() {
        assert!(Instant::now() < deadline, "alcyon never listened");
        std::thread::sleep(Duration::from_millis(20));
    }
    s
}

/// (head, de-chunked body) of `GET uri`.
fn get(st: SocketAddr, uri: &str) -> (String, String) {
    let mut c = TcpStream::connect(st).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    write!(c, "GET {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut raw = Vec::new();
    c.read_to_end(&mut raw).expect("read");
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
    let head = String::from_utf8_lossy(&raw[..at]).into_owned();
    let mut b = &raw[at + 4..];
    let mut body = Vec::new();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        loop {
            let eol = b.windows(2).position(|w| w == b"\r\n").expect("size");
            let n = usize::from_str_radix(std::str::from_utf8(&b[..eol]).expect("hex"), 16).expect("n");
            if n == 0 {
                break;
            }
            body.extend_from_slice(&b[eol + 2..eol + 2 + n]);
            b = &b[eol + 4 + n..];
        }
    } else {
        body.extend_from_slice(b);
    }
    (head, String::from_utf8(body).expect("utf8"))
}

fn cli(s: &Setup, cmd: &str) -> String {
    let mut c = UnixStream::connect(&s.sock).expect("cli");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn ctype(head: &str) -> String {
    head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-type:").map(|v| v.trim().to_string())).unwrap_or_default()
}

fn keys(body: &str) -> String {
    body.lines().map(|l| l.rsplit_once(':').map_or(l, |(k, _)| k)).collect::<Vec<_>>().join("\n") + "\n"
}

#[test]
fn typed_page_is_the_haproxy_one() {
    let s = start("", "");
    let (head, body) = get(s.st, "/s;typed");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(ctype(&head), "text/plain", "{head}");
    assert_eq!(keys(&body), include_str!("../data/stats_typed_page_keys.txt"));
}

/// Oracle: `;typed` wins over `;csv` (either order), `;json` and `;json-schema` over `;typed`.
#[test]
fn typed_wins_over_csv_but_not_json() {
    let s = start("", "");
    for uri in ["/s;csv;typed", "/s;typed;csv"] {
        assert!(get(s.st, uri).1.starts_with("F.2.0.0.pxname.1:KNSV:str:f1\n"), "{uri}");
    }
    for uri in ["/s;typed;json", "/s;json;typed"] {
        assert!(get(s.st, uri).1.starts_with("[[{\"objType\""), "{uri}");
    }
    assert!(get(s.st, "/s;typed;json-schema").1.starts_with("{\"$schema\""));
}

/// Oracle: the CLI prints the schema of `;json-schema`, then the empty line ending a CLI answer.
#[test]
fn cli_show_schema_json() {
    let s = start("", "");
    let want = include_str!("../data/stats_json_schema.json");
    assert_eq!(cli(&s, "show schema json"), format!("{want}\n"));
    assert_eq!(cli(&s, "show schema json extra"), format!("{want}\n"));
}

fn algos(s: &Setup) -> Vec<String> {
    get(s.st, "/s;typed").1.lines().filter(|l| l.contains(".algo.")).map(|l| l.rsplit(':').next().unwrap_or("").to_string()).collect()
}

/// Oracle: a backend without `balance` (own or from `defaults`) is `unknown`, an explicit
/// `balance roundrobin` is `roundrobin`.
#[test]
fn algo_unknown_without_balance_line() {
    let s = start("    stats show-legends\n", "");
    assert_eq!(algos(&s), ["unknown", "unknown"]);
    let s = start("    stats show-legends\n", "    balance roundrobin\n");
    assert_eq!(algos(&s), ["roundrobin", "unknown"]);
    let s = start("    stats show-legends\n", "    balance leastconn\n");
    assert_eq!(algos(&s), ["leastconn", "unknown"]);
}
