// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The stats page's `;json` and `;json-schema` (T573; `HAProxy` `src/stats-json.c`): before,
//! both answered with the HTML page. The fixtures are `HAProxy` 3.5-dev8-885761-29's answers
//! for the same configuration (2 frontends, 2 backends, 3 servers): the schema byte for
//! byte, and for each row type the list of `pos name origin.nature.scope type`.

use crate::common;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Setup {
    child: common::Alcyon,
    st: SocketAddr,
    cfg: std::path::PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start() -> Setup {
    start_with("")
}

fn start_with(extra: &str) -> Setup {
    let (st, f2) = (common::reserve_addr(), common::reserve_addr());
    let cfg = std::env::temp_dir().join(format!("alcyon-t573-{}-{}.cfg", std::process::id(), st.port()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\
             frontend f1\n    bind {st}\n    stats enable\n    stats uri /s\n{extra}    default_backend b1\n\
             frontend f2\n    bind {f2}\n    default_backend b2\n\
             backend b1\n    server s1 127.0.0.1:19001\n    server s2 127.0.0.1:19002\n\
             backend b2\n    server s3 127.0.0.1:19003\n"
        ),
    )
    .expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn");
    let s = Setup { child, st, cfg };
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

fn ctype(head: &str) -> String {
    head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-type:").map(|v| v.trim().to_string())).unwrap_or_default()
}

#[test]
fn json_schema_is_the_haproxy_one() {
    let s = start();
    let (head, body) = get(s.st, "/s;json-schema");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(ctype(&head), "application/json", "{head}");
    assert_eq!(body, include_str!("../data/stats_json_schema.json"));
}

#[test]
fn json_rows_have_the_haproxy_fields() {
    let s = start();
    let (head, body) = get(s.st, "/s;json");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(ctype(&head), "application/json", "{head}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", &body[..body.len().min(200)]));
    let rows = v.as_array().expect("array of rows");
    // f1 f2 | b1: s1 s2 BACKEND | b2: s3 BACKEND, in the oracle's order, with its ids.
    let ids: Vec<(String, u64, u64)> = rows
        .iter()
        .map(|r| {
            let c = &r[0];
            (c["objType"].as_str().unwrap_or("").to_string(), c["proxyId"].as_u64().unwrap_or(99), c["id"].as_u64().unwrap_or(99))
        })
        .collect();
    let want: Vec<(String, u64, u64)> = [("Frontend", 2, 0), ("Frontend", 3, 0), ("Server", 4, 1), ("Server", 4, 2), ("Backend", 4, 0), ("Server", 5, 1), ("Backend", 5, 0)]
        .iter()
        .map(|&(t, p, i)| (t.to_string(), p, i))
        .collect();
    assert_eq!(ids, want);
    // Each row type: the oracle's fields, in its order, with its tags and value types.
    let fixture = include_str!("../data/stats_json_fields.txt");
    for ty in ["Frontend", "Server", "Backend"] {
        let want: Vec<String> = fixture.lines().filter(|l| l.starts_with(ty)).map(|l| l[ty.len() + 1..].to_string()).collect();
        let row = rows.iter().find(|r| r[0]["objType"] == ty).expect("row");
        let got: Vec<String> = row
            .as_array()
            .expect("cells")
            .iter()
            .map(|c| {
                let t = &c["tags"];
                format!("{} {} {}.{}.{} {}", c["field"]["pos"], c["field"]["name"].as_str().unwrap_or(""), t["origin"].as_str().unwrap_or(""), t["nature"].as_str().unwrap_or(""), t["scope"].as_str().unwrap_or(""), c["value"]["type"].as_str().unwrap_or(""))
            })
            .collect();
        assert_eq!(got, want, "{ty} row");
        assert!(row[0]["processNum"] == 1);
    }
    assert_eq!(rows[0][0]["value"]["value"], "f1");
    assert_eq!(rows[2][0]["value"]["value"], "b1");
    assert_eq!(rows[2][1]["value"]["value"], "s1");
    assert!(body.ends_with("]]\n"), "ends as the oracle: {:?}", &body[body.len() - 8..]);
}

/// `;json` wins over `;csv` in the same URI, as in the oracle, and `;json` is the CLI's
/// `show stat json` rows.
#[test]
fn json_page_wins_over_csv_and_is_chunked_in_one_piece() {
    let s = start();
    let (head, body) = get(s.st, "/s;csv;json");
    assert_eq!(ctype(&head), "application/json", "{head}");
    assert!(body.starts_with("[[{\"objType\":\"Frontend\""), "{}", &body[..body.len().min(80)]);
    let (head, _) = get(s.st, "/s;json;csv");
    assert_eq!(ctype(&head), "application/json", "{head}");
}

/// The server's `addr` is in the page's rows only under `stats show-legends` (oracle: absent
/// from `;json` and `;csv` without it, present with it); the CLI always has it.
#[test]
fn server_address_only_with_show_legends() {
    let plain = start();
    let legends = start_with("    stats show-legends\n");
    for (uri, key) in [("/s;json", "\"addr\""), ("/s;csv", "127.0.0.1:19001")] {
        assert!(!get(plain.st, uri).1.contains(key), "{uri} without show-legends");
        assert!(get(legends.st, uri).1.contains(key), "{uri} with show-legends");
    }
}
