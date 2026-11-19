// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The stats page's `;scope=` filter and the admin POST that changes a server's state
//! (reg-test `webstats/webstats-scope-and-post-change.vtc`).
//!
//! `GET /?;csv;scope=b1` answers 200 with the rows of the proxies whose name holds the scope
//! text, case-insensitively (`strnistr(px->id, ...)`, `stats_dump_proxy_to_buffer`): the
//! proxies that do not match are skipped whole. A POST to the stats URI with the form body
//! (`b=<backend>&action=<verb>&s=<server>...`) is answered by a `303` to `<uri>;st=<CODE>`
//! with the request's `?scope=<text>` appended, and alters the servers of the backend named
//! by `b` (a name, or `#<id>` as `proxy_be_by_name` reads it, the ids starting at 2 for the
//! first section). Set `T281_ORACLE=/path/to/haproxy` to run this test against `HAProxy`:
//! every value was measured on `HAProxy` 3.5-dev11.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proxy {
    child: Child,
    fe: SocketAddr,
    sock: std::path::PathBuf,
    _cfg: tempfile::NamedTempFile,
    _dir: tempfile::TempDir,
}

fn spawn() -> Proxy {
    let fe = common::reserve_addr();
    let be = common::reserve_port(); // nothing listens: no checks are configured, so "no check"
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let cfg = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    let cfg_path = cfg.path().to_str().unwrap().to_owned();
    let cfg_txt = format!(
        r#"global
    stats socket {sock} mode 600 level admin
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    mode http
frontend fe1
    bind {fe}
    stats enable
    stats refresh 5s
    stats uri /
    stats admin if TRUE
backend b1
    server srv1 127.0.0.1:{be}
    server srv2 127.0.0.1:{be}
    server srv3 127.0.0.1:{be}
backend b2
    server srv1 127.0.0.1:{be}
    server srv2 127.0.0.1:{be}
"#,
        sock = sock.display(),
        fe = fe,
        be = be,
    );
    std::fs::write(&cfg_path, cfg_txt).unwrap();
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = common::alcyon_command(&bin)
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the proxy");
    let started = Instant::now();
    while !common::wait_listening(fe) {
        assert!(started.elapsed() < Duration::from_secs(10), "the proxy never listened");
        std::thread::sleep(Duration::from_millis(20));
    }
    Proxy { child, fe, sock, _cfg: cfg, _dir: dir }
}

/// One request on a fresh connection (`connection: close` ends the answer); the status line
/// and the lower-cased headers, then the whole body, de-chunked.
fn spawn_backup() -> Proxy {
    // One active and two backup servers: once the active goes down, the backend's weight
    // must fall to the weight of the *first* usable backup (measured on the oracle).
    let fe = common::reserve_addr();
    let be = common::reserve_port(); // nothing listens: no checks are configured, so "no check"
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let cfg = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    let cfg_path = cfg.path().to_str().unwrap().to_owned();
    let cfg_txt = format!(
        r#"global
    stats socket {sock} mode 600 level admin
defaults
    timeout client 5s
    timeout server 5s
    timeout connect 5s
    mode http
frontend fe1
    bind {fe}
    stats enable
    stats refresh 5s
    stats uri /
    stats admin if TRUE
backend b1
    server a1 127.0.0.1:{be}
    server bk1 127.0.0.1:{be} backup
    server bk2 127.0.0.1:{be} backup
"#,
        sock = sock.display(),
        fe = fe,
        be = be,
    );
    std::fs::write(&cfg_path, cfg_txt).unwrap();
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = common::alcyon_command(&bin)
        .arg("-f")
        .arg(&cfg_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the proxy");
    let started = Instant::now();
    while !common::wait_listening(fe) {
        assert!(started.elapsed() < Duration::from_secs(10), "the proxy never listened");
        std::thread::sleep(Duration::from_millis(20));
    }
    Proxy { child, fe, sock, _cfg: cfg, _dir: dir }
}

fn http(fe: SocketAddr, req: &str) -> (String, Vec<(String, String)>, String) {
    let mut s = TcpStream::connect(fe).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    let txt = String::from_utf8_lossy(&all).into_owned();
    let (head, body) = txt.split_once("\r\n\r\n").unwrap_or((txt.as_str(), ""));
    let mut lines = head.lines();
    let status = lines.next().unwrap_or("").to_owned();
    let hdrs: Vec<(String, String)> = lines
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect();
    let chunked = hdrs.iter().any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        let mut out = String::new();
        let mut rest = body;
        loop {
            let Some((size_line, next)) = rest.split_once("\r\n") else { break };
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let Some(data) = next.get(..size) else { break };
            out.push_str(data);
            rest = next.get(size + 2..).unwrap_or(""); // skip the chunk's trailing `\r\n`
        }
        out
    } else if let Some((_, v)) = hdrs.iter().find(|(k, _)| k == "content-length") {
        let n: usize = v.parse().unwrap_or(body.len());
        body.get(..n).unwrap_or(body).to_owned()
    } else {
        body.to_owned()
    };
    (status, hdrs, body)
}

fn header<'a>(hdrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hdrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn status_of(proxies_csv: &str, px: &str, sv: &str) -> Option<String> {
    // `show stat`'s rows: the status is the column after `wredis` (index 17).
    proxies_csv
        .lines()
        .find(|l| l.starts_with(&format!("{px},{sv},")))
        .map(|l| l.split(',').nth(17).unwrap_or("").to_owned())
}

#[test]
fn scope_and_post_change() {
    let mut p = spawn();

    // 1. `GET /;csv;`: the whole page (reg-test client c1).
    let (st, _, _) = http(p.fe, "GET /;csv; HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /;csv; : {st}");

    // 2. `GET /?;csv;scope=b1`: 200, only the proxies whose name holds `b1` (c2 and c3).
    let (st, _, body) = http(p.fe, "GET /?;csv;scope=b1 HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /?;csv;scope=b1 : {st}");
    assert!(body.contains("\nb1,BACKEND"), "scope=b1 lost the b1 rows:\n{body}");
    assert!(!body.contains("\nb2,BACKEND"), "scope=b1 kept the b2 rows:\n{body}");

    // 3. The form's POST: the verb, the backend by numeric id (`#3` is b1, the sections are
    //    numbered from 2), the servers by name. The answer is the redirect (measured).
    let post = |url: &str, body: &str| {
        let req = format!(
            "POST {url} HTTP/1.1\r\nhost: h\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let (st, hdrs, _) = http(p.fe, &req);
        (st, header(&hdrs, "location").unwrap_or("").to_owned())
    };

    let (st, loc) = post("/?scope=b2", "s=srv1&s=srv2&s=srv3&action=maint&b=%233");
    assert!(st.starts_with("HTTP/1.1 303"), "POST /?scope=b2 : {st}");
    assert_eq!(loc, "/;st=DONE?scope=b2", "the redirect of the scoped POST");

    let (st, loc) = post("/", "s=srv2&action=drain&b=%233");
    assert!(st.starts_with("HTTP/1.1 303"), "POST / drain : {st}");
    assert_eq!(loc, "/;st=DONE", "the redirect of the drain POST");

    let (st, loc) = post("/", "s=srv1&action=maint&b=%234");
    assert!(st.starts_with("HTTP/1.1 303"), "POST / maint : {st}");
    assert_eq!(loc, "/;st=DONE", "the redirect of the maint POST");

    // 4. `GET /?;csv;scope=fe1`: 200 again (c3's last request).
    let (st, _, body) = http(p.fe, "GET /?;csv;scope=fe1 HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /?;csv;scope=fe1 : {st}");
    assert!(body.contains("\nfe1,FRONTEND"), "scope=fe1 lost the fe1 row:\n{body}");
    assert!(!body.contains("\nb1,BACKEND"), "scope=fe1 kept the b1 rows:\n{body}");

    // 4b. Edges of the scope parsing, each measured on the oracle:
    //  * the scan only finds `scope=` with 8 bytes or more left to the end of the URI
    //    (`http_handle_stats` loops `h <= end - 8`): `scope=a` is too late, `scope=ab` is not;
    let (st, _, body) = http(p.fe, "GET /;csv;scope=a HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /;csv;scope=a : {st}");
    assert!(body.contains("\nb1,BACKEND"), "scope=a is too late to be found, the page must be unscoped:\n{body}");

    let (st, _, body) = http(p.fe, "GET /;csv;scope=ab HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /;csv;scope=ab : {st}");
    assert!(!body.contains("\nb1,BACKEND"), "scope=ab scoped out every proxy:\n{body}");
    //  * the match is case-insensitive (`strnistr`):
    let (st, _, body) = http(p.fe, "GET /;csv;scope=B1 HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /;csv;scope=B1 : {st}");
    assert!(body.contains("\nb1,BACKEND"), "scope=B1 lost the b1 rows:\n{body}");
    assert!(!body.contains("\nb2,BACKEND"), "scope=B1 kept the b2 rows:\n{body}");
    //  * the text is clamped to 20 bytes (`STAT_SCOPE_TXT_MAXLEN`), the rest ignored:
    let (st, _, body) = http(p.fe, "GET /;csv;scope=b1234567890123456789ab HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET scope clamp : {st}");
    assert!(!body.contains("\nb1,BACKEND"), "the clamped scope scoped out every proxy:\n{body}");
    //  * an invalid byte clears the scope (`invalid_char`):
    let (st, _, body) = http(p.fe, "GET /;csv;scope=b%21 HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /;csv;scope=b%21 : {st}");
    assert!(body.contains("\nb1,BACKEND"), "scope=b%21 holds an invalid byte and must be cleared:\n{body}");
    //  * the text ends at the next `;` (or `&`, or space):
    let (st, _, body) = http(p.fe, "GET /;csv;scope=b1;x HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
    assert!(st.starts_with("HTTP/1.1 200"), "GET /;csv;scope=b1;x : {st}");
    assert!(body.contains("\nb1,BACKEND"), "scope=b1;x lost the b1 rows:\n{body}");
    assert!(!body.contains("\nb2,BACKEND"), "scope=b1;x kept the b2 rows:\n{body}");

    // 5. The states `show stat` reports afterwards (the reg-test's final CLI check).
    let mut s = std::os::unix::net::UnixStream::connect(&p.sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"show stat\n").unwrap();
    let mut all = String::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        all.push_str(&String::from_utf8_lossy(&chunk[..n]));
        if all.contains("End of output") {
            break;
        }
    }
    // The `.*` of the reg-test: the status word anywhere in the row.
    for (px, sv, want) in [
        ("b1", "srv1", "MAINT"),
        ("b1", "srv2", "DRAIN"),
        ("b1", "srv3", "MAINT"),
        ("b1", "BACKEND", "DOWN"),
        ("b2", "srv1", "MAINT"),
        ("b2", "srv2", "no check"),
        ("b2", "BACKEND", "UP"),
    ] {
        let Some(status) = status_of(&all, px, sv) else {
            panic!("show stat has no row {px},{sv}:\n{all}");
        };
        assert!(
            status.contains(want),
            "{px},{sv} : the status is {status:?}, the reg-test wants {want}"
        );
    }

    common::stop(&mut p.child);
}

/// The backend's `weight` and `uweight` columns once no active server is usable: `HAProxy`
/// keeps the weight of the *first* usable backup (`px->lbprm.fbck`, set by `recount_servers`
/// and read by `update_backend_weight`), not the sum of all backups.
#[test]
fn backend_weight_is_the_first_backup_when_no_active_is_usable() {
    let mut p = spawn_backup();
    let csv = |p: &Proxy| {
        let (st, _, body) = http(p.fe, "GET /;csv; HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n");
        assert!(st.starts_with("HTTP/1.1 200"), "GET /;csv; : {st}");
        // The page's header line names the columns; the backend row is `b1,BACKEND,...`.
        let head = body.lines().next().unwrap().strip_prefix("# ").unwrap().split(',');
        let row = body
            .lines()
            .find(|l| l.starts_with("b1,BACKEND"))
            .unwrap_or_else(|| panic!("no b1,BACKEND row:\n{body}"));
        let pairs: Vec<(&str, &str)> = head.zip(row.split(',')).collect();
        let get = |name: &str| -> String {
            pairs
                .iter()
                .find(|(h, _)| *h == name)
                .map(|(_, v)| (*v).to_string())
                .unwrap_or_else(|| panic!("no column {name} in the header:\n{body}"))
        };
        (get("status"), get("weight"), get("uweight"), get("act"), get("bck"))
    };

    // All servers up: the weight is the single active's, the two backups are counted only
    // in `bck` (measured on the oracle: `UP,1,1,1,2`).
    let (status, weight, uweight, act, bck) = csv(&p);
    assert_eq!((status.as_str(), weight.as_str(), uweight.as_str(), act.as_str(), bck.as_str()),
               ("UP", "1", "1", "1", "2"), "before the maint:\n{status},{weight},{uweight},{act},{bck}");

    // The active goes to maintenance: the backend stays UP on its backups, and the weight
    // is that of the first usable backup (measured on the oracle: `UP,1,1,0,2`).
    let req = format!(
        "POST / HTTP/1.1\r\nhost: h\r\ncontent-length: {}\r\nconnection: close\r\n\r\ns=a1&action=maint&b=b1",
        b"s=a1&action=maint&b=b1".len()
    );
    let (st, hdrs, _) = http(p.fe, &req);
    assert!(st.starts_with("HTTP/1.1 303"), "POST maint a1 : {st}");
    assert_eq!(header(&hdrs, "location").unwrap_or(""), "/;st=DONE");

    let (status, weight, uweight, act, bck) = csv(&p);
    assert_eq!((status.as_str(), act.as_str(), bck.as_str()), ("UP", "0", "2"),
               "after the maint:\n{status},{weight},{uweight},{act},{bck}");
    assert_eq!(weight.as_str(), "1", "the weight must be the first usable backup's (1), not the sum of both ({uweight})");
    assert_eq!(uweight.as_str(), "1", "uweight follows the same first backup");

    common::stop(&mut p.child);
}
