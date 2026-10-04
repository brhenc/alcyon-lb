// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `show table` prints entries as HAProxy does (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 with `http-request track-sc0 req.hdr(x-k)` and a
//! request `GET /` with `X-K: abc`, `Host: x` :
//!
//! * the header is `# table: <name>, type: <type>, size:<size>, used:<n>`;
//! * an entry is `0x<address>: key=<key> use=<trackers> exp=<ms left> shard=0`, then only
//!   the data types the table stores, in HAProxy's fixed order (not the order of `store`):
//!   `server_id gpt0 gpc0 gpc0_rate conn_cnt conn_rate conn_cur sess_cnt sess_rate
//!   http_req_cnt http_req_rate http_err_cnt http_err_rate bytes_in_cnt bytes_in_rate
//!   bytes_out_cnt bytes_out_rate gpc1 gpc1_rate http_fail_cnt http_fail_rate`, then the
//!   arrays (`gpt0 gpt1 ...`, `gpc0 gpc1 ...`, `gpc0_rate(<ms>) ...`), then `glitch_cnt
//!   glitch_rate`; a rate is written `<name>(<period in ms>)=<n>`;
//! * `use=` is 1 while a stream tracks the entry (and `conn_cur=1`), and `exp=` is the
//!   whole `expire` again (60000 of 60 s) at the moment the stream is done with it;
//! * a binary key is its bytes in lowercase hex.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn server(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                thread::sleep(delay);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            });
        }
    });
    addr
}

fn start(table: &str, rules: &str, delay: Duration) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!("ibex_t149b_st_{}_{n}.sock", std::process::id()));
    let be = server(delay);
    let text = format!(
        "global\n  nbthread 1\n  stats socket {sock} mode 600 level admin\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  stick-table {table}\n  http-request track-sc0 req.hdr(x-k)\n{rules}  default_backend b\nbackend b\n  server s1 {be}\n",
        sock = sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f, sock };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    (ibex, fe)
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn send(fe: SocketAddr) -> TcpStream {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-K: abc\r\n\r\n").expect("send");
    c
}

fn finish(mut c: TcpStream) {
    let mut buf = [0u8; 512];
    let _ = c.read(&mut buf);
}

/// The entry line with its address and `exp=` value replaced, and the `exp` read apart.
fn normalise(out: &str) -> (Vec<String>, Vec<u64>) {
    let mut exps = Vec::new();
    let lines = out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            if !l.starts_with("0x") {
                return l.to_string();
            }
            let (_, rest) = l.split_once(": ").expect("an entry has a colon");
            rest.split(' ')
                .map(|w| match w.strip_prefix("exp=") {
                    Some(n) => {
                        exps.push(n.parse().expect("exp is a number"));
                        "exp=N".to_string()
                    }
                    None => w.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    (lines, exps)
}

#[test]
fn the_stored_types_are_printed_in_haproxys_order() {
    let (ibex, fe) = start(
        "type string len 20 size 100 expire 60s store http_fail_rate(20s),gpc1_rate(20s),gpc1,bytes_out_rate(20s),bytes_out_cnt,bytes_in_rate(20s),bytes_in_cnt,\
         http_err_rate(20s),http_err_cnt,http_req_rate(20s),http_req_cnt,sess_rate(20s),sess_cnt,conn_cur,conn_rate(20s),conn_cnt,gpc0_rate(20s),gpc0,gpt0,server_id,http_fail_cnt",
        "  http-request sc-inc-gpc0(0)\n  http-request sc-set-gpt0(0) 7\n",
        Duration::ZERO,
    );
    finish(send(fe));
    thread::sleep(Duration::from_millis(200));
    let (lines, exps) = normalise(&cli(&ibex, "show table f"));
    assert_eq!(lines[0], "# table: f, type: string, size:100, used:1");
    // The byte counts depend on the bytes the server sends, and are not what this checks.
    let line = lines[1].split(' ').map(|w| if w.starts_with("bytes_") { w.split('=').next().unwrap().to_string() + "=B" } else { w.to_string() }).collect::<Vec<_>>().join(" ");
    assert_eq!(
        line,
        "key=abc use=0 exp=N shard=0 server_id=0 gpt0=7 gpc0=1 gpc0_rate(20000)=1 conn_cnt=1 conn_rate(20000)=1 conn_cur=0 sess_cnt=0 sess_rate(20000)=0 \
         http_req_cnt=1 http_req_rate(20000)=1 http_err_cnt=0 http_err_rate(20000)=0 bytes_in_cnt=B bytes_in_rate(20000)=B bytes_out_cnt=B \
         bytes_out_rate(20000)=B gpc1=0 gpc1_rate(20000)=0 http_fail_cnt=0 http_fail_rate(20000)=0"
    );
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!((59_000..=60_000).contains(&exps[0]), "exp {exps:?}");
}

#[test]
fn the_array_types_follow_the_others() {
    let (ibex, fe) = start(
        "type string len 20 size 100 expire 60s store gpt(2),gpc(2),gpc_rate(2,30s),glitch_cnt,glitch_rate(20s),http_req_cnt",
        "",
        Duration::ZERO,
    );
    finish(send(fe));
    thread::sleep(Duration::from_millis(200));
    let (lines, _) = normalise(&cli(&ibex, "show table f"));
    assert_eq!(
        lines[1],
        "key=abc use=0 exp=N shard=0 http_req_cnt=1 gpt0=0 gpt1=0 gpc0=0 gpc1=0 gpc0_rate(30000)=0 gpc1_rate(30000)=0 glitch_cnt=0 glitch_rate(20000)=0"
    );
}

#[test]
fn a_tracked_entry_is_in_use_until_the_stream_ends() {
    let (ibex, fe) = start("type string len 20 size 100 expire 60s store conn_cur,http_req_cnt", "", Duration::from_millis(1500));
    let c = send(fe);
    thread::sleep(Duration::from_millis(500));
    let (lines, exps) = normalise(&cli(&ibex, "show table f"));
    assert_eq!(lines[1], "key=abc use=1 exp=N shard=0 conn_cur=1 http_req_cnt=1");
    let during = exps[0];
    assert!(during < 60_000, "{exps:?}");
    finish(c);
    thread::sleep(Duration::from_millis(200));
    let (lines, exps) = normalise(&cli(&ibex, "show table f"));
    assert_eq!(lines[1], "key=abc use=0 exp=N shard=0 conn_cur=0 http_req_cnt=1");
    assert!(exps[0] > during, "the entry was touched when the stream let go of it: {during} then {exps:?}");
}

#[test]
fn the_data_filter_reads_any_stored_type() {
    let (ibex, fe) = start("type string len 20 size 100 expire 60s store http_req_cnt,bytes_in_cnt,http_req_rate(10s)", "", Duration::ZERO);
    finish(send(fe));
    thread::sleep(Duration::from_millis(200));
    for (filter, shown) in [
        ("data.bytes_in_cnt gt 30", true),
        ("data.bytes_in_cnt lt 30", false),
        ("data.http_req_cnt eq 1", true),
        ("data.http_req_rate ge 1", true),
        ("data.http_req_rate ge 2", false),
    ] {
        let out = cli(&ibex, &format!("show table f {filter}"));
        assert_eq!(out.contains("key=abc"), shown, "{filter}: {out}");
    }
}

/// Measured: `http-request track-sc0` tracks for one request, not for the connection: two
/// requests with different keys on one connection leave two entries, one request each.
#[test]
fn each_request_of_a_connection_tracks_its_own_key() {
    let (ibex, fe) = start("type string len 20 size 100 expire 60s store gpc0,conn_cnt,http_req_cnt", "  http-request sc-inc-gpc0(0)\n", Duration::ZERO);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    for k in ["aaa", "bbb"] {
        c.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\nX-K: {k}\r\n\r\n").as_bytes()).expect("send");
        let mut buf = [0u8; 512];
        let _ = c.read(&mut buf);
    }
    // Measured: `use=0` for both with the connection still open, since a request is a
    // stream there. Ibex keeps the slot until the connection closes (T149b leftovers).
    drop(c);
    thread::sleep(Duration::from_millis(200));
    let out = cli(&ibex, "show table f");
    let (lines, _) = normalise(&out);
    let mut entries: Vec<&String> = lines.iter().skip(1).collect();
    entries.sort();
    assert_eq!(lines[0], "# table: f, type: string, size:100, used:2", "{out}");
    assert_eq!(
        entries,
        ["key=aaa use=0 exp=N shard=0 gpc0=1 conn_cnt=1 http_req_cnt=1", "key=bbb use=0 exp=N shard=0 gpc0=1 conn_cnt=1 http_req_cnt=1"],
        "{out}"
    );
}
