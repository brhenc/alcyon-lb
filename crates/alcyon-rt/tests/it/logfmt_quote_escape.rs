// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `+Q` and `+E` log-format options on numbers, addresses and quoted strings, measured on the
//! reference `HAProxy` (3.5-dev11-ce79f339c) 2026-11-20 with one `mode http` frontend per format
//! line, each logging `format raw` to a local UDP socket, for the request
//! `GET /a%20b?x="y" HTTP/1.1` with `User-Agent: a"b c` copied into `txn.ua` by
//! `http-request set-var(txn.ua) hdr(User-Agent)`:
//!
//! ```text
//! Q01 "18445" 200 "a"b c" "/a%20b?x=#22y#22" "abc" "127.0.0.1"
//! Q02 a\"b c "/a%20b?x=#22y#22" "1"
//! Q03 "a\"b c" 18445 200 200 "127.0.0.1" "be"
//! Q04 "127.0.0.1" 54748 "127.0.0.1" 29656 "127.0.0.1" 56262 "127.0.0.1" 29652
//! Q05 "127.0.0.1" 44028 "127.0.0.1" 29657 "127.0.0.1" 56266 "127.0.0.1" 29652
//! Q06 127.0.0.1 33344 127.0.0.1 29656 127.0.0.1 56262 127.0.0.1 29652
//! Q07 "127.0.0.1" "127.0.0.1"
//! Q08 "127.0.0.1" "127.0.0.1"
//! Q09 127.0.0.1 127.0.0.1
//! Q10 "/a%20b?x=#22y#22" "127.0.0.1" "29656" 200 "be" "GET /a%20b?x=#22y#22 HTTP/1.1" "1" "0"
//! Q11 "/a%20b?x=#22y#22" "127.0.0.1" "29657" 200 "be" "GET /a%20b?x=#22y#22 HTTP/1.1" "1" "0"
//! Q12 "GET /a%20b?x=#22y#22 HTTP/1.1" "be"
//! Q13 "GET /a%20b?x=#22y#22 HTTP/1.1" "/a%20b?x=#22y#22"
//! Q14 "::1" "::1" "::1" "::1"
//! Q15 "::1" "::1"
//! Q16 "" ""
//! ```
//!
//! Q14/Q15 run on an IPv6 frontend (`[::1]`) against an IPv6 origin, so `%[src]`/`%[dst]` are
//! Ipv6 samples and `%ci`/`%bi` are Ipv6 addresses. Q16 is a frontend with no backend: the 503
//! has no server, so `%bi`/`%si` are the missing IP, which `+Q` renders as `""`.
//!
//! Ports vary per run and are masked to `P` (and `"P"` when the quoting under test adds the
//! quotes); every other byte is compared exactly.
//!
//! What `HAProxy` does with `+Q` / `+E`, per source (`src/log.c`):
//! - a sample expression of any type is converted to a string first
//!   (`sample_convert(SMP_T_STR)` in `sess_build_logline_orig`) and rendered by `lf_text`,
//!   so a sint (`%[dst_port]`), bool, or address (`%[src]`) sample is quoted under `+Q`;
//! - the ip aliases `%ci`/`%fi`/`%bi`/`%si` go through `lf_ip`, which in non-hex mode is
//!   `lf_text`, so they are quoted;
//! - the port aliases `%cp`/`%fp`/`%bp`/`%sp` go through `lf_port`, which in non-hex mode is
//!   `lf_int` (no quoting), and so does `%ST` (`lf_int`);
//! - the text aliases (`%HU`, `%b`, `%r`, ...) go through `lf_text`, quoted;
//! - `+E` escapes the value's own `"` and `\` (`_lf_text_len`) *before* `+Q` wraps the result in
//!   quotes (`_lf_quotetext_len`), so the quotes `+Q` itself adds are never escaped;
//! - `o` is a global option in the log-format grammar (`logformat_aliases[]`, `LOG_FMT_GLOBAL`):
//!   `%{+Q}o` renders nothing but sets the default options for the nodes that follow, so in
//!   Q01 the quoting of `%[dst_port]` comes from the `+Q` that precedes it.
//!
//! Set `T281_ORACLE=/path/to/haproxy` to run against the oracle; it passes all rows.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// (marker, format line, expected body with the per-run ports masked to `P` / `"P"`, backend:
/// `be` = the v4 origin, `be6` = the v6 origin, `-` = no backend, the 503 whose server fields
/// are missing).
const CASES: &[(&str, &str, &str, &str)] = &[
    (
        "Q01",
        "%{+Q}o %[dst_port] %ST %[var(txn.ua)] %HU %[str(abc)] %ci",
        r#""P" 200 "a"b c" "/a%20b?x=#22y#22" "abc" "127.0.0.1""#, "be"
    ),
    (
        "Q02",
        "%{+E}o %[var(txn.ua)] %{+Q}HU %{+Q}[str(1)]",
        r#"a\"b c "/a%20b?x=#22y#22" "1""#, "be"
    ),
    (
        "Q03",
        "%{+Q,+E}[var(txn.ua)] %{+X}[dst_port] %{+X}ST %{+Q}ST %{+Q}ci %{+Q}b",
        r#""a\"b c" P 200 200 "127.0.0.1" "be""#, "be"
    ),
    (
        "Q04",
        "%{+Q}o %ci %cp %fi %fp %bi %bp %si %sp",
        r#""127.0.0.1" P "127.0.0.1" P "127.0.0.1" P "127.0.0.1" P"#, "be"
    ),
    (
        "Q05",
        "%{+Q,+E}o %ci %cp %fi %fp %bi %bp %si %sp",
        r#""127.0.0.1" P "127.0.0.1" P "127.0.0.1" P "127.0.0.1" P"#, "be"
    ),
    (
        "Q06",
        "%ci %cp %fi %fp %bi %bp %si %sp",
        r#"127.0.0.1 P 127.0.0.1 P 127.0.0.1 P 127.0.0.1 P"#, "be"
    ),
    ("Q07", "%{+Q}o %[src] %[dst]", r#""127.0.0.1" "127.0.0.1""#, "be"),
    ("Q08", "%{+Q,+E}o %[src] %[dst]", r#""127.0.0.1" "127.0.0.1""#, "be"),
    ("Q09", "%[src] %[dst]", r#"127.0.0.1 127.0.0.1"#, "be"),
    // `[wait_end]` is Bool/true (alcyon-sample/src/registry.rs:3401; HAProxy
    // smp_fetch_wait_end in src/stream.c) and `[res.comp]` is Bool/false here
    // (registry.rs:2578; HAProxy smp_fetch_res_comp in src/stream.c): Bool samples are
    // converted to "1"/"0" and, like every sample, quoted under +Q.
    (
        "Q10",
        "%{+Q}o %HU %ci %[dst_port] %ST %b %r %[wait_end] %[res.comp]",
        r#""/a%20b?x=#22y#22" "127.0.0.1" "P" 200 "be" "GET /a%20b?x=#22y#22 HTTP/1.1" "1" "0""#, "be"
    ),
    (
        "Q11",
        "%{+Q,+E}o %HU %ci %[dst_port] %ST %b %r %[wait_end] %[res.comp]",
        r#""/a%20b?x=#22y#22" "127.0.0.1" "P" 200 "be" "GET /a%20b?x=#22y#22 HTTP/1.1" "1" "0""#, "be"
    ),
    (
        "Q12",
        "%{+Q,+E}r %{+Q,+E}b",
        r#""GET /a%20b?x=#22y#22 HTTP/1.1" "be""#, "be"
    ),
    (
        "Q13",
        "%{+E}o %{+Q}r %{+Q}HU",
        r#""GET /a%20b?x=#22y#22 HTTP/1.1" "/a%20b?x=#22y#22""#, "be"
    ),
    // IPv6 client and server: `%[src]`/`%[dst]` are Ipv6 samples, `%ci`/`%bi` are Ipv6
    // aliases; all four are quoted text under +Q.
    (
        "Q14",
        "%{+Q}o %[src] %[dst] %ci %bi",
        r#""::1" "::1" "::1" "::1""#, "be6"
    ),
    ("Q15", "%{+Q,+E}o %[src] %[dst]", r#""::1" "::1""#, "be6"),
    // No backend: the 503 has no server, so `%bi`/`%si` are the missing IP; `lf_ip(NULL)`
    // is `lf_text(NULL)`, which `+Q` renders as an empty quoted string.
    ("Q16", "%{+Q}o %bi %si", "\"\" \"\"", "-"),
];

const REQ: &str = "GET /a%20b?x=\"y\" HTTP/1.1\r\nHost: h\r\nUser-Agent: a\"b c\r\nConnection: close\r\n\r\n";

/// Origin server; records the source port of every accepted connection (the `%bp` of the test).
fn origin(v6: bool) -> (SocketAddr, Arc<Mutex<Vec<u16>>>) {
    let addr = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let listener = TcpListener::bind(addr).expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let seen = Arc::new(Mutex::new(Vec::<u16>::new()));
    let seen_bg = Arc::clone(&seen);
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let port = c.peer_addr().map(|a| a.port()).unwrap_or(0);
            seen_bg.lock().expect("poison").push(port);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nf");
        }
    });
    (addr, seen)
}

/// Replace the per-run ports (bare or wrapped in the `+Q` quotes) by `P` / `"P"`.
fn mask_ports(line: &str, ports: &[u16]) -> String {
    line.split(' ')
        .map(|tok| {
            if let Ok(p) = tok.parse::<u16>() {
                if ports.contains(&p) {
                    return "P".to_string();
                }
            }
            if tok.len() >= 2 && tok.starts_with('"') && tok.ends_with('"') {
                if let Ok(p) = tok[1..tok.len() - 1].parse::<u16>() {
                    if ports.contains(&p) {
                        return "\"P\"".to_string();
                    }
                }
            }
            tok.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn quote_and_escape_options_match_haproxy() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    let collector_addr = collector.local_addr().expect("collector addr");
    let (origin_addr, seen_bp) = origin(false);
    let (origin6_addr, seen6_bp) = origin(true);
    // The IPv6 frontends bind `[::1]:<the same port reservation scheme>`; the 503 frontend
    // (no backend) is fine on v4.
    let fe_addrs: Vec<SocketAddr> = CASES
        .iter()
        .map(|(_, _, _, be)| {
            let port = common::reserve_port();
            if *be == "be6" { format!("[::1]:{port}").parse().expect("v6 fe addr") } else { format!("127.0.0.1:{port}").parse().expect("v4 fe addr") }
        })
        .collect();

    let mut cfg = String::new();
    cfg.push_str(
        "defaults\n  mode http\n  log global\n  option dontlognull\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n",
    );
    for (i, (mark, fmt, _, be)) in CASES.iter().enumerate() {
        let backend = match *be {
            "be" => "default_backend be\n",
            "be6" => "default_backend be6\n",
            _ => "", // no backend: the 503, whose server fields are missing
        };
        cfg.push_str(&format!(
            "frontend {mark}\n  bind {}\n  log {} format raw local0\n  log-format '{mark} {fmt}'\n  \
             http-request set-var(txn.ua) hdr(User-Agent)\n  {backend}",
            fe_addrs[i], collector_addr
        ));
    }
    cfg.push_str(&format!("backend be\n  server s1 {origin_addr}\n"));
    cfg.push_str(&format!("backend be6\n  server s2 {origin6_addr}\n"));

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_path = dir.path().join("logfmt_quote_escape.cfg");
    std::fs::write(&cfg_path, &cfg).expect("write cfg");
    let mut child = Command::new(bin());
    child
        .args(["-f", cfg_path.to_str().expect("cfg path")])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let proc = Proc(child.spawn().expect("spawn"));
    for fe in &fe_addrs {
        assert!(common::wait_listening(*fe), "never listened on {fe}");
    }

    // `wait_listening` probes each frontend with a connection it closes without sending
    // anything. Those null sessions log nothing (`option dontlognull`), so the collector only
    // sees the lines of the real requests below.

    // One request per frontend, in order. The local port of each client connection is its `%cp`;
    // the proxy opens a fresh backend connection per request (the server replies
    // `Connection: close`), so the origin's i-th accepted peer port is the `%bp` of request i.
    let mut cps: Vec<u16> = Vec::new();
    for fe in &fe_addrs {
        let mut c = TcpStream::connect(*fe).expect("connect");
        cps.push(c.local_addr().expect("client addr").port());
        c.set_write_timeout(Some(Duration::from_secs(5))).expect("write timeout");
        c.write_all(REQ.as_bytes()).expect("send");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("read timeout");
        let mut buf = [0u8; 1024];
        let _ = c.read(&mut buf);
        c.flush().expect("flush");
    }

    // Collect every log line until the collector is quiet. A session can be logged more than
    // once on a close race (the reference binary emits a second line with the frontend as
    // `%b`), so each marker keeps all its lines and the check below picks the one that is the
    // line of the finished request.
    let mut bodies: Vec<Vec<String>> = vec![Vec::new(); CASES.len()];
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(20);
    let quiet = Duration::from_millis(600);
    let mut last = Instant::now();
    let mut complete = false;
    while Instant::now() < deadline && !complete {
        let _ = collector.set_read_timeout(Some(Duration::from_millis(100)));
        if let Ok((n, _)) = collector.recv_from(&mut buf) {
            last = Instant::now();
            let line = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
            for (i, (mark, _, _, _)) in CASES.iter().enumerate() {
                if let Some(rest) = line.strip_prefix(mark) {
                    if let Some(body) = rest.strip_prefix(' ') {
                        bodies[i].push(body.to_string());
                    }
                }
            }
        }
        complete = bodies.iter().all(|b| !b.is_empty()) && Instant::now() - last >= quiet;
        thread::sleep(Duration::from_millis(10));
    }
    drop(proc);

    let sp = origin_addr.port();
    let ports: Vec<u16> = {
        let mut v = vec![sp, origin6_addr.port()];
        v.extend(fe_addrs.iter().map(|a| a.port()));
        v.extend(cps.iter().copied());
        v.extend(seen_bp.lock().expect("poison").iter().copied());
        v.extend(seen6_bp.lock().expect("poison").iter().copied());
        v
    };

    for (i, (mark, fmt, want, _)) in CASES.iter().enumerate() {
        assert!(!bodies[i].is_empty(), "{mark} format {fmt}: no log line");
        let matched = bodies[i]
            .iter()
            .find(|body| mask_ports(body, &ports) == *want);
        let body = matched.unwrap_or_else(|| {
            panic!(
                "{mark} format {fmt}: none of {:?} matches {want:?}",
                bodies[i]
            )
        });
        assert_eq!(&mask_ports(body, &ports), want, "{mark} format {fmt}");
    }
}
