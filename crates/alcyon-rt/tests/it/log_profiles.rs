// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `log-profile` sections and `log ... profile`, as the reference `HAProxy`
//! (3.5-dev11-ce79f339c) sends them. Measured 2026-11-19 with a UDP syslog
//! collector; each target below logs the same request(s) as its neighbours:
//!
//! ```text
//! fe1 no profile (httplog)   : <134>1 TS - haproxy PID - - 127.0.0.1:CPORT [DATE] fe1 be/app1 0/0/0/0/0 200 54 - - ---- S/S/0/0/0 0/0 "GET / HTTP/1.1"
//! fe1 logprof1               : <134>1 TS - haproxy PID - sdclose close
//! fe1 logprof2 (log-tag "custom") : <134>1 TS - custom PID - - txn_close
//! fe1 logprof1, format rfc3164 : <134>LEGACY localhost haproxy[PID]: close
//! fe2 no profile (tcp, logasap, "%B") : <134>1 TS - haproxy PID - - +0
//! fe2 logprof1 (logasap)     : <134>1 TS - haproxy PID - - +0      (no "response" step: the normal format stands)
//! fe2 logprof2 (logasap)     : <134>1 TS - custom PID - - txn_connect
//! fe2 logprof3 (logasap)     : (nothing: the step is dropped)
//! fe3 logprof1 (tcp)         : <134>1 TS - haproxy PID - sdclose close
//! fe3 logprof2 (tcp)         : <134>1 TS - custom PID - - txn_close
//! fe4 503, logprof2          : <134>1 TS - custom PID - - error     (one line: the error step consumes the log)
//! fe4 503, logprof3          : <134>1 TS - haproxy PID - - error
//! fe5 log-steps connect,close: <134>1 TS - haproxy PID - - connect  then  <134>1 TS - haproxy PID - - close
//! fe6 log-steps all          : accept, request, connect, response, close (one line each, in that order)
//! fe7 log-steps close + 4x do-log : start:tcp-req-conn, http-req, http-res, http-after-res, txn_close
//! ```
//!
//! `TS`, `LEGACY`, `CPORT`, `DATE` and `S` stand for the fields that differ from
//! one run to the next (timestamp, client port, httplog date, connection
//! counters); `PID` is the process id. Every other byte is compared verbatim.
//!
//! The configuration errors are the ones `haproxy -c` (or the startup check)
//! prints, measured on the oracle:
//!
//! ```text
//! 'on' expects a log step.
//! expected values are: 'accept', 'request', 'connect', 'response', 'close', 'error' or 'any'.
//! Or one of the additional log steps: 'http-req', 'http-res', 'http-after-res', 'tcp-req-conn', 'tcp-req-sess', 'tcp-req-cont', 'tcp-res-cont'.
//!
//! log-profile section 'p1' has the same name as another log-profile section declared at <file>:3.
//!
//! log directive declared in proxy section 'fe' in file '<file>' at line 5 unknown log-profile 'nosuch'.
//! ```
//!
//! Run against `HAProxy` with `T281_ORACLE=/path/to/haproxy`; it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const REQUEST: &str = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// The tiny HTTP server standing in for the vtc's backends.
fn responder() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut chunk) {
                    Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        }
    });
    addr
}

/// Writes `cfg` to a temp file, runs the binary with `args -f <file>` and returns the output.
fn run_cfg(args: &[&str], cfg: &str) -> Output {
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut cmd = Command::new(bin());
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("-f").arg(f.path());
    let out = cmd.output().expect("run binary");
    drop(f);
    out
}

fn get(addr: SocketAddr) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(REQUEST.as_bytes()).expect("send");
    let mut b = [0u8; 4096];
    while s.read(&mut b).map(|n| n > 0).unwrap_or(false) {}
}

/// `get`, retrying while the listener is not up yet. A refused connect is
/// never logged by the proxy, so the first accepted attempt is the only line.
fn get_wait(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut s = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(_) => {
                if Instant::now() >= deadline {
                    panic!("no listener on {addr}");
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    };
    s.write_all(REQUEST.as_bytes()).expect("send");
    let mut b = [0u8; 4096];
    while s.read(&mut b).map(|n| n > 0).unwrap_or(false) {}
}

/// Replaces the fields that change from run to run with fixed tokens, so the
/// remaining bytes can be compared verbatim against the oracle's.
fn normalize(line: &str) -> String {
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.len() < 5 {
        return line.to_string();
    }
    // rfc3164: `<134><Mon> <DD> <HH:MM:SS> <host> <tag>[<pid>]: <msg>`
    if !t[0].ends_with("1") {
        let raw = t[4];
        let tag = raw.split('[').next().unwrap_or(raw);
        let msg = t[5..].join(" ");
        return format!("<134>LEGACY {} {}[PID]: {}", t[3], tag, msg);
    }
    // rfc5424: `<134>1 <TS> - <tag> <pid> <msgid> <sd> <msg>`. The timings and
    // counter fields are both `d/d/d/d/d`, so they are resolved by position: in
    // httplog the counter follows the `----` (`%tsc`) token and the timings
    // immediately precede the 3-digit status.
    let mut out = vec![t[0], "TS", t[2], t[3], "PID"];
    let msg = &t[5..];
    let mut i = 0;
    while i < msg.len() {
        let tok = msg[i];
        let prev = if i > 0 { Some(msg[i - 1]) } else { None };
        let next = if i + 1 < msg.len() { Some(msg[i + 1]) } else { None };
        let next_status = next.map_or(false, |n| n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit()));
        if tok.starts_with("127.0.0.1:") {
            out.push("127.0.0.1:CPORT");
        } else if tok.starts_with('[') && tok.ends_with(']') {
            out.push("[DATE]");
        } else if is_slash5(tok) && prev == Some("----") {
            out.push("S/S/0/0/0");
        } else if is_slash5(tok) && next_status {
            out.push("0/0/0/0/0");
        } else {
            out.push(tok);
        }
        i += 1;
    }
    out.join(" ")
}

/// `d/d/d/d/d` with five numeric fields (a timings or counter field).
fn is_slash5(tok: &str) -> bool {
    let p: Vec<&str> = tok.split('/').collect();
    p.len() == 5 && p.iter().all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
}

#[test]
fn a_bad_log_step_is_rejected_with_haproxy_message() {
    let out = run_cfg(
        &["-c"],
        "defaults\n  mode http\nlog-profile p1\n  on bogus format \"x\"\n",
    );
    assert!(!out.status.success(), "rc={:?}", out.status.code());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(
            "'on' expects a log step.\nexpected values are: 'accept', 'request', 'connect', 'response', 'close', 'error' or 'any'.\nOr one of the additional log steps: 'http-req', 'http-res', 'http-after-res', 'tcp-req-conn', 'tcp-req-sess', 'tcp-req-cont', 'tcp-res-cont'."
        ),
        "stderr was: {err}"
    );
}

#[test]
fn a_duplicate_log_profile_is_rejected_with_haproxy_message() {
    let out = run_cfg(
        &["-c"],
        "defaults\n  mode http\nlog-profile p1\n  on close format \"close\"\nlog-profile p1\n  on close format \"close\"\n",
    );
    assert!(!out.status.success(), "rc={:?}", out.status.code());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("log-profile section 'p1' has the same name as another log-profile section declared at"),
        "stderr was: {err}"
    );
}

#[test]
fn a_log_directive_with_an_unknown_profile_is_refused() {
    // `profile <name>` precedes the facility; the name is checked at startup,
    // where the oracle prints (and exits 1):
    // `log directive declared in proxy section 'fe' in file '<file>' at line 5 unknown log-profile 'nosuch'.`
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\nfrontend fe\n  bind {addr}\n  log 127.0.0.1:514 profile nosuch local0\n"
    );
    let out = run_cfg(&[], &cfg);
    assert!(!out.status.success(), "rc={:?}", out.status.code());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("log directive declared in proxy section 'fe'")
            && err.contains("unknown log-profile 'nosuch'."),
        "stderr was: {err}"
    );
}

#[test]
fn a_minimal_log_profile_is_accepted() {
    let out = run_cfg(
        &["-c"],
        "defaults\n  mode http\nlog-profile p1\n  on close format \"close\"\n",
    );
    assert!(out.status.success(), "rc={:?} stderr={}", out.status.code(), String::from_utf8_lossy(&out.stderr));
}

/// A thread draining one collector until `stop`.
fn drain(sock: UdpSocket, stop: Instant, lines: Arc<Mutex<Vec<String>>>) {
    sock.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");
    let mut buf = [0u8; 8192];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => lines.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned()),
            Err(_) if Instant::now() < stop => {}
            Err(_) => break,
        }
    }
}

fn expect(col: &str, got: &[String], want: &[&str]) {
    assert_eq!(
        got.len(),
        want.len(),
        "{col}: expected {} line(s), got {}\n{:?}",
        want.len(),
        got.len(),
        got
    );
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "{col} line {i}");
    }
}

#[test]
fn profiled_targets_log_each_step_as_haproxy_does() {
    let be = responder();
    let mut socks = Vec::new();
    for _ in 0..15 {
        socks.push(UdpSocket::bind("127.0.0.1:0").expect("collector bind"));
    }
    let c: Vec<SocketAddr> = socks.iter().map(|s| s.local_addr().expect("addr")).collect();
    let f: Vec<SocketAddr> = (0..7).map(|_| common::reserve_addr()).collect();

    let cfg = format!(
        r#"defaults
  mode http
  timeout connect 5s
  timeout client 5s
  timeout server 5s
  log-tag "haproxy"

frontend fe1
  bind {a}
  mode http
  option httplog
  log udp@{b} format rfc5424 local0
  log udp@{cc} format rfc5424 profile logprof1 local0
  log udp@{d} format rfc5424 profile logprof2 local0
  log udp@{e} format rfc3164 profile logprof1 local0
  default_backend be

frontend fe2
  bind {g}
  mode tcp
  log-format "%B"
  option logasap
  log udp@{h} format rfc5424 local0
  log udp@{i} format rfc5424 profile logprof1 local0
  log udp@{j} format rfc5424 profile logprof2 local0
  log udp@{k} format rfc5424 profile logprof3 local0
  default_backend be_tcp

listen fe3
  bind {m}
  mode tcp
  log-format "%B"
  log udp@{n} format rfc5424 profile logprof1 local0
  log udp@{o} format rfc5424 profile logprof2 local0
  default_backend be_tcp

listen fe4
  bind {p}
  timeout client 5ms
  mode http
  log-format "%B"
  log udp@{q} format rfc5424 profile logprof2 local0
  log udp@{r} format rfc5424 profile logprof3 local0

listen fe5
  bind {s}
  mode http
  log-format "dummy"
  log-steps connect,close
  log udp@{t} format rfc5424 profile logprof4 local0
  default_backend be

listen fe6
  bind {u}
  mode http
  log-format "dummy"
  log-steps all
  log udp@{v} format rfc5424 profile logprof4 local0
  default_backend be

frontend fe7
  bind {w}
  mode http
  log-format "dummy"
  log-steps close
  log udp@{x} format rfc5424 profile logprof5 local0
  default_backend be

  tcp-request connection do-log
  http-request do-log
  http-response do-log
  http-after-response do-log

log-profile logprof1
  on close format "close" sd "sdclose"

log-profile logprof2
  log-tag "custom"
  on error format "error"
  on any format "%OG"

log-profile logprof3
  on error format "error"
  on any drop

log-profile logprof4
  on accept format "accept"
  on request format "request"
  on connect format "connect"
  on response format "response"
  on close format "close"

log-profile logprof5
  on tcp-req-conn format "start:tcp-req-conn"
  on any format "%OG"

backend be
  mode http
  server app1 {be}

backend be_tcp
  mode tcp
  server app1 {be}
"#,
        a = f[0],
        b = c[0],
        cc = c[1],
        d = c[2],
        e = c[3],
        g = f[1],
        h = c[4],
        i = c[5],
        j = c[6],
        k = c[7],
        m = f[2],
        n = c[8],
        o = c[9],
        p = f[3],
        q = c[10],
        r = c[11],
        s = f[4],
        t = c[12],
        u = f[5],
        v = c[13],
        w = f[6],
        x = c[14],
        be = be,
    );

    let mut f2 = tempfile::NamedTempFile::new().expect("tempfile");
    f2.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = common::alcyon_command(bin())
        .arg("-f")
        .arg(f2.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");

    let stop = Instant::now() + Duration::from_secs(5);
    let mut holders = Vec::new();
    for sock in socks {
        let lines = Arc::new(Mutex::new(Vec::new()));
        holders.push(lines.clone());
        thread::spawn(move || drain(sock, stop, lines));
    }

    // Drive the frontends. `get_wait` retries until the listener accepts; a
    // refused connect logs nothing, so no spurious line is emitted while the
    // proxy is coming up (unlike a connect-and-close probe, which an HTTP
    // frontend logs as `<BADREQ>`).
    get_wait(f[0]);
    get(f[1]);
    get(f[2]);
    // fe4 has no backend and `timeout client 5ms`: hold the idle connection so the
    // timeout closes it and the 503 is logged, as measured on the oracle. The
    // process is up by now (fe1 answered), so fe4 is listening too.
    let idle = TcpStream::connect(f[3]).expect("connect fe4");
    thread::sleep(Duration::from_millis(300));
    drop(idle);
    get(f[4]);
    get(f[5]);
    get(f[6]);

    // Every line lands well before the deadline; wait until all 23 are in.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let total: usize = holders.iter().map(|h| h.lock().unwrap().len()).sum();
        // 1 + 1 + 1 + 1 + 1 + 1 + 1 + 0 + 1 + 1 + 1 + 1 + 2 + 5 + 5 = 23
        if total >= 23 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    // Give the drain threads' own deadline a beat to run past the last line.
    thread::sleep(Duration::from_millis(200));

    let mut lines: Vec<Vec<String>> = Vec::new();
    for h in &holders {
        lines.push(h.lock().unwrap().clone().iter().map(|s| normalize(s)).collect());
    }

    common::stop(&mut child);

    const L: &str = "<134>1 TS - haproxy PID - - ";
    expect("fe1/no-profile", &lines[0], &[
        "<134>1 TS - haproxy PID - - 127.0.0.1:CPORT [DATE] fe1 be/app1 0/0/0/0/0 200 54 - - ---- S/S/0/0/0 0/0 \"GET / HTTP/1.1\"",
    ]);
    expect("fe1/logprof1", &lines[1], &["<134>1 TS - haproxy PID - sdclose close"]);
    expect("fe1/logprof2", &lines[2], &["<134>1 TS - custom PID - - txn_close"]);
    expect("fe1/logprof1/rfc3164", &lines[3], &["<134>LEGACY localhost haproxy[PID]: close"]);
    expect("fe2/no-profile", &lines[4], &[&format!("{L}+0")]);
    expect("fe2/logprof1", &lines[5], &[&format!("{L}+0")]);
    expect("fe2/logprof2", &lines[6], &["<134>1 TS - custom PID - - txn_connect"]);
    expect("fe2/logprof3 (drop)", &lines[7], &[]);
    expect("fe3/logprof1", &lines[8], &["<134>1 TS - haproxy PID - sdclose close"]);
    expect("fe3/logprof2", &lines[9], &["<134>1 TS - custom PID - - txn_close"]);
    expect("fe4/logprof2", &lines[10], &["<134>1 TS - custom PID - - error"]);
    expect("fe4/logprof3", &lines[11], &["<134>1 TS - haproxy PID - - error"]);
    expect("fe5/log-steps", &lines[12], &[&format!("{L}connect"), &format!("{L}close")]);
    expect("fe6/log-steps-all", &lines[13], &[
        &format!("{L}accept"),
        &format!("{L}request"),
        &format!("{L}connect"),
        &format!("{L}response"),
        &format!("{L}close"),
    ]);
    expect("fe7/do-log", &lines[14], &[
        &format!("{L}start:tcp-req-conn"),
        &format!("{L}http-req"),
        &format!("{L}http-res"),
        &format!("{L}http-after-res"),
        &format!("{L}txn_close"),
    ]);
}

#[test]
fn extra_steps_sd_only_and_tcp_do_log_match_oracle() {
    let be = responder();
    let mut socks = Vec::new();
    for _ in 0..4 {
        socks.push(UdpSocket::bind("127.0.0.1:0").expect("collector bind"));
    }
    let c: Vec<SocketAddr> = socks.iter().map(|s| s.local_addr().expect("addr")).collect();
    let f: Vec<SocketAddr> = (0..4).map(|_| common::reserve_addr()).collect();

    let cfg = format!(
        r#"defaults
  mode http
  timeout connect 5s
  timeout client 5s
  timeout server 5s
  log-tag "haproxy"

frontend fe_tcp_dolog
  bind {f0}
  mode http
  log-format "dummy"
  log-steps close
  log udp@{c0} format rfc5424 profile p_any local0
  tcp-request session do-log
  tcp-request content do-log
  default_backend be

frontend fe_connect_only
  bind {f1}
  mode http
  log-format "%OG"
  log-steps connect
  log udp@{c1} format rfc5424 local0
  default_backend be

frontend fe_sd_only
  bind {f2}
  mode http
  log-format "%ST"
  log-steps close
  log udp@{c2} format rfc5424 profile p_sd local0
  default_backend be

frontend fe_plain_dolog
  bind {f3}
  mode http
  log-format "%OG"
  log-steps close
  http-request do-log
  log udp@{c3} format rfc5424 local0
  default_backend be

log-profile p_any
  on any format "%OG"

log-profile p_sd
  on close sd "sdonly"

backend be
  mode http
  server app1 {be}
"#,
        f0 = f[0],
        f1 = f[1],
        f2 = f[2],
        f3 = f[3],
        c0 = c[0],
        c1 = c[1],
        c2 = c[2],
        c3 = c[3],
        be = be,
    );

    let mut cfg_file = tempfile::NamedTempFile::new().expect("tempfile");
    cfg_file.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = common::alcyon_command(bin())
        .arg("-f")
        .arg(cfg_file.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");

    let stop = Instant::now() + Duration::from_secs(5);
    let mut holders = Vec::new();
    for sock in socks {
        let lines = Arc::new(Mutex::new(Vec::new()));
        holders.push(lines.clone());
        thread::spawn(move || drain(sock, stop, lines));
    }

    get_wait(f[0]);
    get(f[1]);
    get(f[2]);
    get(f[3]);

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let total: usize = holders.iter().map(|h| h.lock().unwrap().len()).sum();
        if total >= 7 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(200));

    let lines: Vec<Vec<String>> = holders
        .iter()
        .map(|h| h.lock().unwrap().iter().map(|s| normalize(s)).collect())
        .collect();

    common::stop(&mut child);

    const L: &str = "<134>1 TS - haproxy PID - - ";
    expect("fe_tcp_dolog", &lines[0], &[
        &format!("{L}tcp-req-sess"),
        &format!("{L}tcp-req-cont"),
        &format!("{L}txn_close"),
    ]);
    expect("fe_connect_only", &lines[1], &[&format!("{L}txn_connect")]);
    expect("fe_sd_only", &lines[2], &["<134>1 TS - haproxy PID - sdonly 200"]);
    expect("fe_plain_dolog", &lines[3], &[&format!("{L}http-req"), &format!("{L}txn_close")]);
}
