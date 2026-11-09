// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `log-format-sd` (T303): the STRUCTURED-DATA field of an `rfc5424` log line.
//!
//! Measured on HAProxy 3.5-dev8-885761-29 with a UDP collector (`log <udp> format rfc5424
//! local0`) and a `ring` read back with `show events`:
//! - A stream's line (HTTP and TCP, `log-format` or `option httplog`/`tcplog`), an
//!   `error-log-format` line (a request the mux refused) and an embryonic one (a failed TLS
//!   handshake, a refused PROXY header) carry the rendered SD between the MSGID and the text.
//! - Lines `HAProxy` sends through `send_log` (`Connect from`, server state changes, proxy
//!   stop) carry `-`, and so does every line of a proxy without `log-format-sd`, and one whose
//!   SD rendered to nothing.
//! - Only an rfc5424 header has the field: rfc3164, `raw` and `short` lines are unchanged.
//! - Values are not escaped unless the format says `+E`, which puts a backslash before `"`,
//!   `\` and `]`; `+Q` quotes without escaping. Runs of spaces in the format merge into one.
//! - `defaults` hands it down; a frontend's own replaces it; a backend ignores it; a fetch
//!   that does not exist or reads headers is refused at load, in "failed to parse
//!   log-format-sd" words.
//!
//! Set `T303_ORACLE=/path/to/haproxy` to run these tests against HAProxy.
use crate::common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const PLAIN: &[u8] = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
const PROXIED: &[u8] = b"PROXY TCP4 127.0.0.1 127.0.0.1 1 2\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n";
const TIMEOUTS: &str = "  timeout connect 2s\n  timeout client 1s\n  timeout server 2s\n";

fn cert() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem")
}

fn binary() -> String {
    std::env::var("T303_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// A received line with what changes from run to run taken out: an rfc5424 one as
/// `<PRI>1 <host> <tag> <msgid> <SD and text>` (no timestamp, no pid), an rfc3164 one as
/// `<PRI> <text>`, anything else as it came.
fn normal(raw: &[u8]) -> String {
    let l = String::from_utf8_lossy(raw).trim_end().to_string();
    let p: Vec<&str> = l.splitn(7, ' ').collect();
    if p.len() == 7 && p[0].starts_with('<') && p[0].ends_with(">1") {
        return format!("{} {} {} {} {}", p[0], p[2], p[3], p[5], p[6]);
    }
    match (l.find('>'), l.split_once("]: ")) {
        (Some(e), Some((_, text))) if l.starts_with('<') => format!("{} {text}", &l[..=e]),
        _ => l,
    }
}

/// What `template` (with `@LOG@`, `@B0@`..`@B3@`, `@CERT@`, `@SOCK@`) logged for each probe
/// `(bind, bytes, half-close)`, each probe's lines sorted, and what `show events <ring>` said
/// at the end when `ring` names one. `Err` is what the process said when it did not start.
fn session(template: &str, probes: &[(usize, &[u8], bool)], ring: Option<&str>) -> Result<(Vec<Vec<String>>, Vec<String>), String> {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(400))).expect("timeout");
    let binds = [common::reserve_addr(), common::reserve_addr(), common::reserve_addr(), common::reserve_addr()];
    let sock = std::env::temp_dir().join(format!("t303-{}-{}.sock", std::process::id(), binds[0].port()));
    let mut cfg = template
        .replace("@LOG@", &collector.local_addr().expect("addr").to_string())
        .replace("@CERT@", cert())
        .replace("@SOCK@", &sock.display().to_string());
    for (i, b) in binds.iter().enumerate() {
        cfg = cfg.replace(&format!("@B{i}@"), &b.to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write");
    let mut child = common::Alcyon(Command::new(binary()).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("spawn"));
    if !common::wait_listening(binds[0]) {
        common::stop(&mut child);
        let mut stderr = String::new();
        let _ = child.stderr.take().map(|mut e| e.read_to_string(&mut stderr));
        return Err(stderr);
    }
    std::thread::sleep(Duration::from_millis(300));
    let mut buf = [0u8; 4096];
    while collector.recv(&mut buf).is_ok() {}
    let mut out = Vec::new();
    for (bind, send, half_close) in probes {
        let mut c = TcpStream::connect(binds[*bind]).expect("connect");
        c.write_all(send).expect("send");
        if *half_close {
            c.shutdown(Shutdown::Write).expect("shutdown");
        }
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(3) {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        drop(c);
        let mut lines = Vec::new();
        while let Ok(n) = collector.recv(&mut buf) {
            lines.push(normal(&buf[..n]));
        }
        lines.sort();
        out.push(lines);
    }
    let events = ring.map_or_else(Vec::new, |r| {
        let mut c = UnixStream::connect(&sock).expect("stats socket");
        c.write_all(format!("show events {r}\n").as_bytes()).expect("ask");
        let mut text = String::new();
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let _ = c.read_to_string(&mut text);
        text.lines().filter(|l| !l.is_empty()).map(|l| normal(l.as_bytes())).collect()
    });
    common::stop(&mut child);
    let _ = std::fs::remove_file(&sock);
    Ok((out, events))
}

fn logs(r: Result<(Vec<Vec<String>>, Vec<String>), String>) -> Vec<Vec<String>> {
    r.unwrap_or_else(|e| panic!("did not start: {e}")).0
}

#[test]
fn a_served_request_carries_it_on_rfc5424_targets_only() {
    // Two `log` lines in the frontend and two from `global`.
    let cfg = format!(
        "global\n  log @LOG@ format rfc5424 local0\n  log @LOG@ local1\n\
         defaults\n  mode http\n{TIMEOUTS}frontend t\n  bind @B0@\n  log global\n\
         log @LOG@ format raw local2\n  log @LOG@ format short local3\n  option httplog\n\
         log-format-sd [ex@1\\ ci=\\\"%ci\\\"\\ st=\\\"%ST\\\"]\n  log-format \"L %ST\"\n  http-request return status 200\n\
         frontend o\n  bind @B1@\n  log @LOG@ local1\n  log-format-sd [ex@1]\n  log-format \"O %ST\"\n  http-request return status 200\n"
    );
    let r = logs(session(&cfg, &[(0, PLAIN, false), (1, PLAIN, false)], None));
    assert_eq!(r[0], ["<134>1 - haproxy - [ex@1 ci=\"127.0.0.1\" st=\"200\"] L 200", "<142> L 200", "<6>L 200", "L 200"]);
    assert_eq!(r[1], ["<142> O 200"], "no rfc5424 target");
}

#[test]
fn values_are_escaped_with_plus_e_only() {
    let cfg = format!(
        "defaults\n  mode http\n{TIMEOUTS}frontend t\n  bind @B0@\n  log @LOG@ format rfc5424 local0\n\
         log-format-sd [ex@1\\ h=\\\"%{{+E}}[var(txn.x)]\\\"\\ q=%{{+Q}}[var(txn.x)]\\ r=%[var(txn.x)]]\n  log-format \"L\"\n\
         http-request set-var(txn.x) req.hdr(x)\n  http-request return status 200\n"
    );
    let r = logs(session(&cfg, &[(0, b"GET / HTTP/1.1\r\nHost: h\r\nx: a\"b\\c]d\r\n\r\n", false)], None));
    assert_eq!(r[0], [r#"<134>1 - haproxy - [ex@1 h="a\"b\\c\]d" q="a"b\c]d" r=a"b\c]d] L"#]);
}

#[test]
fn error_and_embryonic_lines_carry_it_and_connect_lines_do_not() {
    let cfg = format!(
        "defaults\n  mode http\n{TIMEOUTS}  log @LOG@ format rfc5424 local0\n  log-format-sd [def@1\\ f=\\\"%[fe_name]\\\"]\n\
         frontend u\n  bind @B0@\n  bind @B1@ ssl crt @CERT@\n  bind @B2@ accept-proxy\n  option httplog\n\
         error-log-format \"ELF %ST\"\n  http-request return status 200\n\
         frontend v\n  bind @B3@ accept-proxy\n  http-request return status 200\n"
    );
    let r = logs(session(&cfg, &[(0, PLAIN, false), (0, b"GARBAGE\r\n\r\n", false), (1, b"", true), (2, b"PROXY FOO\r\n", false), (3, PROXIED, false), (3, b"PROXY FOO\r\n", false)], None));
    assert_eq!(r[0].len(), 1, "{r:#?}");
    assert!(r[0][0].starts_with("<134>1 - haproxy - [def@1 f=\"u\"] 127.0.0.1:") && r[0][0].ends_with(" \"GET / HTTP/1.1\""), "{r:#?}");
    assert_eq!(r[1], ["<134>1 - haproxy - [def@1 f=\"u\"] ELF 400"]);
    assert_eq!(r[2], ["<134>1 - haproxy - [def@1 f=\"u\"] ELF 0"], "a failed TLS handshake");
    assert_eq!(r[3], ["<134>1 - haproxy - [def@1 f=\"u\"] ELF 0"], "a refused PROXY header");
    assert_eq!(r[4].len(), 1, "{r:#?}");
    assert_eq!(r[4], ["<134>1 - haproxy - - Connect from 127.0.0.1:1 to 127.0.0.1:2 (v/HTTP)"]);
    // A frontend without a `log-format` logs a refused PROXY header with the plain line.
    assert_eq!(r[5].len(), 1, "{r:#?}");
    assert!(r[5][0].starts_with("<134>1 - haproxy - [def@1 f=\"v\"] 127.0.0.1:") && r[5][0].ends_with(": Received an unhandled protocol in the PROXY protocol header"), "{r:#?}");
}

#[test]
fn tcp_and_plain_error_lines_carry_it_spaces_merge_and_nothing_is_a_dash() {
    // `retries 0`: the server is a closed port, and with the default 3 retries a second apart
    // the `tc` line is logged at 3001 ms, as the probe's own 3 s read gives up; a host that
    // stalls it 400 ms lands the line in the next probe's window (T614b, gate log
    // fe46f0ea3b476101). The line (`SC`) is the same, at once.
    let cfg = format!(
        "defaults\n{TIMEOUTS}  log @LOG@ format rfc5424 local0\n\
         frontend tc\n  mode tcp\n  bind @B0@\n  option tcplog\n  log-format-sd \"[t@1   a=\\\"%ci\\\"]   x\"\n  default_backend b\n\
         frontend e\n  mode http\n  bind @B1@\n  log-format \"E\"\n  log-format-sd %{{-M}}[var(txn.nope)]\n  http-request return status 200\n\
         frontend n\n  mode http\n  bind @B2@\n  log-format \"N\"\n  http-request return status 200\n\
         frontend p\n  mode http\n  bind @B3@ accept-proxy\n  option httplog\n  log-format-sd \"[p@1 f=\\\"%f\\\"]\"\n  http-request return status 200\n\
         backend b\n  mode tcp\n  retries 0\n  log-format-sd \"[b@1]\"\n  server s 127.0.0.1:1\n"
    );
    let r = logs(session(&cfg, &[(0, b"hi", true), (1, PLAIN, false), (2, PLAIN, false), (3, b"PROXY FOO\r\n", false)], None));
    assert_eq!(r[0].len(), 1, "{r:#?}");
    assert!(r[0][0].starts_with("<134>1 - haproxy - [t@1 a=\"127.0.0.1\"] x 127.0.0.1:") && r[0][0].contains(" tc b/s "), "{r:#?}");
    assert_eq!(r[1], ["<134>1 - haproxy - - E"], "rendered empty");
    assert_eq!(r[2], ["<134>1 - haproxy - - N"], "none configured");
    // Without `error-log-format`, the plain line of a refused PROXY header carries it too.
    assert_eq!(r[3].len(), 1, "{r:#?}");
    assert!(r[3][0].starts_with("<134>1 - haproxy - [p@1 f=\"p\"] 127.0.0.1:") && r[3][0].ends_with(": Received an unhandled protocol in the PROXY protocol header"), "{r:#?}");
}

#[test]
fn a_ring_in_rfc5424_carries_it() {
    let cfg = format!(
        "global\n  stats socket @SOCK@ level admin\nring r\n  format rfc5424\n  size 32768\n\
         defaults\n  mode http\n{TIMEOUTS}frontend t\n  bind @B0@\n  log ring@r local0\n  option dontlognull\n\
         log-format-sd \"[a@1 b=\\\"%f\\\"]\"\n  log-format \"x\"\n  http-request return status 200\n"
    );
    // `dontlognull`: the connection that saw the port open is not in the ring.
    let (_, events) = session(&cfg, &[(0, PLAIN, false)], Some("r")).unwrap_or_else(|e| panic!("did not start: {e}"));
    assert_eq!(events, ["<134>1 - haproxy - [a@1 b=\"t\"] x"]);
}

#[test]
fn a_bad_format_is_refused_and_a_backend_ignores_it() {
    let starts = |extra: &str| {
        let cfg = format!("defaults\n  mode http\n{TIMEOUTS}frontend t\n  bind @B0@\n  log @LOG@ format rfc5424 local0\n  {extra}\n  http-request return status 200\n");
        session(&cfg, &[], None)
    };
    let e = starts("log-format-sd \"%[nosuchfetch]\"").expect_err("bad fetch");
    assert!(e.contains("failed to parse log-format-sd") && e.contains("nosuchfetch"), "{e}");
    let e = starts("log-format-sd \"%[req.hdr(x)]\"").expect_err("headers are gone when the line is made");
    assert!(e.contains("failed to parse log-format-sd : sample fetch <req.hdr> may not be reliably used here"), "{e}");
    let e = starts("log-format-sd \"%{+Q\"").expect_err("truncated");
    assert!(e.contains("failed to parse log-format-sd") && e.contains("truncated line after '+Q'"), "{e}");
    assert!(starts("log-format-sd").is_err());
    assert!(starts("default_backend b\nbackend b\n  log-format-sd \"x\"\n  server s 127.0.0.1:1").is_ok(), "accepted and ignored in a backend");
}

/// `HAProxy` gives a frontend with an rfc5424 target and no `log-format-sd` a default one,
/// and any format it compiles makes it log a connection that fails before its session
/// (`to_log`): with `log` and no format at all, a refused PROXY header is logged only when
/// a target is rfc5424 or there is a `log-format-sd`.
#[test]
fn without_a_log_format_an_rfc5424_target_or_an_sd_logs_a_refused_proxy_header() {
    let cfg = format!(
        "defaults\n  mode http\n{TIMEOUTS}\
         frontend a\n  bind @B0@ accept-proxy\n  log @LOG@ format rfc5424 local0\n  http-request return status 200\n\
         frontend b\n  bind @B1@ accept-proxy\n  log @LOG@ local1\n  log-format-sd \"[b@1]\"\n  http-request return status 200\n\
         frontend c\n  bind @B2@ accept-proxy\n  log @LOG@ local2\n  http-request return status 200\n"
    );
    let bad = &b"PROXY FOO\r\n"[..];
    let r = logs(session(&cfg, &[(0, bad, false), (1, bad, false), (2, bad, false)], None));
    const MSG: &str = ": Received an unhandled protocol in the PROXY protocol header";
    assert_eq!(r[0].len(), 1, "{r:#?}");
    assert!(r[0][0].starts_with("<134>1 - haproxy - - 127.0.0.1:") && r[0][0].ends_with(MSG), "{r:#?}");
    assert_eq!(r[1].len(), 1, "{r:#?}");
    assert!(r[1][0].starts_with("<142> 127.0.0.1:") && r[1][0].ends_with(MSG), "{r:#?}");
    assert!(r[2].is_empty(), "{r:#?}");
}
