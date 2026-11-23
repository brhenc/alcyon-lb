// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `fc_*`/`bc_*` TCP_INFO fetches (`smp_fetch_fc_*`/`smp_fetch_bc_*`, `HAProxy`'s
//! `src/tcp_sample.c`): `fc_rtt`, `fc_rttvar`, `bc_rtt`, `bc_rttvar` and the `fc_unacked`,
//! `fc_sacked`, `fc_lost`, `fc_retrans`, `fc_fackets`, `fc_reordering` counters. The value
//! is one field of `getsockopt(TCP_INFO)` on the stream's client socket (`fc_*`) or server
//! socket (`bc_*`), read only when the fetch is evaluated; the RTT fetches answer
//! milliseconds by default and microseconds with the `us` argument.
//!
//! The values vary from run to run, so the tests check shapes, on both binaries
//! (`T281_ORACLE` for `HAProxy`, 3.5-dev11, measured 2026-11-23 on loopback):
//!
//! - a configuration with every fetch in `http-request` rules loads;
//! - over loopback `fc_rtt(us)` and `bc_rtt(us)` are greater than 0, `fc_rtt` (ms) and the
//!   counters are non-negative integers;
//! - `bc_*` give no sample in `http-request` rules, where the server connection does not
//!   exist yet (no `smp->strm->scb` in `HAProxy`'s `get_tcp_info`), and `fc_*` do; in
//!   `http-response` rules `bc_*` do;
//! - in a TCP frontend, a `tcp-request content` rule on `fc_rtt(us)` does not fire and one
//!   on `bc_rtt(us)` does (measured on the oracle: the sample and the lack of one);
//! - `fc_pkts_in`, `fc_pkts_out`, `bc_retrans` stay refused as unknown fetch methods;
//! - on a frontend with a QUIC bind, `HAProxy` answers the RTT and loss fetches from the
//!   QUIC connection's own statistics (`quic_get_info`, `src/proto_quic.c`), which Alcyon
//!   does not read: Alcyon refuses `fc_rtt`, `fc_rttvar`, `fc_lost` and `fc_reordering` at
//!   load there rather than answering from a socket that is not the client's (an
//!   Alcyon-only check; the oracle may well accept the configuration).

use crate::common;

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

/// The ten fetches this module covers: the `fc_*` eight and the `bc_*` two.
const FC: [&str; 8] = [
    "fc_rtt",
    "fc_rttvar",
    "fc_unacked",
    "fc_sacked",
    "fc_lost",
    "fc_retrans",
    "fc_fackets",
    "fc_reordering",
];
const BC: [&str; 2] = ["bc_rtt", "bc_rttvar"];
/// The fetches `HAProxy` does not know at all: they stay refused, on both binaries.
const UNKNOWN: [&str; 3] = ["fc_pkts_in", "fc_pkts_out", "bc_retrans"];

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct Proxy {
    child: Child,
    _cfg: NamedTempFile,
}

impl Proxy {
    fn start(cfg: &str) -> Self {
        let mut file = NamedTempFile::new().expect("tmp");
        file.write_all(cfg.as_bytes()).expect("write cfg");
        let child = Command::new(bin())
            .arg("-f")
            .arg(file.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn proxy");
        assert!(
            common::wait_listening(Self::first_bind(cfg)),
            "proxy never listened on its first bind:\n{cfg}"
        );
        Proxy { child, _cfg: file }
    }

    /// The first `bind <addr>` of the configuration: where `wait_listening` looks.
    fn first_bind(cfg: &str) -> SocketAddr {
        cfg.lines()
            .find_map(|l| l.trim().strip_prefix("bind ").map(|r| r.split_whitespace().next().unwrap()))
            .expect("a bind line")
            .parse()
            .expect("bind addr")
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// `alcyon -c` / `haproxy -c` on `cfg`: exit code and stderr.
fn check(cfg: &str) -> (i32, String) {
    check_with(&bin(), cfg)
}

/// `check` with a fixed binary: the QUIC test judges Alcyon alone, whatever `T281_ORACLE`
/// is.
fn check_alcyon(cfg: &str) -> (i32, String) {
    check_with(env!("CARGO_BIN_EXE_alcyon"), cfg)
}

fn check_with(b: &str, cfg: &str) -> (i32, String) {
    let mut file = NamedTempFile::new().expect("tmp");
    file.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(b)
        .args(["-c", "-f"])
        .arg(file.path())
        .output()
        .expect("check");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// A plain HTTP/1 server that closes the connection after one 200.
fn http_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("backend addr");
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    if conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").is_err() {
                        return;
                    }
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });
    addr
}

/// Sends `GET /` and reads until close: the whole response, as lossy text.
fn get(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").expect("write");
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// The value of header `name` (case-insensitive) in a response's head.
fn hdr<'a>(resp: &'a str, name: &str) -> Option<&'a str> {
    let head = resp.split("\r\n\r\n").next().unwrap_or(resp);
    head.lines()
        .skip(1)
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim().eq_ignore_ascii_case(name)).then_some(v.trim())
        })
}

/// A non-negative integer: what a counter or a millisecond RTT must parse as.
fn sint(v: &str, what: &str, resp: &str) -> i64 {
    v.parse::<i64>()
        .unwrap_or_else(|_| panic!("{what} is not an integer: {v:?} in\n{resp}"))
}

/// `http-mode` matrix: every fetch in `http-request` `set-var` rules (echoed in the
/// response head as `y-*`), and every fetch direct in `http-response` `set-header` rules
/// (`z-*`). The `y-*` values are the request phase's, the `z-*` the response phase's.
#[test]
fn http_mode_request_and_response_phases() {
    let fe = common::reserve_addr();
    let b1 = http_backend();
    let mut req_vars = String::new();
    let mut y_echo = String::new();
    let mut z_direct = String::new();
    for (i, f) in FC.iter().chain(BC.iter()).enumerate() {
        req_vars.push_str(&format!("  http-request set-var(txn.r{i}) {f}\n"));
        y_echo.push_str(&format!("  http-response set-header y-{i} \"%[var(txn.r{i})]\"\n"));
        z_direct.push_str(&format!("  http-response set-header z-{i} \"%[{f}]\"\n"));
    }
    // The RTTs in their `us` unit, where loopback says they must be greater than 0. The
    // request-phase one goes through a variable: `set-header` in a request rule writes the
    // request to the server, which this bare backend does not echo back.
    req_vars.push_str("  http-request set-var(txn.us1) fc_rtt(us)\n");
    y_echo.push_str("  http-response set-header y-fcrttus \"%[var(txn.us1)]\"\n");
    z_direct.push_str("  http-response set-header z-fcrttus \"%[fc_rtt(us)]\"\n");
    z_direct.push_str("  http-response set-header z-bcrttus \"%[bc_rtt(us)]\"\n");
    let cfg = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n{req_vars}{y_echo}{z_direct}  default_backend be\n\
         backend be\n  balance roundrobin\n  server s1 {b1}\n"
    );
    let _p = Proxy::start(&cfg);
    let r = get(fe);
    assert!(r.starts_with("HTTP/1.1 200"), "no response: {r}");

    // Request phase: the client socket exists, the server connection does not. The `fc_*`
    // fetches sample; `HAProxy`'s `get_tcp_info` has no server `conn` yet, so `bc_*` do
    // not: the variable stays unset and `set-header` renders it as the empty string.
    for (i, f) in FC.iter().enumerate() {
        let v = hdr(&r, &format!("y-{i}")).unwrap_or_else(|| panic!("y-{i} ({f}) missing:\n{r}"));
        let n = sint(v, &format!("y-{i} ({f})"), &r);
        assert!(n >= 0, "{f} is negative: {n}");
    }
    assert!(sint(
        hdr(&r, "y-0").unwrap_or_else(|| panic!("y-0 (fc_rtt) missing:\n{r}")),
        "y-0 (fc_rtt)",
        &r
    ) >= 0);
    assert!(
        sint(
            hdr(&r, "y-fcrttus").unwrap_or_else(|| panic!("y-fcrttus (fc_rtt(us)) missing:\n{r}")),
            "y-fcrttus (fc_rtt(us))",
            &r
        ) > 0,
        "fc_rtt(us) is 0 over loopback:\n{r}"
    );
    for (i, f) in BC.iter().enumerate().map(|(i, f)| (8 + i, f)) {
        assert_eq!(
            hdr(&r, &format!("y-{i}")).unwrap_or_else(|| panic!("y-{i} ({f}) missing:\n{r}")),
            "",
            "{f} must give no sample in http-request rules (no server connection yet):\n{r}"
        );
    }

    // Response phase: the server connection exists, so every fetch samples.
    for (i, f) in FC.iter().chain(BC.iter()).enumerate() {
        let v = hdr(&r, &format!("z-{i}")).unwrap_or_else(|| panic!("z-{i} ({f}) missing:\n{r}"));
        let n = sint(v, &format!("z-{i} ({f})"), &r);
        assert!(n >= 0, "{f} is negative: {n}");
    }
    // The response phase's `fc_rttvar` (z-1) is 0 on a short loopback stream: only the
    // plain RTT in its `us` unit must be greater than 0 there.
    assert!(
        sint(
            hdr(&r, "z-fcrttus").unwrap_or_else(|| panic!("z-fcrttus (fc_rtt(us)) missing:\n{r}")),
            "z-fcrttus (fc_rtt(us))",
            &r
        ) > 0,
        "fc_rtt(us) is 0 over loopback:\n{r}"
    );
    assert!(
        sint(
            hdr(&r, "z-bcrttus").unwrap_or_else(|| panic!("z-bcrttus (bc_rtt(us)) missing:\n{r}")),
            "z-bcrttus (bc_rtt(us))",
            &r
        ) > 0,
        "bc_rtt(us) is 0 over loopback:\n{r}"
    );
}

/// A TCP echo backend: answers `PONG\n` to the first bytes of a connection.
fn echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("backend addr");
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            thread::spawn(move || {
                let mut chunk = [0u8; 64];
                match conn.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                let _ = conn.write_all(b"PONG\n");
            });
        }
    });
    addr
}

/// Sends `PING\n` to a TCP frontend and reads whatever comes: `PONG` if the stream was
/// relayed, nothing (reset or close) if a `tcp-request content` rule rejected it.
fn tcp_probe(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let _ = c.write_all(b"PING\n");
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// TCP mode, the three `tcp-request` checkpoints, as measured on the oracle (2026-12-11,
/// loopback): in `connection` and `session` rules `fc_rtt(us)`/`fc_unacked` sample (the
/// client socket is TCP), so the `reject unless` does not fire and the stream is relayed;
/// in `content` rules `fc_rtt(us)` samples but `bc_rtt(us)` does not (no server connection
/// yet), so a rule on the latter rejects the stream.
#[test]
fn tcp_request_content_rule_samples_fc_not_bc() {
    let fe_c = common::reserve_addr();
    let fe_s = common::reserve_addr();
    let fe_fc = common::reserve_addr();
    let fe_bc = common::reserve_addr();
    let b1 = echo_backend();
    let b2 = echo_backend();
    let b3 = echo_backend();
    let b4 = echo_backend();
    let cfg = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode tcp\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fec\n  bind {fe_c}\n  tcp-request connection reject unless {{ fc_rtt(us) ge 0 }}\n  default_backend bec\n\
         backend bec\n  balance roundrobin\n  server s3 {b3}\n\
         frontend fes\n  bind {fe_s}\n  tcp-request session reject unless {{ fc_unacked ge 0 }}\n  default_backend bes\n\
         backend bes\n  balance roundrobin\n  server s4 {b4}\n\
         frontend fcf\n  bind {fe_fc}\n  tcp-request content reject unless {{ fc_rtt(us) ge 0 }}\n  default_backend bcf\n\
         backend bcf\n  balance roundrobin\n  server s1 {b1}\n\
         frontend fbc\n  bind {fe_bc}\n  tcp-request content reject unless {{ bc_rtt(us) ge 0 }}\n  default_backend bbc\n\
         backend bbc\n  balance roundrobin\n  server s2 {b2}\n"
    );
    let _p = Proxy::start(&cfg);
    assert!(
        tcp_probe(fe_c).contains("PONG"),
        "fc_rtt(us) must sample in tcp-request connection rules (the client socket is TCP):\n{cfg}"
    );
    assert!(
        tcp_probe(fe_s).contains("PONG"),
        "fc_unacked must sample in tcp-request session rules (the client socket is TCP):\n{cfg}"
    );
    assert!(
        tcp_probe(fe_fc).contains("PONG"),
        "fc_rtt(us) must sample in tcp-request content rules (the client socket is TCP):\n{cfg}"
    );
    let got = tcp_probe(fe_bc);
    assert!(
        !got.contains("PONG"),
        "bc_rtt(us) must give no sample in tcp-request content rules (no server connection yet): {got:?}"
    );
}

/// The reader itself: values off a live socket, the unknown-index arm, and the
/// `getsockopt` failure on a descriptor that is not a TCP socket.
#[test]
fn tcp_info_val_reads_the_socket_and_survives_a_bad_fd() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _hold = thread::spawn(move || {
        let (conn, _) = listener.accept().expect("accept");
        std::mem::forget(conn);
    });
    let cli = TcpStream::connect(addr).expect("connect");
    let fd = cli.as_raw_fd();
    assert!(alcyon_rt::raw::tcp_info_val(fd, 0).is_some(), "tcpi_rtt must be readable");
    assert!(alcyon_rt::raw::tcp_info_val(fd, 7).is_some(), "tcpi_reordering must be readable");
    assert_eq!(alcyon_rt::raw::tcp_info_val(fd, 9), Some(0), "an unknown index answers 0");
    assert_eq!(alcyon_rt::raw::tcp_info_val(-99, 0), None, "a bad descriptor must fail getsockopt");
}

/// The ten fetches load in `http-request` rules on both binaries; the three `HAProxy` does
/// not know stay refused as unknown fetch methods.
#[test]
fn fetches_load_and_unknown_stay_refused() {
    let fe = common::reserve_addr();
    let mut lines = String::new();
    for f in FC.iter().chain(BC.iter()) {
        lines.push_str(&format!("  http-request set-header h-{f} \"%[{f}]\"\n"));
    }
    let cfg = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n{lines}  default_backend be\n\
         backend be\n  balance roundrobin\n  http-response set-header hb \"%[fc_rtt]\"\n  server s1 127.0.0.1:1\n"
    );
    let (code, out) = check(&cfg);
    assert_eq!(code, 0, "the ten fetches must load:\n{out}");

    for f in UNKNOWN {
        let cfg = format!(
            "global\n  nbthread 1\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {fe}\n  http-request set-header h \"%[{f}]\"\n  default_backend be\n\
             backend be\n  balance roundrobin\n  server s1 127.0.0.1:1\n"
        );
        let (code, out) = check(&cfg);
        assert_ne!(code, 0, "{f} must stay refused:\n{out}");
        assert!(
            out.contains("unknown fetch method") && out.contains(f),
            "{f}: expected 'unknown fetch method', got:\n{out}"
        );
    }
}

/// On a frontend with a QUIC bind, `HAProxy` answers the RTT and loss fetches from the
/// QUIC connection's own statistics (`quic_get_info`, `src/proto_quic.c`), which Alcyon
/// does not read. Alcyon must refuse them at load there, with a reason, rather than
/// answering from a socket that is not the client's. Alcyon-only: the oracle may accept
/// the configuration, and a QUIC handshake would be needed to compare values.
#[test]
fn quic_frontend_refuses_rtt_fetches() {
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    for f in ["fc_rtt", "fc_rttvar", "fc_lost", "fc_reordering"] {
        let cfg = format!(
            "global\n  nbthread 1\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  http-request set-header x \"%[{f}]\"\n  default_backend be\n\
             backend be\n  balance roundrobin\n  server s1 127.0.0.1:1\n"
        );
        let (code, out) = check_alcyon(&cfg);
        assert_ne!(code, 0, "{f} loaded on a QUIC frontend:\n{out}");
        assert!(
            out.contains(f) && out.contains("not implemented in Alcyon"),
            "{f}: expected a load-time refusal with a reason, got:\n{out}"
        );
    }
    // The counters `HAProxy` never answers on QUIC (`quic_get_info` has no value for
    // them) stay accepted: they give no sample there, as here.
    for f in ["fc_unacked", "fc_sacked", "fc_retrans", "fc_fackets"] {
        let cfg = format!(
            "global\n  nbthread 1\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  http-request set-header x \"%[{f}]\"\n  default_backend be\n\
             backend be\n  balance roundrobin\n  server s1 127.0.0.1:1\n"
        );
        let (code, out) = check_alcyon(&cfg);
        assert_eq!(code, 0, "{f} must load on a QUIC frontend (no sample, as in HAProxy):\n{out}");
    }
    // A `listen` section with a QUIC bind is refused the same way.
    let quic2 = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         listen ls\n  bind quic4@{quic2} ssl crt {crt} alpn h3\n  http-request set-header x \"%[fc_rtt]\"\n  default_backend be\n\
         backend be\n  balance roundrobin\n  server s1 127.0.0.1:1\n"
    );
    let (code, out) = check_alcyon(&cfg);
    assert_ne!(code, 0, "fc_rtt loaded on a QUIC listen:\n{out}");
    assert!(
        out.contains("fc_rtt") && out.contains("not implemented in Alcyon"),
        "fc_rtt on a QUIC listen: expected a load-time refusal with a reason, got:\n{out}"
    );
    // The refusal also applies to a rule's condition, and the same condition loads on a
    // plain TCP frontend.
    let cfg = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  http-request deny if {{ fc_rtt ge 0 }}\n  default_backend be\n\
         backend be\n  balance roundrobin\n  server s1 127.0.0.1:1\n"
    );
    let (code, out) = check_alcyon(&cfg);
    assert_ne!(code, 0, "an fc_rtt condition loaded on a QUIC frontend:\n{out}");
    let plain = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {plain}\n  http-request deny if {{ fc_rtt ge 0 }}\n  default_backend be\n\
         backend be\n  balance roundrobin\n  server s1 127.0.0.1:1\n"
    );
    let (code, out) = check_alcyon(&cfg);
    assert_eq!(code, 0, "an fc_rtt condition must load on a plain frontend:\n{out}");
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A stream of an HTTP/2 connection reads the connection's TCP socket: `fc_rtt` and the
/// `fc_*` counters answer in its `http-request` rules (`smp->sess->origin` is the client
/// connection in `HAProxy`, whatever the mux). The status of each stream's response says
/// whether the rule saw a sample: 200 (`:status`, HPACK static index 8, first byte `0x88`)
/// when `fc_rtt(us)` and `fc_unacked` both sample, 403 otherwise.
#[test]
fn h2_streams_read_the_connection_socket() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe} proto h2\n\
         \x20 http-request return status 200 if {{ fc_rtt(us) gt 0 }} {{ fc_unacked ge 0 }}\n\
         \x20 http-request return status 403\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(bin())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(common::wait_listening(fe), "never listened");

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(50))).ok();
    // GET / on streams 1 and 3: :method GET, :scheme http, :path /, :authority "x".
    let req = [0x82, 0x86, 0x84, 0x01, 0x01, b'x'];
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    hello.extend_from_slice(&h2_frame(1, 5, 1, &req));
    hello.extend_from_slice(&h2_frame(1, 5, 3, &req));
    c.write_all(&hello).expect("send");

    let mut first: Vec<(u32, u8)> = Vec::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let t0 = std::time::Instant::now();
    while first.len() < 2 && t0.elapsed() < Duration::from_secs(5) {
        match c.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let stream = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            if buf[3] == 1 && len > 0 {
                assert_eq!(buf[4] & 0x28, 0, "HEADERS with padding/priority: {:02x?}", &buf[..9 + len]);
                first.push((stream, buf[9]));
            }
            buf.drain(..9 + len);
        }
    }
    common::stop(&mut child);

    first.sort_unstable();
    assert_eq!(first, vec![(1, 0x88), (3, 0x88)], "(stream, first header-block byte): 0x88 = :status 200, fc_* sampled");
}
