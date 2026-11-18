// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The per-process rate limits `maxconnrate`, `maxsessrate`, `maxsslrate` and the run-time
//! `set rate-limit connections|sessions|ssl-sessions global`: reached, the listeners stop
//! accepting until the rate over the last second falls back under the limit; the connections
//! wait in the kernel backlog and nothing is refused or closed (src/listener.c).
//!
//! Measured on `HAProxy 3.5-dev11` (`nbthread 1`, `maxconnrate 2`, five connections opened at
//! once, a request sent on each): the first two are answered in ~4 ms, the third at ~1004 ms,
//! the fourth at ~1504 ms, the fifth at ~2005 ms; all five in the end. The assertions keep
//! wide margins around that: at most two answered within 750 ms, the rest by 10 s.
//!
//! The `global` keyword errors are byte-exact from the oracle (`-c`): no argument is
//! `'<kw>' expects an integer argument.`, a second argument is
//! `'<kw>' cannot handle unexpected argument '<a>'.`, a second non-zero line is the warning
//! `'<kw>' already specified. Continuing.` (the first stays, the load continues).
//!
//! Alcyon has no HTTP compression, so `maxcomprate` and `set rate-limit http-compression
//! global` are refused with a clear error (docs/differences.md); the oracle accepts both.
//!
//! Run these tests against `HAProxy` with
//! `T281_ORACLE=/var/tmp/qwen-next-eval/oracle/haproxy`: every row passes, the
//! compression rows apart (they say so, and take the oracle's side there).

use crate::common;
use rustix::process::{kill_process, Pid, Signal};

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn oracle() -> bool {
    std::env::var("T281_ORACLE").is_ok()
}

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct App {
    child: Child,
    sock: PathBuf,
    dir: PathBuf,
}

impl Drop for App {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A backend that answers every request with a two-byte body, one thread per connection.
fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut c = c;
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Spawns the binary with a ready `cfg` file and waits for `fe` to listen and the stats
/// socket to come up.
fn launch(cfg: String, fe: SocketAddr, dir: PathBuf, sock: PathBuf) -> App {
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child = Command::new(bin())
        .arg("-f")
        .arg(dir.join("cfg"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let app = App { child, sock, dir };
    assert!(common::wait_listening(fe), "not listening");
    let end = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&app.sock).is_err() {
        assert!(Instant::now() < end, "the stats socket never came up");
        thread::sleep(Duration::from_millis(25));
    }
    app
}

/// Starts the binary with `nbthread 1`, a stats socket, the given `global` lines and one
/// frontend on a fresh address; waits for it to listen.
fn start(global_extra: &str) -> (App, SocketAddr) {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("alcyon_ratemax_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let cfg = format!(
        "global\n  nbthread 1\n  stats socket {} level admin\n{global_extra}\
         defaults\n  mode http\n  timeout client 15s\n  timeout connect 2s\n  timeout server 15s\n\
         frontend f\n  bind {fe}\n  default_backend be\nbackend be\n  server s {}\n",
        sock.display(),
        backend()
    );
    (launch(cfg, fe, dir.clone(), sock.clone()), fe)
}

/// As [`start`], but two plain frontends: `f1` may carry extra lines (its `maxconn`).
fn start2(global_extra: &str, f1_extra: &str) -> (App, SocketAddr, SocketAddr) {
    let fe1 = common::reserve_addr();
    let fe2 = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("alcyon_ratemax2_{}_{}", std::process::id(), fe1.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let cfg = format!(
        "global\n  nbthread 1\n  stats socket {} level admin\n{global_extra}\
         defaults\n  mode http\n  timeout client 15s\n  timeout connect 2s\n  timeout server 15s\n\
         frontend f1\n  bind {fe1}\n{f1_extra}  default_backend be\n\
         frontend f2\n  bind {fe2}\n  default_backend be\nbackend be\n  server s {}\n",
        sock.display(),
        backend()
    );
    (launch(cfg, fe1, dir.clone(), sock.clone()), fe1, fe2)
}

/// As [`start_tls`], but with a second plain frontend.
fn start_tls_plain(global_extra: &str) -> (App, SocketAddr, SocketAddr, Vec<u8>) {
    let fe = common::reserve_addr();
    let plain = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("alcyon_ratemaxtls2_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (crt, der) = test_crt(&dir);
    let sock = dir.join("s.sock");
    let be = backend();
    let cfg = format!(
        "global\n  nbthread 1\n  stats socket {} level admin\n{global_extra}\
         defaults\n  mode http\n  timeout client 15s\n  timeout connect 2s\n  timeout server 15s\n\
         frontend ft\n  bind {fe} ssl crt {}\n  default_backend be\n\
         frontend fp\n  bind {plain}\n  default_backend be\nbackend be\n  server s {be}\n",
        sock.display(),
        crt.display()
    );
    let app = launch(cfg, fe, dir.clone(), sock.clone());
    (app, fe, plain, der)
}

/// Opens `n` connections at once and sends a request on each; the answers are read with
/// [`answer`].
fn open(fe: SocketAddr, n: usize) -> Vec<TcpStream> {
    let mut conns = Vec::new();
    for _ in 0..n {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        conns.push(c);
    }
    conns
}

/// Reads the first answer byte: the moment the connection was served, relative to `t0`.
fn answer(c: &mut TcpStream, t0: Instant) -> Duration {
    let mut b = [0u8; 12];
    c.read(&mut b).expect("answer");
    Instant::now().saturating_duration_since(t0)
}

/// Closes the socket in place (a `Vec` element cannot be dropped out of the vec).
fn close(c: &mut TcpStream) {
    let _ = c.shutdown(Shutdown::Both);
}

/// Nothing is refused or closed: a connection under a limit simply waits. Asserts that `c`
/// is neither answered nor closed within `ms`.
fn not_early(c: &mut TcpStream, ms: u64) {
    c.set_read_timeout(Some(Duration::from_millis(ms))).expect("timeout");
    let mut b = [0u8; 12];
    match c.read(&mut b) {
        Ok(0) => panic!("closed within {ms} ms"),
        Ok(_) => panic!("answered within {ms} ms"),
        Err(_) => {}
    }
    c.set_read_timeout(None).expect("timeout");
}

fn cli(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &Path, key: &str) -> String {
    cli(sock, "show info")
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")).map(str::to_string))
        .unwrap_or_default()
}

/// Opens `n` connections at once, sends a request on each, and returns the answer times
/// (the first byte) relative to the first connect.
fn burst(fe: SocketAddr, n: usize) -> Vec<Duration> {
    let mut out = Vec::new();
    let t0 = Instant::now();
    let mut conns = Vec::new();
    for _ in 0..n {
        conns.push(TcpStream::connect(fe).expect("connect"));
    }
    for c in &mut conns {
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    }
    for c in &mut conns {
        let mut b = [0u8; 12];
        c.read(&mut b).expect("answer");
        out.push(Instant::now().saturating_duration_since(t0));
    }
    out
}

/// Opens `n` TLS connections at once, sends a request on each, and returns the answer times
/// relative to the first handshake start.
fn burst_tls(fe: SocketAddr, n: usize, der: &[u8]) -> Vec<Duration> {
    use rustls::pki_types::{CertificateDer, ServerName};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(der.to_vec())).expect("trust");
    let cfg = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let server = ServerName::try_from("localhost").expect("name");
    let t0 = Instant::now();
    let mut conns = Vec::new();
    for _ in 0..n {
        let sock = TcpStream::connect(fe).expect("connect");
        let conn = rustls::ClientConnection::new(std::sync::Arc::clone(&cfg), server.clone()).expect("tls");
        let mut side = rustls::StreamOwned::new(conn, sock);
        side.flush().expect("handshake");
        conns.push(side);
    }
    let mut out = Vec::new();
    for c in &mut conns {
        c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("send");
    }
    for c in &mut conns {
        let mut b = [0u8; 12];
        c.read(&mut b).expect("answer");
        out.push(Instant::now().saturating_duration_since(t0));
    }
    out
}

/// A self-signed `localhost` certificate: the combined PEM for `bind ... ssl crt` and the
/// DER of the certificate itself.
fn test_crt(dir: &Path) -> (PathBuf, Vec<u8>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let der = cert.cert.der().to_vec();
    let mut pem = cert.cert.pem().into_bytes();
    pem.extend_from_slice(cert.key_pair.serialize_pem().as_bytes());
    let path = dir.join("crt.pem");
    std::fs::write(&path, pem).expect("crt");
    (path, der)
}

/// A frontend with one TLS bind.
fn start_tls(global_extra: &str) -> (App, SocketAddr, Vec<u8>) {
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("alcyon_ratemaxssl_{}_{}", std::process::id(), fe.port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (crt, der) = test_crt(&dir);
    let sock = dir.join("s.sock");
    let be = backend();
    let cfg = format!(
        "global\n  nbthread 1\n  stats socket {} level admin\n{global_extra}\
         defaults\n  mode http\n  timeout client 15s\n  timeout connect 2s\n  timeout server 15s\n\
         frontend f\n  bind {fe} ssl crt {}\n  default_backend be\nbackend be\n  server s {}\n",
        sock.display(),
        crt.display(),
        be
    );
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child = Command::new(bin())
        .arg("-f")
        .arg(dir.join("cfg"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let app = App { child, sock, dir };
    assert!(common::wait_listening(fe), "not listening");
    let end = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&app.sock).is_err() {
        assert!(Instant::now() < end, "the stats socket never came up");
        thread::sleep(Duration::from_millis(25));
    }
    (app, fe, der)
}

/// `maxconnrate 2` from the configuration: five connections at once, at most two answered in
/// the first 750 ms, all five in the end.
#[test]
fn conn_rate_limit_from_config() {
    let (app, fe) = start("  maxconnrate 2\n");
    let t = burst(fe, 5);
    let early = t.iter().filter(|d| **d < Duration::from_millis(750)).count();
    assert!(early <= 2, "at most two may be accepted in the first second, got {early:?} at {t:?}");
    assert!(t.iter().all(|d| *d < Duration::from_secs(10)), "all five must be served, got {t:?}");
    drop(app);
}

/// `set rate-limit connections global 2` at run time stops the same way; back to `0` and the
/// backlog is served at once.
#[test]
fn conn_rate_limit_at_run_time() {
    let (app, fe) = start("");
    assert_eq!(cli(&app.sock, "set rate-limit connections global 2"), "\n");
    assert_eq!(info(&app.sock, "ConnRateLimit"), "2");
    let t = burst(fe, 5);
    let early = t.iter().filter(|d| **d < Duration::from_millis(750)).count();
    assert!(early <= 2, "at most two may be accepted in the first second, got {early:?} at {t:?}");
    assert_eq!(cli(&app.sock, "set rate-limit connections global 0"), "\n");
    assert_eq!(info(&app.sock, "ConnRateLimit"), "0");
    assert!(t.iter().all(|d| *d < Duration::from_secs(10)), "all five must be served, got {t:?}");
    // No limit any more: a fresh burst is served at once.
    let t2 = burst(fe, 5);
    assert!(t2.iter().all(|d| *d < Duration::from_secs(1)), "limit 0 is no limit, got {t2:?}");
    drop(app);
}

/// `maxsessrate 2` from the configuration: the sessions, not the connections, are limited.
#[test]
fn sess_rate_limit_from_config() {
    let (app, fe) = start("  maxsessrate 2\n");
    let t = burst(fe, 5);
    let early = t.iter().filter(|d| **d < Duration::from_millis(750)).count();
    assert!(early <= 2, "at most two may be accepted in the first second, got {early:?} at {t:?}");
    assert!(t.iter().all(|d| *d < Duration::from_secs(10)), "all five must be served, got {t:?}");
    drop(app);
}

/// `maxsslrate 2` limits the TLS listener only; the sessions are counted before the
/// handshake, as `HAProxy` counts them at the accept.
#[test]
fn ssl_rate_limit_from_config() {
    let (app, fe, der) = start_tls("  maxsslrate 2\n");
    let t = burst_tls(fe, 5, &der);
    let early = t.iter().filter(|d| **d < Duration::from_millis(750)).count();
    assert!(early <= 2, "at most two may be accepted in the first second, got {early:?} at {t:?}");
    assert!(t.iter().all(|d| *d < Duration::from_secs(10)), "all five must be served, got {t:?}");
    drop(app);
}

/// The `global` keyword errors, byte-exact from the oracle (`-c`), and the warning of a
/// second non-zero line.
#[test]
fn global_keyword_argument_checks() {
    let base = "defaults\n  mode http\nfrontend f\n  bind 127.0.0.1:8099\n  default_backend be\nbackend be\n  server s 127.0.0.1:9099\n";
    let dir = std::env::temp_dir().join(format!("alcyon_ratemaxcfg_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");

    let check = |tag: &str, glb: &str, want_rc: i32, want: &str, want_not: &str| {
        let path = dir.join(format!("{tag}.cfg"));
        let text = format!("global\n  {glb}\n{base}");
        std::fs::write(&path, text).expect("cfg");
        let p = Command::new(bin())
            
            .arg("-c")
            .arg("-f")
            .arg(&path)
            .output()
            .expect("spawn");
        assert_eq!(p.status.code(), Some(want_rc), "{tag}: stderr {}", String::from_utf8_lossy(&p.stderr));
        let err = String::from_utf8_lossy(&p.stderr);
        assert!(err.contains(want), "{tag}: missing {want:?} in {err}");
        if !want_not.is_empty() {
            assert!(!err.contains(want_not), "{tag}: unexpected {want_not:?} in {err}");
        }
        let _ = std::fs::remove_file(&path);
    };

    check("noarg", "maxconnrate", 1, "'maxconnrate' expects an integer argument.", "");
    check("two", "maxconnrate 2 3", 1, "'maxconnrate' cannot handle unexpected argument '3'.", "");
    check("sps_noarg", "maxsessrate", 1, "'maxsessrate' expects an integer argument.", "");
    check("sps_two", "maxsessrate 2 3", 1, "'maxsessrate' cannot handle unexpected argument '3'.", "");
    check("ssl_noarg", "maxsslrate", 1, "'maxsslrate' expects an integer argument.", "");
    check("ssl_two", "maxsslrate 2 3", 1, "'maxsslrate' cannot handle unexpected argument '3'.", "");
    check(
        "dup",
        "maxconnrate 2\n  maxconnrate 3",
        0,
        "'maxconnrate' already specified. Continuing.",
        "Fatal errors",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `maxcomprate` and `set rate-limit http-compression global`: the oracle accepts both;
/// Alcyon has no HTTP compression and refuses both with a clear error.
#[test]
fn compression_rate_limit() {
    if oracle() {
        // The oracle loads it and the command answers an empty line.
        let (app, _fe) = start("  maxcomprate 100\n");
        assert_eq!(cli(&app.sock, "set rate-limit http-compression global 200"), "\n");
        return;
    }
    // Config: refused at load, the message names the keyword.
    let dir = std::env::temp_dir().join(format!("alcyon_ratemaxcomp_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("cfg");
    std::fs::write(
        &path,
        "global\n  maxcomprate 100\ndefaults\n  mode http\nfrontend f\n  bind 127.0.0.1:8099\n  default_backend be\nbackend be\n  server s 127.0.0.1:9099\n",
    )
    .expect("cfg");
    let p = Command::new(bin()).arg("-c").arg("-f").arg(&path).output().expect("spawn");
    assert_eq!(p.status.code(), Some(1), "stderr {}", String::from_utf8_lossy(&p.stderr));
    let err = String::from_utf8_lossy(&p.stderr);
    assert!(err.contains("maxcomprate"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);

    // Command: refused, the reply is non-empty and names compression.
    let (app, _fe) = start("");
    let r = cli(&app.sock, "set rate-limit http-compression global 200");
    assert!(!r.trim().is_empty(), "the oracle answers an empty line; Alcyon must refuse");
    assert!(
        r.to_ascii_lowercase().contains("compression"),
        "the refusal must name what it refuses: {r:?}"
    );
    drop(app);
}

/// The oracle accepts a negative limit (no range check), prints it unsigned in `show info`
/// (measured: `maxconnrate -1` -> `ConnRateLimit: 4294967295`), and its unsigned `freq`
/// reads huge: no limit at all.
#[test]
fn negative_limit_is_unlimited() {
    let (app, fe) = start("  maxconnrate -1\n  maxsessrate -2\n  maxsslrate -3\n");
    assert_eq!(info(&app.sock, "ConnRateLimit"), "4294967295");
    assert_eq!(info(&app.sock, "SessRateLimit"), "4294967294");
    assert_eq!(info(&app.sock, "SslRateLimit"), "4294967293");
    let t = burst(fe, 5);
    assert!(
        t.iter().all(|d| *d < Duration::from_secs(2)),
        "a negative limit is no limit, got {t:?}"
    );
    drop(app);
}

/// `maxsslrate` applies to `ssl` binds only (the `BC_O_USE_SSL` test in src/listener.c):
/// the plain frontend of the same process is not limited at all.
#[test]
fn ssl_rate_limit_ignores_plain_listeners() {
    let (app, tls_fe, plain_fe, der) = start_tls_plain("  maxsslrate 2\n");
    let t_plain = burst(plain_fe, 1);
    assert!(
        t_plain[0] < Duration::from_millis(750),
        "the plain listener is not limited: {t_plain:?}"
    );
    let t = burst_tls(tls_fe, 5, &der);
    let early = t.iter().filter(|d| **d < Duration::from_millis(750)).count();
    assert!(early <= 2, "at most two TLS sessions in the first second, got {early:?} at {t:?}");
    assert!(t.iter().all(|d| *d < Duration::from_secs(10)), "all five must be served, got {t:?}");
    drop(app);
}

/// A frontend's `maxconn` stop and the rate stop coexist: each listener is stopped for its
/// own reason and resumes on its own condition -- the rate-paused one is not re-armed by
/// the frontend's resume path, and every connection is served in the end.
///
/// No connection is assumed to be the fast one: which listener the engine wakes first is
/// not the config order, and the trailing-second window is a sliding one. The invariants:
/// the burst is spread across the second (at most the limit is admitted at once) and
/// nothing is refused or closed.
#[test]
fn rate_pause_with_full_frontend() {
    let (app, f1, f2) = start2("  maxconnrate 2\n", "  maxconn 1\n");
    let t0 = Instant::now();
    // A silent connection takes f1's single `maxconn` slot while the rate works.
    let mut hold = vec![TcpStream::connect(f1).expect("connect")];
    std::thread::sleep(Duration::from_millis(500)); // the hold is admitted, f1 is full
    let mut c = open(f2, 3);
    let tb = [
        answer(&mut c[0], t0),
        answer(&mut c[1], t0),
        answer(&mut c[2], t0),
    ];
    assert!(tb.iter().all(|d| *d < Duration::from_secs(10)), "all three served: {tb:?}");
    let early = tb.iter().filter(|d| **d < Duration::from_millis(750)).count();
    assert!(early <= 2, "at most two admitted at once, got {early} early in {tb:?}");
    assert!(
        tb[2] - tb[0] > Duration::from_millis(500),
        "the burst must be spread across the second: {tb:?}"
    );
    // A second connection on f1 waits for its `maxconn` (f2 may wait for the rate at the
    // same time): nothing is refused or closed.
    let mut c5 = open(f1, 1);
    not_early(&mut c5[0], 150);
    close(&mut hold[0]); // f1 has room again: c5 is served (the rate may hold it a moment)
    let a5 = answer(&mut c5[0], t0);
    assert!(a5 < Duration::from_secs(8), "c5 {a5:?}");
    drop(app);
}

/// `global maxconn` stops every listener; when the count falls back the stopped listeners
/// come back, still subject to the per-second limit, and every connection is served.
#[test]
fn rate_pause_with_global_maxconn() {
    let (app, f2, f3) = start2("  maxconn 3\n  maxconnrate 2\n", "");
    let t0 = Instant::now();
    // Three silent connects fill the `global maxconn 3`; the rate admits them in two
    // passes, so the third waits the trailing second out.
    let mut h = vec![
        TcpStream::connect(f2).expect("connect"),
        TcpStream::connect(f2).expect("connect"),
        TcpStream::connect(f3).expect("connect"),
    ];
    for _ in 0..100 {
        if info(&app.sock, "CurrConns") == "3" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(info(&app.sock, "CurrConns"), "3");
    // Two more: stopped by the global limit, nothing refused or closed.
    let mut c4 = open(f2, 1);
    let mut c5 = open(f3, 1);
    not_early(&mut c4[0], 300);
    not_early(&mut c5[0], 300);
    close(&mut h[0]); // global 2/3: the stopped listeners come back
    let a4 = answer(&mut c4[0], t0);
    assert!(a4 < Duration::from_secs(8), "c4 {a4:?}");
    let a5 = answer(&mut c5[0], t0);
    assert!(a5 < Duration::from_secs(10), "c5 {a5:?}");
    drop(app);
}

/// `SIGTTOU` while the rate has stopped a listener: the listener's queue is reset (the
/// `tcp_suspend_receiver` behaviour), and the `SIGTTIN` resume leaves the stop to the rate,
/// which re-checks on the next accept.
#[test]
fn signal_resume_settles_a_rate_paused_listener() {
    let (app, fe) = start("  maxconnrate 2\n");
    // `wait_listening` probed the frontend: let its admission fall out of the rate window
    // so the burst below starts from a clean one.
    thread::sleep(Duration::from_millis(1200));
    let t0 = Instant::now();
    let mut c = open(fe, 2);
    let a1 = answer(&mut c[0], t0);
    let a2 = answer(&mut c[1], t0);
    assert!(a1 < Duration::from_millis(750) && a2 < Duration::from_millis(750), "c1 {a1:?} c2 {a2:?}");
    // The third waits the trailing second out: the listener is rate-paused now.
    let mut c3 = open(fe, 1);
    not_early(&mut c3[0], 300);
    signal(app.child.id(), Signal::Ttou);
    std::thread::sleep(Duration::from_millis(200));
    signal(app.child.id(), Signal::Ttin);
    // The connection queued behind the stop is reset by the pause (both engines do it).
    c3[0].set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let mut b = [0u8; 8];
    match c3[0].read(&mut b) {
        Err(_) | Ok(0) => {}
        Ok(n) => panic!("the queued connection must be reset by SIGTTOU, got {n} bytes: {b:?}"),
    }
    close(&mut c[0]);
    close(&mut c[1]);
    // The socket comes back to the listening state on SIGTTIN; wait for that rather than
    // racing it, then a new connection is served again (the rate may hold it a moment).
    assert!(common::wait_listening(fe), "the listener did not come back after SIGTTIN");
    let mut c4 = open(fe, 1);
    let a4 = answer(&mut c4[0], t0);
    assert!(a4 < Duration::from_secs(10), "c4 {a4:?}");
    drop(app);
}

fn signal(pid: u32, sig: Signal) {
    if let Some(p) = Pid::from_raw(i32::try_from(pid).unwrap_or(0)) {
        let _ = kill_process(p, sig);
    }
}
