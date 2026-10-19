// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `show sess` and `shutdown session(s)` on the CLI, at `nbthread 4` (T218).
//!
//! The CLI is served by one worker; the streams are spread over all of them. Both commands
//! must reach every worker, as HAProxy's do (`cli_io_handler_dump_sess` walks
//! `ha_thread_ctx[thr].streams` for every thread; `srv_shutdown_streams` every stream of
//! the server).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-05, `nbthread 4`, a request waiting
//! on a slow server, a TCP stream and an idle connection with no request:
//!
//! ```text
//! 0x3e11cfc0: proto=tcpv4 src=127.0.0.1:58610 fe=fe be=be srv=s1 ts=00 epoch=0 age=4s calls=2 rate=0 cpu=0 lat=0 rq[f=848000h,i=0,an=8000h,ax=] rp[f=80000000h,i=0,an=1400000h,ax=] scf=[8,402h,fd=1/18,rex=,wex=] scb=[8,1411h,fd=1/20,rex=26s,wex=] exp=1s rc=0 c_exp=
//! 0x3e11de90: proto=tcpv4 src=127.0.0.1:38798 fe=fetcp be=betcp srv=s1 ts=00 epoch=0 age=4s calls=2 rate=0 cpu=0 lat=0 rq[f=848000h,i=0,an=00h,ax=] rp[f=80008000h,i=0,an=00h,ax=] scf=[8,0h,fd=1/21,rex=26s,wex=] scb=[8,1h,fd=1/22,rex=26s,wex=] exp=1s rc=0 c_exp=
//! 0x3e11ec10: proto=unix_stream src=unix:1 fe=GLOBAL be=<NONE> srv=<none> ts=00 epoch=0 age=0s calls=1 rate=0 cpu=0 lat=0 rq[f=10848100h,i=0,an=00h,ax=] rp[f=80008000h,i=0,an=00h,ax=] scf=[8,0h,fd=1/23,rex=10s,wex=] scb=[8,1h,fd=1/-1,rex=,wex=] exp=10s rc=0 c_exp=
//! ```
//!
//! The idle connection is not listed (HTTP/1 creates no stream before a request), the CLI
//! connection's own stream is. `show sess help`, `show sess foo`, `show sess backend nope`,
//! `shutdown session`, `shutdown session 0x1234` answer the texts asserted below.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A server that accepts connections and holds them, reading and discarding, until the
/// peer closes.
fn holding_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while matches!(conn.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    addr
}

struct Ibex {
    child: Child,
    sock: PathBuf,
    cfg: PathBuf,
    fe: SocketAddr,
    /// A `mode http` frontend to the same server.
    fh: SocketAddr,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start(srv: SocketAddr) -> Ibex {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir();
    let tag = format!("ibex_t218_{}_{n}", std::process::id());
    let (sock, cfg) = (tmp.join(format!("{tag}.sock")), tmp.join(format!("{tag}.cfg")));
    let (fe, fh) = (common::reserve_addr(), common::reserve_addr());
    let text = format!(
        "global\n  stats socket {sock} mode 600 level admin\n  nbthread 4\n\
         defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 30s\n  timeout server 30s\n\
         frontend ft\n  bind {fe}\n  default_backend bt\n\
         backend bt\n  server s1 {srv}\n\
         backend other\n  server o1 {srv}\n\
         frontend fh\n  mode http\n  bind {fh}\n  default_backend bh\n\
         backend bh\n  mode http\n  server h1 {srv}\n",
        sock = sock.display(),
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, sock, cfg, fe, fh };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    // The probe connection of `wait_listening` is a stream until the proxy has seen it close;
    // on a loaded host that is after the first `show sess`, and would be counted with the
    // test's own clients. The CLI's own stream in the answer shows it is the CLI that spoke.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = cli(&ibex, "show sess");
        if (out.contains(" proto=unix_stream ") && !out.contains(" fe=ft ")) || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    ibex
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `n` clients with a TCP stream each, every one forwarded to the server (one byte sent).
/// With `nbthread 4` the kernel spreads them over the four listeners.
fn clients(ibex: &Ibex, n: usize) -> Vec<TcpStream> {
    let v: Vec<TcpStream> = (0..n)
        .map(|_| {
            let mut c = TcpStream::connect(ibex.fe).expect("connect");
            c.write_all(b"x").expect("send");
            c
        })
        .collect();
    // Every stream established, and its byte forwarded (`rq[...,i=0`, not yet `i=1`: on a
    // loaded host the byte can still be in the request buffer), before the test looks.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !settled(&cli(ibex, "show sess"), &v) {
        std::thread::sleep(Duration::from_millis(20));
    }
    v
}

fn line_for<'a>(out: &'a str, c: &TcpStream) -> Option<&'a str> {
    let needle = format!(" src={} fe=ft ", c.local_addr().expect("addr"));
    out.lines().find(|l| l.contains(&needle))
}

fn settled(out: &str, cs: &[TcpStream]) -> bool {
    cs.iter().all(|c| line_for(out, c).is_some_and(|l| l.contains(" rq[f=000000h,i=0,")))
}

fn srcs_listed(out: &str, cs: &[TcpStream]) -> usize {
    cs.iter().filter(|c| line_for(out, c).is_some()).count()
}

fn age_secs(line: &str) -> u64 {
    let a = line.split(" age=").nth(1).expect("age=").split(' ').next().expect("age value");
    a.strip_suffix('s').and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("age `{a}` in: {line}"))
}

/// Whether the proxy closed `c`, within `wait`.
fn closed(c: &mut TcpStream, wait: Duration) -> bool {
    c.set_read_timeout(Some(wait)).expect("timeout");
    let mut b = [0u8; 16];
    match c.read(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
    }
}

#[test]
fn show_sess_lists_every_workers_streams_with_growing_age() {
    let ibex = start(holding_server());
    let cs = clients(&ibex, 16);
    let out = cli(&ibex, "show sess");
    assert_eq!(srcs_listed(&out, &cs), cs.len(), "all 16 streams, on all four workers, must be listed:\n{out}");
    for c in &cs {
        let l = line_for(&out, c).expect("listed");
        // The field order of HAProxy's line, with Ibex's values where it has them.
        assert!(l.starts_with("0x"), "{l}");
        assert!(l.contains(": proto=tcpv4 src="), "{l}");
        assert!(l.contains(" fe=ft be=bt srv=s1 ts=00 epoch=0 age="), "{l}");
        assert!(l.contains(" calls=0 rate=0 cpu=0 lat=0 rq[f=000000h,i=0,an=00h,ax=] rp[f=000000h,i=0,an=00h,ax=] scf=[8,0h,fd=1/"), "{l}");
        assert!(l.contains(",rex=29s,wex=] scb=[8,0h,fd=1/") || l.contains(",rex=30s,wex=] scb=[8,0h,fd=1/"), "{l}");
        assert!(l.contains(" rc=0 c_exp="), "{l}");
    }
    // The CLI connection's own stream, as HAProxy lists it.
    let own = out.lines().find(|l| l.contains(" proto=unix_stream ")).unwrap_or_else(|| panic!("CLI stream:\n{out}"));
    assert!(own.contains(": proto=unix_stream src=unix:1 fe=GLOBAL be=<NONE> srv=<none> ts=00 epoch=0 age=0s "), "{own}");
    assert!(own.contains(",wex=] scb=[8,0h,fd=1/-1,rex=,wex=] exp="), "{own}");

    let ages: Vec<u64> = cs.iter().map(|c| age_secs(line_for(&out, c).expect("listed"))).collect();
    std::thread::sleep(Duration::from_millis(2100));
    let later = cli(&ibex, "show sess");
    for (c, a) in cs.iter().zip(ages) {
        let l = line_for(&later, c).unwrap_or_else(|| panic!("still listed:\n{later}"));
        assert!(age_secs(l) >= a + 2, "age must grow by the 2 s waited: was {a}, now {l}");
    }
}

#[test]
fn a_finished_stream_is_gone_from_the_next_show_sess() {
    let ibex = start(holding_server());
    let mut cs = clients(&ibex, 8);
    let gone = cs.remove(3);
    let gone_src = gone.local_addr().expect("addr");
    drop(gone);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut out = cli(&ibex, "show sess");
    while out.contains(&format!(" src={gone_src} ")) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        out = cli(&ibex, "show sess");
    }
    assert!(!out.contains(&format!(" src={gone_src} ")), "closed stream still listed:\n{out}");
    assert_eq!(srcs_listed(&out, &cs), cs.len(), "the others stay:\n{out}");
}

#[test]
fn show_sess_filters_and_refusals() {
    let ibex = start(holding_server());
    let cs = clients(&ibex, 8);
    // Filters, as HAProxy's: the CLI stream has no backend and is not listed by them.
    for f in ["backend bt", "server bt/s1", "frontend ft"] {
        let out = cli(&ibex, &format!("show sess {f}"));
        assert_eq!(srcs_listed(&out, &cs), cs.len(), "show sess {f}:\n{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with("0x")).count(), cs.len(), "show sess {f}:\n{out}");
    }
    let out = cli(&ibex, "show sess show-uri");
    assert_eq!(srcs_listed(&out, &cs), cs.len(), "show sess show-uri:\n{out}");
    let out = cli(&ibex, "show sess backend other");
    assert_eq!(out.lines().filter(|l| l.starts_with("0x")).count(), 0, "{out}");
    assert_eq!(cli(&ibex, "show sess backend nope"), "No such backend.\n\n");
    assert_eq!(cli(&ibex, "show sess server bt/nope"), "No such server.\n\n");
    assert_eq!(cli(&ibex, "show sess server bt"), "Require 'backend/server'.\n\n");
    assert_eq!(cli(&ibex, "show sess frontend nope"), "No such frontend.\n\n");
    assert_eq!(cli(&ibex, "show sess backend"), "Missing backend name.\n\n");
    assert_eq!(cli(&ibex, "show sess backend bt frontend ft"), "Only one of backend, frontend or server may be set.\n\n");
    assert_eq!(cli(&ibex, "show sess server"), "Missing server name (<backend>/<server>).\n\n");
    assert_eq!(cli(&ibex, "show sess frontend"), "Missing frontend name.\n\n");
    // Commands after a `;` run once the workers have answered.
    let both = cli(&ibex, "show sess backend other; show info");
    assert!(both.starts_with("\nName: "), "{both:?}");
    // In `prompt` mode: two waiting commands on one line, then the next line.
    let mut s = UnixStream::connect(&ibex.sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(b"prompt\nshow sess backend other; show sess server bt/s1\nshow cli level\nquit\n").expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert_eq!(srcs_listed(&out, &cs), cs.len(), "{out}");
    assert!(out.contains("\n> \n> ") && out.ends_with("admin\n\n> "), "{out:?}");
    assert_eq!(cli(&ibex, "show sess foo"), "Unsupported option 'foo', try 'help' for more info.\n\n");
    let help = cli(&ibex, "show sess help");
    assert!(help.starts_with("Usage: show sess [<id> | all | help] [<options>*]\n"), "{help}");
    assert!(help.ends_with("Without any argument, all streams are dumped in a shorter format.\n\n"), "{help}");
    // The long format is not implemented: an explicit error, never an empty list.
    for c in ["show sess all", "show sess older 1", "show sess susp", "show sess 0x1234"] {
        let out = cli(&ibex, c);
        assert!(out.contains("not supported"), "`{c}` must refuse explicitly, answered: {out:?}");
    }
}

#[test]
fn help_lists_show_sess_as_haproxy_does() {
    let ibex = start(holding_server());
    let help = cli(&ibex, "help");
    for l in [
        "show sess [help|<id>|all] [opts...]     : report the list of current streams or dump this exact stream",
        "shutdown session [id]                   : kill a specific session",
    ] {
        assert!(help.lines().any(|h| h.trim() == l), "help must list `{l}`:\n{help}");
    }
}

#[test]
fn shutdown_sessions_server_closes_every_workers_streams() {
    let ibex = start(holding_server());
    let mut cs = clients(&ibex, 16);
    let reply = cli(&ibex, "shutdown sessions server bt/s1");
    let open: Vec<SocketAddr> = cs
        .iter_mut()
        .filter_map(|c| (!closed(c, Duration::from_secs(3))).then(|| c.local_addr().expect("addr")))
        .collect();
    assert!(open.is_empty(), "{} of 16 streams were not shut down: {open:?}", open.len());
    assert_eq!(reply, "\n", "HAProxy answers an empty line");
}

#[test]
fn shutdown_session_by_id() {
    let ibex = start(holding_server());
    let mut cs = clients(&ibex, 8);
    assert_eq!(cli(&ibex, "shutdown session"), "Session pointer expected (use 'show sess').\n\n");
    assert_eq!(cli(&ibex, "shutdown session foo"), "Session pointer expected (use 'show sess').\n\n");
    assert_eq!(cli(&ibex, "shutdown session 0x1234"), "No such session (use 'show sess').\n\n");
    let out = cli(&ibex, "show sess");
    for i in [1usize, 6] {
        let id = line_for(&out, &cs[i]).expect("listed").split(':').next().expect("id").to_string();
        assert_eq!(cli(&ibex, &format!("shutdown session {id}")), "\n", "shutdown session {id}");
        assert!(closed(&mut cs[i], Duration::from_secs(3)), "stream {id} was not shut down");
    }
    let out = cli(&ibex, "show sess");
    assert_eq!(srcs_listed(&out, &cs), cs.len() - 2, "only the two named streams go:\n{out}");
    assert_eq!(cli(&ibex, "shutdown session 0777"), "No such session (use 'show sess').\n\n");
    assert_eq!(cli(&ibex, "shutdown sessions server bt/nope"), "No such server.\n\n");
    // Ibex's own `shutdown sessions backend` (HAProxy has none) reaches every worker too.
    assert_eq!(cli(&ibex, "shutdown sessions backend nope"), "No such backend.\n\n");
    assert_eq!(cli(&ibex, "shutdown sessions backend bt"), "\n");
    for (i, c) in cs.iter_mut().enumerate() {
        assert!(i == 1 || i == 6 || closed(c, Duration::from_secs(3)), "stream {i} was not shut down");
    }
}

/// HTTP/1 creates a stream for a request, not for a connection: an idle connection is not
/// listed, one whose request waits for the server is, with its URI under `show-uri`.
#[test]
fn show_sess_lists_http_requests_not_idle_connections() {
    let ibex = start(holding_server());
    let idle = TcpStream::connect(ibex.fh).expect("connect");
    let mut req = TcpStream::connect(ibex.fh).expect("connect");
    req.write_all(b"GET /waiting HTTP/1.1\r\nhost: x\r\n\r\n").expect("send");
    let needle = format!(" src={} fe=fh be=bh srv=h1 ", req.local_addr().expect("addr"));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = cli(&ibex, "show sess show-uri");
    while !out.contains(&needle) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        out = cli(&ibex, "show sess show-uri");
    }
    let line = out.lines().find(|l| l.contains(&needle)).unwrap_or_else(|| panic!("the request is listed:\n{out}"));
    assert!(line.ends_with(" uri=\"/waiting\""), "{line}");
    let idle_src = format!(" src={} ", idle.local_addr().expect("addr"));
    assert!(!out.contains(&idle_src), "an idle connection has no stream:\n{out}");
    // The request would hold the soft stop until `timeout server`, past `common::stop`'s
    // patience: a killed instrumented ibex writes no coverage.
    assert_eq!(cli(&ibex, "shutdown sessions server bh/h1"), "\n");
}

/// A server echoing what it reads.
fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 || conn.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// While a `show sess` waits for a worker that has not answered yet, the worker serving the
/// CLI goes on serving its own traffic; the command is answered once the other worker runs.
/// Two engines in this process stand for two workers: only the CLI's is driven at first.
#[test]
fn the_cli_worker_keeps_serving_while_show_sess_waits() {
    use ibex_rt::engine::Engine;
    let sock = std::env::temp_dir().join(format!("ibex_t218_inproc_{}.sock", std::process::id()));
    let fe = common::reserve_addr();
    let cfg = format!(
        "listen ft\n  bind {fe}\n  mode tcp\n  timeout client 10s\n  timeout server 10s\n  timeout connect 1s\n  server s1 {}\n",
        echo_server()
    );
    let mut cli_worker = Engine::new(&ibex_config::parse_str(&cfg).expect("cfg"), 256).expect("engine 0");
    let mut other = Engine::new(&ibex_config::parse_str("defaults\n  mode tcp\n").expect("cfg"), 256).expect("engine 1");
    let boxes = ibex_rt::mailbox::Mailboxes::new(2).expect("mailboxes");
    cli_worker.share_mailboxes(&boxes, 0).expect("share 0");
    other.share_mailboxes(&boxes, 1).expect("share 1");
    cli_worker.bind_cli_socket(&sock).expect("cli socket");

    let mut cli = UnixStream::connect(&sock).expect("cli connect");
    cli.set_nonblocking(true).expect("nonblocking");
    cli.write_all(b"show sess\n").expect("send");

    // Traffic through the CLI's worker, from another thread, while only that worker runs.
    let client = std::thread::spawn(move || {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let mut got = Vec::new();
        for i in 0..5 {
            c.write_all(format!("ping{i}").as_bytes()).expect("send");
            let mut buf = [0u8; 16];
            let n = c.read(&mut buf).expect("echo through the CLI's worker");
            got.push(String::from_utf8_lossy(&buf[..n]).to_string());
        }
        (got, c)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = cli_worker.run_once();
    }
    assert!(client.is_finished(), "the CLI's worker stopped serving while `show sess` waited");
    let (got, _conn) = client.join().expect("client");
    assert_eq!(got, ["ping0", "ping1", "ping2", "ping3", "ping4"]);
    // More input wakes the connection; it still waits.
    cli.write_all(b"show info\n").expect("send");
    for _ in 0..20 {
        let _ = cli_worker.run_once();
    }
    let mut buf = [0u8; 4096];
    assert!(
        matches!(cli.read(&mut buf), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "`show sess` must wait for the worker that has not answered"
    );

    // The other worker runs once: the answer comes.
    let _ = other.run_once();
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let _ = cli_worker.run_once();
        match cli.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
    let out = String::from_utf8_lossy(&out);
    // Worker 0 answered before the echo client connected: like HAProxy, `show sess` lists
    // the streams that existed when it was issued.
    assert!(out.contains(" proto=unix_stream src=unix:1 fe=GLOBAL "), "the CLI's own stream:\n{out}");

    // The same for `shutdown session`.
    let mut cli = UnixStream::connect(&sock).expect("cli connect");
    cli.set_nonblocking(true).expect("nonblocking");
    cli.write_all(b"shutdown session 0x1234\n").expect("send");
    for _ in 0..20 {
        let _ = cli_worker.run_once();
    }
    cli.write_all(b"more\n").expect("send");
    for _ in 0..20 {
        let _ = cli_worker.run_once();
    }
    assert!(matches!(cli.read(&mut buf), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock));
    let _ = other.run_once();
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let _ = cli_worker.run_once();
        match cli.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
    assert_eq!(String::from_utf8_lossy(&out), "No such session (use 'show sess').\n\n");
    drop(cli_worker);
    let _ = std::fs::remove_file(&sock);
}

// ---- the stream-connector timers (T219) ----------------------------------------------
//
// Measured on HAProxy 3.5-dev8-885761-29 on 2026-10-05, `nbthread 4`, `timeout client 30s`,
// `timeout server 40s`, `timeout connect 5s`, 3 s after each stream began. `sc_ep_rcv_ex`
// is the last read activity plus the timeout while the side may still receive;
// `sc_ep_snd_ex` the first send-blocked time plus the timeout while a send is blocked.
//
// ```text
// state                         scf rex  scf wex  scb rex  scb wex  c_exp
// idle keep-alive               (no stream is listed)
// request headers partly sent   (no stream is listed)
// request done, slow server     -        -        ~37s     -        -
// response to a slow reader     -        ~27s     -        -        -
// request body uploaded slowly  ~27s     -        -        -        -
// server connect in progress    -        -        -        -        ~2s
// ```

/// The server of the timer tests: `/fast` is answered, `/big` gets a body no socket buffer
/// holds, anything else is read and never answered.
fn timer_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(n) if n > 0 => head.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                if head.starts_with(b"GET /fast") {
                    let _ = conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
                } else if head.starts_with(b"GET /big") {
                    let n = 30_000_000usize;
                    let _ = conn.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {n}\r\n\r\n").as_bytes());
                    let _ = conn.write_all(&vec![b'x'; n]);
                }
                while matches!(conn.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    addr
}

fn start_timers() -> Ibex {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir();
    let tag = format!("ibex_t219_{}_{n}", std::process::id());
    let (sock, cfg) = (tmp.join(format!("{tag}.sock")), tmp.join(format!("{tag}.cfg")));
    let (fh, srv) = (common::reserve_addr(), timer_server());
    let text = format!(
        "global\n  stats socket {sock} mode 600 level admin\n  nbthread 4\n\
         defaults\n  mode http\n  timeout connect 5s\n  timeout client 30s\n  timeout server 40s\n\
         frontend fh\n  bind {fh}\n  use_backend bc if {{ path_beg /conn }}\n  default_backend bh\n\
         backend bh\n  server h1 {srv}\n\
         backend bc\n  server c1 10.255.255.1:80\n",
        sock = sock.display(),
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, sock, cfg, fe: fh, fh };
    assert!(common::wait_listening(fh), "ibex never listened with:\n{text}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    ibex
}

/// `human_time` text as seconds (`26s`, `1m2s`, `300ms`).
fn secs_of(t: &str) -> f64 {
    let mut total = 0.0;
    let mut rest = t;
    while !rest.is_empty() {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        rest = &rest[digits.len()..];
        let unit: String = rest.chars().take_while(|c| !c.is_ascii_digit()).collect();
        rest = &rest[unit.len()..];
        let v: f64 = digits.parse().unwrap_or_else(|_| panic!("time `{t}`"));
        total += match unit.as_str() {
            "ms" => v / 1000.0,
            "s" => v,
            "m" => v * 60.0,
            "h" => v * 3600.0,
            "d" => v * 86400.0,
            u => panic!("unit `{u}` in `{t}`"),
        };
    }
    total
}

/// The text of `key=` in `line` (after `scope`, when given), up to the next `,` / `]` / space.
fn field<'a>(line: &'a str, scope: &str, key: &str) -> &'a str {
    let from = if scope.is_empty() { line } else { line.split(scope).nth(1).unwrap_or_else(|| panic!("{scope} in {line}")) };
    let v = from.split(&format!("{key}=")).nth(1).unwrap_or_else(|| panic!("{key}= in {line}"));
    v.split([',', ']', ' ']).next().expect("value")
}

/// What one timer must show: nothing, or about that many seconds left.
#[derive(Clone, Copy)]
enum Want {
    Empty,
    About(f64),
}

fn check(line: &str, scope: &str, key: &str, want: Want) {
    let got = field(line, scope, key);
    match want {
        Want::Empty => assert!(got.is_empty(), "{scope} {key} must be empty, got `{got}` in:\n{line}"),
        Want::About(exp) => {
            assert!(!got.is_empty(), "{scope} {key} must be about {exp}s, got nothing in:\n{line}");
            let v = secs_of(got);
            assert!((v - exp).abs() <= 6.0, "{scope} {key}={got} is not about {exp}s in:\n{line}");
        }
    }
}

/// The `show sess` line of `c`'s stream after `wait`; `None` if it is not listed.
fn timer_line(ibex: &Ibex, c: &TcpStream, wait: Duration) -> Option<String> {
    let needle = format!(" src={} ", c.local_addr().expect("addr"));
    std::thread::sleep(wait);
    let out = cli(ibex, "show sess");
    out.lines().find(|l| l.contains(&needle)).map(str::to_string)
}

fn timer_client(ibex: &Ibex, payload: &[u8]) -> TcpStream {
    let mut c = TcpStream::connect(ibex.fh).expect("connect");
    c.write_all(payload).expect("send");
    c
}

#[test]
fn timers_idle_keepalive_connection_is_not_listed() {
    let ibex = start_timers();
    let mut c = timer_client(&ibex, b"GET /fast HTTP/1.1\r\nhost: x\r\n\r\n");
    let mut buf = [0u8; 256];
    let _ = c.read(&mut buf).expect("response");
    assert!(timer_line(&ibex, &c, Duration::from_millis(500)).is_none(), "idle connection listed");
}

#[test]
fn timers_partial_request_headers_have_no_stream() {
    let ibex = start_timers();
    let c = timer_client(&ibex, b"GET /x HTTP/1.1\r\nhost: x\r\n");
    let line = timer_line(&ibex, &c, Duration::from_secs(2));
    assert!(line.is_none(), "HAProxy creates the stream when the head is complete, listed: {line:?}");
}

#[test]
fn timers_request_done_waiting_on_slow_server() {
    let ibex = start_timers();
    let c = timer_client(&ibex, b"GET /x HTTP/1.1\r\nhost: x\r\n\r\n");
    let line = timer_line(&ibex, &c, Duration::from_secs(2)).expect("listed");
    check(&line, "scf=[", "rex", Want::Empty);
    check(&line, "scf=[", "wex", Want::Empty);
    check(&line, "scb=[", "rex", Want::About(38.0));
    check(&line, "scb=[", "wex", Want::Empty);
    check(&line, "", "c_exp", Want::Empty);
    assert_eq!(cli(&ibex, "shutdown sessions server bh/h1"), "\n");
}

#[test]
fn timers_response_to_a_slow_reader() {
    let ibex = start_timers();
    let c = timer_client(&ibex, b"GET /big HTTP/1.1\r\nhost: x\r\n\r\n");
    let line = timer_line(&ibex, &c, Duration::from_secs(2)).expect("listed");
    check(&line, "scf=[", "rex", Want::Empty);
    check(&line, "scf=[", "wex", Want::About(28.0));
    check(&line, "scb=[", "rex", Want::Empty);
    check(&line, "scb=[", "wex", Want::Empty);
    check(&line, "", "c_exp", Want::Empty);
    assert_eq!(cli(&ibex, "shutdown sessions server bh/h1"), "\n");
}

#[test]
fn timers_request_body_uploaded_slowly() {
    let ibex = start_timers();
    let c = timer_client(&ibex, b"POST /x HTTP/1.1\r\nhost: x\r\ncontent-length: 1000000\r\n\r\nyyyy");
    let line = timer_line(&ibex, &c, Duration::from_secs(2)).expect("listed");
    check(&line, "scf=[", "rex", Want::About(28.0));
    check(&line, "scf=[", "wex", Want::Empty);
    check(&line, "scb=[", "rex", Want::Empty);
    check(&line, "scb=[", "wex", Want::Empty);
    check(&line, "", "c_exp", Want::Empty);
    assert_eq!(cli(&ibex, "shutdown sessions server bh/h1"), "\n");
}

#[test]
fn timers_server_connect_in_progress() {
    let ibex = start_timers();
    let c = timer_client(&ibex, b"GET /conn HTTP/1.1\r\nhost: x\r\n\r\n");
    let line = timer_line(&ibex, &c, Duration::from_secs(2)).expect("listed");
    check(&line, "scf=[", "rex", Want::Empty);
    check(&line, "scf=[", "wex", Want::Empty);
    check(&line, "scb=[", "rex", Want::Empty);
    check(&line, "scb=[", "wex", Want::Empty);
    check(&line, "", "c_exp", Want::About(3.0));
    assert_eq!(cli(&ibex, "shutdown sessions backend bc"), "\n");
}
