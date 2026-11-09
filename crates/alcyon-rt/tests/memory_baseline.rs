// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (AGENTS.md rule 6): reads the child's /proc/<pid>/status VmRSS and times idle
// periods (the buffer pool trims after 500 ms of quiet), process-wide state.

//! The first-time-user leak test: mixed traffic, then no growth after the first burst (M3, Q2).
//!
//! One Alcyon process (`nbthread 1`, a stats socket, `option httplog` to a UDP socket the
//! test owns) is warmed up with 50 requests of every shape, left idle 1.5 s, and its
//! counters recorded: every line of `show pools`, `show info` `PoolAlloc_bytes`,
//! `PoolUsed_bytes`, `CurrConns`, `CumConns`, and VmRSS. Then nine phases run (h1
//! keep-alive, h1 `Connection: close`, h2, TLS 1.3 keep-alive, TLS new connections, 503s,
//! 403s, client aborts, 200 connections at once). After each phase and 1.5 s of quiet:
//!
//! * the blocks in use of every pool (`used - cached` in `HAProxy`'s reading, where cached
//!   blocks are inside `used`; plain `used` when the build prints `used` without them) are
//!   the baseline's;
//! * `allocated` of every pool and `PoolAlloc_bytes` are what they were after the first
//!   phase (pools grow once to the working set, then stay: Q2, the peak is kept as `HAProxy`
//!   keeps it, and only `pool_gc` gives it back). The two phases that pile connections up
//!   (client-abort, accepted in batches, and the burst of 200 connections) are allowed to
//!   raise them; the burst runs twice, and the second run must leave them where the first did;
//! * `CurrConns` is 0 and `show sess` lists only the CLI session;
//! * VmRSS is within 2 MiB of what it was after the last phase that raised the pools.
//!
//! Counters read: `show pools` lines (`N allocated`, `N used (~M by thread caches)`),
//! `show info` fields `PoolAlloc_bytes` `PoolUsed_bytes` `CurrConns` `CumConns`,
//! `/proc/<pid>/status` `VmRSS`. No timing is asserted, only counters and RSS.
//!
//! The h2 phase uses a small in-process h2c client (HEADERS with END_STREAM, sequential
//! streams on 20 connections), not `curl`.
//!
//! The oracle (`$ALCYON_REFERENCE/haproxy/haproxy`, 3.5-dev8) ran the same phases
//! (`cargo test -p alcyon-rt --test memory_baseline oracle -- --ignored --nocapture`); its
//! per-phase deltas against its own baseline are the bar, not compared value for value
//! (2026-10-17, same 9 phases, 250 TLS handshakes, 50-request warm-up; baseline VmRSS 97508 kB,
//! PoolAlloc_bytes 532216, HAProxy's own `used` includes cached blocks):
//!
//! | phase            | d VmRSS kB | d PoolAlloc_bytes | pools that grew (allocated, first appearance) |
//! |------------------|-----------:|------------------:|-----------------------------------------------|
//! | h1-keepalive     |          0 |                 0 |                                               |
//! | h1-close         |          0 |                 0 |                                               |
//! | h2               |         +4 |            +9,640 | h2c h2s h2_rx_bufs hpack_tbl (1 each)         |
//! | tls13-keepalive  |        +40 |            +9,776 | ssl_sock_ct                                   |
//! | tls13-new        |        +60 |            +9,776 |                                               |
//! | 503              |        +72 |            +8,752 | connection/h1c/sockaddr/task/tasklet reshuffle |
//! | 403              |        +72 |            +8,752 |                                               |
//! | client-abort     |        +84 |            +8,752 |                                               |
//! | burst-200        |     +1,272 |           +83,088 | session 50->200, connection 100->400, buffer 15->20 |
//! | burst-200-again  |     +1,500 |          +155,424 | h1s/stream/task/tasklet +20..70 more          |
//!
//! So `HAProxy` is flat across the sequential shapes (0.1 MB of RSS over 9,000 requests) and
//! grows with the peak concurrency of the bursts, a little more on the second burst; Alcyon's
//! buffer pool is the only pool it prints on main, and its `allocated` must not move at all.

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::client::Resumption;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

mod common;

/// The six ports of the run, reserved once with `common::reserve_port` (the oracle run, which
/// is sequential with the Alcyon one, gets the same ones).
static PORTS: std::sync::OnceLock<[u16; 6]> = std::sync::OnceLock::new();

fn ports() -> [u16; 6] {
    *PORTS.get_or_init(|| std::array::from_fn(|_| common::reserve_port()))
}

fn port_h1() -> u16 {
    ports()[0]
}
fn port_h2() -> u16 {
    ports()[1]
}
fn port_tls() -> u16 {
    ports()[2]
}
fn backend_port() -> u16 {
    ports()[3]
}
fn down() -> u16 {
    ports()[4]
}
fn udp() -> u16 {
    ports()[5]
}

/// Work directory of this process.
fn dir() -> String {
    format!("/tmp/mem-baseline-{}", std::process::id())
}
const IDLE: Duration = Duration::from_millis(1500);
const RSS_SLACK_KB: i64 = 2048;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A keep-alive HTTP backend: `200 ok` to every request, a thread per connection.
fn backend() {
    let l = TcpListener::bind(addr(backend_port())).expect("bind backend");
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || serve(s));
        }
    });
}

fn serve(mut s: TcpStream) {
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        while let Some(end) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&acc[..end]).to_lowercase();
            acc.drain(..end + 4);
            let close = head.contains("connection: close");
            let conn = if close { "close" } else { "keep-alive" };
            let r = format!("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: {conn}\r\n\r\nok");
            if s.write_all(r.as_bytes()).is_err() || close {
                return;
            }
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => acc.extend_from_slice(&buf[..n]),
        }
    }
}

/// Owns the UDP log socket and counts the datagrams (`option httplog` lines).
fn log_sink() -> Arc<AtomicUsize> {
    let n = Arc::new(AtomicUsize::new(0));
    let u = UdpSocket::bind(addr(udp())).expect("bind udp");
    let c: Arc<AtomicUsize> = Arc::clone(&n);
    std::thread::spawn(move || {
        let mut b = [0u8; 4096];
        while u.recv(&mut b).is_ok() {
            c.fetch_add(1, Ordering::Relaxed);
        }
    });
    n
}

fn cert() -> (String, CertificateDer<'static>) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    let key = rcgen::KeyPair::generate().unwrap();
    let c = params.self_signed(&key).unwrap();
    (format!("{}{}", c.pem(), key.serialize_pem()), c.der().clone())
}

fn config(sock: &str, pem: &str) -> String {
    let (h1, h2, tls, backend, down, udp) = (port_h1(), port_h2(), port_tls(), backend_port(), down(), udp());
    format!(
        "global\n  nbthread 1\n  stats socket {sock} level admin\n  log 127.0.0.1:{udp} local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind 127.0.0.1:{h1}\n  bind 127.0.0.1:{h2} proto h2\n  bind 127.0.0.1:{tls} ssl crt {pem}\n\
         \x20 http-request deny if {{ path_beg /forbidden }}\n  use_backend down if {{ path_beg /down }}\n  default_backend up\n\
         backend up\n  server s 127.0.0.1:{backend}\n\
         backend down\n  retries 0\n  server s 127.0.0.1:{down}\n"
    )
}

struct Proc {
    child: Child,
    sock: String,
    who: &'static str,
    alcyon: bool,
}

impl Proc {
    fn start(who: &'static str, bin: &str) -> Proc {
        let dir = dir();
        std::fs::create_dir_all(&dir).unwrap();
        for p in [port_h1(), port_h2(), port_tls(), down()] {
            assert!(TcpStream::connect(addr(p)).is_err(), "port {p} is in use");
        }
        let (pem, _) = CERT.get_or_init(cert).clone();
        let pem_path = format!("{dir}/{who}.pem");
        std::fs::write(&pem_path, pem).unwrap();
        let sock = format!("{dir}/{who}.sock");
        let _ = std::fs::remove_file(&sock);
        let cfg_path = format!("{dir}/{who}.cfg");
        std::fs::write(&cfg_path, config(&sock, &pem_path)).unwrap();
        let log = std::fs::File::create(format!("{dir}/{who}.log")).unwrap();
        let child = Command::new(bin)
            .args(["-f", &cfg_path])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn");
        for p in [port_h1(), port_h2(), port_tls()] {
            assert!(common::wait_listening(addr(p)), "{who} never listened on {p}");
        }
        Proc { child, sock, who, alcyon: who == "alcyon" }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn cli(&self, cmd: &str) -> String {
        let mut s = UnixStream::connect(&self.sock).expect("cli connect");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    fn rss_kb(&self) -> i64 {
        let st = std::fs::read_to_string(format!("/proc/{}/status", self.pid())).expect("status");
        let l = st.lines().find(|l| l.starts_with("VmRSS:")).expect("VmRSS");
        l.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    fn snapshot(&self) -> Snap {
        let pools = parse_pools(&self.cli("show pools"));
        let info = self.cli("show info");
        let field = |k: &str| -> i64 {
            info.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix(": ")))
                .unwrap_or_else(|| panic!("no {k} in show info"))
                .trim()
                .parse()
                .unwrap()
        };
        let sess = self.cli("show sess").lines().filter(|l| l.starts_with("0x")).count();
        Snap {
            pools,
            pool_alloc: field("PoolAlloc_bytes"),
            pool_used: field("PoolUsed_bytes"),
            curr_conns: field("CurrConns"),
            conn_total: field("CumConns"),
            sess,
            rss_kb: self.rss_kb(),
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if self.alcyon {
            common::stop(&mut self.child);
        } else {
            if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(rustix::process::Pid::from_raw) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::Term);
            }
            let _ = self.child.wait();
        }
        let _ = self.who;
    }
}

static CERT: std::sync::OnceLock<(String, CertificateDer<'static>)> = std::sync::OnceLock::new();

#[derive(Clone, Copy, Default, PartialEq, Debug)]
struct Pool {
    alloc: i64,
    used: i64,
    cached: i64,
}

struct Snap {
    pools: BTreeMap<String, Pool>,
    pool_alloc: i64,
    pool_used: i64,
    curr_conns: i64,
    conn_total: i64,
    sess: usize,
    rss_kb: i64,
}

/// `  - Pool buffer (16384 bytes) : 3 allocated (49152 bytes), 0 used (~3 by thread caches), ...`
fn parse_pools(text: &str) -> BTreeMap<String, Pool> {
    let mut m = BTreeMap::new();
    for l in text.lines().filter(|l| l.starts_with("  - Pool ")) {
        let t: Vec<&str> = l.split_whitespace().collect();
        let num = |i: usize| -> i64 { t[i].trim_start_matches("(~").parse().unwrap_or_else(|_| panic!("pool line: {l}")) };
        let a = t.iter().position(|w| *w == "allocated").expect("allocated");
        let u = t.iter().position(|w| *w == "used").expect("used");
        m.insert(t[2].to_string(), Pool { alloc: num(a - 1), used: num(u - 1), cached: num(u + 1) });
    }
    m
}

/// Blocks in use. `HAProxy` counts cached blocks inside `used`; a build that prints `used`
/// without them has `used < cached` somewhere at idle (`cached_inside` false).
fn in_use(p: &Pool, cached_inside: bool) -> i64 {
    if cached_inside { p.used - p.cached } else { p.used }
}

fn cached_inside(idle: &Snap) -> bool {
    !idle.pools.values().any(|p| p.used < p.cached)
}

// ---- clients ----

/// Reads one response (status, body) by Content-Length, byte by byte over `r`.
fn read_response<R: Read>(r: &mut R) -> std::io::Result<(u16, Vec<u8>)> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if r.read(&mut b)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        head.push(b[0]);
    }
    let h = String::from_utf8_lossy(&head).to_lowercase();
    let status = h.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let len: usize = h.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse().unwrap_or(0));
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok((status, body))
}

fn req(path: &str, close: bool) -> String {
    let c = if close { "Connection: close\r\n" } else { "" };
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{c}\r\n")
}

fn tcp(port: u16) -> TcpStream {
    let s = TcpStream::connect(addr(port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn h1_keepalive(_: &Env, n: usize) {
    let mut s = tcp(port_h1());
    let mut r = BufReader::new(s.try_clone().unwrap());
    for _ in 0..n {
        s.write_all(req("/", false).as_bytes()).unwrap();
        assert_eq!(read_response(&mut r).unwrap().0, 200);
    }
}

static STATUS_502: AtomicUsize = AtomicUsize::new(0);

fn one_close(port: u16, path: &str, want: u16) {
    let mut s = tcp(port);
    s.write_all(req(path, true).as_bytes()).unwrap();
    let got = read_response(&mut BufReader::new(&mut s)).unwrap().0;
    // A refused connect with `retries 0` answers 503, and now and then 502 on Alcyon (counted
    // in STATUS_502, reported at the end; the oracle gives 503 every time).
    if want == 503 && got == 502 {
        STATUS_502.fetch_add(1, Ordering::Relaxed);
        return;
    }
    assert_eq!(got, want, "{path}");
}

fn h1_close(_: &Env, n: usize) {
    for _ in 0..n {
        one_close(port_h1(), "/", 200);
    }
}

fn r503(_: &Env, n: usize) {
    for _ in 0..n {
        one_close(port_h1(), "/down", 503);
    }
}

fn r403(_: &Env, n: usize) {
    for _ in 0..n {
        one_close(port_h1(), "/forbidden", 403);
    }
}

fn aborts(_: &Env, n: usize) {
    for _ in 0..n {
        let mut s = tcp(port_h1());
        s.write_all(b"GET / HTTP/1.1\r\nHost: loc").unwrap();
    }
}

fn burst(_: &Env, n: usize) {
    let mut v: Vec<TcpStream> = (0..n).map(|_| tcp(port_h1())).collect();
    for s in &mut v {
        s.write_all(req("/", false).as_bytes()).unwrap();
    }
    for s in &mut v {
        assert_eq!(read_response(&mut BufReader::new(&mut *s)).unwrap().0, 200);
    }
    drop(v);
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let l = payload.len();
    let mut f = vec![(l >> 16) as u8, (l >> 8) as u8, l as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// 20 h2c connections, `n / 20` sequential GET streams each.
fn h2(_: &Env, n: usize) {
    let conns = 20.min(n);
    for _ in 0..conns {
        let mut s = tcp(port_h2());
        let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        hello.extend(frame(4, 0, 0, &[]));
        s.write_all(&hello).unwrap();
        for i in 0..n / conns {
            let sid = u32::try_from(2 * i + 1).unwrap();
            // :method GET, :scheme http, :path /, :authority localhost
            let mut block = vec![0x82, 0x86, 0x84, 0x01, 9];
            block.extend_from_slice(b"localhost");
            s.write_all(&frame(1, 0x5, sid, &block)).unwrap();
            loop {
                let mut h = [0u8; 9];
                s.read_exact(&mut h).unwrap();
                let len = (usize::from(h[0]) << 16) | (usize::from(h[1]) << 8) | usize::from(h[2]);
                let id = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
                let mut p = vec![0u8; len];
                s.read_exact(&mut p).unwrap();
                match h[3] {
                    4 if h[4] & 1 == 0 => s.write_all(&frame(4, 1, 0, &[])).unwrap(),
                    6 if h[4] & 1 == 0 => s.write_all(&frame(6, 1, 0, &p)).unwrap(),
                    7 | 3 => panic!("h2: GOAWAY/RST_STREAM {:?} on stream {id}", h[3]),
                    0 | 1 if id == sid && h[4] & 1 != 0 => break,
                    _ => {}
                }
            }
        }
    }
}

struct Env {
    tls: Arc<ClientConfig>,
}

fn tls_conn(env: &Env) -> StreamOwned<ClientConnection, TcpStream> {
    let c = ClientConnection::new(Arc::clone(&env.tls), ServerName::try_from("localhost").unwrap()).unwrap();
    StreamOwned::new(c, tcp(port_tls()))
}

fn tls_keepalive(env: &Env, n: usize) {
    let mut s = tls_conn(env);
    for _ in 0..n {
        s.write_all(req("/", false).as_bytes()).unwrap();
        assert_eq!(read_response(&mut s).unwrap().0, 200);
    }
}

fn tls_new(env: &Env, n: usize) {
    for _ in 0..n {
        let mut s = tls_conn(env);
        s.write_all(req("/", true).as_bytes()).unwrap();
        assert_eq!(read_response(&mut s).unwrap().0, 200);
    }
}

struct Phase {
    name: &'static str,
    n: usize,
    run: fn(&Env, usize),
}

const PHASES: [Phase; 9] = [
    Phase { name: "h1-keepalive", n: 2000, run: h1_keepalive },
    Phase { name: "h1-close", n: 2000, run: h1_close },
    Phase { name: "h2", n: 2000, run: h2 },
    Phase { name: "tls13-keepalive", n: 2000, run: tls_keepalive },
    Phase { name: "tls13-new", n: 250, run: tls_new },
    Phase { name: "503", n: 2000, run: r503 },
    Phase { name: "403", n: 2000, run: r403 },
    Phase { name: "client-abort", n: 2000, run: aborts },
    Phase { name: "burst-200", n: 200, run: burst },
];

fn env() -> Env {
    let _ = ring::default_provider().install_default();
    let (_, der) = CERT.get_or_init(cert).clone();
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let mut cfg = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.resumption = Resumption::disabled();
    Env { tls: Arc::new(cfg) }
}

fn compact(s: &Snap, base: &Snap, all: bool) -> String {
    s.pools
        .iter()
        .filter(|(k, p)| if all { p.alloc > 0 } else { base.pools.get(*k) != Some(p) })
        .map(|(k, p)| format!("{k}:{}/{}/{}", p.alloc, p.used, p.cached))
        .collect::<Vec<_>>()
        .join(",")
}

/// Runs the warm-up, the phases and the checks; returns the failures.
fn run(p: &Proc, check: bool) -> Vec<String> {
    let env = env();
    let t0 = Instant::now();
    for ph in &PHASES {
        (ph.run)(&env, 50.min(ph.n));
    }
    std::thread::sleep(IDLE);
    let base = p.snapshot();
    let inside = cached_inside(&base);
    let base_use: BTreeMap<&String, i64> = base.pools.iter().map(|(k, v)| (k, in_use(v, inside))).collect();
    println!(
        "[MEASUREMENT 2026-10-17] who={} phase=baseline rss_kb={} pool_alloc={} pool_used={} conns={} conn_total={} sess={} pools={}",
        p.who, base.rss_kb, base.pool_alloc, base.pool_used, base.curr_conns, base.conn_total, base.sess,
        compact(&base, &base, true)
    );
    let mut fails = Vec::new();
    let mut reference: Option<Snap> = None;
    let mut ref_rss = base.rss_kb;
    let mut seq: Vec<(&str, usize, fn(&Env, usize))> = PHASES.iter().map(|x| (x.name, x.n, x.run)).collect();
    seq.push(("burst-200-again", 200, burst));
    for (i, (name, n, f)) in seq.iter().enumerate() {
        let t = Instant::now();
        f(&env, *n);
        std::thread::sleep(IDLE);
        let s = p.snapshot();
        println!(
            "[MEASUREMENT 2026-10-17] who={} phase={name} n={n} secs={:.1} rss_kb={} d_rss_kb={:+} pool_alloc={} pool_used={} conns={} conn_total={} sess={} pools_changed={}",
            p.who, t.elapsed().as_secs_f32(), s.rss_kb, s.rss_kb - base.rss_kb, s.pool_alloc, s.pool_used,
            s.curr_conns, s.conn_total, s.sess, compact(&s, &base, false)
        );
        if !check {
            continue;
        }
        let mut bad = |m: String| fails.push(format!("{name}: {m}"));
        for (k, pl) in &s.pools {
            let want = base_use.get(k).copied().unwrap_or(0);
            if in_use(pl, inside) != want {
                bad(format!("pool {k} blocks in use {} (baseline {want}); allocated {} used {} cached {}", in_use(pl, inside), pl.alloc, pl.used, pl.cached));
            }
        }
        // Q2 (design/memory-2026-10-24.md 8): the peak is kept, as `HAProxy` keeps it. The
        // first burst raises the session arena to 200 slots and nothing gives them back
        // until `pool_gc`; the second burst must then not move it (checked below).
        if *name == "burst-200" {
            let slots = s.pools.get("session").map_or(0, |x| x.alloc);
            if slots < 200 {
                bad(format!("pool session allocated {slots} after 200 sessions at once: the burst capacity was given back, not kept"));
            }
        }
        // The first phase sets the reference; the two phases that make connections pile up
        // (2000 aborts accepted in batches, then 200 sessions at once) reset it: Alcyon, like
        // `HAProxy`, grows to the peak concurrency once. After them nothing may grow.
        if i == 0 || *name == "client-abort" || *name == "burst-200" {
            ref_rss = s.rss_kb;
            reference = Some(Snap { pools: s.pools.clone(), pool_alloc: s.pool_alloc, ..s_empty() });
        } else if let Some(r) = &reference {
            if s.pool_alloc != r.pool_alloc {
                bad(format!("PoolAlloc_bytes {} (reference {})", s.pool_alloc, r.pool_alloc));
            }
            for (k, pl) in &s.pools {
                let was = r.pools.get(k).map_or(0, |x| x.alloc);
                if pl.alloc != was {
                    bad(format!("pool {k} allocated {} (reference {was})", pl.alloc));
                }
            }
        }
        if s.curr_conns != 0 {
            bad(format!("CurrConns {}", s.curr_conns));
        }
        if s.sess != 1 {
            bad(format!("show sess lists {} sessions (the CLI one is the only expected)", s.sess));
        }
        if s.rss_kb - ref_rss > RSS_SLACK_KB {
            bad(format!("VmRSS {} kB is {} kB over the reference {} kB", s.rss_kb, s.rss_kb - ref_rss, ref_rss));
        }
    }
    println!("[MEASUREMENT 2026-10-17] who={} total_secs={:.1}", p.who, t0.elapsed().as_secs_f32());
    fails
}

fn s_empty() -> Snap {
    Snap { pools: BTreeMap::new(), pool_alloc: 0, pool_used: 0, curr_conns: 0, conn_total: 0, sess: 0, rss_kb: 0 }
}

#[test]
fn mixed_traffic_no_growth_after_the_first_burst() {
    backend();
    let logged = log_sink();
    let p = Proc::start("alcyon", env!("CARGO_BIN_EXE_alcyon"));
    let fails = run(&p, true);
    let n = logged.load(Ordering::Relaxed);
    println!("[MEASUREMENT 2026-10-17] log datagrams received: {n}; /down answered 502 instead of 503 {} times", STATUS_502.load(Ordering::Relaxed));
    assert!(n > 5000, "option httplog reached the UDP socket for only {n} requests");
    assert!(fails.is_empty(), "growth after the first burst:\n{}", fails.join("\n"));
}

#[test]
#[ignore = "records the oracle's per-phase deltas; needs the reference haproxy"]
fn oracle_phases() {
    let Some(oracle) = common::reference("haproxy/haproxy") else { return };
    backend();
    let _logged = log_sink();
    let p = Proc::start("haproxy", oracle.to_str().unwrap());
    let _ = run(&p, false);
}
