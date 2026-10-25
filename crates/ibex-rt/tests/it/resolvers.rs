// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Run-time A/AAAA resolution for `server ... resolvers` (T484, DNS slice S1b), against a fake
//! UDP nameserver in this file (a port of the design's `fakedns.py`: one zone per name,
//! changed while Ibex runs, every query logged with its time, type and id).
//!
//! Each test is a row of `docs/design/dns-2026-10-25.md` appendix A, measured on `HAProxy
//! 3.5-dev8-885761-29`; the log lines and `show servers state` columns are `HAProxy`'s byte for
//! byte. The timers are shorter than in the appendix (`timeout resolve 300ms` and the like) so
//! the file runs in seconds; the oracle's behaviour does not depend on their size.

use crate::common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// What the fake nameserver answers for a name.
#[derive(Clone, Debug)]
enum Zone {
    A(Vec<Ipv4Addr>),
    Nx,
    Refused,
    ServFail,
    /// NOERROR, no answer.
    NoData,
    /// No reply at all.
    Silent,
}

/// One query the fake nameserver saw.
#[derive(Clone, Debug)]
struct Query {
    at: Instant,
    qtype: u16,
    name: String,
    id: u16,
    /// The OPT record's payload size, 0 without one.
    edns: u16,
}

struct FakeDns {
    addr: SocketAddr,
    zone: Arc<Mutex<HashMap<String, Zone>>>,
    log: Arc<Mutex<Vec<Query>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for FakeDns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn base_zone() -> HashMap<String, Zone> {
    let a = |v: &[[u8; 4]]| Zone::A(v.iter().map(|o| Ipv4Addr::from(*o)).collect());
    HashMap::from([
        ("a1.test".to_string(), a(&[[10, 0, 0, 1]])),
        ("multi.test".to_string(), a(&[[10, 0, 0, 1], [10, 0, 0, 2], [10, 0, 0, 3]])),
        ("be.test".to_string(), a(&[[127, 0, 0, 1]])),
        ("nx.test".to_string(), Zone::Nx),
    ])
}

impl FakeDns {
    #[allow(clippy::many_single_char_names)]
    fn start() -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the fake nameserver");
        sock.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");
        let addr = sock.local_addr().expect("addr");
        let zone = Arc::new(Mutex::new(base_zone()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (z, l, s) = (Arc::clone(&zone), Arc::clone(&log), Arc::clone(&stop));
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while !s.load(Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
                let Some((q, qend)) = parse_query(&buf[..n]) else { continue };
                let answer = z.lock().expect("zone").get(&q.name).cloned().unwrap_or(Zone::Nx);
                l.lock().expect("log").push(q.clone());
                if let Some(reply) = build_reply(&buf[..qend], &answer) {
                    let _ = sock.send_to(&reply, from);
                }
            }
        });
        Self { addr, zone, log, stop }
    }

    fn set(&self, name: &str, z: Zone) {
        self.zone.lock().expect("zone").insert(name.to_string(), z);
    }

    fn queries(&self) -> Vec<Query> {
        self.log.lock().expect("log").clone()
    }
}

/// The question of a query, and where it ends.
fn parse_query(b: &[u8]) -> Option<(Query, usize)> {
    if b.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([b[0], b[1]]);
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*b.get(i)?);
        i += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(b.get(i..i + len)?).to_ascii_lowercase());
        i += len;
    }
    let qtype = u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]);
    let qend = i + 4;
    // The OPT record follows the question: root name, type 41, then the payload size.
    let edns = match b.get(qend..qend + 5) {
        Some([0, 0, 41, hi, lo]) => u16::from_be_bytes([*hi, *lo]),
        _ => 0,
    };
    Some((Query { at: Instant::now(), qtype, name: labels.join("."), id, edns }, qend))
}

fn build_reply(question: &[u8], z: &Zone) -> Option<Vec<u8>> {
    let rcode = match z {
        Zone::Silent => return None,
        Zone::Nx => 3,
        Zone::Refused => 5,
        Zone::ServFail => 2,
        Zone::A(_) | Zone::NoData => 0,
    };
    let ips: &[Ipv4Addr] = if let Zone::A(v) = z { v } else { &[] };
    let qtype = u16::from_be_bytes([question[question.len() - 4], question[question.len() - 3]]);
    // An A query is answered with the A records; an AAAA one with nothing (NODATA).
    let ips = if qtype == 1 { ips } else { &[] };
    let mut r = Vec::with_capacity(512);
    r.extend_from_slice(&question[..2]);
    r.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1]);
    r.extend_from_slice(&u16::try_from(ips.len()).expect("count").to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&question[12..]);
    for ip in ips {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    Some(r)
}

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
    fe: SocketAddr,
    out: Arc<Mutex<Vec<String>>>,
    err: Arc<Mutex<Vec<String>>>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn collect(r: impl Read + Send + 'static) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let l = Arc::clone(&lines);
    thread::spawn(move || {
        for line in BufReader::new(r).lines().map_while(Result::ok) {
            l.lock().expect("lines").push(line);
        }
    });
    lines
}

/// Starts Ibex with `resolvers r` on `ns`, the `resolvers` lines `extra`, and `servers` in
/// `listen l`.
fn start(ns: SocketAddr, extra: &str, servers: &str, global: &str) -> Ibex {
    let fe = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("ibex_t484_{}_{}.sock", std::process::id(), fe.port()));
    let text = format!(
        "global\n  log stdout format raw local0\n  stats socket {} level admin\n{global}\
         resolvers r\n  nameserver ns1 {ns}\n{extra}\
         defaults\n  mode http\n  log global\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         listen l\n  bind {fe}\n{servers}",
        sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex");
    let out = collect(child.stdout.take().expect("stdout"));
    let err = collect(child.stderr.take().expect("stderr"));
    let ibex = Ibex { child, _cfg: f, sock, fe, out, err };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}\nstderr: {:?}", ibex.err.lock());
    ibex
}

impl Ibex {
    fn cli(&self, cmd: &str) -> String {
        let mut s = UnixStream::connect(&self.sock).expect("connect to the stats socket");
        s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    /// `srv_addr srv_op_state srv_admin_state` of `sv` in `show servers state`, and its
    /// `srv_fqdn`.
    fn state(&self, sv: &str) -> (String, String) {
        let out = self.cli("show servers state l");
        let f: Vec<&str> = out
            .lines()
            .map(|l| l.split(' ').collect::<Vec<_>>())
            .find(|f| f.get(3) == Some(&sv))
            .unwrap_or_else(|| panic!("no {sv} in {out:?}"));
        (format!("{} {} {}", f[4], f[5], f[6]), f[17].to_string())
    }

    /// Waits up to `secs` for `sv`'s state to be `want`.
    fn wait_state(&self, sv: &str, want: &str, secs: u64) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let got = self.state(sv).0;
            if got == want {
                return;
            }
            assert!(Instant::now() < deadline, "{sv} never reached '{want}', last '{got}'; log {:?}", self.log());
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// The log lines (stdout, `format raw`).
    fn log(&self) -> Vec<String> {
        self.out.lock().expect("out").clone()
    }

    fn stderr(&self) -> Vec<String> {
        self.err.lock().expect("err").clone()
    }

    /// Waits up to `secs` for the log line `line`, also printed on stderr as a warning.
    fn wait_log(&self, line: &str, secs: u64) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !self.log().iter().any(|l| l == line) {
            assert!(Instant::now() < deadline, "no log line {line:?} in {:?}", self.log());
            thread::sleep(Duration::from_millis(20));
        }
        let warn = format!("[WARNING]  ({}) : {line}", self.child.id());
        assert!(self.stderr().contains(&warn), "no {warn:?} in {:?}", self.stderr());
    }
}

const UP: &str = "l/s1: IP changed from '(none)' to '10.0.0.1' by 'r/ns1'.";
const RESOLVES: &str = "Server l/s1 ('a1.test') is UP/READY (resolves again).";
const READY: &str = "Server l/s1 administratively READY thanks to valid DNS answer.";
const LEFT: &str = "0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.";

/// A.t1a: a name with `resolvers` starts in maintenance (the NOTICE), and the first answer
/// gives it its address and brings it out, with three log lines. Each query carries the
/// OPT record (`edns=512`), and the ids are random.
#[test]
fn t1a_a_name_comes_up_at_its_first_answer() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    assert_eq!(ibex.state("s1").1, "a1.test");
    ibex.wait_log(UP, 2);
    ibex.wait_log(RESOLVES, 2);
    ibex.wait_log(READY, 2);
    assert!(
        ibex.stderr().iter().any(|l| l.ends_with(": 'server l/s1' : could not resolve address 'a1.test', disabling server.")),
        "{:?}",
        ibex.stderr()
    );
    let q = dns.queries();
    assert!(q.iter().all(|q| q.qtype == 1 && q.name == "a1.test" && q.edns == 512), "{q:?}");
}

/// A.t1b: `init-addr none` starts the same, without the NOTICE.
#[test]
fn t1b_init_addr_none_is_the_same_without_the_notice() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", "  server s1 a1.test:80 resolvers r init-addr none\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.wait_log(UP, 2);
    ibex.wait_log(READY, 2);
    assert!(!ibex.stderr().iter().any(|l| l.contains("could not resolve")), "{:?}", ibex.stderr());
}

/// A.t1c: `init-addr <ip>` serves that address until the first answer replaces it; the
/// server was never in maintenance, so only the address line.
#[test]
fn t1c_init_addr_ip_is_replaced_by_the_answer() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.wait_log("l/s1: IP changed from '10.9.9.9' to '10.0.0.1' by 'r/ns1'.", 2);
    assert!(!ibex.log().iter().any(|l| l.contains("READY")), "{:?}", ibex.log());
}

/// A.t2: one query every `timeout resolve` whatever the TTL (300 s here), each with a new id.
#[test]
fn t2_one_query_every_timeout_resolve() {
    let dns = FakeDns::start();
    let _ibex = start(dns.addr, "  timeout resolve 500ms\n", "  server s1 a1.test:80 resolvers r\n", "");
    thread::sleep(Duration::from_millis(2300));
    let q = dns.queries();
    assert!(q.len() >= 4, "{q:?}");
    for w in q.windows(2) {
        let gap = w[1].at.duration_since(w[0].at).as_millis();
        assert!((400..=600).contains(&gap), "gap {gap} ms in {q:?}");
        assert_ne!(w[0].id, w[1].id, "{q:?}");
    }
}

/// A.t3: a changed answer moves the server at the next resolution, logged.
#[test]
fn t3_a_changed_answer_moves_the_server() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 2)]));
    ibex.wait_state("s1", "10.0.0.2 2 0", 3);
    ibex.wait_log("l/s1: IP changed from '10.0.0.1' to '10.0.0.2' by 'r/ns1'.", 2);
}

/// Two HTTP servers on 127.0.0.1:P and 127.0.0.2:P answering `X-Server: <their address>`,
/// keep-alive, and how many connections each accepted.
fn two_backends() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    for _ in 0..50 {
        let a = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = a.local_addr().expect("addr").port();
        let Ok(b) = TcpListener::bind(("127.0.0.2", port)) else { continue };
        let counts = [a, b].map(|l| {
            let n = Arc::new(AtomicUsize::new(0));
            let c = Arc::clone(&n);
            let me = l.local_addr().expect("addr").ip();
            thread::spawn(move || {
                for conn in l.incoming().flatten() {
                    c.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || serve(conn, &me.to_string()));
                }
            });
            n
        });
        let [na, nb] = counts;
        return (port, na, nb);
    }
    panic!("no port free on both 127.0.0.1 and 127.0.0.2");
}

fn serve(mut c: TcpStream, me: &str) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf.drain(..end + 4);
            let body = me.as_bytes();
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            if c.write_all(head.as_bytes()).and_then(|()| c.write_all(body)).is_err() {
                return;
            }
        }
        match c.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// One request on `c` (keep-alive), the body of the answer.
fn get(c: &mut TcpStream) -> String {
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).into_owned();
            }
        }
        let n = c.read(&mut chunk).expect("read");
        assert!(n > 0, "closed after {:?}", String::from_utf8_lossy(&buf));
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A.t3b: a client keep-alive connection lives across the swap; its next request goes to
/// the new address.
#[test]
fn t3b_a_keep_alive_client_follows_the_swap() {
    let (port, _, _) = two_backends();
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &format!("  server s1 be.test:{port} resolvers r\n"), "");
    ibex.wait_state("s1", "127.0.0.1 2 0", 3);
    let mut c = TcpStream::connect(ibex.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    assert_eq!(get(&mut c), "127.0.0.1");
    assert_eq!(get(&mut c), "127.0.0.1");
    dns.set("be.test", Zone::A(vec![Ipv4Addr::new(127, 0, 0, 2)]));
    ibex.wait_state("s1", "127.0.0.2 2 0", 3);
    assert_eq!(get(&mut c), "127.0.0.2");
    assert_eq!(get(&mut c), "127.0.0.2");
}

/// `nbthread 2`: the answer is applied by the worker that owns the resolvers (0); fresh
/// connections, accepted by both workers, all go to the new address.
#[test]
fn an_answer_reaches_every_worker() {
    let (port, _, _) = two_backends();
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &format!("  server s1 be.test:{port} resolvers r\n"), "  nbthread 2\n");
    ibex.wait_state("s1", "127.0.0.1 2 0", 3);
    dns.set("be.test", Zone::A(vec![Ipv4Addr::new(127, 0, 0, 2)]));
    ibex.wait_state("s1", "127.0.0.2 2 0", 3);
    for _ in 0..20 {
        let mut c = TcpStream::connect(ibex.fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        assert_eq!(get(&mut c), "127.0.0.2");
    }
}

/// Item 3 of the task: a health check follows the resolved address (it read the address
/// fixed when it was built).
#[test]
fn a_health_check_follows_the_resolved_address() {
    let (port, _, on_b) = two_backends();
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &format!("  server s1 be.test:{port} resolvers r check inter 200ms\n"), "");
    ibex.wait_state("s1", "127.0.0.1 2 0", 3);
    dns.set("be.test", Zone::A(vec![Ipv4Addr::new(127, 0, 0, 2)]));
    ibex.wait_state("s1", "127.0.0.2 2 0", 3);
    let deadline = Instant::now() + Duration::from_secs(3);
    while on_b.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline, "no check reached the new address");
        thread::sleep(Duration::from_millis(20));
    }
}

const FAST: &str = "  timeout resolve 300ms\n  timeout retry 200ms\n  resolve_retries 2\n";

/// A.t4: NX is retried with the same id, then held: the server keeps its address for `hold
/// nx` after the last valid answer, then goes to maintenance with no address; a valid answer
/// brings it back.
#[test]
fn t4_nx_is_held_then_takes_the_server_down() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 1500ms\n"), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    dns.set("a1.test", Zone::Nx);
    let nx_at = Instant::now();
    thread::sleep(Duration::from_millis(900));
    assert_eq!(ibex.state("s1").0, "10.0.0.1 2 0", "down before the hold ran out");
    ibex.wait_state("s1", "- 0 32", 3);
    assert!(nx_at.elapsed() >= Duration::from_millis(1400), "{:?}", nx_at.elapsed());
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS NX status). {LEFT}"), 2);
    // Every NX'd query was sent twice with one id.
    let q = dns.queries();
    let ids: Vec<u16> = q.iter().filter(|q| q.at > nx_at).map(|q| q.id).collect();
    assert!(ids.len() >= 4 && ids[0] == ids[1] && ids[1] != ids[2] && ids[2] == ids[3], "{q:?}");
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    let n = ibex.log().iter().filter(|l| *l == UP).count();
    assert_eq!(n, 2, "{:?}", ibex.log());
}

/// A.t4b: a name never valid stays in maintenance; its errors are not logged as a change.
#[test]
fn t4b_a_name_never_valid_stays_in_maintenance() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, FAST, "  server s1 nx.test:80 resolvers r\n", "");
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(ibex.state("s1"), ("- 0 32".to_string(), "nx.test".to_string()));
    assert!(!ibex.log().iter().any(|l| l.contains("l/s1")), "{:?}", ibex.log());
    let q = dns.queries();
    assert!(q.len() >= 4 && q[0].id == q[1].id && q[1].id != q[2].id, "{q:?}");
}

fn held_down(z: Zone, hold: &str, reason: &str) {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  {hold} 1s\n"), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    dns.set("a1.test", z);
    ibex.wait_state("s1", "- 0 32", 4);
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance ({reason}). {LEFT}"), 2);
}

/// A.t5: a silent nameserver is a timeout, under `hold timeout`.
#[test]
fn t5_silence_is_a_timeout() {
    held_down(Zone::Silent, "hold timeout", "DNS timeout status");
}

/// A.t6: REFUSED, under `hold refused`.
#[test]
fn t6_refused() {
    held_down(Zone::Refused, "hold refused", "DNS refused status");
}

/// A.t6b: SERVFAIL is "other".
#[test]
fn t6b_servfail_is_other() {
    held_down(Zone::ServFail, "hold other", "unspecified DNS error");
}

/// A.t6c: NODATA is "other" too.
#[test]
fn t6c_nodata_is_other() {
    held_down(Zone::NoData, "hold other", "unspecified DNS error");
}

/// A.t7: a nameserver nobody listens on (ICMP unreachable) is a timeout; the `init-addr`
/// address serves until then, and a name never valid goes down at its first error.
#[test]
fn t7_a_dead_nameserver_is_a_timeout() {
    let dead = UdpSocket::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let ibex = start(dead, &format!("{FAST}  hold timeout 30s\n"), "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0");
    ibex.wait_state("s1", "- 0 32", 3);
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS timeout status). {LEFT}"), 2);
}

/// A.t12b: two servers on one name with one address: the first takes it, the second has
/// none and stays in maintenance, silently.
#[test]
fn t12b_two_servers_one_address() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", "  server s1 a1.test:80 resolvers r\n  server s2 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    thread::sleep(Duration::from_millis(1200));
    assert_eq!(ibex.state("s2").0, "- 0 32");
    assert!(!ibex.log().iter().any(|l| l.contains("l/s2")), "{:?}", ibex.log());
    // One resolution for both.
    assert!(dns.queries().len() <= 3, "{:?}", dns.queries());
}

/// A.t12c: `resolve-opts allow-dup-ip` shares it; the second server's line says `DNS cache`.
#[test]
fn t12c_allow_dup_ip_shares_the_address() {
    let dns = FakeDns::start();
    let ibex = start(
        dns.addr,
        "",
        "  server s1 a1.test:80 resolvers r resolve-opts allow-dup-ip\n  server s2 a1.test:80 resolvers r resolve-opts allow-dup-ip\n",
        "",
    );
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.wait_state("s2", "10.0.0.1 2 0", 3);
    ibex.wait_log(UP, 2);
    ibex.wait_log("l/s2: IP changed from '(none)' to '10.0.0.1' by 'DNS cache'.", 2);
    ibex.wait_log("Server l/s2 administratively READY thanks to valid DNS answer.", 2);
}

/// A.t19: `resolve-net` picks the address in the network; F7: a server keeps its address
/// while it is still in the answer, whatever the order.
#[test]
fn t19_resolve_net_picks_the_network_and_the_current_address_stays() {
    let dns = FakeDns::start();
    let ibex = start(
        dns.addr,
        "  timeout resolve 300ms\n",
        "  server s1 multi.test:80 resolvers r resolve-net 10.0.0.2/32\n  server s2 multi.test:80 resolvers r resolve-prefer ipv4\n",
        "",
    );
    ibex.wait_state("s1", "10.0.0.2 2 0", 3);
    // s2's pick starts after the item s1 took (`r_res->next`): 10.0.0.3, as HAProxy (run
    // 2026-10-25 on this configuration).
    ibex.wait_state("s2", "10.0.0.3 2 0", 3);
    dns.set("multi.test", Zone::A([3, 1, 2].map(|o| Ipv4Addr::new(10, 0, 0, o)).to_vec()));
    thread::sleep(Duration::from_millis(1000));
    assert_eq!(ibex.state("s1").0, "10.0.0.2 2 0");
    assert_eq!(ibex.state("s2").0, "10.0.0.3 2 0");
    assert_eq!(ibex.log().iter().filter(|l| l.starts_with("l/s2: IP changed")).count(), 1, "{:?}", ibex.log());
}

/// A.t18 and §2.8.2: `dns-accept-family auto`. On a host with no IPv6 route (`HAProxy`'s probe,
/// a UDP `connect` to `2001::`), only A is asked, whatever `resolve-prefer` says.
#[test]
fn t18_auto_families_ask_aaaa_only_with_an_ipv6_route() {
    let v6 = UdpSocket::bind("[::]:0").and_then(|s| s.connect("[2001::]:53")).is_ok();
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", "  server s1 a1.test:80 resolvers r resolve-prefer ipv6\n", "");
    if v6 {
        // AAAA first (NODATA here), then A at once.
        ibex.wait_state("s1", "10.0.0.1 2 0", 3);
        let q = dns.queries();
        assert!(q[0].qtype == 28 && q[1].qtype == 1 && q[0].id == q[1].id, "{q:?}");
    } else {
        ibex.wait_state("s1", "10.0.0.1 2 0", 3);
        thread::sleep(Duration::from_millis(1100));
        let q = dns.queries();
        assert!(q.iter().all(|q| q.qtype == 1), "{q:?}");
    }
}

/// `show stat` says `MAINT (resolution)` with an empty address while the name has none.
#[test]
fn show_stat_follows_the_resolution() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::Nx);
    let ibex = start(dns.addr, FAST, "  server s1 a1.test:80 resolvers r\n", "");
    let row = |ibex: &Ibex| {
        let stat = ibex.cli("show stat");
        let mut lines = stat.lines();
        let header: Vec<String> = lines.next().expect("header").trim_start_matches("# ").split(',').map(str::to_string).collect();
        let col = |n: &str| header.iter().position(|c| c == n).expect("column");
        let row: Vec<&str> = lines.find(|l| l.starts_with("l,s1,")).expect("row").split(',').collect();
        (row[col("status")].to_string(), row[col("addr")].to_string())
    };
    assert_eq!(row(&ibex), ("MAINT (resolution)".to_string(), String::new()));
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    assert_eq!(row(&ibex), ("no check".to_string(), "10.0.0.1:80".to_string()));
}

/// `ibex -c` on `cfg`: whether it passed, and stderr.
fn check(cfg: &str) -> (bool, String) {
    let f = NamedTempFile::new().expect("tmp");
    std::fs::write(f.path(), cfg).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The parser: an unknown section is `HAProxy`'s alert; `default-server resolvers` is
/// inherited; a SRV name stays refused (T487).
#[test]
fn the_server_keyword_is_checked() {
    let base = "resolvers r\n  nameserver ns1 127.0.0.1:53\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nlisten l\n  bind 127.0.0.1:0\n";
    let (ok, err) = check(&format!("{base}  server s1 a1.test:80 resolvers nosuch\n"));
    assert!(!ok && err.contains("proxy 'l', server 's1': unable to find required resolvers 'nosuch'"), "{err}");
    let (ok, err) = check(&format!("{base}  default-server resolvers r\n  server s1 a1.test:80\n"));
    assert!(ok, "{err}");
    let (ok, err) = check(&format!("{base}  server s1 a1.test:80 resolvers r init-addr libc\n"));
    assert!(!ok && err.contains("could not resolve address 'a1.test'"), "{err}");
    let (ok, err) = check(&format!("{base}  server s1 _http._tcp.a.test resolvers r\n"));
    assert!(!ok && err.contains("DNS SRV record name"), "{err}");
}

/// F14, A.t16: a check that ends in a layer-4 timeout asks for a resolution at once (the
/// server may have moved), but only when the last one is older than `hold valid`.
#[test]
fn a_layer4_timeout_triggers_a_resolution_after_hold_valid() {
    let run = |hold_valid: &str| {
        let dns = FakeDns::start();
        // 192.0.2.1 (TEST-NET-1) answers nothing: every check times out.
        dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(192, 0, 2, 1)]));
        let _ibex = start(
            dns.addr,
            &format!("  timeout resolve 10s\n  hold valid {hold_valid}\n"),
            "  timeout check 100ms\n  server s1 a1.test:80 resolvers r check inter 300ms\n",
            "",
        );
        thread::sleep(Duration::from_millis(2000));
        dns.queries().len()
    };
    // Measured on HAProxy (A.t16): `hold valid` 10 s, no query but the first.
    assert_eq!(run("10s"), 1);
    assert!(run("100ms") >= 3, "the timeouts asked for no resolution");
}

/// T490: a reload keeps the address the resolver gave. The old process's `show servers
/// state` is the new one's server-state file; the server's default `init-addr` is
/// `last,libc,none`, so it starts on the old address, up, instead of in maintenance until
/// the first answer, and moves when an answer differs. `HAProxy` 3.5-dev8, same file:
/// `10.0.0.9 2 0` at start with the nameserver silent or answering NX (held), and
/// `b/s1: IP changed from '10.0.0.9' to '10.0.0.2' by 'r/ns1'.` once it answers 10.0.0.2.
#[test]
fn a_reload_keeps_the_resolved_address() {
    let dns = FakeDns::start();
    let servers = "  server s1 a1.test:80 resolvers r\n";
    let old = start(dns.addr, "", servers, "");
    old.wait_state("s1", "10.0.0.1 2 0", 3);
    let dir = tempfile::tempdir().expect("tmpdir");
    let file = dir.path().join("state");
    std::fs::write(&file, old.cli("show servers state")).expect("write the state file");
    drop(old);
    dns.set("a1.test", Zone::Silent);
    let global = format!("  server-state-file {}\n", file.display());
    let new = start(dns.addr, "", &format!("  load-server-state-from-file global\n{servers}"), &global);
    assert_eq!(new.state("s1"), ("10.0.0.1 2 0".to_string(), "a1.test".to_string()));
    assert!(!new.stderr().iter().any(|l| l.contains("could not resolve")), "{:?}", new.stderr());
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 2)]));
    new.wait_state("s1", "10.0.0.2 2 0", 5);
    new.wait_log("l/s1: IP changed from '10.0.0.1' to '10.0.0.2' by 'r/ns1'.", 2);
}
