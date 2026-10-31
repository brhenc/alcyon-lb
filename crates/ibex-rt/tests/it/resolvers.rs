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
use std::fmt::Write as _;
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
    /// TC over UDP (header and question only), the full answer over TCP.
    Truncated(Vec<Ipv4Addr>),
    /// TC on both transports.
    AlwaysTruncated,
    /// TC over UDP, then over TCP a frame of one byte (shorter than a DNS header id).
    ShortTcpFrame,
    /// This many A records (10.x.y.z), whatever the transport.
    Many(usize),
    /// One AAAA record, whatever the type asked.
    Aaaa(std::net::Ipv6Addr),
    /// A records to an A query, AAAA records to an AAAA query (T489); either may be empty
    /// (NODATA).
    Dual(Vec<Ipv4Addr>, Vec<std::net::Ipv6Addr>),
    /// SRV records `(priority, weight, port, target)` and additional A records
    /// `(owner, address)` (T487); an SRV query only, NODATA for the others.
    Srv(Vec<(u16, u16, u16, String)>, Vec<(String, Ipv4Addr)>),
    /// An SRV record of the name asked (to `t1.test:80`), then this A record to an A query:
    /// an answer record that is no address.
    SrvThenA(Ipv4Addr),
}

/// An SRV zone whose additional records are the targets' addresses (`ar`) or none.
fn srv_zone(recs: &[(u16, u16, &str, Option<[u8; 4]>)]) -> Zone {
    Zone::Srv(
        recs.iter().map(|&(w, p, t, _)| (10, w, p, t.to_string())).collect(),
        recs.iter().filter_map(|&(_, _, t, ip)| ip.map(|ip| (t.to_string(), Ipv4Addr::from(ip)))).collect(),
    )
}

/// `name` in DNS wire form, uncompressed.
fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for l in name.split('.').filter(|l| !l.is_empty()) {
        out.push(u8::try_from(l.len()).expect("label"));
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    out
}

/// One query the fake nameserver saw.
#[derive(Clone, Debug)]
struct Query {
    at: Instant,
    qtype: u16,
    name: String,
    id: u16,
    /// Asked over TCP.
    tcp: bool,
    /// The OPT record's payload size, 0 without one.
    edns: u16,
}

struct FakeDns {
    addr: SocketAddr,
    zone: Arc<Mutex<HashMap<String, Zone>>>,
    log: Arc<Mutex<Vec<Query>>>,
    stop: Arc<AtomicBool>,
    /// TCP connections accepted.
    tcp_conns: Arc<AtomicUsize>,
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
        // The same port over UDP and TCP.
        let (sock, tcp) = loop {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the fake nameserver");
            if let Ok(t) = TcpListener::bind(sock.local_addr().expect("addr")) {
                break (sock, t);
            }
        };
        sock.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");
        tcp.set_nonblocking(true).expect("nonblocking");
        let addr = sock.local_addr().expect("addr");
        let zone = Arc::new(Mutex::new(base_zone()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let tcp_conns = Arc::new(AtomicUsize::new(0));
        let (z, l, s) = (Arc::clone(&zone), Arc::clone(&log), Arc::clone(&stop));
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while !s.load(Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
                let Some((q, qend)) = parse_query(&buf[..n], false) else { continue };
                let answer = z.lock().expect("zone").get(&q.name).cloned().unwrap_or(Zone::Nx);
                l.lock().expect("log").push(q.clone());
                if let Some(reply) = build_reply(&buf[..qend], &answer, false) {
                    let _ = sock.send_to(&reply, from);
                }
            }
        });
        let (z, l, s, c) = (Arc::clone(&zone), Arc::clone(&log), Arc::clone(&stop), Arc::clone(&tcp_conns));
        thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let Ok((mut conn, _)) = tcp.accept() else {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                c.fetch_add(1, Ordering::Relaxed);
                let (z, l, s) = (Arc::clone(&z), Arc::clone(&l), Arc::clone(&s));
                thread::spawn(move || {
                    conn.set_nonblocking(false).expect("blocking");
                    conn.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");
                    while !s.load(Ordering::Relaxed) {
                        let mut len = [0u8; 2];
                        match conn.read_exact(&mut len) {
                            Ok(()) => {}
                            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                            Err(_) => return,
                        }
                        let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
                        conn.set_read_timeout(None).expect("timeout");
                        if conn.read_exact(&mut msg).is_err() {
                            return;
                        }
                        conn.set_read_timeout(Some(Duration::from_millis(50))).expect("timeout");
                        let Some((q, qend)) = parse_query(&msg, true) else { continue };
                        let answer = z.lock().expect("zone").get(&q.name).cloned().unwrap_or(Zone::Nx);
                        l.lock().expect("log").push(q);
                        if let Some(reply) = build_reply(&msg[..qend], &answer, true) {
                            let mut out = u16::try_from(reply.len()).expect("size").to_be_bytes().to_vec();
                            out.extend_from_slice(&reply);
                            if conn.write_all(&out).is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        Self { addr, zone, log, stop, tcp_conns }
    }

    fn set(&self, name: &str, z: Zone) {
        self.zone.lock().expect("zone").insert(name.to_string(), z);
    }

    fn queries(&self) -> Vec<Query> {
        self.log.lock().expect("log").clone()
    }
}

/// The question of a query, and where it ends.
fn parse_query(b: &[u8], tcp: bool) -> Option<(Query, usize)> {
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
    Some((Query { at: Instant::now(), qtype, name: labels.join("."), id, tcp, edns }, qend))
}

fn build_reply(question: &[u8], z: &Zone, tcp: bool) -> Option<Vec<u8>> {
    let truncated = match z {
        Zone::Truncated(_) | Zone::ShortTcpFrame => !tcp,
        Zone::AlwaysTruncated => true,
        _ => false,
    };
    if matches!(z, Zone::ShortTcpFrame) && tcp {
        return Some(vec![0xff]);
    }
    let rcode = match z {
        Zone::Silent => return None,
        Zone::Nx => 3,
        Zone::Refused => 5,
        Zone::ServFail => 2,
        Zone::A(_) | Zone::NoData | Zone::Truncated(_) | Zone::AlwaysTruncated | Zone::ShortTcpFrame | Zone::Many(_) | Zone::Aaaa(_) | Zone::Dual(..) | Zone::Srv(..) | Zone::SrvThenA(_) => 0,
    };
    let many: Vec<Ipv4Addr>;
    let ips: &[Ipv4Addr] = match z {
        Zone::A(v) => v,
        Zone::Truncated(v) if tcp => v,
        Zone::Dual(v, _) => v,
        Zone::Many(n) => {
            many = (0..*n).map(|i| Ipv4Addr::new(10, u8::try_from(i >> 16).expect("octet"), u8::try_from((i >> 8) & 255).expect("octet"), u8::try_from(i & 255).expect("octet"))).collect();
            &many
        }
        _ => &[],
    };
    let qtype = u16::from_be_bytes([question[question.len() - 4], question[question.len() - 3]]);
    // An A query is answered with the A records; an AAAA one with nothing (NODATA).
    let ips = if qtype == 1 { ips } else { &[] };
    let v6: Vec<std::net::Ipv6Addr> = match z {
        Zone::Aaaa(v6) => vec![*v6],
        Zone::Dual(_, v6) if qtype == 28 => v6.clone(),
        _ => Vec::new(),
    };
    if let Zone::Srv(recs, ar) = z {
        let (recs, ar): (&[_], &[_]) = if qtype == 33 { (recs, ar) } else { (&[], &[]) };
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&question[..2]);
        r.extend_from_slice(&[0x81, 0x80, 0, 1]);
        r.extend_from_slice(&u16::try_from(recs.len()).expect("count").to_be_bytes());
        r.extend_from_slice(&[0, 0]);
        r.extend_from_slice(&u16::try_from(ar.len()).expect("count").to_be_bytes());
        r.extend_from_slice(&question[12..]);
        for (prio, weight, port, target) in recs {
            let t = wire_name(target);
            r.extend_from_slice(&[0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 1, 0x2c]);
            r.extend_from_slice(&u16::try_from(6 + t.len()).expect("len").to_be_bytes());
            for v in [prio, weight, port] {
                r.extend_from_slice(&v.to_be_bytes());
            }
            r.extend_from_slice(&t);
        }
        for (owner, ip) in ar {
            r.extend_from_slice(&wire_name(owner));
            r.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
            r.extend_from_slice(&ip.octets());
        }
        return Some(r);
    }
    if let Zone::SrvThenA(ip) = z {
        let t = wire_name("t1.test");
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&question[..2]);
        r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, if qtype == 1 { 2 } else { 1 }, 0, 0, 0, 0]);
        r.extend_from_slice(&question[12..]);
        r.extend_from_slice(&[0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 1, 0x2c]);
        r.extend_from_slice(&u16::try_from(6 + t.len()).expect("len").to_be_bytes());
        r.extend_from_slice(&[0, 10, 0, 10, 0, 80]);
        r.extend_from_slice(&t);
        if qtype == 1 {
            r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
            r.extend_from_slice(&ip.octets());
        }
        return Some(r);
    }
    let mut r = Vec::with_capacity(512);
    r.extend_from_slice(&question[..2]);
    r.extend_from_slice(&[0x81 | if truncated { 2 } else { 0 }, 0x80 | rcode, 0, 1]);
    r.extend_from_slice(&u16::try_from(ips.len() + v6.len()).expect("count").to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&question[12..]);
    for ip in ips {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    for v6 in v6 {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 1, 0x2c, 0, 16]);
        r.extend_from_slice(&v6.octets());
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
fn start(ns: impl std::fmt::Display, extra: &str, servers: &str, global: &str) -> Ibex {
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

    /// `srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_fqdn srv_port
    /// srvrecord` of `sv` in `show servers state`: the columns of design A.t11.
    fn srv_cols(&self, sv: &str) -> String {
        let out = self.cli("show servers state l");
        let f: Vec<&str> = out
            .lines()
            .map(|l| l.split(' ').collect::<Vec<_>>())
            .find(|f| f.get(3) == Some(&sv))
            .unwrap_or_else(|| panic!("no {sv} in {out:?}"));
        [4, 5, 6, 7, 8, 17, 18, 19].map(|i| f[i]).join(" ")
    }

    /// Waits up to `secs` for [`Self::srv_cols`] of `sv` to be `want`.
    fn wait_srv(&self, sv: &str, want: &str, secs: u64) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let got = self.srv_cols(sv);
            if got == want {
                return;
            }
            assert!(Instant::now() < deadline, "{sv} never reached '{want}', last '{got}'; log {:?}", self.log());
            thread::sleep(Duration::from_millis(20));
        }
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
    // The UP line is written just after the state changes: wait for it rather than count at once.
    let t0 = Instant::now();
    let mut n = 0;
    while t0.elapsed() < Duration::from_secs(3) {
        n = ibex.log().iter().filter(|l| *l == UP).count();
        if n >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(n, 2, "{:?}", ibex.log());
}

/// The server-state log (T404) does not write a second line for what the resolver already
/// reports: one "going DOWN for maintenance" on the log and on stderr, with the DNS cause.
#[test]
fn t4c_nx_maintenance_is_logged_once() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 500ms\n"), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    dns.set("a1.test", Zone::Nx);
    ibex.wait_state("s1", "- 0 32", 4);
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS NX status). {LEFT}"), 2);
    thread::sleep(Duration::from_millis(500));
    let n = |v: Vec<String>| v.iter().filter(|l| l.contains("going DOWN for maintenance")).count();
    assert_eq!(n(ibex.log()), 1, "{:?}", ibex.log());
    assert_eq!(n(ibex.stderr()), 1, "{:?}", ibex.stderr());
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

/// A.t7 (re-measured, T510): a nameserver nobody listens on (ICMP unreachable) is a timeout, but
/// the hold is counted from `last_valid`, which a resolution starts with at its creation: the
/// `init-addr` address keeps serving for the whole `hold timeout`, then the server goes down at
/// the first error after it (HAProxy: `hold timeout 30s` -> DOWN at 31.2 s, "(DNS timeout status)").
#[test]
fn t7_a_dead_nameserver_is_held_from_the_start() {
    let dead = UdpSocket::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let ibex = start(dead, &format!("{FAST}  hold timeout 1500ms\n"), "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    let t0 = Instant::now();
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0");
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0", "down before the hold ran out");
    ibex.wait_state("s1", "- 0 32", 4);
    assert!(t0.elapsed() >= Duration::from_millis(1500), "{:?}", t0.elapsed());
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS timeout status). {LEFT}"), 2);
}

/// T510: the same with `init-addr libc` (HAProxy: kept 30 s, "(DNS timeout status)").
#[test]
fn t7b_a_dead_nameserver_libc_init_addr_is_held() {
    let dead = UdpSocket::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let ibex = start(dead, &format!("{FAST}  hold timeout 1500ms\n"), "  server s1 localhost:80 resolvers r init-addr libc\n", "");
    let t0 = Instant::now();
    assert!(ibex.state("s1").0.ends_with(" 2 0"), "{:?}", ibex.state("s1"));
    thread::sleep(Duration::from_millis(1100));
    assert!(ibex.state("s1").0.ends_with(" 2 0"), "down before the hold ran out: {:?}", ibex.state("s1"));
    ibex.wait_state("s1", "- 0 32", 4);
    assert!(t0.elapsed() >= Duration::from_millis(1500), "{:?}", t0.elapsed());
}

/// T510: NX from the start with an `init-addr`: held `hold nx` from the creation, log
/// "(DNS NX status)" (HAProxy: DOWN at 31.2 s with `hold nx 30s`).
#[test]
fn t7c_nx_from_the_start_is_held_from_the_start() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 1500ms\n"), "  server s1 nx.test:80 resolvers r init-addr 10.9.9.9\n", "");
    let t0 = Instant::now();
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0");
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0", "down before the hold ran out");
    ibex.wait_state("s1", "- 0 32", 4);
    assert!(t0.elapsed() >= Duration::from_millis(1500), "{:?}", t0.elapsed());
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS NX status). {LEFT}"), 2);
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

/// T513: a server-state file line for a server whose name has no address yet, with the
/// operator's maintenance (33) or drain (40) under `SRV_ADMF_RMAINT`. Measured on `HAProxy`
/// 3.5-dev8: `- 0 33` and `- 0 40` at load, both `MAINT (resolution)` in `show stat`; once the
/// names resolve, `10.0.0.1 0 1` `MAINT` ("resolves again but remains in maintenance") and
/// `10.0.0.2 2 8` `DRAIN` ("is UP/DRAIN (resolves again)", "remains in forced drain mode").
/// Ibex dropped the kept state: `- 0 32` twice, then both UP/READY.
#[test]
fn a_state_file_keeps_the_operators_state_of_an_unresolved_server() {
    let dns = FakeDns::start();
    dns.set("b.test", Zone::Nx);
    dns.set("c.test", Zone::Nx);
    let mut state = NamedTempFile::new().expect("tmp");
    write!(
        state,
        "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight \
         srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state \
         srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl \
         srv_check_port srv_check_addr srv_agent_addr srv_agent_port\n\
         2 l 1 s1 - 0 33 1 1 1 1 0 0 0 0 0 0 b.test 80 - 0 0 - - 0\n\
         2 l 2 s2 - 0 40 1 1 1 1 0 0 0 0 0 0 c.test 80 - 0 0 - - 0\n"
    )
    .expect("write state");
    let ibex = start(
        dns.addr,
        &format!("{FAST}  hold nx 500ms\n"),
        "  load-server-state-from-file global\n  server s1 b.test:80 resolvers r init-addr none\n  server s2 c.test:80 resolvers r init-addr none\n",
        &format!("  server-state-file {}\n", state.path().display()),
    );
    let status = |ibex: &Ibex, sv: &str| {
        let stat = ibex.cli("show stat");
        let mut lines = stat.lines();
        let header: Vec<String> = lines.next().expect("header").trim_start_matches("# ").split(',').map(str::to_string).collect();
        let col = header.iter().position(|c| c == "status").expect("column");
        lines.find(|l| l.starts_with(&format!("l,{sv},"))).expect("row").split(',').nth(col).expect("status").to_string()
    };
    assert_eq!(ibex.state("s1").0, "- 0 33");
    assert_eq!(ibex.state("s2").0, "- 0 40");
    assert_eq!((status(&ibex, "s1"), status(&ibex, "s2")), ("MAINT (resolution)".to_string(), "MAINT (resolution)".to_string()));
    dns.set("b.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    dns.set("c.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 2)]));
    ibex.wait_state("s1", "10.0.0.1 0 1", 3);
    ibex.wait_state("s2", "10.0.0.2 2 8", 3);
    assert_eq!((status(&ibex, "s1"), status(&ibex, "s2")), ("MAINT".to_string(), "DRAIN".to_string()));
    ibex.wait_log("Server l/s1 ('b.test') resolves again but remains in maintenance.", 2);
    ibex.wait_log("Server l/s2 ('c.test') is UP/DRAIN (resolves again).", 2);
    ibex.wait_log("Server l/s2 remains in forced drain mode.", 2);
}

/// T522, 3.5-dev8: an unresolved server (`init-addr none`) whose state-file line has
/// `srv_op_state 0` is stopped by the file before `HAProxy` puts it in resolution maintenance, so
/// stderr says `Server l/s1 is DOWN, changed from server-state after a reload. 0 active and 0
/// backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.` for any admin
/// state of the line (0, 32, 33, 40); the log targets, not up yet, get nothing. Ibex said nothing.
#[test]
fn a_state_file_stopping_an_unresolved_server_is_said_on_stderr() {
    for admin in ["0", "32", "33", "40"] {
        let dns = FakeDns::start();
        dns.set("b.test", Zone::Nx);
        let mut state = NamedTempFile::new().expect("tmp");
        write!(
            state,
            "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight \
             srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state \
             srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl \
             srv_check_port srv_check_addr srv_agent_addr srv_agent_port\n\
             2 l 1 s1 - 0 {admin} 1 1 1 1 0 0 0 0 0 0 b.test 80 - 0 0 - - 0\n"
        )
        .expect("write state");
        let ibex = start(
            dns.addr,
            &format!("{FAST}  hold nx 500ms\n"),
            "  load-server-state-from-file global\n  server s1 b.test:80 resolvers r init-addr none\n",
            &format!("  server-state-file {}\n", state.path().display()),
        );
        let said = format!(
            "[WARNING]  ({}) : Server l/s1 is DOWN, changed from server-state after a reload. 0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.",
            ibex.child.id()
        );
        assert!(ibex.stderr().contains(&said), "admin {admin}: no {said:?} in {:?}", ibex.stderr());
        assert!(!ibex.log().iter().any(|l| l.contains("changed from server-state")), "admin {admin}: {:?}", ibex.log());
    }
}

/// `ibex -c` on `cfg`: whether it passed, and stderr.
fn check(cfg: &str) -> (bool, String) {
    let f = NamedTempFile::new().expect("tmp");
    std::fs::write(f.path(), cfg).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run ibex -c");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The parser: an unknown section is `HAProxy`'s alert; `default-server resolvers` is
/// inherited; an SRV name is accepted with `resolvers`, and libc is no method for it (T487).
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
    assert!(ok, "{err}");
    let (ok, err) = check(&format!("{base}  server s1 _http._tcp.a.test resolvers r init-addr libc\n"));
    assert!(!ok && err.contains("no method found to resolve address '_http._tcp.a.test'"), "{err}");
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

/// The text of `show resolvers` for one nameserver, every counter 0 (`HAProxy` 3.5-dev8, measured).
fn zeros(name: &str) -> String {
    let mut s = format!(" nameserver {name}:\n");
    for (c, pad) in COUNTER_PADS {
        let _ = writeln!(s, "  {c}:{pad}0");
    }
    s
}

/// The 16 counters of `show resolvers` in order, with the spaces after the colon.
const COUNTER_PADS: [(&str, &str); 16] = [
    ("sent", "         "),
    ("snd_error", "    "),
    ("valid", "        "),
    ("update", "       "),
    ("cname", "        "),
    ("cname_error", "  "),
    ("any_err", "      "),
    ("nx", "           "),
    ("timeout", "      "),
    ("refused", "      "),
    ("other", "        "),
    ("invalid", "      "),
    ("too_big", "      "),
    ("truncated", "    "),
    ("tcp_fallback", " "),
    ("outdated", "     "),
];

/// The counters of nameserver `ns` of section `sec` in `show resolvers`.
fn counters(ibex: &Ibex, sec: &str, ns: &str) -> HashMap<String, u64> {
    let out = ibex.cli(&format!("show resolvers {sec}"));
    let mut lines = out.lines().skip_while(|l| *l != format!(" nameserver {ns}:")).skip(1);
    let mut m = HashMap::new();
    for l in lines.by_ref().take_while(|l| l.starts_with("  ")) {
        let (k, v) = l.trim().split_once(':').expect("name: value");
        m.insert(k.to_string(), v.trim().parse().expect("a number"));
    }
    assert_eq!(m.len(), 16, "{out}");
    m
}

/// T485, measured on `HAProxy` 3.5-dev8: the section header, each nameserver and its 16 counters
/// (`name:` padded to 14 columns), the blank line that ends a CLI answer and nothing between
/// sections. A section no server uses is listed; an unknown one is an error.
#[test]
fn show_resolvers_lists_every_section_byte_for_byte() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  nameserver ns2 127.0.0.1:9\nresolvers empty\n", "", "");
    let want = format!("Resolvers section r\n{}{}Resolvers section empty\n\n", zeros("ns1"), zeros("ns2"));
    assert_eq!(ibex.cli("show resolvers"), want);
    assert_eq!(ibex.cli("show resolvers r"), format!("Resolvers section r\n{}{}\n", zeros("ns1"), zeros("ns2")));
    assert_eq!(ibex.cli("show resolvers nosuch"), "Can't find that resolvers section\n\n");
}

/// A.t5: every query sent is counted by its nameserver, every valid answer too, and a changed
/// address once as `update`; a silent nameserver counts `sent` and nothing else (`timeout`
/// stays 0 on `HAProxy`).
#[test]
fn show_resolvers_counts_sent_valid_update() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold timeout 1s\n"), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    dns.set("a1.test", Zone::Silent);
    ibex.wait_state("s1", "- 0 32", 4);
    let c = counters(&ibex, "r", "ns1");
    assert!(c["valid"] >= 1 && c["sent"] > c["valid"], "{c:?}");
    assert_eq!(c["update"], 1, "{c:?}");
    for k in ["snd_error", "cname", "cname_error", "any_err", "nx", "timeout", "refused", "other", "invalid", "too_big", "truncated", "tcp_fallback", "outdated"] {
        assert_eq!(c[k], 0, "{k} in {c:?}");
    }
}

/// A.t10: ns1 says NXDOMAIN, ns2 answers: `nx` on ns1, `valid` and `update` on ns2, and the
/// address is ns2's.
#[test]
fn show_resolvers_counts_each_nameserver_apart() {
    let (dns1, dns2) = (FakeDns::start(), FakeDns::start());
    dns1.set("a1.test", Zone::Nx);
    dns2.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 9)]));
    let ibex = start(dns1.addr, &format!("{FAST}  nameserver ns2 {}\n", dns2.addr), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.9 2 0", 3);
    let (c1, c2) = (counters(&ibex, "r", "ns1"), counters(&ibex, "r", "ns2"));
    // ns1's NX can land after ns2's answer ended the resolution: then it counts `outdated`.
    assert!(c1["nx"] + c1["outdated"] >= 1 && c1["valid"] == 0 && c1["update"] == 0, "{c1:?}");
    assert!(c2["valid"] >= 1 && c2["update"] == 1 && c2["nx"] == 0, "{c2:?}");
    assert!(c1["sent"] >= 1 && c2["sent"] >= 1);
}

/// REFUSED, NODATA and SERVFAIL go to `refused`, `any_err` and `other`.
#[test]
fn show_resolvers_counts_error_classes() {
    for (z, key) in [(Zone::Refused, "refused"), (Zone::NoData, "any_err"), (Zone::ServFail, "other")] {
        let dns = FakeDns::start();
        dns.set("a1.test", z);
        let ibex = start(dns.addr, FAST, "  server s1 a1.test:80 resolvers r\n", "");
        let deadline = Instant::now() + Duration::from_secs(3);
        while counters(&ibex, "r", "ns1")[key] == 0 {
            assert!(Instant::now() < deadline, "{key} stays 0: {:?}", counters(&ibex, "r", "ns1"));
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// A datagram the resolver cannot place: an id nobody waits for is `outdated`, a short one
/// `invalid`... only from the configured nameserver (the socket is connected to it).
#[test]
fn show_resolvers_counts_outdated_and_too_big() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    sock.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let ibex = start(sock.local_addr().expect("addr"), "  accepted_payload_size 512\n", "  server s1 a1.test:80 resolvers r\n", "");
    let mut buf = [0u8; 600];
    let (_, from) = sock.recv_from(&mut buf).expect("a query");
    // An id that is not the query's: outdated.
    let q = u16::from_be_bytes([buf[0], buf[1]]);
    let mut reply = vec![0u8; 12];
    reply[..2].copy_from_slice(&q.wrapping_add(1).to_be_bytes());
    sock.send_to(&reply, from).expect("send");
    // More than accepted_payload_size: too_big.
    sock.send_to(&[0u8; 600], from).expect("send");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let c = counters(&ibex, "r", "ns1");
        if c["outdated"] == 1 && c["too_big"] == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "{c:?}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// `haproxy_resolver_*` (`rslv_promex_*`, `resolvers.c:4282`): one gauge per counter and
/// nameserver, labelled `resolver` and `nameserver`, with the descriptions of `resolv_stats`.
#[test]
fn the_exporter_has_the_resolver_metrics() {
    let dns = FakeDns::start();
    let ibex = start(
        dns.addr,
        "",
        "  http-request use-service prometheus-exporter if { path /metrics }\n  server s1 a1.test:80 resolvers r\n",
        "",
    );
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    let scrape = |q: &str| {
        let mut c = TcpStream::connect(ibex.fe).expect("connect");
        c.write_all(format!("GET /metrics{q} HTTP/1.0\r\n\r\n").as_bytes()).expect("send");
        let mut s = String::new();
        let _ = c.read_to_string(&mut s);
        s
    };
    let all = scrape("?scope=resolvers");
    let metrics = [
        ("sent", "Sent"),
        ("send_error", "Send error"),
        ("valid", "Valid"),
        ("update", "Update"),
        ("cname", "CNAME"),
        ("cname_error", "CNAME error"),
        ("any_err", "Any errors"),
        ("nx", "NX"),
        ("timeout", "Timeout"),
        ("refused", "Refused"),
        ("other", "Other"),
        ("invalid", "Invalid"),
        ("too_big", "Too big"),
        ("truncated", "Truncated"),
        ("tcp_fallback", "TCP fallback"),
        ("outdated", "Outdated"),
    ];
    for (n, d) in metrics {
        let name = format!("haproxy_resolver_{n}");
        assert!(all.contains(&format!("# HELP {name} {d}\n# TYPE {name} gauge\n{name}{{resolver=\"r\",nameserver=\"ns1\"}} ")), "{name} in {all}");
    }
    assert!(!all.contains("haproxy_server_"), "{all}");
    let sent = all.lines().find(|l| l.starts_with("haproxy_resolver_sent{")).expect("sent");
    assert!(sent.rsplit(' ').next().expect("v").parse::<u64>().expect("n") >= 1, "{sent}");
    // `metrics=` filters like the others, and `scope=resolver` is HAProxy's module name.
    let one = scrape("?scope=resolver&metrics=haproxy_resolver_nx");
    assert!(one.contains("haproxy_resolver_nx{") && !one.contains("haproxy_resolver_sent"), "{one}");
}

// --- T486: `server-template` with a name (F11; A.t12, A.t12b, A.t12c) ---

/// A.t12: three slots on a three-address name take one address each (the first logs the
/// nameserver, the others `DNS cache`); when `10.0.0.2` leaves the answer its slot goes to
/// maintenance at that answer with `No IP for server ` (trailing space) and no hold, and the
/// other two keep theirs. One resolution serves the three slots.
#[test]
fn t12_template_slots_take_distinct_addresses_and_the_one_that_lost_its_address_goes_down() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", "  server-template srv 3 multi.test:80 resolvers r\n", "");
    for (sv, ip) in [("srv1", "10.0.0.1"), ("srv2", "10.0.0.2"), ("srv3", "10.0.0.3")] {
        ibex.wait_state(sv, &format!("{ip} 2 0"), 3);
        assert_eq!(ibex.state(sv).1, "multi.test");
    }
    ibex.wait_log("l/srv1: IP changed from '(none)' to '10.0.0.1' by 'r/ns1'.", 2);
    ibex.wait_log("l/srv2: IP changed from '(none)' to '10.0.0.2' by 'DNS cache'.", 2);
    ibex.wait_log("l/srv3: IP changed from '(none)' to '10.0.0.3' by 'DNS cache'.", 2);
    dns.set("multi.test", Zone::A([1, 3].map(|o| Ipv4Addr::new(10, 0, 0, o)).to_vec()));
    ibex.wait_state("srv2", "- 0 32", 3);
    assert_eq!(ibex.state("srv1").0, "10.0.0.1 2 0");
    assert_eq!(ibex.state("srv3").0, "10.0.0.3 2 0");
    assert!(
        ibex.log().iter().any(|l| l.starts_with("Server l/srv2 is going DOWN for maintenance (No IP for server ). 2 active and 0 backup servers left.")),
        "{:?}",
        ibex.log()
    );
    // One resolution for the three slots: one query per 300 ms, not three.
    let n = dns.queries().len();
    let secs = dns.queries().last().map_or(0.0, |q| q.at.duration_since(dns.queries()[0].at).as_secs_f64());
    assert!(n as f64 <= secs / 0.3 + 3.0, "{n} queries in {secs:.2} s");
}

/// A.t12b with a template of 2: one address, so the second slot has none and stays in
/// maintenance, silently; `allow-dup-ip` (A.t12c) gives it the same one, `DNS cache`.
#[test]
fn t12b_template_of_two_on_a_one_address_name() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", "  server-template s 2 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    thread::sleep(Duration::from_millis(1200));
    assert_eq!(ibex.state("s2").0, "- 0 32");
    assert!(!ibex.log().iter().any(|l| l.contains("l/s2")), "{:?}", ibex.log());

    let ibex = start(dns.addr, "", "  server-template s 2 a1.test:80 resolvers r resolve-opts allow-dup-ip\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.wait_state("s2", "10.0.0.1 2 0", 3);
    ibex.wait_log(UP, 2);
    ibex.wait_log("l/s2: IP changed from '(none)' to '10.0.0.1' by 'DNS cache'.", 2);
}

/// Ten slots on a three-address name: three take an address each, the other seven stay in
/// maintenance with `-`, and nothing else is logged for them.
#[test]
fn ten_slots_on_three_addresses() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", "  server-template s 10 multi.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.wait_state("s3", "10.0.0.3 2 0", 3);
    thread::sleep(Duration::from_millis(800));
    for n in 4..=10 {
        assert_eq!(ibex.state(&format!("s{n}")).0, "- 0 32", "s{n}");
    }
    assert_eq!(ibex.log().iter().filter(|l| l.contains("IP changed")).count(), 3, "{:?}", ibex.log());
}

/// Waits until counter `key` of `ns1` satisfies `ok`.
fn wait_counter(ibex: &Ibex, key: &str, secs: u64, ok: impl Fn(u64) -> bool) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let v = counters(ibex, "r", "ns1")[key];
        if ok(v) {
            return v;
        }
        assert!(Instant::now() < deadline, "{key} stays {v}: {:?}", counters(ibex, "r", "ns1"));
        thread::sleep(Duration::from_millis(20));
    }
}

/// A.t9 (T488): a truncated UDP answer is asked again over TCP, to the same nameserver, at
/// once, numbered by the connection: 1, 2, ... (T489, oracle case t487/ttc.json: UDP ids
/// random, TCP `id=1`, `id=2`, `id=3` on one connection); the counters `truncated` and `tcp_fallback` move together, `sent`
/// counts both transports, and one TCP connection serves every query.
#[test]
fn t9_a_truncated_udp_answer_is_asked_again_over_tcp() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::Truncated(vec![Ipv4Addr::new(10, 0, 0, 7)]));
    let ibex = start(dns.addr, FAST, "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.7 2 0", 3);
    wait_counter(&ibex, "valid", 3, |v| v >= 2);
    let q = dns.queries();
    let (udp, tcp): (Vec<_>, Vec<_>) = q.iter().partition(|q| !q.tcp);
    assert!(!tcp.is_empty(), "{q:?}");
    assert!(!q[0].tcp, "{q:?}");
    assert!(q[1].tcp, "over TCP: {q:?}");
    let tcp_ids: Vec<u16> = tcp.iter().map(|q| q.id).collect();
    assert_eq!(tcp_ids, (1..=u16::try_from(tcp.len()).expect("few")).collect::<Vec<_>>(), "TCP ids count from 1: {q:?}");
    assert!(q[1].at.duration_since(q[0].at) < Duration::from_millis(100), "at once: {q:?}");
    assert!(tcp.iter().all(|q| q.edns == 512), "{q:?}");
    assert_eq!(dns.tcp_conns.load(Ordering::Relaxed), 1);
    let c = counters(&ibex, "r", "ns1");
    assert_eq!(c["truncated"], c["tcp_fallback"], "{c:?}");
    assert!(c["tcp_fallback"] >= 2, "{c:?}");
    assert_eq!(c["sent"], (udp.len() + tcp.len()) as u64, "{c:?} {q:?}");
    assert_eq!(c["valid"], tcp.len() as u64, "{c:?}");
    // The truncated UDP answer used no try: nothing timed out or was held.
    assert_eq!(c["other"], 0, "{c:?}");
}

/// A.t15 (T488): `accepted_payload_size 4096` is announced on both transports.
#[test]
fn t15_the_payload_size_is_announced_over_udp_and_tcp() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::Truncated(vec![Ipv4Addr::new(10, 0, 0, 7)]));
    let ibex = start(dns.addr, &format!("{FAST}  accepted_payload_size 4096\n"), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.7 2 0", 3);
    let q = dns.queries();
    assert!(q.iter().any(|q| q.tcp) && q.iter().all(|q| q.edns == 4096), "{q:?}");
}

/// A.t15c (T488): `tcp@` sends everything over TCP, on one connection, and no datagram.
#[test]
fn t15c_a_tcp_nameserver_is_asked_over_tcp_only() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    let ibex = start(format!("tcp@{}", dns.addr), FAST, "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    wait_counter(&ibex, "valid", 3, |v| v >= 3);
    let q = dns.queries();
    assert!(q.iter().all(|q| q.tcp && q.edns == 512), "{q:?}");
    assert_eq!(dns.tcp_conns.load(Ordering::Relaxed), 1);
    // T489, oracle case t489/tcpids.json: `id=1`, `id=2`, ... on the connection.
    let ids: Vec<u16> = q.iter().map(|q| q.id).collect();
    assert_eq!(ids, (1..=u16::try_from(q.len()).expect("few")).collect::<Vec<_>>(), "{q:?}");
    let c = counters(&ibex, "r", "ns1");
    assert_eq!((c["tcp_fallback"], c["truncated"], c["snd_error"]), (0, 0, 0), "{c:?}");
}

/// T513 (defect E of T484): two nameservers on one address, `tcp@A` and `A`, are two
/// nameservers. `HAProxy` 3.5-dev8 asks both every time (`timeout resolve 1s`, 3.5 s: ns1
/// `sent 4 valid 1 outdated 3`, ns2 `sent 4 valid 3 update 1 outdated 1`); Ibex sent one
/// query and counted it on ns1.
#[test]
fn two_nameservers_on_one_address_are_both_asked() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    let ibex = start(format!("tcp@{}", dns.addr), &format!("{FAST}  nameserver ns2 {}\n", dns.addr), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    wait_counter(&ibex, "sent", 3, |v| v >= 3);
    thread::sleep(Duration::from_millis(100));
    let (c1, c2) = (counters(&ibex, "r", "ns1"), counters(&ibex, "r", "ns2"));
    assert!(c2["sent"] >= 2, "ns2 is asked too: {c2:?}");
    assert!(c1["sent"].abs_diff(c2["sent"]) <= 1, "{c1:?} {c2:?}");
    // Each answer is counted on the nameserver that gave it: the first one valid, the
    // other outdated.
    assert!(c1["valid"] + c1["outdated"] >= 2 && c2["valid"] + c2["outdated"] >= 2, "{c1:?} {c2:?}");
    assert_eq!(c1["update"] + c2["update"], 1, "{c1:?} {c2:?}");
    let q = dns.queries();
    assert!(q.iter().any(|q| q.tcp) && q.iter().any(|q| !q.tcp), "both transports: {q:?}");
}

/// A TCP answer of 4,000 records (about 64 KB, over `accepted_payload_size`) is taken whole.
#[test]
fn a_tcp_answer_of_4000_records_is_accepted() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::Many(4000));
    let ibex = start(format!("tcp@{}", dns.addr), FAST, "  server s1 a1.test:80 resolvers r\n", "");
    wait_counter(&ibex, "valid", 3, |v| v >= 1);
    assert!(ibex.state("s1").0.starts_with("10.0."), "{:?}", ibex.state("s1"));
    let c = counters(&ibex, "r", "ns1");
    assert_eq!((c["too_big"], c["invalid"], c["other"]), (0, 0, 0), "{c:?}");
}

/// A TCP port nobody listens on (measured on `HAProxy`): the queries count as `sent`, nothing
/// is an error, the resolution gets no answer.
#[test]
fn a_tcp_nameserver_that_refuses_connections_is_silent() {
    let dead = UdpSocket::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let ibex = start(format!("tcp@{dead}"), &format!("{FAST}  hold timeout 30s\n"), "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    wait_counter(&ibex, "sent", 4, |v| v >= 4);
    let c = counters(&ibex, "r", "ns1");
    assert_eq!((c["snd_error"], c["valid"], c["truncated"]), (0, 0, 0), "{c:?}");
}

/// `udp@`: a truncated answer is not asked again over TCP; it is `truncated`, then `Other`.
#[test]
fn a_udp_nameserver_has_no_tcp_fallback() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::Truncated(vec![Ipv4Addr::new(10, 0, 0, 7)]));
    let ibex = start(format!("udp@{}", dns.addr), FAST, "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    wait_counter(&ibex, "truncated", 3, |v| v >= 2);
    let c = counters(&ibex, "r", "ns1");
    assert_eq!((c["tcp_fallback"], c["valid"]), (0, 0), "{c:?}");
    assert!(dns.queries().iter().all(|q| !q.tcp), "{:?}", dns.queries());
    assert_eq!(dns.tcp_conns.load(Ordering::Relaxed), 0);
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0");
}

/// A truncated answer over TCP is `Other`: no further fallback, the server is not moved.
#[test]
fn a_truncated_tcp_answer_is_other() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::AlwaysTruncated);
    let ibex = start(dns.addr, FAST, "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    wait_counter(&ibex, "truncated", 3, |v| v >= 4);
    let c = counters(&ibex, "r", "ns1");
    assert!(c["tcp_fallback"] >= 2 && c["valid"] == 0, "{c:?}");
    assert_eq!(dns.tcp_conns.load(Ordering::Relaxed), 1);
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0");
}

/// T527: a TCP reply frame of one byte has no message id to match: dropped, counted nowhere
/// (`dns_session_io_handler` memcpy's the id and drops an unknown one; measured on
/// 3.5-dev8-885761-29 with a nameserver that answers a 1-byte frame: `sent` and `truncated`
/// grow, `invalid`, `outdated`, `timeout` and `valid` stay 0).
#[test]
fn a_one_byte_tcp_reply_frame_is_dropped_uncounted() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::ShortTcpFrame);
    let ibex = start(dns.addr, FAST, "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    wait_counter(&ibex, "tcp_fallback", 3, |v| v >= 2);
    let c = counters(&ibex, "r", "ns1");
    for k in ["invalid", "outdated", "valid", "other"] {
        assert_eq!(c[k], 0, "{k} in {c:?}");
    }
    assert_eq!(ibex.state("s1").0, "10.9.9.9 2 0");
}

/// Six names truncated at once share the one connection (four queries in flight at most, the
/// rest wait their turn) and every one is answered.
#[test]
fn many_queries_share_one_tcp_connection() {
    let dns = FakeDns::start();
    let mut servers = String::new();
    for i in 1..=6u8 {
        dns.set(&format!("n{i}.test"), Zone::Truncated(vec![Ipv4Addr::new(10, 0, 1, i)]));
        let _ = writeln!(servers, "  server s{i} n{i}.test:80 resolvers r");
    }
    let ibex = start(dns.addr, FAST, &servers, "");
    for i in 1..=6u8 {
        ibex.wait_state(&format!("s{i}"), &format!("10.0.1.{i} 2 0"), 3);
    }
    assert_eq!(dns.tcp_conns.load(Ordering::Relaxed), 1);
}

/// The connection is closed after 5 s without a query and opened again for the next one.
#[test]
fn an_idle_tcp_connection_is_closed_and_reopened() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::Truncated(vec![Ipv4Addr::new(10, 0, 0, 7)]));
    let ibex = start(dns.addr, "  timeout resolve 7s\n  timeout retry 1s\n", "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.7 2 0", 3);
    assert_eq!(dns.tcp_conns.load(Ordering::Relaxed), 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while dns.tcp_conns.load(Ordering::Relaxed) < 2 {
        assert!(Instant::now() < deadline, "no second connection");
        thread::sleep(Duration::from_millis(50));
    }
    wait_counter(&ibex, "valid", 3, |v| v >= 2);
}

// --- Covercheck (T484): the operator-visible paths no test above reached, each measured on
// `HAProxy` 3.5-dev8-885761-29 with the same configuration (2026-10-26). ---

/// A name is asked as it is written: `HAProxy` checks no character of a server's name
/// (`resolv_str_to_dn_label`), so `a!b.test` is sent and its answer taken (measured: `s1
/// 10.0.0.7 2 0`, "IP changed from '(none)' to '10.0.0.7'").
#[test]
fn a_name_is_asked_as_it_is_written() {
    let dns = FakeDns::start();
    dns.set("a!b.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 7)]));
    let ibex = start(dns.addr, "", "  server s1 a!b.test:80 resolvers r init-addr none\n", "");
    ibex.wait_state("s1", "10.0.0.7 2 0", 3);
    ibex.wait_log("l/s1: IP changed from '(none)' to '10.0.0.7' by 'r/ns1'.", 2);
    assert!(dns.queries().iter().all(|q| q.name == "a!b.test"), "{:?}", dns.queries());
}

/// A nameserver nobody listens on, three names asked at once: `HAProxy`'s socket is not
/// connected, so the ICMP unreachable a datagram draws fails no later send (measured: `sent:
/// 21  snd_error: 0` in 2.2 s); every query counts as sent.
#[test]
fn a_dead_nameserver_counts_every_query_sent() {
    let dead = UdpSocket::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let servers = "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n  server s2 a2.test:80 resolvers r init-addr 10.9.9.8\n  server s3 a3.test:80 resolvers r init-addr 10.9.9.7\n";
    let ibex = start(dead, &format!("{FAST}  hold timeout 30s\n"), servers, "");
    wait_counter(&ibex, "sent", 5, |v| v >= 12);
    let c = counters(&ibex, "r", "ns1");
    assert_eq!(c["snd_error"], 0, "{c:?}");
}

/// A `tcp@` nameserver on a multicast address: the kernel refuses the connect at once
/// (`ENETUNREACH`); the queries count as sent, the resolution times out (measured: `sent: 9`
/// in 3 s, "going DOWN for maintenance (DNS timeout status)" after `hold timeout`).
#[test]
fn a_tcp_nameserver_that_cannot_be_reached_is_a_timeout() {
    let ibex = start("tcp@224.0.0.1:53", &format!("{FAST}  hold timeout 1s\n"), "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    ibex.wait_state("s1", "- 0 32", 5);
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS timeout status). {LEFT}"), 2);
    let c = counters(&ibex, "r", "ns1");
    assert!(c["sent"] >= 4 && c["snd_error"] == 0, "{c:?}");
}

/// A listener whose accept queue is full (backlog 0, one connection waiting): the SYN goes
/// unanswered and the connect never completes. `HAProxy` counts each query sent when it is
/// queued for the connection (measured: `sent: 8` in 2.8 s, no connection accepted, DOWN with
/// "DNS timeout status").
#[test]
fn a_tcp_nameserver_that_never_accepts_counts_its_queries_sent() {
    use rustix::net::{AddressFamily, SocketType};
    let fd = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).expect("socket");
    rustix::net::bind_v4(&fd, &std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind");
    rustix::net::listen(&fd, 0).expect("listen");
    let listener = TcpListener::from(fd);
    let addr = listener.local_addr().expect("addr");
    let _filler = TcpStream::connect(addr).expect("fill the accept queue");
    let ibex = start(format!("tcp@{addr}"), &format!("{FAST}  hold timeout 1s\n"), "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    ibex.wait_state("s1", "- 0 32", 5);
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS timeout status). {LEFT}"), 2);
    let c = counters(&ibex, "r", "ns1");
    assert!(c["sent"] >= 4 && c["snd_error"] == 0, "{c:?}");
}

#[derive(Clone, Copy)]
enum TcpMode {
    /// Reads the query, closes (FIN).
    Fin,
    /// Closes with the query unread (RST).
    Rst,
    /// Answers `10.0.0.1` in two writes 100 ms apart, the first of 5 bytes.
    Split,
}

/// A TCP nameserver that behaves as `mode` says, and the connections it accepted.
fn tcp_ns(mode: TcpMode) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let conns = Arc::new(AtomicUsize::new(0));
    let n = Arc::clone(&conns);
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            n.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || loop {
                let mut len = [0u8; 2];
                if c.read_exact(&mut len).is_err() {
                    return;
                }
                if let TcpMode::Rst = mode {
                    // The query is left unread: closing sends a reset.
                    thread::sleep(Duration::from_millis(20));
                    return;
                }
                let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
                if c.read_exact(&mut msg).is_err() {
                    return;
                }
                if let TcpMode::Fin = mode {
                    return;
                }
                let Some((_, qend)) = parse_query(&msg, true) else { return };
                let reply = build_reply(&msg[..qend], &Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]), true).expect("reply");
                let mut out = u16::try_from(reply.len()).expect("size").to_be_bytes().to_vec();
                out.extend_from_slice(&reply);
                if c.write_all(&out[..5]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
                if c.write_all(&out[5..]).is_err() {
                    return;
                }
            });
        }
    });
    (addr, conns)
}

/// A TCP nameserver that closes, or resets, the connection after reading a query: each try
/// opens a new one, and the resolution times out (measured, both: 8 connections and `sent: 8`
/// in 2.8 s, DOWN with "DNS timeout status").
#[test]
fn a_tcp_nameserver_that_closes_or_resets_after_the_query_is_a_timeout() {
    for mode in [TcpMode::Fin, TcpMode::Rst] {
        let (addr, conns) = tcp_ns(mode);
        let ibex = start(format!("tcp@{addr}"), &format!("{FAST}  hold timeout 1s\n"), "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
        ibex.wait_state("s1", "- 0 32", 5);
        ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (DNS timeout status). {LEFT}"), 2);
        let c = counters(&ibex, "r", "ns1");
        assert!(c["sent"] >= 4 && c["snd_error"] == 0 && c["valid"] == 0, "{c:?}");
        assert!(conns.load(Ordering::Relaxed) >= 4, "{}", conns.load(Ordering::Relaxed));
    }
}

/// A TCP answer that comes in two segments is put together (measured: `10.0.0.1 2 0`).
#[test]
fn a_tcp_answer_in_two_segments_is_assembled() {
    let (addr, _) = tcp_ns(TcpMode::Split);
    let ibex = start(format!("tcp@{addr}"), FAST, "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.wait_log("l/s1: IP changed from '10.9.9.9' to '10.0.0.1' by 'r/ns1'.", 2);
}

/// F14: a layer-4 timeout asks again for its own server's name only (measured, 2 s: `a1.test`
/// asked 4 times, `b.test` once).
#[test]
fn a_layer4_timeout_triggers_only_its_own_resolution() {
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(192, 0, 2, 1)]));
    dns.set("b.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 9)]));
    let _ibex = start(
        dns.addr,
        "  timeout resolve 10s\n  hold valid 100ms\n",
        "  timeout check 100ms\n  server s1 a1.test:80 resolvers r check inter 300ms\n  server s2 b.test:80 resolvers r\n",
        "",
    );
    thread::sleep(Duration::from_millis(2000));
    let q = dns.queries();
    assert!(q.iter().filter(|q| q.name == "a1.test").count() >= 3, "{q:?}");
    assert_eq!(q.iter().filter(|q| q.name == "b.test").count(), 1, "{q:?}");
}

/// F7 scores: a server whose `init-addr` is in the answer keeps it (the current address breaks
/// the tie), and one whose address scores 15 (preferred family, its network, unused, current)
/// keeps it at once; neither logs a change (measured: `10.0.0.2 2 0`, `10.0.0.5 2 0`, no line).
#[test]
fn a_server_keeps_an_address_still_in_the_answer() {
    let dns = FakeDns::start();
    dns.set("multi2.test", Zone::A([4, 5, 6].map(|o| Ipv4Addr::new(10, 0, 0, o)).to_vec()));
    let ibex = start(
        dns.addr,
        "  timeout resolve 300ms\n",
        "  server s1 multi.test:80 resolvers r init-addr 10.0.0.2\n  server s2 multi2.test:80 resolvers r resolve-prefer ipv4 resolve-net 10.0.0.5/32 init-addr 10.0.0.5\n",
        "",
    );
    wait_counter(&ibex, "valid", 3, |v| v >= 4);
    assert_eq!(ibex.state("s1").0, "10.0.0.2 2 0");
    assert_eq!(ibex.state("s2").0, "10.0.0.5 2 0");
    assert!(!ibex.log().iter().any(|l| l.contains("IP changed")), "{:?}", ibex.log());
}

/// A valid answer with no address of a family in use (an AAAA record for an A query, on a
/// host with no IPv6 route): "No IP for server" (measured: `- 0 32`, "Server l/s1 is going
/// DOWN for maintenance (No IP for server ). 0 active ..."). With an IPv6 route the record
/// is an address, so the case does not exist there.
#[test]
fn an_answer_with_no_usable_address_takes_the_server_down() {
    if UdpSocket::bind("[::]:0").and_then(|s| s.connect("[2001::]:53")).is_ok() {
        return;
    }
    let dns = FakeDns::start();
    dns.set("a1.test", Zone::Aaaa("2001:db8::1".parse().expect("v6")));
    let ibex = start(dns.addr, FAST, "  server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n", "");
    ibex.wait_state("s1", "- 0 32", 3);
    ibex.wait_log(&format!("Server l/s1 is going DOWN for maintenance (No IP for server ). {LEFT}"), 2);
}

/// A server its checks found DOWN loses its name: "was DOWN and now enters maintenance"
/// (measured, `hold nx 500ms`).
#[test]
fn a_server_down_by_its_checks_enters_maintenance_when_its_name_goes() {
    let dead = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port();
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 500ms\n"), &format!("  server s1 be.test:{dead} resolvers r check inter 100ms fall 1 rise 1\n"), "");
    ibex.wait_state("s1", "127.0.0.1 0 0", 3);
    dns.set("be.test", Zone::Nx);
    ibex.wait_state("s1", "- 0 32", 4);
    ibex.wait_log("Server l/s1 was DOWN and now enters maintenance (DNS NX status).", 2);
}

/// The servers left count the backup ones (measured: "0 active and 1 backup servers left.
/// Running on backup.").
#[test]
fn a_backup_server_takes_over_when_the_name_goes() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 500ms\n"), "  server s1 a1.test:80 resolvers r\n  server s2 127.0.0.1:9 backup\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    dns.set("a1.test", Zone::Nx);
    ibex.wait_state("s1", "- 0 32", 4);
    ibex.wait_log(
        "Server l/s1 is going DOWN for maintenance (DNS NX status). 0 active and 1 backup servers left. Running on backup. 0 sessions active, 0 requeued, 0 remaining in queue.",
        2,
    );
}

/// `disabled`: the answer is taken but the server stays in maintenance; losing the name says
/// nothing more, and `SRV_ADMF_FMAINT` stays with `RMAINT` (measured: `10.0.0.1 0 5`, then
/// `- 0 37` with no line, then `10.0.0.1 0 5` and the "remains in maintenance" line again).
#[test]
fn a_disabled_server_resolves_but_stays_in_maintenance() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 500ms\n"), "  server s1 a1.test:80 resolvers r disabled\n", "");
    let again = "Server l/s1 ('a1.test') resolves again but remains in maintenance.";
    ibex.wait_state("s1", "10.0.0.1 0 5", 3);
    ibex.wait_log(again, 2);
    dns.set("a1.test", Zone::Nx);
    ibex.wait_state("s1", "- 0 37", 4);
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    ibex.wait_state("s1", "10.0.0.1 0 5", 3);
    thread::sleep(Duration::from_millis(300));
    let log = ibex.log();
    assert_eq!(log.iter().filter(|l| *l == again).count(), 2, "{log:?}");
    assert!(!log.iter().any(|l| l.contains("enters maintenance") || l.contains("going DOWN")), "{log:?}");
}

/// The operator's maintenance (`set server state maint`) outlives a DNS maintenance: `- 0 33`
/// while the name is gone, and back in maintenance when it resolves again (measured: `10.0.0.1
/// 0 1`, "resolves again but remains in maintenance").
#[test]
fn the_operators_maintenance_outlives_a_dns_maintenance() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 500ms\n"), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.cli("set server l/s1 state maint");
    ibex.wait_state("s1", "10.0.0.1 0 1", 2);
    dns.set("a1.test", Zone::Nx);
    ibex.wait_state("s1", "- 0 33", 4);
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    ibex.wait_state("s1", "10.0.0.1 0 1", 3);
    ibex.wait_log("Server l/s1 ('a1.test') resolves again but remains in maintenance.", 2);
}

/// The operator's drain outlives it too: `- 0 40`, then `10.0.0.1 2 8` with "is UP/DRAIN
/// (resolves again)" and "remains in forced drain mode", in that order (measured).
#[test]
fn the_operators_drain_outlives_a_dns_maintenance() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, &format!("{FAST}  hold nx 500ms\n"), "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    ibex.cli("set server l/s1 state drain");
    ibex.wait_state("s1", "10.0.0.1 2 8", 2);
    dns.set("a1.test", Zone::Nx);
    ibex.wait_state("s1", "- 0 40", 4);
    dns.set("a1.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 1)]));
    ibex.wait_state("s1", "10.0.0.1 2 8", 3);
    let drain = "Server l/s1 ('a1.test') is UP/DRAIN (resolves again).";
    let remains = "Server l/s1 remains in forced drain mode.";
    ibex.wait_log(drain, 2);
    ibex.wait_log(remains, 2);
    let log = ibex.log();
    let at = |t: &str| log.iter().position(|l| l == t).expect("line");
    assert!(at(drain) < at(remains) && at(remains) < log.iter().rposition(|l| l == READY).expect("ready"), "{log:?}");
}

/// The CLI moves the admin state kept under a DNS maintenance (measured on a name never
/// resolved: maint `- 0 33`; drain `- 0 40` with "leaving forced maintenance but remains in
/// maintenance"; ready `- 0 32`; maint, ready: the line again).
#[test]
fn the_cli_sets_the_admin_state_kept_under_a_dns_maintenance() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, FAST, "  server s1 nx.test:80 resolvers r\n", "");
    let leaving = "Server l/s1 is leaving forced maintenance but remains in maintenance.";
    for (cmd, want) in [("maint", "- 0 33"), ("drain", "- 0 40"), ("ready", "- 0 32"), ("maint", "- 0 33"), ("ready", "- 0 32")] {
        ibex.cli(&format!("set server l/s1 state {cmd}"));
        ibex.wait_state("s1", want, 2);
    }
    ibex.wait_log(leaving, 2);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(ibex.log().iter().filter(|l| *l == leaving).count(), 2, "{:?}", ibex.log());
}

/// The IPv6 route is probed again after 30 s (`INET6_CONNECTIVITY_CACHE_TIME`); the
/// resolutions go on at their period across it.
#[test]
fn the_ipv6_route_is_probed_again_after_30_s() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout resolve 1s\n", "  server s1 a1.test:80 resolvers r\n", "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    thread::sleep(Duration::from_secs(32));
    let q = dns.queries();
    let late = q.iter().filter(|x| x.at.duration_since(q[0].at) > Duration::from_secs(30)).count();
    assert!(late >= 1, "{q:?}");
    assert_eq!(ibex.state("s1").0, "10.0.0.1 2 0");
}

const SRV: &str = "_http._tcp.srv.test";

/// `server-template srv <n> _http._tcp.srv.test resolvers r<opts>`.
fn srv_template(n: usize, opts: &str) -> String {
    format!("  server-template srv {n} {SRV} resolvers r{opts}\n")
}

/// T487, A.t11 (`HAProxy` 3.5-dev8, `timeout resolve 1s`, `hold obsolete 2s`; here 300 ms and
/// 1 s): a template of 3 on an SRV answer of 2 records with their additional A records. In key
/// order (`XXH32` of the target) each record fills the first free slot: `srv1 10.1.0.1 2 64 2 1
/// t1.test 8080`, `srv2 10.1.0.2 2 64 1 1 t2.test 8081` (weights 512 -> 2, 256 -> 1,
/// `SRV_ADMF_FQDN_CHANGED`), `srv3 - 0 32 1 1 - 0`; no A query for a target with an
/// additional record. The FQDN line is logged, not printed on stderr. t2 dropped: removed once
/// not seen for `hold obsolete`, `- 0 96 1 1 - 0`, "entry removed from SRV record".
#[test]
fn t11_srv_records_fill_the_slots_with_their_additional_records() {
    let (port, _, _) = two_backends();
    let dns = FakeDns::start();
    let two = srv_zone(&[(512, port, "t1.test", Some([127, 0, 0, 1])), (256, 8081, "t2.test", Some([10, 1, 0, 2]))]);
    dns.set(SRV, two);
    dns.set("t1.test", Zone::A(vec![Ipv4Addr::new(10, 9, 9, 9)]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n  hold obsolete 1s\n", &srv_template(3, ""), "");
    ibex.wait_srv("srv1", &format!("127.0.0.1 2 64 2 1 t1.test {port} {SRV}"), 3);
    assert_eq!(ibex.srv_cols("srv2"), format!("10.1.0.2 2 64 1 1 t2.test 8081 {SRV}"));
    assert_eq!(ibex.srv_cols("srv3"), format!("- 0 32 1 1 - 0 {SRV}"));
    ibex.wait_log(&format!("l/srv1: IP changed from '(none)' to '127.0.0.1', port changed from '+0' to '{port}' by 'DNS additional record'."), 3);
    ibex.wait_log("l/srv2: IP changed from '(none)' to '10.1.0.2', port changed from '+0' to '8081' by 'DNS additional record'.", 3);
    ibex.wait_log("Server l/srv1 ('t1.test') is UP/READY (resolves again).", 3);
    ibex.wait_log("Server l/srv2 administratively READY thanks to valid DNS answer.", 3);
    let fqdn = "l/srv1 changed its FQDN from (null) to t1.test by 'SRV record'";
    assert!(ibex.log().iter().any(|l| l == fqdn), "no {fqdn:?} in {:?}", ibex.log());
    assert!(!ibex.stderr().iter().any(|l| l.ends_with(fqdn)), "{fqdn:?} on stderr: {:?}", ibex.stderr());
    assert!(dns.queries().iter().all(|q| q.qtype == 33), "{:?}", dns.queries());

    dns.set(SRV, srv_zone(&[(512, port, "t1.test", Some([127, 0, 0, 1]))]));
    let t = Instant::now();
    ibex.wait_srv("srv2", &format!("- 0 96 1 1 - 0 {SRV}"), 4);
    // Last seen at most 300 ms before the change, removed 1 s after.
    assert!(t.elapsed() >= Duration::from_millis(650), "removed after {:?}", t.elapsed());
    ibex.wait_log("Server l/srv2 is going DOWN for maintenance (entry removed from SRV record). 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.", 3);
    assert_eq!(ibex.srv_cols("srv1"), format!("127.0.0.1 2 64 2 1 t1.test {port} {SRV}"));
    // The SRV port reaches the connection.
    let mut c = TcpStream::connect(ibex.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    assert_eq!(get(&mut c), "127.0.0.1");
}

/// T487, A.t11b (`HAProxy` 3.5-dev8, `timeout resolve 1s`, default `hold obsolete 0`): without
/// additional records a slot takes the target and port first (`- 0 96 2 1 t1.test 8080`), and
/// each target gets an A resolution of its own, first asked one `timeout resolve` after the SRV
/// answer (`SRV` at 0.38; `A t1.test`, `A t2.test`, `SRV` at 1.38): `10.1.0.1 2 64`, "IP changed
/// ... by 'r/ns1'". A record gone is removed at the next answer without it, and its target's A
/// queries stop.
#[test]
fn t11b_without_additional_records_each_target_is_resolved() {
    let dns = FakeDns::start();
    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", None), (256, 8081, "t2.test", None)]));
    dns.set("t1.test", Zone::A(vec![Ipv4Addr::new(10, 1, 0, 1)]));
    dns.set("t2.test", Zone::A(vec![Ipv4Addr::new(10, 1, 0, 2)]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &srv_template(3, ""), "");
    ibex.wait_srv("srv2", &format!("10.1.0.2 2 64 1 1 t2.test 8081 {SRV}"), 3);
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"), 3);
    ibex.wait_log("l/srv1: IP changed from '(none)' to '10.1.0.1' by 'r/ns1'.", 3);
    ibex.wait_log("Server l/srv1 ('t1.test') is UP/READY (resolves again).", 3);
    let q = dns.queries();
    let first = |name: &str| q.iter().find(|q| q.name == name).map(|q| q.at).unwrap_or_else(|| panic!("no query for {name}: {q:?}"));
    let gap = first("t1.test").duration_since(first(SRV));
    assert!(gap >= Duration::from_millis(250), "A t1.test {gap:?} after the first SRV query");
    assert!(q.iter().any(|q| q.name == "t2.test" && q.qtype == 1), "{q:?}");
    assert_eq!(ibex.srv_cols("srv3"), format!("- 0 32 1 1 - 0 {SRV}"));

    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", None)]));
    ibex.wait_srv("srv2", &format!("- 0 96 1 1 - 0 {SRV}"), 3);
    ibex.wait_log("Server l/srv2 is going DOWN for maintenance (entry removed from SRV record). 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.", 3);
    let n = dns.queries().iter().filter(|q| q.name == "t2.test").count();
    thread::sleep(Duration::from_millis(900));
    assert_eq!(dns.queries().iter().filter(|q| q.name == "t2.test").count(), n, "t2.test still asked");
    assert_eq!(ibex.srv_cols("srv1"), format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"));
}

/// T487, measured on `HAProxy` 3.5-dev8 (`accepted_payload_size 8192`): 100 records
/// `t<i>.test:900<i>` with additional records `10.2.0.<i+1>` on a template of 3: the first
/// three in key order fill the slots, `t0`, `t35`, `t11`, the rest wait.
#[test]
fn an_srv_answer_of_100_records_fills_a_template_of_3_in_key_order() {
    let dns = FakeDns::start();
    let recs: Vec<(u16, u16, String, Option<[u8; 4]>)> =
        (0..100u16).map(|i| (256, 9000 + i, format!("t{i}.test"), Some([10, 2, 0, u8::try_from(i + 1).expect("octet")]))).collect();
    let refs: Vec<(u16, u16, &str, Option<[u8; 4]>)> = recs.iter().map(|(w, p, t, a)| (*w, *p, t.as_str(), *a)).collect();
    dns.set(SRV, srv_zone(&refs));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n  accepted_payload_size 8192\n", &srv_template(3, ""), "");
    ibex.wait_srv("srv1", &format!("10.2.0.1 2 64 1 1 t0.test 9000 {SRV}"), 3);
    assert_eq!(ibex.srv_cols("srv2"), format!("10.2.0.36 2 64 1 1 t35.test 9035 {SRV}"));
    assert_eq!(ibex.srv_cols("srv3"), format!("10.2.0.12 2 64 1 1 t11.test 9011 {SRV}"));
}

/// T487, measured on `HAProxy` 3.5-dev8: `resolve-opts ignore-weight` keeps the slots' weight
/// (1 for a weight of 512), and an additional record for a name that no SRV record targets is
/// dropped: the target is resolved on its own (`- 0 96`, then `10.1.0.1 2 64` by 'r/ns1').
#[test]
fn ignore_weight_and_an_additional_record_for_another_name() {
    let dns = FakeDns::start();
    dns.set(SRV, Zone::Srv(vec![(10, 512, 8080, "t1.test".into())], vec![("evil.test".into(), Ipv4Addr::new(10, 6, 6, 6))]));
    dns.set("t1.test", Zone::A(vec![Ipv4Addr::new(10, 1, 0, 1)]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &srv_template(2, " resolve-opts ignore-weight"), "");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 1 1 t1.test 8080 {SRV}"), 3);
    ibex.wait_log("l/srv1: IP changed from '(none)' to '10.1.0.1' by 'r/ns1'.", 3);
    assert_eq!(ibex.srv_cols("srv2"), format!("- 0 32 1 1 - 0 {SRV}"));
    assert!(!ibex.log().iter().any(|l| l.contains("10.6.6.6")), "{:?}", ibex.log());
}

/// T487, measured on `HAProxy` 3.5-dev8 (cases t487/tnx.json, trefused.json, ttimeout.json,
/// tservfail.json: `hold <status> 1s`, the SRV name NX, REFUSED, silent or SERVFAIL after one answer): once the
/// resolution's tries have all failed past the hold of that status, every record goes and its
/// slot with it: `- 0 96 2 1 - 0` (the weight stays), "entry removed from SRV record", and the
/// proxy has no server left.
fn an_srv_resolution_that_fails(zone: Zone, hold: &str) {
    let dns = FakeDns::start();
    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", Some([10, 1, 0, 1]))]));
    let ibex = start(dns.addr, &format!("  timeout resolve 300ms\n  timeout retry 200ms\n  hold {hold} 300ms\n"), &srv_template(2, ""), "");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"), 3);
    dns.set(SRV, zone);
    ibex.wait_srv("srv1", &format!("- 0 96 2 1 - 0 {SRV}"), 5);
    ibex.wait_log("Server l/srv1 is going DOWN for maintenance (entry removed from SRV record). 0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.", 3);
    // In the log as is, on stderr as an ALERT (`proxy 'l' ...`).
    assert!(ibex.log().iter().any(|l| l == "proxy l has no server available!"), "{:?}", ibex.log());
    let alert = format!("[ALERT]    ({}) : proxy 'l' has no server available!", ibex.child.id());
    assert!(ibex.stderr().contains(&alert), "{:?}", ibex.stderr());
    assert_eq!(ibex.srv_cols("srv2"), format!("- 0 32 1 1 - 0 {SRV}"));
}

#[test]
fn an_srv_resolution_that_fails_past_its_hold_drops_its_records() {
    an_srv_resolution_that_fails(Zone::Nx, "nx");
}

#[test]
fn an_srv_resolution_refused_or_timed_out_past_its_hold_drops_its_records() {
    an_srv_resolution_that_fails(Zone::Refused, "refused");
    an_srv_resolution_that_fails(Zone::Silent, "timeout");
    // SERVFAIL is `other` (case t487/tservfail.json).
    an_srv_resolution_that_fails(Zone::ServFail, "other");
}

/// T487, measured on `HAProxy` 3.5-dev8 (case t487/tdup.json): two SRV records on one target
/// (ports 8080, 8081), no additional records: both slots take the target, one A resolution
/// serves them (one `A t1.test` per period), and only the first slot takes its address (srv2
/// stays `- 0 96 1 1 t1.test 8081`, as on HAProxy).
#[test]
fn two_srv_records_on_one_target_share_its_resolution() {
    let dns = FakeDns::start();
    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", None), (256, 8081, "t1.test", None)]));
    dns.set("t1.test", Zone::A(vec![Ipv4Addr::new(10, 1, 0, 1)]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &srv_template(3, ""), "");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"), 3);
    thread::sleep(Duration::from_millis(700));
    assert_eq!(ibex.srv_cols("srv2"), format!("- 0 96 1 1 t1.test 8081 {SRV}"));
    let a: Vec<Instant> = dns.queries().iter().filter(|q| q.name == "t1.test").map(|q| q.at).collect();
    assert!(a.len() >= 2, "{a:?}");
    assert!(a.windows(2).all(|w| w[1].duration_since(w[0]) >= Duration::from_millis(200)), "two A queries per period: {a:?}");
}

/// T487, measured on `HAProxy` 3.5-dev8 (case t487/tarx.json, `hold obsolete 1s`): the SRV record
/// stays but its additional record goes; once that is older than `hold obsolete` the slot
/// resolves its target on its own: `A t1.test` from then on, "IP changed from '10.1.0.1' to
/// '10.1.0.9' by 'r/ns1'".
#[test]
fn an_additional_record_gone_past_hold_obsolete_gives_way_to_a_resolution() {
    let dns = FakeDns::start();
    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", Some([10, 1, 0, 1]))]));
    dns.set("t1.test", Zone::A(vec![Ipv4Addr::new(10, 1, 0, 9)]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n  hold obsolete 600ms\n", &srv_template(2, ""), "");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"), 3);
    assert!(!dns.queries().iter().any(|q| q.name == "t1.test"), "{:?}", dns.queries());
    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", None)]));
    ibex.wait_srv("srv1", &format!("10.1.0.9 2 64 2 1 t1.test 8080 {SRV}"), 4);
    ibex.wait_log("l/srv1: IP changed from '10.1.0.1' to '10.1.0.9' by 'r/ns1'.", 3);
}

/// T487, measured on `HAProxy` 3.5-dev8 (case t487/tinv.json): an SRV target with a character
/// no host name has (`t*1.test`) is logged at every answer, "invalid fqdn 't*1.test' by 'SRV
/// record'", and the slot keeps no target (`srv_fqdn` `-`, no `SRV_ADMF_FQDN_CHANGED`: 0) but
/// takes the address of the additional record, the port and the weight (2); its UP line names
/// no host: "Server l/srv1 ('(null)') is UP/READY (resolves again)."
#[test]
fn an_srv_target_that_is_no_host_name_is_logged_and_kept_out() {
    let dns = FakeDns::start();
    dns.set(SRV, srv_zone(&[(512, 8080, "t*1.test", Some([10, 1, 0, 1]))]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &srv_template(2, ""), "");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 0 2 1 - 8080 {SRV}"), 3);
    let inv = "invalid fqdn 't*1.test' by 'SRV record'";
    let deadline = Instant::now() + Duration::from_secs(3);
    while ibex.log().iter().filter(|l| *l == inv).count() < 2 {
        assert!(Instant::now() < deadline, "{:?}", ibex.log());
        thread::sleep(Duration::from_millis(20));
    }
    ibex.wait_log("Server l/srv1 ('(null)') is UP/READY (resolves again).", 3);
    assert!(!dns.queries().iter().any(|q| q.qtype == 1), "{:?}", dns.queries());
}

/// T487, measured on `HAProxy` 3.5-dev8 (cases t487/tip.json, tport.json): the additional record
/// moves a slot the CLI moved back, logging only what differs: after `set server l/srv1 addr
/// 10.1.0.9` "IP changed from '10.1.0.9' to '10.1.0.1' by 'DNS additional record'." (no port
/// part); after `set server l/srv1 addr 10.1.0.1 port 9000` "port changed from '9000' to '8080'
/// by 'DNS additional record'." (no IP part).
#[test]
fn an_additional_record_logs_only_the_ip_or_only_the_port_it_changes() {
    let dns = FakeDns::start();
    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", Some([10, 1, 0, 1]))]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", &srv_template(1, ""), "");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"), 3);
    ibex.cli("set server l/srv1 addr 10.1.0.9");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"), 3);
    ibex.wait_log("l/srv1: IP changed from '10.1.0.9' to '10.1.0.1' by 'DNS additional record'.", 3);
    ibex.cli("set server l/srv1 addr 10.1.0.1 port 9000");
    ibex.wait_log("l/srv1: port changed from '9000' to '8080' by 'DNS additional record'.", 3);
    assert_eq!(ibex.srv_cols("srv1"), format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"));
}

/// T487, measured on `HAProxy` 3.5-dev8 (case t487/thold.json, `hold nx 10s`): an SRV
/// resolution that fails while its last valid answer is inside `hold nx` keeps its records:
/// the slot stays `10.1.0.1 2 64`, no DOWN line.
#[test]
fn an_srv_resolution_failing_within_its_hold_keeps_its_records() {
    let dns = FakeDns::start();
    dns.set(SRV, srv_zone(&[(512, 8080, "t1.test", Some([10, 1, 0, 1]))]));
    let ibex = start(dns.addr, "  timeout resolve 300ms\n  timeout retry 200ms\n  hold nx 10s\n", &srv_template(1, ""), "");
    ibex.wait_srv("srv1", &format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"), 3);
    dns.set(SRV, Zone::Nx);
    thread::sleep(Duration::from_millis(2500));
    assert!(dns.queries().iter().filter(|q| q.name == SRV).count() >= 5, "{:?}", dns.queries());
    assert_eq!(ibex.srv_cols("srv1"), format!("10.1.0.1 2 64 2 1 t1.test 8080 {SRV}"));
    assert!(!ibex.log().iter().any(|l| l.contains("going DOWN")), "{:?}", ibex.log());
}

/// `both.test`: 10.0.0.1 and 2001:db8::1; `v6only.test`: 2001:db8::6 (design A.t8, A.t18).
fn dual_zone(dns: &FakeDns) {
    dns.set("both.test", Zone::Dual(vec![Ipv4Addr::new(10, 0, 0, 1)], vec!["2001:db8::1".parse().expect("v6")]));
    dns.set("v6only.test", Zone::Dual(Vec::new(), vec!["2001:db8::6".parse().expect("v6")]));
}

/// T489, `dns-accept-family` with fixed families (`resolv_active_families`, the query type at
/// `resolvers.c:2179`). Measured on `HAProxy` 3.5-dev8 (`tools/battery/repro/vv-dns/t489/fam*.json`,
/// `timeout resolve 1s`): `ipv4,ipv6` asks `resolve-prefer`'s type, IPv6 by default
/// (fam46both: AAAA only, `2001:db8::1`; fam46v6: `2001:db8::6`; fam46both4 with `resolve-prefer
/// ipv4`: A only, `10.0.0.1`); `ipv6` asks AAAA whatever the preference (fam6both: `2001:db8::1`;
/// fam6a1: an A-only name gets NODATA, the same id three times, stays `- 0 32`); `ipv4` asks A
/// (fam4both, `resolve-prefer ipv6`: `10.0.0.1`).
#[test]
fn dns_accept_family_fixes_the_query_type() {
    for (family, server, want, qtype) in [
        ("ipv4,ipv6", "both.test:80 resolvers r", "2001:db8::1 2 0", 28),
        ("ipv4,ipv6", "v6only.test:80 resolvers r", "2001:db8::6 2 0", 28),
        ("ipv4,ipv6", "both.test:80 resolvers r resolve-prefer ipv4", "10.0.0.1 2 0", 1),
        ("ipv6", "both.test:80 resolvers r resolve-prefer ipv4", "2001:db8::1 2 0", 28),
        ("ipv4", "both.test:80 resolvers r resolve-prefer ipv6", "10.0.0.1 2 0", 1),
    ] {
        let dns = FakeDns::start();
        dual_zone(&dns);
        let ibex = start(dns.addr, "  timeout resolve 300ms\n", &format!("  server s1 {server}\n"), &format!("  dns-accept-family {family}\n"));
        ibex.wait_state("s1", want, 3);
        thread::sleep(Duration::from_millis(700));
        let q = dns.queries();
        assert!(q.len() >= 2 && q.iter().all(|q| q.qtype == qtype), "{family} {server}: {q:?}");
    }
    // `ipv6` and a name with only an A record: AAAA, NODATA, its tries share one id; never A.
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout retry 200ms\n", "  server s1 a1.test:80 resolvers r\n", "  dns-accept-family ipv6\n");
    thread::sleep(Duration::from_millis(900));
    assert_eq!(ibex.state("s1").0, "- 0 32");
    let q = dns.queries();
    assert!(q.len() >= 3 && q.iter().all(|q| q.qtype == 28) && q[..3].iter().all(|x| x.id == q[0].id), "{q:?}");
}

/// T489: `auto` anywhere in the list is `auto` (famauto6, `auto,ipv6` on a host with no IPv6
/// route: `v6only.test` is asked A only and stays in maintenance).
#[test]
fn dns_accept_family_auto_wins_in_a_list() {
    let v6 = UdpSocket::bind("[::]:0").and_then(|s| s.connect("[2001::]:53")).is_ok();
    let dns = FakeDns::start();
    dual_zone(&dns);
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", "  server s1 v6only.test:80 resolvers r\n", "  dns-accept-family auto,ipv6\n");
    thread::sleep(Duration::from_millis(900));
    let q = dns.queries();
    if v6 {
        assert_eq!(ibex.state("s1").0, "2001:db8::6 2 0");
    } else {
        assert_eq!(ibex.state("s1").0, "- 0 32");
        assert!(!q.is_empty() && q.iter().all(|q| q.qtype == 1), "{q:?}");
    }
}

/// A.t15b at run time, on the system's `/etc/resolv.conf` (`HAProxy` reads that file only):
/// `parse-resolv-conf` before `ns1` lists the system's nameservers first in `show resolvers`,
/// each named after its address (oracle: `nameserver 127.0.0.53:` then `nameserver ns1:`).
#[test]
fn t15b_parse_resolv_conf_nameservers_come_first() {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else { return };
    let Some(first) = text.lines().find_map(|l| l.strip_prefix("nameserver").filter(|r| r.starts_with([' ', '\t'])).and_then(|r| r.split_whitespace().next())) else { return };
    let dns = FakeDns::start();
    let ibex = start(format!("{}\n  parse-resolv-conf\n  nameserver ns2 127.0.0.1:9", dns.addr), "", "  server s1 a1.test:80 resolvers r\n", "");
    let out = ibex.cli("show resolvers");
    let names: Vec<&str> = out.lines().filter_map(|l| l.strip_prefix(" nameserver ")).collect();
    assert_eq!(names.first(), Some(&"ns1:"), "{out}");
    assert_eq!(names.get(1), Some(&format!("{first}:").as_str()), "{out}");
    assert_eq!(names.last(), Some(&"ns2:"), "{out}");
}

/// Runs `ibex -c` on `cfg` with `/etc/resolv.conf` replaced by `conf` (bind-mounted in a user
/// and mount namespace), or with an empty `/etc` when `conf` is `None`. `None` when this host
/// cannot make the namespace.
fn check_with_resolv_conf(cfg: &str, conf: Option<&str>) -> Option<(i32, Vec<String>)> {
    if !Command::new("unshare").args(["-rm", "true"]).status().is_ok_and(|s| s.success()) {
        return None;
    }
    let dir = tempfile::tempdir().expect("tmp");
    let c = dir.path().join("t.cfg");
    std::fs::write(&c, cfg).expect("cfg");
    let mount = if let Some(conf) = conf {
        let r = dir.path().join("resolv.conf");
        std::fs::write(&r, conf).expect("conf");
        format!("mount --bind {} /etc/resolv.conf", r.display())
    } else {
        let e = dir.path().join("etc");
        std::fs::create_dir(&e).expect("dir");
        format!("mount --bind {} /etc", e.display())
    };
    let out = Command::new("unshare")
        .args(["-rm", "sh", "-c", &format!("{mount} && exec {} -c -f {}", env!("CARGO_BIN_EXE_ibex"), c.display())])
        .output()
        .expect("unshare");
    let pid = regex_lite_pid(&String::from_utf8_lossy(&out.stderr));
    Some((out.status.code().unwrap_or(-1), pid.lines().map(|l| l.replace(&c.display().to_string(), "t.cfg")).collect()))
}

/// stderr with the `(pid)` of each line as `(P)`.
fn regex_lite_pid(s: &str) -> String {
    s.lines()
        .map(|l| match (l.find(" ("), l.find(") : ")) {
            (Some(a), Some(b)) if a < b && l[a + 2..b].bytes().all(|c| c.is_ascii_digit()) => format!("{} (P){}", &l[..a], &l[b + 1..]),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// T489: the warnings and the fatal error of `parse-resolv-conf` as `HAProxy` 3.5-dev8 prints
/// them (`unshare -rm`, the same files): one warning on the line of the keyword, several each
/// on a line of its own indented 8 (`indent_msg`); a missing file is fatal.
#[test]
fn parse_resolv_conf_warnings_and_failure_are_haproxys() {
    let cfg = |rs: &str| format!("resolvers r\n{rs}defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nlisten l\n  bind 127.0.0.1:0\n");
    let one = cfg("  nameserver 10.0.0.9 127.0.0.1:5300\n  parse-resolv-conf\n");
    let Some((rc, err)) = check_with_resolv_conf(&one, Some("nameserver 10.0.0.9\n")) else { return };
    assert_eq!(rc, 0, "{err:?}");
    assert!(err.contains(&"[WARNING]  (P) : config : parsing [t.cfg:3]: Parsing [/etc/resolv.conf:1] : generated name for /etc/resolv.conf nameserver '10.0.0.9' conflicts with another nameserver (declared at t.cfg:2), it appears to be a duplicate and will be excluded.".to_string()), "{err:?}");
    let (rc, err) = check_with_resolv_conf(&cfg("  parse-resolv-conf\n"), Some("nameserver\nnameserver 10.0.0.1\nnameserver 1.2.3.4#53\n")).expect("unshare");
    assert_eq!(rc, 0, "{err:?}");
    let at = err.iter().position(|l| l == "[WARNING]  (P) : config : parsing [t.cfg:2]: ").unwrap_or_else(|| panic!("{err:?}"));
    assert_eq!(
        err[at + 1..at + 3],
        [
            "        parsing [/etc/resolv.conf:1] : nameserver line is missing address.".to_string(),
            "        parsing [/etc/resolv.conf:3] : address '1.2.3.4#53' could not be recognized, nameserver will be excluded.".to_string()
        ]
    );
    let (rc, err) = check_with_resolv_conf(&cfg("  parse-resolv-conf\n"), None).expect("unshare");
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        [
            "[ALERT]    (P) : config : parsing [t.cfg:2]: failed to open /etc/resolv.conf.",
            "[ALERT]    (P) : config : Error(s) found in configuration file : t.cfg",
            "[ALERT]    (P) : config : Fatal errors found in configuration."
        ]
    );
}

/// A.t21 (T489): `set server <b>/<s> fqdn` (`cli_parse_set_server`, `srv_update_fqdn`,
/// `srv_set_fqdn`), measured on `HAProxy` 3.5-dev8 (cases t489/fqdn.json, fqdn2.json): the
/// reply names the change, `srv_fqdn` shows the new name at once, the address follows the new
/// name's answer (`by 'r/ns1'`) and `srv_admin_state` then has `SRV_ADMF_FQDN_CHANGED` (64);
/// nothing is logged for the change itself. A server written as an address with `resolvers`
/// starts resolving (`from (null)`). A name equal but for case or a final dot is the same
/// resolution: the reply says changed, `srv_fqdn` stays. The refusals in `HAProxy`'s order.
#[test]
fn t21_set_server_fqdn_switches_the_resolution() {
    let dns = FakeDns::start();
    dns.set("a2.test", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 2)]));
    dns.set("_http._tcp.srv.test", srv_zone(&[(256, 8080, "t1.test", Some([10, 1, 0, 1]))]));
    let ibex = start(
        dns.addr,
        "  timeout resolve 300ms\n",
        "  server s1 a1.test:80 resolvers r\n  server s2 127.0.0.1:80\n  server s3 10.0.0.9:80 resolvers r\n  server-template t 1 _http._tcp.srv.test resolvers r\n",
        "",
    );
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    let cli = |c: &str| ibex.cli(c).trim_end().to_string();
    assert_eq!(cli("set server l/s1 fqdn a2.test"), "l/s1 changed its FQDN from a1.test to a2.test by 'stats socket command'");
    assert_eq!(ibex.state("s1").1, "a2.test");
    assert_eq!(cli("set server l/s1 fqdn a2.test"), "no need to change the FDQN by 'stats socket command'");
    assert_eq!(cli("set server l/s2 fqdn"), "set server <b>/<s> fqdn requires a FQDN.");
    assert_eq!(cli("set server l/s2 fqdn a2.test"), "set server <b>/<s> fqdn failed because no resolution is configured.");
    assert_eq!(cli("set server l/t1 fqdn a2.test"), "set server <b>/<s> fqdn failed because SRV resolution is configured.");
    assert_eq!(cli("set server l/s1 fqdn a/b"), "invalid fqdn 'a/b' by 'stats socket command'");
    assert_eq!(cli("set server l/s1 fqdn a..b"), "could not update l/s1 FQDN by 'stats socket command'");
    ibex.wait_state("s1", "10.0.0.2 2 64", 3);
    assert!(ibex.log().contains(&"l/s1: IP changed from '10.0.0.1' to '10.0.0.2' by 'r/ns1'.".to_string()), "{:?}", ibex.log());
    assert!(!ibex.log().iter().any(|l| l.starts_with("l/s1 changed its FQDN")), "{:?}", ibex.log());
    assert_eq!(cli("set server l/s1 fqdn A2.TEST"), "l/s1 changed its FQDN from a2.test to A2.TEST by 'stats socket command'");
    assert_eq!(ibex.state("s1").1, "a2.test");
    assert_eq!(cli("set server l/s3 fqdn a1.test"), "l/s3 changed its FQDN from (null) to a1.test by 'stats socket command'");
    assert_eq!(ibex.state("s3").1, "a1.test");
    ibex.wait_state("s3", "10.0.0.1 2 64", 3);
    // The old name is no longer asked once s1 left it (s3 asks a1.test from now on).
    let q = dns.queries();
    assert!(q.iter().any(|q| q.name == "a2.test"), "{q:?}");
}

// --- do-resolve (T489): oracle cases tools/battery/repro/vv-dns/t489/dr*.json ---

/// The rules of `listen l` that resolve `expr` into `txn.ip` and answer with it.
fn dr_rules(args: &str, expr: &str) -> String {
    format!("  http-request do-resolve(txn.ip,r{args}) {expr}\n  http-request return status 200 content-type text/plain lf-string \"%[var(txn.ip)]\"\n")
}

/// One request for `path` on a new connection: the body and how long it took.
fn dr_get(ibex: &Ibex, path: &str) -> (String, Duration) {
    let t = Instant::now();
    let mut c = TcpStream::connect(ibex.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).expect("send");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "{text:?}");
    (text.split_once("\r\n\r\n").map_or("", |(_, b)| b).to_string(), t.elapsed())
}

/// A.t14 (dr14, drhold): the first request waits for the answer, a second one inside `hold
/// valid` is answered from the cache (one query); past `hold valid` the name is asked again.
#[test]
fn t14_do_resolve_answers_from_the_cache_inside_hold_valid() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  hold valid 600ms\n", &dr_rules(",ipv4", "str(a1.test)"), "");
    assert_eq!(dr_get(&ibex, "/").0, "10.0.0.1");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(dr_get(&ibex, "/").0, "10.0.0.1");
    assert_eq!(dns.queries().len(), 1, "{:?}", dns.queries());
    let c = counters(&ibex, "r", "ns1");
    assert_eq!((c["sent"], c["valid"]), (1, 1), "{c:?}");
    thread::sleep(Duration::from_millis(700));
    assert_eq!(dr_get(&ibex, "/").0, "10.0.0.1");
    assert_eq!(dns.queries().len(), 2, "{:?}", dns.queries());
    assert!(dns.queries().iter().all(|q| q.qtype == 1 && q.name == "a1.test"));
}

/// drnx, drsil, drhdr: a name that does not resolve (NX, silence) holds the request for the
/// whole resolution (every try), then the rules go on without the variable; a name that is no
/// host name (`bad..name`) is not asked and the rules go on at once; the next rule runs.
#[test]
fn do_resolve_without_an_answer_sets_nothing_and_goes_on() {
    let dns = FakeDns::start();
    dns.set("sil.test", Zone::Silent);
    let rules = format!("{}  http-request set-header x-n after\n", dr_rules(",ipv4", "path,ltrim(/)"));
    let ibex = start(dns.addr, "  timeout retry 200ms\n  resolve_retries 2\n", &rules, "");
    for name in ["nx.test", "sil.test"] {
        let (body, took) = dr_get(&ibex, &format!("/{name}"));
        assert_eq!(body, "", "{name}");
        assert!(took >= Duration::from_millis(350) && took < Duration::from_millis(2000), "{name}: {took:?}");
    }
    let before = dns.queries().len();
    let (body, took) = dr_get(&ibex, "/bad..name");
    assert_eq!(body, "");
    assert!(took < Duration::from_millis(200), "{took:?}");
    assert_eq!(dns.queries().len(), before);
    assert_eq!(dr_get(&ibex, "/A1.TEST").0, "10.0.0.1");
}

/// drsrv: the server resolution of the same name is the cache (`resolv_link_resolution` shares
/// it): the request is answered without a query of its own.
#[test]
fn do_resolve_shares_a_servers_resolution() {
    let dns = FakeDns::start();
    let rules = format!("{}  server s1 a1.test:80 resolvers r\n", dr_rules(",ipv4", "str(a1.test)"));
    let ibex = start(dns.addr, "  timeout resolve 5s\n", &rules, "");
    ibex.wait_state("s1", "10.0.0.1 2 0", 3);
    let n = dns.queries().len();
    assert_eq!(dr_get(&ibex, "/").0, "10.0.0.1");
    assert_eq!(dns.queries().len(), n, "{:?}", dns.queries());
}

/// dr6, drdef: the family is a preference; on a host without an IPv6 route (`auto`) A is asked.
/// With `dns-accept-family ipv4,ipv6` the default asks AAAA first.
#[test]
fn do_resolve_family_is_a_preference() {
    let v6 = UdpSocket::bind("[::]:0").and_then(|s| s.connect("[2001::]:53")).is_ok();
    let dns = FakeDns::start();
    dual_zone(&dns);
    let ibex = start(dns.addr, "", &dr_rules(",ipv6", "str(both.test)"), "");
    if !v6 {
        assert_eq!(dr_get(&ibex, "/").0, "10.0.0.1");
    }
    drop(ibex);
    let dns = FakeDns::start();
    dual_zone(&dns);
    let ibex = start(dns.addr, "", &dr_rules("", "str(both.test)"), "  dns-accept-family ipv4,ipv6\n");
    assert_eq!(dr_get(&ibex, "/").0, "2001:db8::1");
    let ibex4 = start(dns.addr, "", &dr_rules(",ipv4", "str(both.test)"), "  dns-accept-family ipv4,ipv6\n");
    assert_eq!(dr_get(&ibex4, "/").0, "10.0.0.1");
    drop(ibex);
}

/// drtcpd, drtcp, drtcpsil: `tcp-request content do-resolve` waits inside the
/// `inspect-delay` only; without one nothing is asked; at its end the rules go on.
#[test]
fn tcp_request_content_do_resolve_waits_inside_the_inspect_delay() {
    let dns = FakeDns::start();
    dns.set("sil.test", Zone::Silent);
    let rules = |delay: &str, name: &str| {
        format!("{delay}  tcp-request content do-resolve(sess.ip,r,ipv4) str({name})\n  http-request return status 200 content-type text/plain lf-string \"%[var(sess.ip)]\"\n")
    };
    let ibex = start(dns.addr, "", &rules("  tcp-request inspect-delay 2s\n", "a1.test"), "");
    assert_eq!(dr_get(&ibex, "/").0, "10.0.0.1");
    drop(ibex);
    let n = dns.queries().len();
    let ibex = start(dns.addr, "", &rules("", "a1.test"), "");
    assert_eq!(dr_get(&ibex, "/").0, "");
    assert_eq!(dns.queries().len(), n);
    drop(ibex);
    let ibex = start(dns.addr, "", &rules("  tcp-request inspect-delay 400ms\n", "sil.test"), "");
    let (body, took) = dr_get(&ibex, "/");
    assert_eq!(body, "");
    assert!(took >= Duration::from_millis(350) && took < Duration::from_millis(1500), "{took:?}");
}

/// The cross-worker path: with two workers every request is answered, whichever worker took
/// it (one asks worker 0, which owns the section).
#[test]
fn do_resolve_answers_on_every_worker() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "", &dr_rules(",ipv4", "str(a1.test)"), "  nbthread 2\n");
    for _ in 0..20 {
        assert_eq!(dr_get(&ibex, "/").0, "10.0.0.1");
    }
    assert!(dns.queries().len() <= 2, "{:?}", dns.queries());
}

/// 2,000 distinct names through `do-resolve` under `tune.resolvers.cache-size 100`: each is
/// answered, and the cache stays one object of a fixed size (`show pools`; one per worker that
/// ran a `do-resolve`).
#[test]
fn do_resolve_cache_is_bounded() {
    let dns = FakeDns::start();
    for i in 0..2000 {
        dns.set(&format!("n{i}.test"), Zone::A(vec![Ipv4Addr::new(10, 9, u8::try_from(i / 256).expect("o"), u8::try_from(i % 256).expect("o"))]));
    }
    let ibex = start(dns.addr, "", &dr_rules(",ipv4", "path,ltrim(/)"), "  nbthread 1\n  tune.resolvers.cache-size 100\n");
    let row = |ibex: &Ibex| ibex.cli("show pools").lines().find(|l| l.contains("do_resolve_cache")).map(str::to_string).unwrap_or_default();
    for i in 0..2000 {
        assert_eq!(dr_get(&ibex, &format!("/n{i}.test")).0, format!("10.9.{}.{}", i / 256, i % 256));
        if i == 10 {
            assert!(!row(&ibex).is_empty(), "{}", ibex.cli("show pools"));
        }
    }
    let first = row(&ibex);
    for i in 0..50 {
        assert_eq!(dr_get(&ibex, &format!("/n{i}.test")).0, format!("10.9.0.{i}"));
    }
    assert_eq!(row(&ibex), first);
    // One worker, one cache: `1 allocated ..., 1 used`.
    assert!(first.contains(": 1 allocated") && first.contains(", 1 used"), "{first}");
}

/// Two requests for a name being resolved share its resolution (one id, `resolve_retries`
/// tries); a binary sample is a name (a sample of another type is cast to one:
/// `do_resolve_casts_the_sample_to_a_name`).
#[test]
fn do_resolve_requests_share_a_pending_resolution() {
    let dns = FakeDns::start();
    dns.set("sil.test", Zone::Silent);
    let rules = format!(
        "  http-request do-resolve(txn.ip,r,ipv4) bin(61312e74657374) if {{ path /bin }}\n  \
         http-request do-resolve(txn.ip,r,ipv4) path,ltrim(/),hex,hex2bin if {{ path /a1.test }}\n{}",
        dr_rules(",ipv4", "str(sil.test)").replace("do-resolve(txn.ip,r,ipv4) str(sil.test)", "do-resolve(txn.ip,r,ipv4) str(sil.test) if { path /sil }")
    );
    let ibex = start(dns.addr, "  timeout retry 300ms\n  resolve_retries 2\n", &rules, "");
    let ibex = Arc::new(ibex);
    let both: Vec<_> = (0..2)
        .map(|_| {
            let i = Arc::clone(&ibex);
            thread::spawn(move || dr_get(&i, "/sil").0)
        })
        .collect();
    for h in both {
        assert_eq!(h.join().expect("join"), "");
    }
    let q = dns.queries();
    assert!(q.len() == 2 && q[0].id == q[1].id, "{q:?}");
    assert_eq!(dr_get(&ibex, "/bin").0, "10.0.0.1");
    assert_eq!(dr_get(&ibex, "/a1.test").0, "10.0.0.1");
}

/// `resolv_action_do_resolve` takes the sample as a string (`sample_fetch_as_type(...,
/// SMP_T_STR)`): measured on `HAProxy` 3.5-dev8, `int(1)` and `bool(1)` ask `1`, `int(1),add(1)`
/// asks `2`, `src` asks `127.0.0.1`, and the answer goes into the variable; a fetch with no
/// value asks nothing.
#[test]
fn do_resolve_casts_the_sample_to_a_name() {
    let dns = FakeDns::start();
    dns.set("1", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 7)]));
    dns.set("2", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 8)]));
    dns.set("127.0.0.1", Zone::A(vec![Ipv4Addr::new(10, 0, 0, 9)]));
    let mut rules = String::new();
    for (path, expr) in [("int", "int(1)"), ("bool", "bool(1)"), ("add", "int(1),add(1)"), ("src", "src"), ("hdr", "req.hdr(x-name)")] {
        let _ = writeln!(rules, "  http-request do-resolve(txn.ip,r,ipv4) {expr} if {{ path /{path} }}");
    }
    rules.push_str("  http-request return status 200 content-type text/plain lf-string \"%[var(txn.ip)]\"\n");
    let ibex = start(dns.addr, "", &rules, "");
    assert_eq!(dr_get(&ibex, "/int").0, "10.0.0.7");
    assert_eq!(dr_get(&ibex, "/bool").0, "10.0.0.7");
    assert_eq!(dr_get(&ibex, "/add").0, "10.0.0.8");
    assert_eq!(dr_get(&ibex, "/src").0, "10.0.0.9");
    // A fetch that finds nothing asks nothing.
    assert_eq!(dr_get(&ibex, "/hdr").0, "");
    let names: Vec<String> = dns.queries().into_iter().map(|q| q.name).collect();
    assert_eq!(names, ["1", "2", "127.0.0.1"]);
}

/// An answer record that is no address (an SRV record of the name asked, before its A record):
/// the address is taken from the A/AAAA records only (`resolv_get_ip_from_response`).
#[test]
fn do_resolve_skips_an_answer_record_that_is_no_address() {
    let dns = FakeDns::start();
    dns.set("mixed.test", Zone::SrvThenA(Ipv4Addr::new(10, 0, 0, 5)));
    let ibex = start(dns.addr, "", &dr_rules(",ipv4", "str(mixed.test)"), "");
    assert_eq!(dr_get(&ibex, "/").0, "10.0.0.5");
}

/// `set server fqdn` onto a name whose resolution has a query in flight: the server joins it,
/// and no query is sent for it (`resolv_trigger_resolution` leaves a running resolution be).
/// s2's resolution, every `timeout resolve`, is the section's next step, where the request is
/// applied; sil.test's query is in flight for the whole `timeout retry`.
#[test]
fn set_server_fqdn_joins_a_resolution_in_flight() {
    let dns = FakeDns::start();
    dns.set("sil.test", Zone::Silent);
    let ibex = start(
        dns.addr,
        "  timeout resolve 300ms\n  timeout retry 5s\n  resolve_retries 1\n",
        "  server s1 sil.test:80 resolvers r init-addr none\n  server s2 a1.test:80 resolvers r\n  server s3 10.0.0.9:80 resolvers r\n",
        "",
    );
    let asked = || dns.queries().iter().filter(|q| q.name == "sil.test").count();
    let t = Instant::now();
    while asked() == 0 && t.elapsed() < Duration::from_secs(3) {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(asked(), 1, "{:?}", dns.queries());
    assert!(ibex.cli("set server l/s3 fqdn sil.test").starts_with("l/s3 changed its FQDN from (null) to sil.test"));
    assert_eq!(ibex.state("s3").1, "sil.test");
    thread::sleep(Duration::from_millis(1000));
    assert_eq!(asked(), 1, "{:?}", dns.queries());
}

/// A request woken while its `do-resolve` still waits (its body comes in meanwhile) waits on:
/// the rule neither asks again nor gives up before the resolution ends.
#[test]
fn do_resolve_woken_by_the_body_waits_on() {
    let dns = FakeDns::start();
    dns.set("sil.test", Zone::Silent);
    let ibex = start(dns.addr, "  timeout retry 300ms\n  resolve_retries 2\n", &dr_rules(",ipv4", "str(sil.test)"), "");
    let t = Instant::now();
    let mut c = TcpStream::connect(ibex.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    c.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\n").expect("send");
    thread::sleep(Duration::from_millis(150));
    c.write_all(b"hello").expect("body");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    let took = t.elapsed();
    assert!(text.starts_with("HTTP/1.1 200"), "{text:?}");
    assert!(took >= Duration::from_millis(550), "{took:?}");
    let q = dns.queries();
    assert!(q.len() == 2 && q[0].id == q[1].id, "{q:?}");
}

/// A section only servers written as addresses name runs (T489): `set server fqdn` gives one
/// of them a name to resolve.
#[test]
fn set_server_fqdn_on_a_section_no_name_uses_yet() {
    let dns = FakeDns::start();
    let ibex = start(dns.addr, "  timeout resolve 300ms\n", "  server s3 10.0.0.9:80 resolvers r\n", "");
    assert!(ibex.cli("set server l/s3 fqdn a1.test").starts_with("l/s3 changed its FQDN from (null) to a1.test"));
    ibex.wait_state("s3", "10.0.0.1 2 64", 3);
}
