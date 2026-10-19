// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `log-forward` sections and the `ring` forwarder, driven the way a collector sees them.
//! What each message comes out as was measured on the reference `HAProxy`
//! (3.5-dev8-885761-29, 2026-10-04): a section per option, a UDP collector, and datagrams
//! sent in each syslog shape. One difference is not copied: `HAProxy` ends every datagram
//! with a line feed and Ibex does not (it never has, for any log line).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use ibex_rt::loghdr::Meta;

fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

fn free_tcp() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

fn collector() -> (UdpSocket, u16) {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.set_read_timeout(Some(Duration::from_millis(1500))).expect("timeout");
    let p = s.local_addr().expect("addr").port();
    (s, p)
}

fn start(cfg: &str) {
    let cfg = ibex_config::parse_str(cfg).expect("parses");
    ibex_rt::logfwd::start(&cfg).expect("starts");
}

/// What the collector got, without the line feed `HAProxy` ends every datagram with (measured
/// 2026-10-04, 3.5-dev8-885761-29: a forwarded `hello` and `hello\n` both arrive as
/// `hello\n`); a datagram without one is a failure, as is a second one.
fn recv(collect: &UdpSocket) -> Option<String> {
    let mut b = [0u8; 2048];
    collect.recv_from(&mut b).ok().map(|(n, _)| {
        let text = String::from_utf8_lossy(&b[..n]).into_owned();
        let line = text.strip_suffix('\n').unwrap_or_else(|| panic!("a datagram ends with a line feed: {text:?}"));
        assert!(!line.ends_with('\n'), "one line feed only: {text:?}");
        line.to_string()
    })
}

/// Sends `msg` to the forwarder and returns what the collector received, if anything.
fn through(port: u16, collect: &UdpSocket, msg: &[u8]) -> Option<String> {
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind");
    tx.send_to(msg, ("127.0.0.1", port)).expect("send");
    recv(collect)
}

fn section(name: &str, port: u16, collector: u16, options: &str, log_args: &str) -> String {
    format!("log-forward {name}\n  dgram-bind 127.0.0.1:{port}\n{options}  log 127.0.0.1:{collector} {log_args}\n")
}

#[test]
fn a_message_keeps_its_shape_or_takes_the_targets_format() {
    let (col, cp) = collector();
    let (p_keep, p_5424, p_iso, p_raw) = (free_udp(), free_udp(), free_udp(), free_udp());
    start(&format!(
        "{}{}{}{}",
        section("fwd_keep", p_keep, cp, "", "local0"),
        section("fwd_5424", p_5424, cp, "", "format rfc5424 local0"),
        section("fwd_iso", p_iso, cp, "", "format iso local0"),
        section("fwd_raw", p_raw, cp, "  option dont-parse-log\n", "format raw local0"),
    ));
    let m3164 = "<134>Oct  4 18:17:12 myhost tag[7]: hello";
    // As it came: the header is rebuilt from what was parsed.
    assert_eq!(through(p_keep, &col, m3164.as_bytes()).as_deref(), Some(m3164));
    // One that came with its own line feed leaves with one (`recv` refuses two).
    assert_eq!(through(p_keep, &col, format!("{m3164}\n").as_bytes()).as_deref(), Some(m3164));
    let m5424 = "<134>1 2026-10-04T18:17:12-00:00 myhost tag 7 - - hello";
    assert_eq!(through(p_keep, &col, m5424.as_bytes()).as_deref(), Some(m5424));
    // `HAProxy` itself sends no hostname: `haproxy[1]:` reads as the host, and the text follows.
    let own = "<134>Oct  4 18:17:12 haproxy[1]: 127.0.0.1:5 GET /";
    assert_eq!(through(p_keep, &col, own.as_bytes()).as_deref(), Some(own));
    // A target's own format: the year of a legacy time is the current one.
    let got = through(p_5424, &col, m3164.as_bytes()).expect("5424");
    assert!(got.starts_with("<134>1 ") && got.ends_with("-10-04T18:17:12-00:00 myhost tag 7 - - hello"), "{got}");
    let got = through(p_iso, &col, m3164.as_bytes()).expect("iso");
    assert!(got.ends_with("-10-04T18:17:12-00:00 hello") && !got.starts_with('<'), "{got}");
    // Not parsed, and written with no header: the message as it is, priority and all.
    assert_eq!(through(p_raw, &col, m3164.as_bytes()).as_deref(), Some(m3164));
}

#[test]
fn a_message_without_a_priority_or_a_host_is_given_both() {
    let (col, cp) = collector();
    let (p_fill, p_keep) = (free_udp(), free_udp());
    start(&format!(
        "{}{}",
        section("fwd_fill", p_fill, cp, "", "local0"),
        section("fwd_keep2", p_keep, cp, "  option host keep\n", "local0"),
    ));
    // The sender's address fills a missing host (the default), and a message with no
    // priority is level 0 of the target's facility: local0 is 16, so 128.
    let got = through(p_fill, &col, b"<14>bare").expect("fill");
    assert!(got.starts_with("<14>") && got.ends_with(" 127.0.0.1 bare"), "{got}");
    let got = through(p_fill, &col, b"no prio at all").expect("fill");
    assert!(got.starts_with("<128>") && got.ends_with(" 127.0.0.1 no prio at all"), "{got}");
    // `keep` leaves it out, and a message that has a priority only comes out as `<pri>text`.
    assert_eq!(through(p_keep, &col, b"<14>bare").as_deref(), Some("<14>bare"));
}

#[test]
fn option_host_replaces_or_appends_the_senders_address() {
    let (col, cp) = collector();
    let (p_rep, p_app) = (free_udp(), free_udp());
    start(&format!(
        "{}{}",
        section("fwd_rep", p_rep, cp, "  option host replace\n", "local0"),
        section("fwd_app", p_app, cp, "  option host append\n", "local0"),
    ));
    let m = b"<134>Oct  4 18:17:12 myhost tag[7]: hello";
    assert_eq!(through(p_rep, &col, m).as_deref(), Some("<134>Oct  4 18:17:12 127.0.0.1 tag[7]: hello"));
    assert_eq!(through(p_app, &col, m).as_deref(), Some("<134>Oct  4 18:17:12 myhost,127.0.0.1 tag[7]: hello"));
}

#[test]
fn a_target_filters_by_level_and_a_message_keeps_its_own_facility() {
    let (col, cp) = collector();
    let p = free_udp();
    start(&section("fwd_lvl", p, cp, "", "local1 notice"));
    // Level 6 is less severe than `notice` (5): dropped. Level 5 passes with its own facility.
    assert_eq!(through(p, &col, b"<134>Oct  4 18:17:12 myhost tag[7]: hello"), None);
    let got = through(p, &col, b"<13>lvl5").expect("level 5");
    assert!(got.starts_with("<13>") && got.ends_with("127.0.0.1 lvl5"), "{got}");
    // No facility of its own: the target's (local1 is 17, so 136).
    let got = through(p, &col, b"plain").expect("plain");
    assert!(got.starts_with("<136>"), "{got}");
}

#[test]
fn a_stream_is_read_in_both_framings() {
    let (col, cp) = collector();
    let (tcp, ntf) = (free_tcp(), free_tcp());
    start(&format!(
        "log-forward fwd_tcp\n  bind 127.0.0.1:{tcp}\n  log 127.0.0.1:{cp} local0\n\
         log-forward fwd_ntf\n  bind 127.0.0.1:{ntf}\n  option assume-rfc6587-ntf\n  log 127.0.0.1:{cp} local0\n"
    ));
    // Non-transparent framing: one message a line.
    let mut c = TcpStream::connect(("127.0.0.1", tcp)).expect("connect");
    c.write_all(b"<14>one\n<14>two\n").expect("write");
    // A TCP peer has an address, which fills the missing host.
    let ends = |got: Option<String>, tail: &str| {
        let got = got.expect("a message");
        assert!(got.starts_with("<14>") && got.ends_with(tail), "{got}");
    };
    ends(recv(&col), " 127.0.0.1 one");
    ends(recv(&col), " 127.0.0.1 two");
    // Octet counting: a length, a blank, then that many bytes, which may hold a line feed.
    let mut c = TcpStream::connect(("127.0.0.1", tcp)).expect("connect");
    c.write_all(b"7 <14>a\nb7 <14>cde").expect("write");
    ends(recv(&col), " 127.0.0.1 a\nb");
    ends(recv(&col), " 127.0.0.1 cde");
    // `assume-rfc6587-ntf`: a message that starts with a digit is a line.
    let mut c = TcpStream::connect(("127.0.0.1", ntf)).expect("connect");
    c.write_all(b"5 not a length\n").expect("write");
    let got = recv(&col).expect("ntf");
    assert!(got.ends_with(" 127.0.0.1 5 not a length"), "{got}");
}

#[test]
fn a_unix_stream_listener_takes_messages_and_has_its_mode() {
    use std::os::unix::fs::PermissionsExt;
    let (col, cp) = collector();
    let path = std::env::temp_dir().join(format!("ibex-logfwd-{}.sock", std::process::id()));
    start(&format!("log-forward fwd_unix\n  bind unix@{} mode 660\n  log 127.0.0.1:{cp} local0\n", path.display()));
    let mode = std::fs::metadata(&path).expect("socket").permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    let mut c = std::os::unix::net::UnixStream::connect(&path).expect("connect");
    c.write_all(b"<14>via unix\n").expect("write");
    // No peer address on a UNIX socket, so nothing fills the host.
    assert_eq!(recv(&col).as_deref(), Some("<14>via unix"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_log_line_naming_no_ring_stops_the_start() {
    let cfg = ibex_config::parse_str("global\n  log ring@nowhere local0\n").expect("parses");
    let err = ibex_rt::logfwd::start(&cfg).expect_err("refused").to_string();
    assert!(err.contains("unknown ring named 'nowhere'"), "{err}");
}

#[test]
fn a_bind_that_cannot_be_made_stops_the_start() {
    let held = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = held.local_addr().expect("addr").port();
    let cfg = ibex_config::parse_str(&format!("log-forward fwd_busy\n  bind 127.0.0.1:{port}\n")).expect("parses");
    let err = ibex_rt::logfwd::start(&cfg).expect_err("refused").to_string();
    assert!(err.contains("cannot bind"), "{err}");
}

/// Accepts one connection and reads until `want` bytes arrived.
fn serve(l: TcpListener, want: usize) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().expect("accept");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut got = Vec::new();
        let mut b = [0u8; 512];
        while got.len() < want {
            match s.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&b[..n]),
            }
        }
        got
    })
}

#[test]
fn a_ring_forwards_its_events_to_its_server_and_keeps_them() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let srv = serve(l, "<134>1 ".len());
    start(&format!(
        "ring fwdring\n  format rfc5424\n  size 4096\n  server s 127.0.0.1:{port}\n"
    ));
    let ring = ibex_rt::ring::find("fwdring").expect("the ring exists");
    // The header is the ring's format; the server gets one event a line.
    let meta = Meta { tag: b"haproxy", pid: b"7", ..Meta::default() };
    ring.write(16, 6, &meta, 1024, b"first event");
    ring.write(16, 6, &meta, 1024, b"second event");
    let got = String::from_utf8(srv.join().expect("server")).expect("text");
    assert!(got.starts_with("<134>1 "), "{got}");
    // Whatever arrived so far, the ring still holds both.
    let all = String::from_utf8(ring.dump(b'\n', false)).expect("text");
    assert_eq!(all.lines().count(), 2, "{all}");
    assert!(all.lines().next().expect("line").ends_with(" - haproxy 7 - - first event"), "{all}");
}

#[test]
fn octet_counting_prefixes_each_event_with_its_length() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let srv = serve(l, "5 hello3 abc".len());
    start(&format!(
        "ring octring\n  size 4096\n  server s 127.0.0.1:{port} log-proto octet-count\n"
    ));
    let ring = ibex_rt::ring::find("octring").expect("the ring exists");
    ring.write(16, 6, &Meta::default(), 1024, b"hello");
    ring.write(16, 6, &Meta::default(), 1024, b"abc");
    assert_eq!(String::from_utf8(srv.join().expect("server")).expect("text"), "5 hello3 abc");
}

#[test]
fn show_events_lists_the_rings_and_dumps_one() {
    start("ring shown\n  description \"the shown one\"\n  size 1024\n");
    let ring = ibex_rt::ring::find("shown").expect("the ring exists");
    ring.write(16, 6, &Meta::default(), 1024, b"a\tb\x1b");
    let list = String::from_utf8(ibex_rt::ring::show_events(&[])).expect("text");
    assert!(list.contains("    shown      : type=buffer, 0 dropped, the shown one\n"), "{list}");
    assert!(list.contains("stdout     : type=fd"), "{list}");
    assert_eq!(ibex_rt::ring::show_events(&["shown"]), b"a\tb\x1b\n");
    assert_eq!(ibex_rt::ring::show_events(&["-s", "shown"]), b"a b?\n");
    assert_eq!(ibex_rt::ring::show_events(&["-0", "shown"]), b"a\tb\x1b\0");
    // `-n` starts at the end, where there is nothing without `-w`.
    assert!(ibex_rt::ring::show_events(&["-n", "shown"]).is_empty());
    assert_eq!(ibex_rt::ring::show_events(&["nosuch"]), b"No such sink: nosuch\n");
    assert!(String::from_utf8_lossy(&ibex_rt::ring::show_events(&["-w", "shown"])).contains("not implemented"));
}

/// The `format` of a `log` line is the header its line is written under, whatever it targets.
/// `HAProxy` (same measurement) writes `HELLO world` under `raw`, `<134>1 <time> - mytag 4242
/// - - HELLO world` under `rfc5424` and `<134>Oct  4 18:26:22 mytag[4242]: HELLO world` when
/// there is none.
#[test]
fn a_log_line_format_decides_the_header() {
    let (col, cp) = collector();
    let sends = |fmt: &str| {
        let cfg = ibex_config::parse_str(&format!("global\n  log 127.0.0.1:{cp} {fmt}local0\n")).expect("parses");
        let t = ibex_rt::SyslogTarget::new(&cfg.global.expect("global").logs[0]);
        assert!(t.send(ibex_config::LogLevel::Info, "mytag[4242]", "", "HELLO world"));
        recv(&col).expect("a line")
    };
    assert_eq!(sends("format raw "), "HELLO world");
    let got = sends("format rfc5424 ");
    assert!(got.starts_with("<134>1 ") && got.ends_with(" - mytag 4242 - - HELLO world"), "{got}");
    let got = sends("");
    assert!(got.starts_with("<134>") && got.ends_with(" mytag[4242]: HELLO world"), "{got}");
}

fn pem(dir: &tempfile::TempDir) -> String {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let path = dir.path().join("c.pem");
    std::fs::write(&path, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("write pem");
    path.display().to_string()
}

/// A ring whose server is `ssl verify none` forwarding into a `log-forward` listener that
/// is `ssl crt`: the same two sections as `ssl/log_forward_ssl.vtc`, and the event comes out
/// of the far side's UDP target.
#[test]
fn a_ring_forwards_over_tls_into_a_tls_listener() {
    let dir = tempfile::tempdir().expect("dir");
    let crt = pem(&dir);
    let (col, cp) = collector();
    let port = free_tcp();
    start(&format!(
        "ring tlsring\n  format rfc5424\n  size 4096\n  server s 127.0.0.1:{port} ssl verify none\n\
         log-forward fwd_tls\n  bind 127.0.0.1:{port} ssl crt {crt}\n  log 127.0.0.1:{cp} local0\n"
    ));
    let ring = ibex_rt::ring::find("tlsring").expect("the ring exists");
    let meta = Meta { tag: b"haproxy", pid: b"7", ..Meta::default() };
    ring.write(16, 6, &meta, 1024, b"over tls");
    let got = recv(&col).expect("the event crossed");
    assert!(got.starts_with("<134>1 ") && got.ends_with(" 127.0.0.1 haproxy 7 - - over tls"), "{got}");
}

#[test]
fn a_tls_bind_with_no_certificate_stops_the_start() {
    let cfg = ibex_config::parse_str(&format!("log-forward fwd_nocrt\n  bind 127.0.0.1:{} ssl\n", free_tcp())).expect("parses");
    let err = ibex_rt::logfwd::start(&cfg).expect_err("refused").to_string();
    assert!(err.contains("no 'crt'"), "{err}");
}

#[test]
fn a_ring_forwards_to_a_unix_socket_and_reconnects_when_it_drops() {
    let path = std::env::temp_dir().join(format!("ibex-ring-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let l = std::os::unix::net::UnixListener::bind(&path).expect("bind");
    start(&format!("ring unixring\n  size 4096\n  server s unix@{}\n", path.display()));
    let ring = ibex_rt::ring::find("unixring").expect("the ring exists");
    ring.write(16, 6, &Meta::default(), 1024, b"one");
    let read_line = |l: &std::os::unix::net::UnixListener| {
        let (mut s, _) = l.accept().expect("accept");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut b = [0u8; 64];
        let n = s.read(&mut b).expect("read");
        b[..n].to_vec()
    };
    assert_eq!(read_line(&l), b"one\n");
    // The collector closed. A write into a connection the peer closed can be lost without an
    // error, so events keep coming until one arrives on a new connection.
    l.set_nonblocking(true).expect("nonblocking");
    let feeder = {
        let ring = std::sync::Arc::clone(&ring);
        std::thread::spawn(move || {
            for i in 0..100 {
                ring.write(16, 6, &Meta::default(), 1024, format!("again {i}").as_bytes());
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let started = std::time::Instant::now();
    let (mut s, _) = loop {
        match l.accept() {
            Ok(c) => break c,
            Err(_) if started.elapsed() < Duration::from_secs(8) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("the forwarder did not reconnect: {e}"),
        }
    };
    s.set_nonblocking(false).expect("blocking");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut b = [0u8; 64];
    let n = s.read(&mut b).expect("read");
    assert!(String::from_utf8_lossy(&b[..n]).contains("again"), "{}", String::from_utf8_lossy(&b[..n]));
    drop(s);
    drop(feeder);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_section_over_its_maxconn_turns_a_connection_away_and_an_idle_one_is_closed() {
    let (col, cp) = collector();
    let port = free_tcp();
    start(&format!(
        "log-forward fwd_max\n  bind 127.0.0.1:{port}\n  maxconn 1\n  timeout client 300ms\n  log 127.0.0.1:{cp} local0\n"
    ));
    let mut first = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    first.write_all(b"<14>kept\n").expect("write");
    assert!(recv(&col).is_some());
    // The second is accepted by the kernel and dropped by the section: it reads end of file.
    let mut second = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    second.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let mut b = [0u8; 1];
    assert!(matches!(second.read(&mut b), Ok(0) | Err(_)));
    // Idle for longer than `timeout client`: closed, and the slot is free again.
    std::thread::sleep(Duration::from_millis(600));
    let mut third = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    third.write_all(b"<14>again\n").expect("write");
    assert!(recv(&col).expect("the slot was released").ends_with("again"));
}

#[test]
fn a_message_with_nothing_after_its_header_is_not_forwarded_and_log_global_adds_the_globals_targets() {
    let (col, cp) = collector();
    let (p_empty, p_global) = (free_udp(), free_udp());
    start(&format!(
        "global\n  log 127.0.0.1:{cp} local0\n{}log-forward fwd_global\n  dgram-bind 127.0.0.1:{p_global}\n  log global\n",
        section("fwd_empty", p_empty, cp, "", "local0"),
    ));
    // Level and facility, and then nothing: `HAProxy` does not send an empty message.
    assert_eq!(through(p_empty, &col, b"<14>"), None);
    // `log global`: this section has no `log` line of its own, the global one is the target.
    let got = through(p_global, &col, b"<14>from global").expect("forwarded");
    assert!(got.ends_with(" 127.0.0.1 from global"), "{got}");
}

#[test]
fn a_stream_that_breaks_its_framing_is_dropped_and_what_came_before_is_kept() {
    let (col, cp) = collector();
    let port = free_tcp();
    start(&format!("log-forward fwd_break\n  bind 127.0.0.1:{port}\n  log 127.0.0.1:{cp} local0\n"));
    let attempt = |bytes: &[u8]| {
        let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        c.write_all(bytes).expect("write");
        // Closing is what ends a stream that stopped short.
        drop(c);
    };
    // A length that is not a number, one cut short, and one that cannot be a length.
    attempt(b"1x not a length");
    attempt(b"9 short");
    attempt(b"99999999999 <14>x");
    assert_eq!(recv(&col), None);
    // The section still serves.
    attempt(b"<14>still here\n");
    assert!(recv(&col).expect("forwarded").ends_with("still here"));
}

#[test]
fn every_section_that_has_log_lines_is_checked_for_the_rings_they_name() {
    for (cfg, section) in [
        ("global\n  log ring@nowhere local0\n", "global"),
        ("defaults\n  log ring@nowhere local0\n", "defaults"),
        ("listen l\n  bind 127.0.0.1:1\n  log ring@nowhere local0\n", "l"),
        ("frontend f\n  bind 127.0.0.1:1\n  log ring@nowhere local0\n", "f"),
        ("backend b\n  log ring@nowhere local0\n", "b"),
        ("log-forward lf\n  log ring@nowhere local0\n", "lf"),
    ] {
        let parsed = ibex_config::parse_str(cfg).expect("parses");
        let err = ibex_rt::logfwd::start(&parsed).expect_err(cfg).to_string();
        assert!(err.contains(&format!("section '{section}'")) && err.contains("'nowhere'"), "{err}");
    }
}

#[test]
fn listeners_that_cannot_start_say_why() {
    // A certificate that is not there.
    let cfg = ibex_config::parse_str(&format!("log-forward fwd_nofile\n  bind 127.0.0.1:{} ssl crt /nonexistent.pem\n", free_tcp())).expect("parses");
    let err = ibex_rt::logfwd::start(&cfg).expect_err("refused").to_string();
    assert!(err.contains("ssl:"), "{err}");
    // A UDP port that is taken, and a socket path that cannot be made.
    let held = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = held.local_addr().expect("addr").port();
    let cfg = ibex_config::parse_str(&format!("log-forward fwd_udp_busy\n  dgram-bind 127.0.0.1:{port}\n")).expect("parses");
    assert!(ibex_rt::logfwd::start(&cfg).expect_err("refused").to_string().contains("cannot bind"));
    let cfg = ibex_config::parse_str("log-forward fwd_unix_bad\n  bind unix@/nonexistent-dir/x.sock\n").expect("parses");
    assert!(ibex_rt::logfwd::start(&cfg).expect_err("refused").to_string().contains("cannot bind"));
}

#[test]
fn a_ring_whose_server_is_not_up_yet_delivers_when_it_is() {
    // The port is bound and not listening, so a connect is refused; holding it keeps another
    // test from taking it while we wait (a freed port was, in a parallel run).
    use rustix::net::{AddressFamily, SocketAddrAny, SocketType};
    let sock = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).expect("socket");
    rustix::net::bind_v4(&sock, &std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let Ok(SocketAddrAny::V4(addr)) = rustix::net::getsockname(&sock) else { panic!("an IPv4 address") };
    let port = addr.port();
    start(&format!("ring latering\n  size 4096\n  timeout connect 200ms\n  server s 127.0.0.1:{port}\n"));
    let ring = ibex_rt::ring::find("latering").expect("the ring exists");
    ring.write(16, 6, &Meta::default(), 1024, b"waiting");
    // Nothing listens: the forwarder retries, and the event is still in the ring.
    std::thread::sleep(Duration::from_millis(600));
    rustix::net::listen(&sock, 16).expect("listen");
    let l = TcpListener::from(sock);
    let srv = serve(l, "waiting\n".len());
    assert_eq!(String::from_utf8(srv.join().expect("server")).expect("text"), "waiting\n");
}

#[test]
fn a_log_line_naming_a_ring_that_does_not_exist_writes_nothing() {
    let cfg = ibex_config::parse_str("global\n  log ring@never_made local0\n").expect("parses");
    let t = ibex_rt::SyslogTarget::new(&cfg.global.expect("global").logs[0]);
    assert!(!t.send(ibex_config::LogLevel::Info, "tag[1]", "", "lost"));
}

#[test]
fn starting_the_same_configuration_again_changes_nothing() {
    // Every worker builds its engine from the one configuration: the second start must not try
    // to bind the same ports again.
    let (col, cp) = collector();
    let p = free_udp();
    let cfg = ibex_config::parse_str(&section("fwd_twice", p, cp, "", "local0")).expect("parses");
    ibex_rt::logfwd::start(&cfg).expect("first");
    ibex_rt::logfwd::start(&cfg).expect("second");
    assert!(through(p, &col, b"<14>once").is_some());
    assert_eq!(recv(&col), None, "one listener, one copy");
}

#[test]
fn a_target_with_a_sample_takes_only_its_share() {
    let (col, cp) = collector();
    let p = free_udp();
    // Of every two lines, the first.
    start(&section("fwd_sample", p, cp, "", "sample 1:2 local0"));
    assert!(through(p, &col, b"<14>first").expect("first").ends_with("first"));
    assert_eq!(through(p, &col, b"<14>second"), None);
    assert!(through(p, &col, b"<14>third").expect("third").ends_with("third"));
}

#[test]
fn a_stream_cut_inside_its_length_is_dropped_and_a_unix_listener_needs_no_mode() {
    let (col, cp) = collector();
    let port = free_tcp();
    let path = std::env::temp_dir().join(format!("ibex-logfwd-nomode-{}.sock", std::process::id()));
    start(&format!(
        "log-forward fwd_cut\n  bind 127.0.0.1:{port}\n  bind unix@{}\n  log 127.0.0.1:{cp} local0\n",
        path.display()
    ));
    drop({
        let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        c.write_all(b"12").expect("write");
        c
    });
    assert_eq!(recv(&col), None);
    let mut c = std::os::unix::net::UnixStream::connect(&path).expect("connect");
    c.write_all(b"<14>no mode\n").expect("write");
    assert!(recv(&col).expect("forwarded").ends_with("no mode"));
    let _ = std::fs::remove_file(&path);
}

/// `log stdout` and `log stderr` write a line and a line feed to the process's own
/// descriptors; `fd@5`, which Ibex cannot write to, drops the line and says so.
#[test]
fn descriptor_targets_write_and_the_rest_are_refused_quietly() {
    let cfg = ibex_config::parse_str("global\n  log stdout format raw local0\n  log stderr format raw local0\n").expect("parses");
    let logs = cfg.global.expect("global").logs;
    for log in &logs {
        let t = ibex_rt::SyslogTarget::new(log);
        assert!(t.send_default("tag[1]", "", "to a descriptor"));
    }
    let cfg = ibex_config::parse_str("global\n  log fd@5 local0\n").expect("parses");
    let t = ibex_rt::SyslogTarget::new(&cfg.global.expect("global").logs[0]);
    assert!(!t.send(ibex_config::LogLevel::Info, "tag[1]", "", "nowhere"));
}

/// Two frontends that log to the same ring share one target, as two that log to the same
/// collector do.
#[test]
fn two_proxies_logging_to_one_ring_share_it() {
    let cfg = ibex_config::parse_str(
        "ring shared_ring\n  size 2048\n\
         frontend a\n  mode tcp\n  bind 127.0.0.1:0\n  log ring@shared_ring local0\n\
         frontend b\n  mode tcp\n  bind 127.0.0.1:0\n  log ring@shared_ring local0\n",
    )
    .expect("parses");
    ibex_rt::Engine::new(&cfg, 64).expect("engine");
    assert!(ibex_rt::ring::find("shared_ring").is_some());
}

/// `HAProxy` 3.5-dev8-885761-29, `tune.bufsize` 16384, 2026-10-10: a TCP connection whose line
/// has no line feed in its first 16384 bytes is closed, and so is one whose octet-counted
/// frame announces more than 16384 bytes (it does not wait for the bytes). A frame of 16384
/// and a line of 16300 are forwarded. Idle connections are not closed without `timeout client`
/// (30 s measured), which is what Ibex does.
#[test]
fn a_tcp_line_or_frame_longer_than_the_buffer_closes_the_connection() {
    let (col, cp) = collector();
    let tcp = free_tcp();
    start(&format!("log-forward fwd_cap\n  bind 127.0.0.1:{tcp}\n  log 127.0.0.1:{cp} local0\n"));
    // Closed means the read ends at once with 0 bytes or a reset, not by our timeout.
    let closed = |c: &mut TcpStream| {
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let mut b = [0u8; 16];
        match c.read(&mut b) {
            Ok(n) => n == 0,
            Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
        }
    };
    // A line with no line feed, 2 MiB of it.
    let mut c = TcpStream::connect(("127.0.0.1", tcp)).expect("connect");
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..32 {
        if c.write_all(&chunk).is_err() {
            break;
        }
    }
    assert!(closed(&mut c), "a 2 MiB line without a line feed kept the connection open");
    // An octet-counted frame that announces 5,000,000 bytes and sends 3.
    let mut c = TcpStream::connect(("127.0.0.1", tcp)).expect("connect");
    c.write_all(b"5000000 <14>abc").expect("write");
    assert!(closed(&mut c), "a 5 MB frame announcement kept the connection open");
    let mut c = TcpStream::connect(("127.0.0.1", tcp)).expect("connect");
    c.write_all(b"16385 <14>abc").expect("write");
    assert!(closed(&mut c), "a frame of 16385 bytes kept the connection open");
    // What fits is still forwarded.
    let mut c = TcpStream::connect(("127.0.0.1", tcp)).expect("connect");
    c.write_all(b"<14>fine\n").expect("write");
    assert!(recv(&col).expect("a message").ends_with(" 127.0.0.1 fine"));
}

/// A `dgram-bind` on a port another socket holds stops the start with exit code 1, as
/// HAProxy's does (measured on 3.5-dev8: `cannot bind socket (Address already in use)`,
/// exit 1).
#[test]
fn a_busy_dgram_bind_stops_the_process_at_start() {
    let held = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = held.local_addr().expect("addr").port();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    std::io::Write::write_all(&mut f, format!("global\n  nbthread 1\nlog-forward lf_busy_start\n  dgram-bind 127.0.0.1:{port}\n  log 127.0.0.1:9 format raw local0\n").as_bytes())
        .expect("write cfg");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).output().expect("run ibex");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("cannot bind 127.0.0.1:") && err.contains("Address already in use"), "{err}");
}
