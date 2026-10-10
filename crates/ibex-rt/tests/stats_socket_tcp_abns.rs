// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `stats socket` on TCP (`ipv4@`, `ipv6@`, `tcp@`, `host:port`) and on Linux abstract
//! sockets (`abns@`, `abnsz@`) (T246). T222 refused them because the CLI was built on unix
//! socket files only. Every expected text and behaviour was measured on 3.5-dev8-885761-29:
//!
//! ```text
//! '::1'                 'stats socket' : invalid address: ':' in '::1'
//! 'ipv6@127.0.0.1:80'   'stats socket' : invalid address: '127.0.0.1' in 'ipv6@127.0.0.1:80'
//! '127.0.0.1:0'         'stats socket' : invalid port '0'          (before the address)
//! '127.0.0.1:99999'     'stats socket' : invalid port '99999'
//! show cli sockets      ipv4@127.0.0.1:P admin all / ipv6@[::1]:P / abns@name / unix@path
//! abns@name             the name zero-padded to the whole sun_path; abnsz@ is not padded
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn cfg(lines: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    write!(f, "global\n{lines}\n").expect("write");
    f
}

fn check(arg: &str) -> (bool, String) {
    let f = cfg(&format!("\tstats socket {arg}"));
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn haproxy_texts_for_bad_tcp_addresses() {
    for (a, text) in [
        ("::1", "'stats socket' : invalid address: ':' in '::1'"),
        ("ipv6@127.0.0.1:80", "'stats socket' : invalid address: '127.0.0.1' in 'ipv6@127.0.0.1:80'"),
        ("ipv4@[::1]:80", "'stats socket' : invalid address: '[::1]' in 'ipv4@[::1]:80'"),
        ("1.2.3.4.5:80", "'stats socket' : invalid address: '1.2.3.4.5' in '1.2.3.4.5:80'"),
        ("nosuchhost.invalid:80", "'stats socket' : invalid address: 'nosuchhost.invalid' in 'nosuchhost.invalid:80'"),
        ("127.0.0.1:0", "'stats socket' : invalid port '0'"),
        ("nosuchhost.invalid:0", "'stats socket' : invalid port '0'"),
        ("127.0.0.1:99999", "'stats socket' : invalid port '99999'"),
        ("127.0.0.1:65536", "'stats socket' : invalid port '65536'"),
        ("127.0.0.1:0-5", "'stats socket' : invalid port '0'"),
        ("127.0.0.1:5-1", "'stats socket' : invalid port range '5-1'"),
        ("127.0.0.1:80x", "'stats socket' : invalid character 'x' in port number '80x' in '127.0.0.1:80x'"),
        ("127.0.0.1:-1", "'stats socket' : port offset not permitted here in '127.0.0.1:-1'"),
        ("127.0.0.1:+5", "'stats socket' : port offset not permitted here in '127.0.0.1:+5'"),
        ("127.0.0.1:", "'stats socket' : missing port specification in '127.0.0.1:'"),
        ("udp@127.0.0.1:80", "'stats socket' : dgram-type address not acceptable in 'udp@127.0.0.1:80'"),
        ("uxdg@/tmp/x", "'stats socket' : dgram-type address not acceptable in 'uxdg@/tmp/x'"),
    ] {
        let (ok, err) = check(a);
        assert!(!ok, "`stats socket {a}` must be refused");
        assert!(err.contains(text), "`stats socket {a}`: expected {text:?} in: {err}");
    }
}

#[test]
fn tcp_and_abstract_forms_haproxy_accepts_are_accepted() {
    for a in [
        "127.0.0.1:19999",
        "ipv4@127.0.0.1:19999",
        "ipv6@[::1]:19999",
        "ipv6@::1:19999",
        "::1:19999",
        "[::1]:19999",
        "*:19999",
        ":19999",
        "tcp@127.0.0.1:19999",
        "tcp4@127.0.0.1:19999",
        "tcp6@[::1]:19999",
        "ip@127.0.0.1:19999",
        "localhost:19999",
        "127.0.0.1:19999 mode 600 level admin expose-fd listeners",
        "abns@foo",
        "abnsz@foo",
    ] {
        let (ok, err) = check(a);
        assert!(ok, "`stats socket {a}` must be accepted: {err}");
    }
}

/// Ranges and `fd@` are accepted by `HAProxy`; Ibex refuses them rather than dropping them.
#[test]
fn forms_ibex_does_not_implement_say_so() {
    for a in ["127.0.0.1:19990-19995", "fd@3", "sockpair@3", "mptcp@127.0.0.1:19999"] {
        let (ok, err) = check(a);
        assert!(!ok, "`stats socket {a}` must be refused");
        assert!(err.contains("not supported by Ibex"), "`stats socket {a}`: {err}");
    }
}

fn start(lines: &str, extra: &[String]) -> (Child, NamedTempFile) {
    let f = cfg(lines);
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    (child, f)
}

fn ask<S: Read + Write>(mut s: S, cmd: &str) -> String {
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn wait<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < end, "{what} never accepted");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tcp(addr: SocketAddr) -> TcpStream {
    wait(&addr.to_string(), || TcpStream::connect(addr).ok())
}

fn abstract_stream(name: &str, padded: bool) -> Option<UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    let mut bytes = name.as_bytes().to_vec();
    if padded {
        bytes.resize(107, 0);
    }
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(&bytes).ok()?;
    UnixStream::connect_addr(&addr).ok()
}

#[test]
fn the_cli_answers_on_tcp_and_abstract_sockets_with_each_level() {
    let p4 = common::reserve_port();
    let p6 = common::reserve_port();
    let abns = format!("ibex-t246-{}", std::process::id());
    let lines = format!(
        "\tstats socket 127.0.0.1:{p4} level admin mode 600\n\
         \tstats socket ipv6@[::1]:{p6}\n\
         \tstats socket abns@{abns} level user\n\
         \tstats socket abnsz@{abns}z"
    );
    let (mut child, _f) = start(&lines, &[]);
    let v4: SocketAddr = format!("127.0.0.1:{p4}").parse().expect("addr");
    let v6: SocketAddr = format!("[::1]:{p6}").parse().expect("addr");

    assert_eq!(ask(tcp(v4), "show cli level"), "admin\n\n");
    let socks = ask(tcp(v4), "show cli sockets");
    assert!(socks.contains(&format!("ipv4@127.0.0.1:{p4} admin all")), "{socks}");

    assert_eq!(ask(tcp(v6), "show cli level"), "operator\n\n");
    let socks = ask(tcp(v6), "show cli sockets");
    assert!(socks.contains(&format!("ipv6@[::1]:{p6} operator all")), "{socks}");

    let s = wait("abns@", || abstract_stream(&abns, true));
    assert_eq!(ask(s, "show cli level"), "user\n\n");
    let s = wait("abns@", || abstract_stream(&abns, true));
    let socks = ask(s, "show cli sockets");
    assert!(socks.contains(&format!("abns@{abns} user all")), "{socks}");
    assert!(abstract_stream(&abns, false).is_none(), "abns@ binds the zero-padded name, not the short one");

    let s = wait("abnsz@", || abstract_stream(&format!("{abns}z"), false));
    assert_eq!(ask(s, "show cli level"), "operator\n\n");
    common::stop(&mut child);
}

/// `_getsocks` cannot carry descriptors over TCP (`SCM_RIGHTS` is unix-only; `HAProxy`'s
/// sendmsg goes out without them). Ibex closes the connection and keeps serving.
#[test]
fn getsocks_over_tcp_sends_no_descriptors_and_the_cli_keeps_serving() {
    let p = common::reserve_port();
    let (mut child, _f) = start(&format!("\tstats socket 127.0.0.1:{p} level admin expose-fd listeners"), &[]);
    let a: SocketAddr = format!("127.0.0.1:{p}").parse().expect("addr");
    let _ = ask(tcp(a), "_getsocks");
    assert_eq!(ask(tcp(a), "show cli level"), "admin\n\n");
    common::stop(&mut child);
}

/// The new process of a `-sf` reload binds the same TCP address while the old one still
/// holds it (`HAProxy`: `SO_REUSEPORT`), then the old one exits and the CLI is the new one's.
#[test]
fn a_tcp_stats_socket_survives_an_sf_reload() {
    let p = common::reserve_port();
    let lines = format!("\tstats socket 127.0.0.1:{p} level admin");
    let a: SocketAddr = format!("127.0.0.1:{p}").parse().expect("addr");
    let (mut old, f) = start(&lines, &[]);
    let info = ask(tcp(a), "show info");
    assert!(info.contains(&format!("Pid: {}", old.id())), "{info}");

    let mut new = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .args(["-sf".to_string(), old.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let end = Instant::now() + Duration::from_secs(10);
    let st = loop {
        if let Some(st) = old.try_wait().expect("wait") {
            break st;
        }
        assert!(Instant::now() < end, "the old process never exited on -sf");
        assert!(new.try_wait().expect("wait").is_none(), "the new process failed to start (could not bind the TCP CLI?)");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(st.success(), "old exit: {st:?}");
    let info = ask(tcp(a), "show info");
    assert!(info.contains(&format!("Pid: {}", new.id())), "{info}");
    common::stop(&mut new);
}

/// The rest of `str2sa_range`'s branches that a stats socket can reach.
#[test]
fn prefixes_and_host_forms() {
    for (a, ok, text) in [
        ("stream+127.0.0.1:19999", true, ""),
        ("stream+/tmp/x.sock", true, ""),
        ("ipv6@*:19999", true, ""),
        ("dgram+127.0.0.1:19999", false, "'stats socket' : dgram-type address not acceptable in 'dgram+127.0.0.1:19999'"),
        ("dgram+abns@x", false, "'stats socket' : dgram-type address not acceptable in 'dgram+abns@x'"),
        ("ipv6@localhost:19999", true, ""),
        ("ipv4@localhost:19999", true, ""),
        ("ipv4@ip6-localhost:19999", false, "'stats socket' : invalid address: 'ip6-localhost' in 'ipv4@ip6-localhost:19999'"),
        ("[::1:19999", false, "'stats socket' : invalid address: '[::1' in '[::1:19999'"),
        ("[]:19999", false, "'stats socket' : invalid address: '[]' in '[]:19999'"),
        ("dgram@127.0.0.1:80", false, "'stats socket' : invalid address: 'dgram@127.0.0.1' in 'dgram@127.0.0.1:80'"),
        ("127.0.0.1:x80", false, "'stats socket' : invalid character 'x' in port number 'x80' in '127.0.0.1:x80'"),
        ("127.0.0.1:1-99999", false, "'stats socket' : invalid port '99999'"),
        ("127.0.0.1:1-5x", false, "'stats socket' : invalid character 'x' in port number '5x' in '127.0.0.1:1-5x'"),
        ("[::1]", false, "'stats socket' : missing port specification in '[::1]'"),
        ("quic+127.0.0.1:19999", false, "not supported by Ibex"),
        ("quic4@127.0.0.1:19999", false, "not supported by Ibex"),
        ("rhttp@x", false, "not supported by Ibex"),
        ("mptcp4@127.0.0.1:19999", false, "not supported by Ibex"),
    ] {
        let (got, err) = check(a);
        assert_eq!(got, ok, "`stats socket {a}`: {err}");
        assert!(err.contains(text), "`stats socket {a}`: expected {text:?} in: {err}");
    }
}

/// A TCP or abstract address that cannot be bound stops the start, as a unix path does.
#[test]
fn an_unbindable_tcp_or_abstract_address_stops_the_start() {
    let abns = format!("ibex-t246-busy-{}", std::process::id());
    for (lines, text) in [
        ("\tstats socket 192.0.2.1:19999".to_string(), "protocol tcpv4: cannot bind socket"),
        ("\tstats socket ipv6@[2001:db8::1]:19999".to_string(), "protocol tcpv6: cannot bind socket"),
        (format!("\tstats socket abns@{abns}\n\tstats socket abns@{abns}"), "protocol abns: cannot bind UNIX socket"),
    ] {
        let f = cfg(&lines);
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).output().expect("run");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{lines}: started");
        assert!(err.contains(text), "{lines}: expected {text:?} in {err}");
    }
}

/// `-x`: the new process takes the TCP CLI listener over from the old one with the others
/// (`_getsocks`), so connections queued on it are not reset when the old one exits.
#[test]
fn x_hands_the_tcp_stats_socket_over() {
    let p = common::reserve_port();
    let dir = tempfile::TempDir::new().expect("dir");
    let sock = dir.path().join("s.sock");
    let lines = format!(
        "\tstats socket {} level admin expose-fd listeners\n\tstats socket 127.0.0.1:{p} level admin",
        sock.display()
    );
    let a: SocketAddr = format!("127.0.0.1:{p}").parse().expect("addr");
    let (mut old, f) = start(&lines, &[]);
    let _ = tcp(a);
    let _ = wait("unix CLI", || UnixStream::connect(&sock).ok());
    let mut new = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .args(["-x".to_string(), sock.display().to_string(), "-sf".to_string(), old.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let end = Instant::now() + Duration::from_secs(10);
    while old.try_wait().expect("wait").is_none() {
        assert!(Instant::now() < end, "the old process never exited");
        assert!(new.try_wait().expect("wait").is_none(), "the new process failed to start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let info = ask(tcp(a), "show info");
    assert!(info.contains(&format!("Pid: {}", new.id())), "{info}");
    common::stop(&mut new);
    let mut err = String::new();
    let _ = new.stderr.take().expect("stderr").read_to_string(&mut err);
    assert!(err.contains("took over 1 listening socket(s)"), "the TCP CLI was not handed over: {err}");
}
